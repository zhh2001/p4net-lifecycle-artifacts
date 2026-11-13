"""Validate measurement logic with synthetic clocks and process observations."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import aggregate, measure
from harness.resources import ProcessTarget


class Clock:
    def __init__(self) -> None:
        self.now = 0

    def __call__(self) -> int:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += round(seconds * 1_000_000_000)


def metadata(fault=None):
    return {
        "run_id": "synthetic-run",
        "session": 1,
        "tool": "p4net",
        "workload": "scale" if fault is None else "fault",
        "switches": 1,
        "configuration_profile": "matched-v1",
        "build_mode": "native-source-empty-cache",
        "fault": fault,
        "python": "3.10.20",
        "input_lock_sha256": "a" * 64,
    }


def observation(target, *, clock_ns, **_kwargs):
    at = clock_ns()
    return {
        "record_type": "process-resource-sample",
        "ok": True,
        "target": {"pid": target.pid, "start_ticks": target.start_ticks, "role": target.role},
        "clock_domain": "synthetic-clock",
        "sample_start_ns": at,
        "sample_end_ns": at,
        "cpu_midpoint_ns": at,
        "user_ticks": at // 10_000_000,
        "system_ticks": 0,
        "cpu_ticks": at // 10_000_000,
        "rss_bytes": 4096,
        "pss_bytes": 2048,
    }


class RecorderTests(unittest.TestCase):
    def make(self, fault=None):
        clock = Clock()
        return measure.Recorder(
            metadata(fault),
            mode="synthetic-validation",
            clock_domain="synthetic-clock",
            clock_ns=clock,
        ), clock

    def test_receive_timestamp_precedes_validation_and_audit(self) -> None:
        recorder, clock = self.make()
        recorder.mark("worker_launch", observed_ns=10)
        recorder.mark("ready_received", observed_ns=30)
        clock.now = 1000
        recorder.accept_ready()
        recorder.mark("stop_request", observed_ns=1000)
        recorder.mark("stop_sent", observed_ns=1002)
        recorder.mark("worker_exit", observed_ns=1100)
        recorder.mark("ordinary_audit_start", observed_ns=1110)
        recorder.mark("ordinary_audit_end", observed_ns=1150)
        result = recorder.finish("completed")
        self.assertEqual(result["metrics"]["task_to_ready_ns"], 20)
        self.assertEqual(result["metrics"]["stop_to_exit_ns"], 100)
        self.assertEqual(result["metrics"]["stop_to_audit_ns"], 150)
        self.assertEqual(result["metrics"]["exit_to_audit_ns"], 50)
        self.assertFalse(result["performance_samples"])
        self.assertEqual(
            aggregate.summarize([result], "synthetic-validation")["groups"][0]["overall"][
                "status_counts"
            ]["completed"],
            1,
        )

    def test_unvalidated_event_cannot_supply_readiness_metric(self) -> None:
        recorder, _ = self.make()
        recorder.mark("worker_launch", observed_ns=1)
        recorder.mark("ready_received", observed_ns=2)
        self.assertNotIn("task_to_ready_ns", recorder.finish("failed")["metrics"])

    def test_rescue_cannot_finish_ordinary_cleanup(self) -> None:
        recorder, _ = self.make()
        recorder.mark("worker_launch", observed_ns=1)
        recorder.mark("stop_request", observed_ns=2)
        recorder.mark("stop_sent", observed_ns=3)
        recorder.mark("ordinary_audit_start", observed_ns=4)
        recorder.mark("ordinary_audit_end", observed_ns=5)
        recorder.mark("safety_start", observed_ns=6)
        with self.assertRaises(ValueError):
            recorder.mark("worker_exit", observed_ns=7)
        result = recorder.finish("timeout")
        self.assertNotIn("stop_to_audit_ns", result["metrics"])
        self.assertNotIn("stop_to_exit_ns", result["metrics"])
        self.assertTrue(result["measurement_issues"])

    def test_marker_order_duplicates_and_failed_delivery(self) -> None:
        recorder, _ = self.make()
        with self.assertRaises(ValueError):
            recorder.mark("ready_received", observed_ns=0)
        recorder.mark("worker_launch", observed_ns=10)
        with self.assertRaises(ValueError):
            recorder.mark("worker_launch", observed_ns=11)
        with self.assertRaises(ValueError):
            recorder.mark("worker_exit", observed_ns=9)
        recorder.mark("stop_request", observed_ns=12)
        recorder.mark("stop_failed", observed_ns=13)
        with self.assertRaises(ValueError):
            recorder.mark("stop_sent", observed_ns=14)
        recorder.mark("worker_exit", observed_ns=15)
        self.assertNotIn("stop_to_exit_ns", recorder.finish("failed")["metrics"])

    def test_recovery_uses_applied_fault_and_validated_restart_ready(self) -> None:
        recorder, _ = self.make("kill-bmv2")
        recorder.mark("worker_launch", observed_ns=1)
        recorder.mark("ready_received", observed_ns=2)
        recorder.accept_ready()
        for name, stamp in (
            ("intervention_start", 10),
            ("intervention_applied", 12),
            ("exit_confirmed", 20),
            ("worker_exit", 25),
            ("ordinary_audit_start", 26),
            ("ordinary_audit_end", 30),
            ("restart_launch", 40),
            ("restart_ready_received", 60),
        ):
            recorder.mark(name, observed_ns=stamp)
        recorder.accept_ready(restart=True)
        result = recorder.finish("failed", recovery_success=False)
        self.assertEqual(result["metrics"]["fault_to_restart_ready_ns"], 48)
        self.assertFalse(result["recovery_success"])

    def test_startup_condition_has_a_different_recovery_anchor(self) -> None:
        recorder, _ = self.make("occupied-grpc")
        for name, stamp in (
            ("condition_ready", 1),
            ("worker_launch", 10),
            ("worker_exit", 15),
            ("ordinary_audit_start", 16),
            ("ordinary_audit_end", 20),
            ("restart_launch", 30),
            ("restart_ready_received", 50),
        ):
            recorder.mark(name, observed_ns=stamp)
        recorder.accept_ready(restart=True)
        result = recorder.finish("completed")
        self.assertEqual(result["metrics"]["initial_launch_to_restart_ready_ns"], 40)
        self.assertNotIn("fault_to_restart_ready_ns", result["metrics"])

    def test_output_does_not_replace_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.json"
            measure.write_record(path, {"original": True})
            with self.assertRaises(FileExistsError):
                measure.write_record(path, {"replacement": True})
            self.assertEqual(json.loads(path.read_text()), {"original": True})

    def test_late_readiness_and_commands_after_exit_are_rejected(self) -> None:
        for marker in ("ready_received", "stop_request", "intervention_start"):
            recorder, _ = self.make()
            recorder.mark("worker_launch", observed_ns=1)
            recorder.mark("worker_exit", observed_ns=2)
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                recorder.mark(marker, observed_ns=3)

    def test_synthetic_records_require_an_explicit_clock(self) -> None:
        with self.assertRaisesRegex(ValueError, "test clock"):
            measure.Recorder(metadata(), mode="synthetic-validation", clock_domain="test")


class WindowTests(unittest.TestCase):
    def run_window(self, read=observation, **kwargs):
        clock = Clock()
        return measure.sample_window(
            [
                ProcessTarget(10, 1, "worker"),
                ProcessTarget(11, 2, "bmv2"),
                ProcessTarget(12, 3, "bmv2"),
            ],
            mode="synthetic-validation",
            clock_domain="synthetic-clock",
            clock_ticks=100,
            clock_ns=clock,
            sleep=clock.sleep,
            read=read,
            **kwargs,
        )

    def test_default_window_has_endpoint_samples_and_per_role_sums(self) -> None:
        result = self.run_window()
        self.assertTrue(result["complete"])
        self.assertEqual(len(result["rounds"]), 101)
        self.assertEqual(result["window_end_ns"], 10_000_000_000)
        self.assertEqual(result["role_metrics"]["worker"]["cpu_percent"], 100)
        self.assertEqual(result["role_metrics"]["bmv2"]["cpu_percent"], 200)
        self.assertEqual(result["role_metrics"]["bmv2"]["rss_bytes"], 8192)
        self.assertEqual(result["role_metrics"]["bmv2"]["pss_bytes"], 4096)

    def test_missing_switch_is_retained_without_a_partial_group_total(self) -> None:
        def missing(target, **kwargs):
            if target.pid == 12:
                return {"ok": False, "target": {"pid": 12}, "error": "exited"}
            return observation(target, **kwargs)

        result = self.run_window(read=missing)
        self.assertFalse(result["complete"])
        self.assertEqual(result["role_metrics"], {})
        self.assertEqual(len(result["rounds"]), 101)
        self.assertTrue(result["errors"])

    def test_window_attachment_keeps_tool_outcome_separate(self) -> None:
        meta = metadata()
        meta["switches"] = 2
        recorder = measure.Recorder(
            meta,
            mode="synthetic-validation",
            clock_domain="synthetic-clock",
            clock_ns=Clock(),
        )
        recorder.mark("worker_launch", observed_ns=0)
        recorder.mark("ready_received", observed_ns=0)
        recorder.accept_ready()
        window = self.run_window()
        window["complete"] = False
        recorder.attach_window(window)
        record = recorder.finish("completed")
        self.assertEqual(record["status"], "completed")
        self.assertNotIn("idle_worker_cpu_percent", record["metrics"])
        self.assertTrue(record["measurement_issues"])

    def test_wrong_mode_or_switch_coverage_cannot_be_attached(self) -> None:
        recorder = measure.Recorder(
            metadata(),
            mode="synthetic-validation",
            clock_domain="synthetic-clock",
            clock_ns=Clock(),
        )
        recorder.mark("worker_launch", observed_ns=0)
        recorder.mark("ready_received", observed_ns=0)
        recorder.accept_ready()
        window = self.run_window()
        with self.assertRaisesRegex(ValueError, "expected worker"):
            recorder.attach_window(window)
        window["mode"] = "pilot"
        with self.assertRaisesRegex(ValueError, "record type or mode"):
            recorder.attach_window(window)

    def test_synthetic_default_cannot_read_live_procfs(self) -> None:
        with (
            patch(
                "harness.resources.Path.read_text",
                side_effect=AssertionError("live read forbidden"),
            ),
            self.assertRaisesRegex(ValueError, "live procfs"),
        ):
            measure.sample_window(
                [ProcessTarget(10, 1, "worker"), ProcessTarget(11, 2, "bmv2")],
                mode="synthetic-validation",
                clock_domain="test",
                clock_ticks=100,
            )

    def test_wrong_clock_domain_invalidates_the_resource_window(self) -> None:
        def other_domain(target, **kwargs):
            result = observation(target, **kwargs)
            result["clock_domain"] = "another-domain"
            return result

        result = self.run_window(read=other_domain)
        self.assertFalse(result["complete"])
        self.assertEqual(result["role_metrics"], {})

    def test_endpoint_read_overrun_is_retained(self) -> None:
        def expensive(target, **kwargs):
            clock = kwargs["clock_ns"]
            result = observation(target, **kwargs)
            clock.now += 200_000_000
            return result

        result = self.run_window(read=expensive, duration_ns=1_000_000_000, interval_ns=100_000_000)
        self.assertGreater(result["missed_deadlines"], 0)
        self.assertGreater(result["overrun_ns"], 0)
        self.assertEqual(result["scheduled_end_ns"], 1_000_000_000)
        self.assertFalse(result["complete"])


if __name__ == "__main__":
    unittest.main()
