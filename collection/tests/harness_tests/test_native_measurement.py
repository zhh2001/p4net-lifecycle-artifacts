"""Check native observer wiring using protocol fixtures and synthetic resources."""

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import measure, native_measurement, spec, supervisor
from harness.resources import ProcessTarget

from harness_tests.test_measure import Clock, observation


def clean(manifest):
    return {key: [] for key in supervisor.RESOURCE_KEYS}


def targets(manifest, worker, event):
    return [
        ProcessTarget(worker["pid"], worker["start_ticks"], "worker"),
        *[ProcessTarget(1_000_000 + i, i, "bmv2") for i in range(manifest["groups"])],
    ]


class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = spec.create(Path(self.temp.name) / "run", configuration_profile="matched-v1")
        self.manifest = spec.load(self.path)
        self.clock = Clock()

    def recorder(self):
        return measure.Recorder(
            {
                "run_id": self.manifest["run_id"],
                "session": 1,
                "tool": "p4net",
                "python": "3.12",
                "input_lock_sha256": "a" * 64,
                "workload": "scale",
                "switches": 1,
                "configuration_profile": "matched-v1",
                "build_mode": "native-source-cold",
                "fault": None,
            },
            mode="synthetic-validation",
            clock_domain="synthetic-clock",
            clock_ns=self.clock,
        )

    def observer(self, **kwargs):
        return native_measurement.Observation(
            recorder=self.recorder(), select_targets=targets, **kwargs
        )

    def code(self, *, valid=True, hang=False):
        hosts = self.manifest["host_names"]
        rows = [
            {"schema_version": 1, "run_id": self.manifest["run_id"], "event": "starting"},
            {
                "schema_version": 1,
                "run_id": self.manifest["run_id"],
                "event": "ready",
                "checks": [
                    {"src": hosts[0], "dst": hosts[1], "ok": valid},
                    {"src": hosts[1], "dst": hosts[0], "ok": valid},
                ],
            },
        ]
        code = "import json,sys,time,signal\n"
        if hang:
            code += "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
        code += f"rows={rows!r}\nfor row in rows: print(json.dumps(row),flush=True)\n"
        code += "sys.stdin.readline()\n"
        if hang:
            return code + "time.sleep(10)\n"
        stopped = {"schema_version": 1, "run_id": self.manifest["run_id"], "event": "stopped"}
        return code + f"print(json.dumps({stopped!r}),flush=True)\n"

    def run_worker(self, observer, *, valid=True, hang=False, audit=clean):
        return supervisor.run(
            self.path,
            worker_command=[sys.executable, "-c", self.code(valid=valid, hang=hang)],
            ready_timeout=2,
            stop_timeout=0.05 if hang else 1,
            audit_fn=audit,
            observation=observer,
        )

    def test_boundary_mode_never_reads_a_clock_or_resource_window(self):
        observer = native_measurement.Observation(select_targets=targets)
        with (
            patch.object(measure, "sample_window", side_effect=AssertionError("live sample")),
            patch.object(measure.time, "monotonic_ns", side_effect=AssertionError("live clock")),
        ):
            result = self.run_worker(observer)
        self.assertTrue(result["ok"])
        self.assertFalse(result["observation"]["performance_samples"])
        self.assertNotIn("markers", result["observation"])
        self.assertNotIn("metrics", result["observation"])
        self.assertEqual(result["observation"]["issues"], [])

    def test_synthetic_window_flows_through_native_ready_before_shutdown(self):
        def sample(items):
            return measure.sample_window(
                items,
                mode="synthetic-validation",
                clock_domain="synthetic-clock",
                clock_ticks=100,
                clock_ns=self.clock,
                sleep=self.clock.sleep,
                read=observation,
            )

        observer = self.observer(sampler=sample)
        result = self.run_worker(observer)
        record = result["observation"]
        self.assertTrue(result["ok"])
        self.assertEqual(record["measurement_issues"], [])
        self.assertEqual(len(record["resource_windows"]["initial"]["rounds"]), 101)
        self.assertIn("idle_bmv2_cpu_percent", record["metrics"])
        self.assertIn("stop_to_audit_ns", record["metrics"])
        self.assertIsNone(record["framework_complete"])
        primary = json.loads((self.path.parent / "measurement-primary.json").read_text())
        self.assertEqual(primary["status"], "completed")
        self.assertNotIn("safety_start", primary["markers"])

    def test_invalid_readiness_cannot_supply_latency_or_start_sampling(self):
        sampler = unittest.mock.Mock()
        observer = self.observer(sampler=sampler)
        result = self.run_worker(observer, valid=False)
        self.assertFalse(result["ok"])
        sampler.assert_not_called()
        self.assertNotIn("task_to_ready_ns", result["observation"]["metrics"])

    def test_resource_failure_does_not_change_successful_task(self):
        observer = self.observer()
        observer.select_targets = lambda *args: (_ for _ in ()).throw(ProcessLookupError("gone"))
        result = self.run_worker(observer)
        self.assertTrue(result["ok"])
        self.assertIn("task_to_ready_ns", result["observation"]["metrics"])
        self.assertTrue(result["observation"]["measurement_issues"])
        self.assertEqual(result["observation"]["resource_windows"], {})

    def test_original_live_audit_precedes_escalation_and_has_no_exit_latency(self):
        observer = self.observer()
        audited = []

        def audit(manifest):
            audited.append({"seen": set(observer.seen)})
            return clean(manifest)

        result = self.run_worker(observer, hang=True, audit=audit)
        record = result["observation"]
        self.assertFalse(result["ok"])
        self.assertNotIn("worker_exit", record["markers"])
        self.assertNotIn("stop_to_exit_ns", record["metrics"])
        self.assertIn("safety_start", record["markers"])
        ordinary = next(
            item for item in audited if ("initial", "ordinary_audit_start") in item["seen"]
        )
        self.assertNotIn(("initial", "safety_start"), ordinary["seen"])
        primary = json.loads((self.path.parent / "measurement-primary.json").read_text())
        self.assertNotIn("safety_start", primary["markers"])

    def test_mismatched_metadata_refuses_launch(self):
        observer = self.observer()
        observer.recorder.metadata["run_id"] = "another-run"
        with patch.object(supervisor.subprocess, "Popen") as launch:
            with self.assertRaisesRegex(ValueError, "differs"):
                self.run_worker(observer)
            launch.assert_not_called()

    def test_framework_completion_does_not_hide_invalid_fault_condition(self):
        observer = self.observer()
        result = observer.finish({"ok": False, "framework_complete": True})
        self.assertEqual(result["status"], "failed")

    def test_missing_receive_clock_cannot_be_replaced_with_a_later_stamp(self):
        observer = self.observer()
        observer.mark("worker_launch")
        observer.received({"event": "ready"}, observed_ns=None)
        observer.ready(self.manifest, {}, {})
        record = observer.finish({"ok": True})
        self.assertNotIn("task_to_ready_ns", record["metrics"])
        self.assertTrue(record["measurement_issues"])

    def test_live_factory_is_opt_in_and_rejects_synthetic_mode(self):
        with self.assertRaisesRegex(ValueError, "pilot or formal"):
            native_measurement.measured_observation(
                {}, mode="synthetic-validation", clock_domain="x"
            )
        with self.assertRaisesRegex(ValueError, "schedule"):
            native_measurement.measured_observation(
                {}, mode="pilot", clock_domain="x", interval_ns=0
            )

    def test_boundary_mode_rejects_out_of_order_events_without_accepting_ready(self):
        observer = native_measurement.Observation(select_targets=targets)
        observer.received({"event": "ready"})
        observer.ready(self.manifest, {"pid": 10, "start_ticks": 1}, {})
        observer.mark("ordinary_audit_end")
        observer.mark("worker_exit")
        record = observer.finish({"ok": True})
        self.assertTrue(record["issues"])
        self.assertEqual(record["targets"], {})
        self.assertEqual(record["boundaries"], [])

    def test_sampler_cannot_substitute_another_process_identity(self):
        def sample(items):
            window = measure.sample_window(
                items,
                mode="synthetic-validation",
                clock_domain="synthetic-clock",
                clock_ticks=100,
                clock_ns=self.clock,
                sleep=self.clock.sleep,
                read=observation,
            )
            window["targets"][0]["start_ticks"] += 1
            return window

        result = self.run_worker(self.observer(sampler=sample))
        self.assertTrue(result["ok"])
        self.assertEqual(result["observation"]["resource_windows"], {})
        self.assertTrue(result["observation"]["measurement_issues"])

    def test_observation_inventory_write_failure_preserves_worker_cleanup(self):
        observer = self.observer()
        original = supervisor.write_json
        children = []
        popen = supervisor.subprocess.Popen

        def spawn(*args, **kwargs):
            child = popen(*args, **kwargs)
            children.append(child)
            return child

        def save(path, value):
            if path.name == "inventory-ordinary-after.json":
                raise PermissionError("observation output unavailable")
            return original(path, value)

        try:
            with (
                patch.object(supervisor, "write_json", side_effect=save),
                patch.object(supervisor.subprocess, "Popen", side_effect=spawn),
            ):
                result = self.run_worker(observer, hang=True)
            self.assertFalse(result["ok"])
            self.assertIsNotNone(children[0].poll())
            self.assertTrue((self.path.parent / "result.json").exists())
            self.assertTrue(
                any(
                    isinstance(issue, dict) and issue.get("context") == "save ordinary inventory"
                    for issue in result["observation"]["measurement_issues"]
                )
            )
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=2)
                for stream in (child.stdin, child.stdout):
                    if stream is not None and not stream.closed:
                        stream.close()


class ReceiveBoundaryTests(unittest.TestCase):
    def test_receive_stamp_precedes_json_decode_and_protocol_validation(self):
        read_fd, write_fd = os.pipe()
        os.write(write_fd, b'{"event":"ready"}\n')
        os.close(write_fd)
        stamps = []
        original = json.loads

        def decode(*args, **kwargs):
            stamps.append("decode")
            return original(*args, **kwargs)

        def clock():
            stamps.append("clock")
            return 123

        with os.fdopen(read_fd, "rb", buffering=0) as stream:
            reader = supervisor.EventReader(stream, clock_ns=clock)
            try:
                with patch.object(supervisor.json, "loads", side_effect=decode):
                    self.assertEqual(reader.read(time.monotonic() + 1), {"event": "ready"})
                self.assertEqual(reader.last_received_ns, 123)
                self.assertEqual(stamps, ["clock", "decode"])
            finally:
                reader.close()
