"""Exercise episode observation hooks with protocol workers and synthetic samples."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import episode, faults, measure, native_measurement, spec

from harness_tests.test_episodes import clean
from harness_tests.test_measure import Clock, observation
from harness_tests.test_native_measurement import targets


class EpisodeObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = spec.create(Path(self.temp.name) / "run", configuration_profile="matched-v1")
        self.manifest = spec.load(self.path)
        self.clock = Clock()

    def run_episode(self, fault="normal-control", *, bad_json=False):
        self.manifest["episode_fault"] = fault
        if bad_json:
            self.manifest["test_behavior"] = "bad-json"
        self.path.write_text(json.dumps(self.manifest))
        recorder = measure.Recorder(
            {
                "run_id": self.manifest["run_id"],
                "session": 1,
                "tool": "p4net",
                "python": "3.12",
                "input_lock_sha256": "a" * 64,
                "workload": "fault",
                "switches": 1,
                "configuration_profile": "matched-v1",
                "build_mode": "native-source-cold",
                "fault": fault,
            },
            mode="synthetic-validation",
            clock_domain="synthetic-clock",
            clock_ns=self.clock,
        )

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

        observer = native_measurement.Observation(
            recorder=recorder, sampler=sample, select_targets=targets
        )
        with (
            patch.object(faults, "require_enclosure"),
            patch.object(episode.audit, "capture", side_effect=clean),
        ):
            result = episode.run_episode(
                self.path,
                Path(sys.executable),
                "harness_tests.fixtures.episode_worker",
                observation=observer,
            )
        return result

    def test_initial_and_restart_windows_use_different_worker_identities(self):
        result = self.run_episode()
        record = result["observation"]
        self.assertTrue(result["recovery_success"])
        self.assertEqual(record["measurement_issues"], [])
        self.assertEqual(set(record["resource_windows"]), {"initial", "restart"})
        first = record["resource_windows"]["initial"]["targets"][0]
        second = record["resource_windows"]["restart"]["targets"][0]
        self.assertNotEqual(first["pid"], second["pid"])
        self.assertIn("stop_to_restart_ready_ns", record["metrics"])
        primary = json.loads((self.path.parent / "measurement-primary.json").read_text())
        self.assertNotIn("safety_start", primary["markers"])
        self.assertIn("safety_start", record["markers"])

    def test_failed_protocol_is_retained_before_safety_without_latency(self):
        result = self.run_episode(bad_json=True)
        record = result["observation"]
        self.assertFalse(result["framework_complete"])
        self.assertNotIn("task_to_ready_ns", record["metrics"])
        self.assertTrue((self.path.parent / "measurement-primary.json").exists())
        self.assertNotIn(
            "safety_start",
            json.loads((self.path.parent / "measurement-primary.json").read_text())["markers"],
        )

    def test_startup_condition_uses_initial_launch_recovery_anchor(self):
        result = self.run_episode("invalid-p4")
        markers = result["observation"]["markers"]
        self.assertIn("condition_ready", markers)
        self.assertIn("initial_launch_to_restart_ready_ns", result["observation"]["metrics"])

    def test_late_exit_after_live_audit_does_not_supply_ordinary_stop_latency(self):
        recorder = measure.Recorder(
            {
                "run_id": "late",
                "session": 1,
                "tool": "p4net",
                "python": "3.12",
                "input_lock_sha256": "a" * 64,
                "workload": "scale",
                "switches": 1,
                "configuration_profile": "matched-v1",
                "build_mode": "cold",
                "fault": None,
            },
            mode="synthetic-validation",
            clock_domain="synthetic-clock",
            clock_ns=self.clock,
        )
        for name in (
            "worker_launch",
            "stop_request",
            "stop_sent",
            "ordinary_audit_start",
            "ordinary_audit_end",
            "worker_exit",
        ):
            recorder.mark(name)
        record = recorder.finish("timeout")
        self.assertNotIn("stop_to_exit_ns", record["metrics"])
        self.assertNotIn("stop_to_audit_ns", record["metrics"])

    def test_failed_intervention_has_no_applied_anchor(self):
        attempt = object.__new__(episode.Attempt)
        observer = native_measurement.Observation()
        attempt.observation = observer
        attempt.phase = "initial"
        observer.mark("worker_launch")

        def fail():
            raise ProcessLookupError("worker exited")

        with self.assertRaises(ProcessLookupError):
            attempt.intervene(fail)
        self.assertIn(("initial", "intervention_failed"), observer.seen)
        self.assertNotIn(("initial", "intervention_applied"), observer.seen)
