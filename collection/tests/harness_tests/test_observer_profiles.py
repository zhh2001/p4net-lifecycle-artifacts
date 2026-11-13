"""Check equal holds and anchored sampling with injected clocks and process data."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from harness import measure, observer_profiles
from harness.resources import ProcessTarget

from harness_tests.test_measure import Clock, metadata, observation

TARGETS = (ProcessTarget(101, 1, "worker"), ProcessTarget(102, 2, "bmv2"))


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.manifest = {
            "run_id": "synthetic-run",
            "groups": 1,
            "configuration_profile": "matched-v1",
        }

    def make(self, profile="S", **kwargs):
        options = {
            "mode": "synthetic-validation",
            "clock_domain": "synthetic-clock",
            "clock_ns": self.clock,
            "sleep": self.clock.sleep,
            "read": observation,
            "select_targets": lambda *_: TARGETS,
        }
        options.update(kwargs)
        return observer_profiles.profile_observation(profile, metadata(), **options)

    def ready(self, observer):
        observer.bind(self.manifest)
        observer.mark("worker_launch", observed_ns=self.clock())
        observer.received({"event": "ready"}, observed_ns=self.clock())
        observer.ready(self.manifest, {}, {})

    def test_construction_does_not_read_clocks_resources_or_sleep(self):
        unexpected = Mock(side_effect=AssertionError("unexpected operation"))
        for profile in observer_profiles.PROFILES:
            self.make(profile, clock_ns=unexpected, sleep=unexpected, read=unexpected)
        unexpected.assert_not_called()

    def test_all_profiles_have_one_ten_second_hold_from_verified_ready(self):
        for profile in observer_profiles.PROFILES:
            with self.subTest(profile=profile):
                self.clock.now = 1_234
                observer = self.make(profile)
                self.ready(observer)
                hold = observer.profile_record()["holds"]["initial"]
                self.assertEqual(hold["anchor_ns"], 1_234)
                self.assertEqual(hold["scheduled_end_ns"], 10_000_001_234)
                self.assertEqual(self.clock.now, 10_000_001_234)
                self.assertTrue(hold["complete"])
                self.assertEqual(hold["extension_ns"], 0)
                self.assertEqual(observer.issues, [])
                boundaries = [item["boundary"] for item in observer.boundaries]
                self.assertLess(
                    boundaries.index("ready_validated"), boundaries.index("targets_verified")
                )
                record = observer.finish({"ok": True})
                if profile == "B":
                    self.assertNotIn("markers", record)
                    self.assertNotIn("holds", record)
                    self.assertFalse(record["performance_samples"])
                else:
                    windows = record["resource_windows"]
                    self.assertEqual(set(windows), {"initial"} if profile == "S" else set())
                    if profile == "S":
                        window = windows["initial"]
                        self.assertEqual(len(window["rounds"]), 101)
                        self.assertEqual(window["window_start_ns"], hold["anchor_ns"])
                        self.assertEqual(window["scheduled_end_ns"], hold["scheduled_end_ns"])

    def test_only_sampled_profile_reads_resources(self):
        reader = Mock(wraps=observation)
        for profile in ("B", "T"):
            self.clock.now = 0
            self.ready(self.make(profile, read=reader))
        reader.assert_not_called()
        self.ready(self.make("S", read=reader))
        self.assertEqual(reader.call_count, 202)

    def test_profile_callback_tail_is_reported_separately_from_sample_overrun(self):
        original = measure.sample_window

        def with_tail(*args, **kwargs):
            result = original(*args, **kwargs)
            self.clock.now += 55
            return result

        observer = self.make()
        with patch.object(measure, "sample_window", side_effect=with_tail):
            self.ready(observer)
        self.assertEqual(observer.holds["initial"]["extension_ns"], 55)
        self.assertEqual(observer.recorder.windows["initial"]["overrun_ns"], 0)

    def test_invalid_ready_or_targets_do_not_start_a_hold(self):
        for profile in observer_profiles.PROFILES:
            observer = self.make(profile)
            observer.ready(self.manifest, {}, {})
            self.assertEqual(observer.holds, {})
            self.assertEqual(self.clock.now, 0)
            observer = self.make(profile, select_targets=lambda *_: TARGETS[:1])
            self.ready(observer)
            self.assertEqual(observer.holds, {})
            self.assertEqual(self.clock.now, 0)
            self.assertTrue(observer.issues)

    def test_duplicate_ready_does_not_repeat_hold(self):
        observer = self.make()
        self.ready(observer)
        observer.ready(self.manifest, {}, {})
        self.assertEqual(self.clock.now, 10_000_000_000)
        self.assertEqual(len(observer.holds), 1)
        self.assertTrue(observer.issues)

    def test_hold_failure_remains_measurement_issue(self):
        observer = self.make("B", sleep=lambda _: None)
        self.ready(observer)
        self.assertFalse(observer.holds["initial"]["complete"])
        self.assertIn("did not advance", observer.issues[0]["message"])
        self.assertEqual(observer.finish({"ok": True})["record_type"], "native-boundary-validation")

    def test_failed_sample_preserves_native_outcome_and_incomplete_window(self):
        def bad_read(target, **kwargs):
            return {**observation(target, **kwargs), "ok": False}

        observer = self.make(read=bad_read)
        self.ready(observer)
        self.assertFalse(observer.holds["initial"]["complete"])
        result = observer.finish({"ok": True})
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["resource_windows"]["initial"]["role_metrics"], {})

    def test_metadata_mismatch_is_rejected_for_each_profile(self):
        for profile in observer_profiles.PROFILES:
            observer = self.make(profile)
            with self.assertRaisesRegex(ValueError, "differs"):
                observer.bind({**self.manifest, "run_id": "another-run"})

    def test_boundary_profile_pilot_still_requires_enclosure_and_is_marked_performance(self):
        observer = self.make("B", mode="pilot")
        with patch(
            "harness.faults.require_enclosure", side_effect=ValueError("enclosure")
        ) as guard:
            with self.assertRaisesRegex(ValueError, "enclosure"):
                observer.bind(self.manifest)
            guard.assert_called_once()
        self.assertTrue(observer.profile_record()["performance_samples"])
        self.assertFalse(observer.finish({"ok": True})["performance_samples"])

    def test_primary_callback_runs_once_after_the_file_is_readable(self):
        seen = []

        def published(path):
            seen.append(json.loads(path.read_text())["record_type"])

        observer = self.make("B", on_primary_published=published)
        with tempfile.TemporaryDirectory() as directory:
            observer.checkpoint(Path(directory) / "primary.json", {"ok": True})
            observer.checkpoint(Path(directory) / "second.json", {"ok": True})
        self.assertEqual(seen, ["native-boundary-validation"])

    def test_failed_primary_write_does_not_notify_and_allows_later_success(self):
        callback = Mock()
        observer = self.make("B", on_primary_published=callback)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "primary.json"
            path.write_text("existing")
            observer.checkpoint(path, {"ok": True})
            callback.assert_not_called()
            self.assertEqual(path.read_text(), "existing")
            observer.checkpoint(Path(directory) / "later.json", {"ok": True})
        callback.assert_called_once()
        self.assertEqual(observer.issues[0]["context"], "save primary observation")

    def test_failed_primary_callback_is_recorded_without_changing_native_status(self):
        callback = Mock(side_effect=OSError("closed channel"))
        observer = self.make("T", on_primary_published=callback)
        with tempfile.TemporaryDirectory() as directory:
            observer.checkpoint(Path(directory) / "primary.json", {"ok": True})
            observer.checkpoint(Path(directory) / "other.json", {"ok": True})
        callback.assert_called_once()
        result = observer.finish({"ok": True})
        self.assertEqual(result["status"], "completed")
        self.assertEqual(
            result["native_observation"]["issues"][0]["context"], "reference primary publication"
        )

    def test_configuration_rejects_invalid_values_without_clock_reads(self):
        unexpected = Mock(side_effect=AssertionError("clock read"))
        cases = (
            {"mode": "native-validation"},
            {"clock_domain": " "},
            {"duration_ns": True},
            {"interval_ns": 0},
            {"duration_ns": 1, "interval_ns": 2},
            {"clock_ticks": 0},
            {"on_primary_published": False},
            {"read": None},
        )
        for options in cases:
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.make(clock_ns=unexpected, **options)
        unexpected.assert_not_called()

    def test_profile_record_is_a_copy_and_does_not_modify_boundary_record(self):
        observer = self.make("B")
        self.ready(observer)
        record = observer.profile_record()
        record["holds"]["initial"]["complete"] = False
        self.assertTrue(observer.holds["initial"]["complete"])
        self.assertNotIn("holds", observer.finish({"ok": True}))

    def test_restart_has_a_second_independent_ten_second_hold(self):
        for profile in observer_profiles.PROFILES:
            with self.subTest(profile=profile):
                self.clock.now = 0
                observer = self.make(profile)
                self.ready(observer)
                for boundary in ("worker_exit", "ordinary_audit_start", "ordinary_audit_end"):
                    observer.mark(boundary, observed_ns=self.clock())
                self.clock.now += 75
                observer.mark("worker_launch", phase="restart", observed_ns=self.clock())
                observer.received({"event": "ready"}, phase="restart", observed_ns=self.clock())
                observer.ready(self.manifest, {}, {}, phase="restart")
                self.assertEqual(observer.issues, [])
                self.assertEqual(self.clock.now, 20_000_000_075)
                self.assertEqual(observer.holds["restart"]["anchor_ns"], 10_000_000_075)
                if profile == "S":
                    self.assertEqual(set(observer.recorder.windows), {"initial", "restart"})

    def test_hold_anchor_follows_target_validation_cost(self):
        def delayed_targets(*_):
            self.clock.now += 125
            return TARGETS

        observer = self.make(select_targets=delayed_targets)
        self.ready(observer)
        self.assertEqual(observer.holds["initial"]["anchor_ns"], 125)
        self.assertEqual(self.clock.now, 10_000_000_125)

    def test_backward_profile_clock_is_retained_as_measurement_failure(self):
        ticks = iter((100, 99))
        observer = self.make("B", clock_ns=lambda: next(ticks))
        self.ready(observer)
        self.assertFalse(observer.holds["initial"]["complete"])
        self.assertIn("moved backward", observer.issues[0]["message"])


class AnchoredWindowTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()

    def sample(self, **options):
        kwargs = {
            "mode": "synthetic-validation",
            "clock_domain": "synthetic-clock",
            "clock_ticks": 100,
            "clock_ns": self.clock,
            "sleep": self.clock.sleep,
            "read": observation,
            "duration_ns": 1_000_000_000,
            "interval_ns": 100_000_000,
        }
        kwargs.update(options)
        return measure.sample_window(TARGETS, **kwargs)

    def test_future_anchor_waits_and_produces_complete_endpoints(self):
        result = self.sample(start_ns=50)
        self.assertTrue(result["complete"])
        self.assertEqual(len(result["rounds"]), 11)
        self.assertEqual(result["window_start_ns"], 50)
        self.assertEqual(result["rounds"][0][0]["sample_start_ns"], 50)
        self.assertEqual(self.clock.now, 1_000_000_050)

    def test_late_anchor_reports_missing_deadlines_without_catchup(self):
        self.clock.now = 250_000_000
        result = self.sample(start_ns=0)
        self.assertFalse(result["complete"])
        self.assertEqual(result["missed_deadlines"], 3)
        self.assertEqual(len(result["rounds"]), 8)
        self.assertEqual(result["role_metrics"], {})
        self.assertEqual(result["rounds"][0][0]["sample_start_ns"], 300_000_000)
        self.assertEqual(self.clock.now, 1_000_000_000)

    def test_expired_anchor_rejects_before_reading(self):
        self.clock.now = 1_000_000_000
        reader = Mock()
        with self.assertRaisesRegex(ValueError, "expired"):
            self.sample(start_ns=0, read=reader)
        reader.assert_not_called()

    def test_anchored_wait_handles_early_wakeup(self):
        def early(seconds):
            self.clock.now += max(1, round(seconds * 1_000_000_000) // 2)

        result = self.sample(start_ns=100, sleep=early)
        self.assertTrue(result["complete"])
        self.assertEqual(result["rounds"][0][0]["sample_start_ns"], 100)
        self.assertEqual(self.clock.now, 1_000_000_100)

    def test_anchored_wait_rejects_stalled_clock(self):
        with self.assertRaisesRegex(ValueError, "did not advance"):
            self.sample(start_ns=100, sleep=lambda _: None)

    def test_anchor_cannot_hide_backward_clock_after_entry(self):
        sequence = iter((100, 99))
        with self.assertRaisesRegex(ValueError, "backward"):
            self.sample(start_ns=1000, clock_ns=lambda: next(sequence))

    def test_default_schedule_retains_legacy_output(self):
        original = self.sample()
        self.clock.now = 0
        anchored = self.sample(start_ns=0)
        self.assertEqual(original, anchored)

    def test_invalid_anchor_is_rejected(self):
        for anchor in (-1, True, 0.5):
            with self.subTest(anchor=anchor), self.assertRaises(ValueError):
                self.sample(start_ns=anchor)
