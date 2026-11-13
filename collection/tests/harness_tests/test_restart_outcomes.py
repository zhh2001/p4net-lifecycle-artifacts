"""Preserve restart outcomes and exclude either phase's unusable measurements."""

import copy
import unittest

from harness import aggregate, measure, native_measurement, native_validation

from harness_tests.test_aggregate import record
from harness_tests.test_measure import metadata


def observed(source):
    recorder = measure.Recorder(
        metadata("normal-control"),
        mode="synthetic-validation",
        clock_domain="synthetic-restart-outcomes",
        clock_ns=lambda: 0,
    )
    recorder.mark("worker_launch", observed_ns=10)
    recorder.mark("ready_received", observed_ns=20)
    recorder.accept_ready()
    recorder.mark("stop_request", observed_ns=30)
    recorder.mark("stop_sent", observed_ns=31)
    recorder.mark("worker_exit", observed_ns=40)
    recorder.mark("ordinary_audit_start", observed_ns=41)
    recorder.mark("ordinary_audit_end", observed_ns=42)
    recorder.mark("restart_launch", observed_ns=50)
    recorder.mark("restart_ready_received", observed_ns=60)
    recorder.accept_ready(restart=True)
    return native_measurement.Observation(recorder=recorder)._record(source)


def source(**changes):
    value = {
        "ok": True,
        "initial": {"ordinary_stop_timeout": False, "ordinary_cleanup_clean": True},
        "restart": {"ordinary_stop_timeout": False, "ordinary_cleanup_clean": True},
        "recovery_success": True,
        "framework_complete": True,
    }
    value.update(changes)
    return value


def functional(value):
    value = copy.deepcopy(value)
    value["performance_samples"] = False
    value["observation"] = native_measurement.Observation()._record(value)
    return value


class RestartOutcomeTests(unittest.TestCase):
    def test_successful_restart_keeps_both_phase_outcomes_and_timing(self):
        native = source()
        before = copy.deepcopy(native)
        value = observed(native)
        self.assertIs(value["restart_ordinary_stop_timeout"], False)
        self.assertIs(value["restart_ordinary_cleanup_clean"], True)
        self.assertIs(value["ordinary_stop_timeout"], False)
        self.assertIs(value["ordinary_cleanup_clean"], True)
        self.assertEqual(value["status"], "completed")
        self.assertEqual(value["metrics"]["task_to_ready_ns"], 10)
        self.assertEqual(value["metrics"]["restart_task_to_ready_ns"], 10)
        self.assertIsNone(aggregate.primary_performance_exclusion(value))
        self.assertEqual(native, before)

    def test_restart_timeout_excludes_the_episode_without_rewriting_native_outcomes(self):
        native = source(
            restart={"ordinary_stop_timeout": True, "ordinary_cleanup_clean": True},
            recovery_success=False,
        )
        before = copy.deepcopy(native)
        value = observed(native)
        self.assertEqual(value["status"], "completed")
        self.assertIs(value["recovery_success"], False)
        self.assertIs(value["framework_complete"], True)
        self.assertIs(value["ordinary_stop_timeout"], False)
        self.assertIs(value["ordinary_cleanup_clean"], True)
        self.assertEqual(aggregate.primary_performance_exclusion(value), "ordinary-stop-timeout")
        self.assertEqual(value["metrics"]["restart_task_to_ready_ns"], 10)
        self.assertEqual(native, before)

    def test_restart_cleanup_failure_excludes_the_whole_episode(self):
        native = source(
            restart={"ordinary_stop_timeout": False, "ordinary_cleanup_clean": False},
            recovery_success=False,
        )
        value = observed(native)
        self.assertEqual(
            aggregate.primary_performance_exclusion(value), "ordinary-cleanup-incomplete"
        )
        self.assertEqual(value["metrics"]["task_to_ready_ns"], 10)
        self.assertEqual(value["metrics"]["restart_task_to_ready_ns"], 10)
        self.assertEqual(value["status"], "completed")

    def test_failed_recovery_alone_does_not_exclude_intact_performance(self):
        value = observed(source(recovery_success=False))
        self.assertIs(value["recovery_success"], False)
        self.assertEqual(value["status"], "completed")
        self.assertIsNone(aggregate.primary_performance_exclusion(value))

    def test_no_restart_phase_remains_unobserved(self):
        for restart in (None, {}, {"blocked": "initial-worker-still-running"}):
            with self.subTest(restart=restart):
                value = observed(source(restart=restart))
                self.assertIsNone(value["restart_ordinary_stop_timeout"])
                self.assertIsNone(value["restart_ordinary_cleanup_clean"])
                self.assertIsNone(aggregate.primary_performance_exclusion(value))
        native = source()
        native.pop("restart")
        value = observed(native)
        self.assertIsNone(value["restart_ordinary_stop_timeout"])
        self.assertIsNone(value["restart_ordinary_cleanup_clean"])

    def test_nullable_restart_fields_are_preserved_without_truth_conversion(self):
        for timeout in (None, False, True):
            for clean in (None, False, True):
                with self.subTest(timeout=timeout, clean=clean):
                    value = observed(
                        source(
                            restart={
                                "ordinary_stop_timeout": timeout,
                                "ordinary_cleanup_clean": clean,
                            }
                        )
                    )
                    self.assertIs(value["restart_ordinary_stop_timeout"], timeout)
                    self.assertIs(value["restart_ordinary_cleanup_clean"], clean)

    def test_invalid_restart_flags_are_rejected_by_observation_validation(self):
        for name in ("ordinary_stop_timeout", "ordinary_cleanup_clean"):
            for invalid in (0, 1, "false", "true", [], {}):
                with self.subTest(name=name, invalid=invalid), self.assertRaises(ValueError):
                    observed(source(restart={name: invalid}))

    def test_functional_native_records_preserve_restart_outcomes_without_performance(self):
        native = functional(
            source(
                restart={"ordinary_stop_timeout": True, "ordinary_cleanup_clean": False},
                recovery_success=False,
            )
        )
        before = copy.deepcopy(native)
        value = native_validation.record(
            metadata("normal-control"), "completed", native_result=native
        )
        self.assertIs(value["restart_ordinary_stop_timeout"], True)
        self.assertIs(value["restart_ordinary_cleanup_clean"], False)
        self.assertIs(value["recovery_success"], False)
        self.assertEqual(value["metrics"], {})
        self.assertNotIn("markers", value)
        self.assertNotIn("resource_windows", value)
        self.assertEqual(native, before)

    def test_functional_absent_and_null_restart_flags_remain_unobserved(self):
        for restart in (None, {}, {"blocked": "fixture"}, {"ordinary_stop_timeout": None}):
            with self.subTest(restart=restart):
                value = native_validation.record(
                    metadata(), "completed", native_result=functional(source(restart=restart))
                )
                self.assertIsNone(value["restart_ordinary_stop_timeout"])
                self.assertIsNone(value["restart_ordinary_cleanup_clean"])

    def test_functional_records_reject_malformed_restart_flags(self):
        for name in ("ordinary_stop_timeout", "ordinary_cleanup_clean"):
            for invalid in (0, 1, "false", [], {}):
                with self.subTest(name=name, invalid=invalid), self.assertRaises(ValueError):
                    native_validation.record(
                        metadata(),
                        "completed",
                        native_result=functional(source(restart={name: invalid})),
                    )

    def test_generic_gate_uses_either_phase_and_existing_reason_precedence(self):
        cases = [
            ({"ordinary_stop_timeout": True}, "ordinary-stop-timeout"),
            ({"restart_ordinary_stop_timeout": True}, "ordinary-stop-timeout"),
            ({"ordinary_cleanup_clean": False}, "ordinary-cleanup-incomplete"),
            ({"restart_ordinary_cleanup_clean": False}, "ordinary-cleanup-incomplete"),
            (
                {"ordinary_cleanup_clean": False, "restart_ordinary_stop_timeout": True},
                "ordinary-stop-timeout",
            ),
            (
                {"ordinary_stop_timeout": True, "restart_ordinary_cleanup_clean": False},
                "ordinary-stop-timeout",
            ),
        ]
        for changes, expected in cases:
            with self.subTest(changes=changes):
                self.assertEqual(
                    aggregate.primary_performance_exclusion(record(**changes)), expected
                )

    def test_generic_validator_and_gate_reject_nonboolean_restart_outcomes(self):
        for name in ("restart_ordinary_stop_timeout", "restart_ordinary_cleanup_clean"):
            for invalid in (0, 1, "true", [], {}):
                value = record(**{name: invalid})
                with self.subTest(name=name, invalid=invalid):
                    with self.assertRaises(ValueError):
                        aggregate.validate_record(value, "synthetic-validation")
                    self.assertEqual(
                        aggregate.primary_performance_exclusion(value), "invalid-native-outcome"
                    )

    def test_legacy_records_without_restart_fields_keep_their_original_classification(self):
        for changes, expected in (
            ({}, None),
            ({"ordinary_stop_timeout": True}, "ordinary-stop-timeout"),
            ({"ordinary_cleanup_clean": False}, "ordinary-cleanup-incomplete"),
        ):
            value = record(**changes)
            self.assertNotIn("restart_ordinary_stop_timeout", value)
            self.assertNotIn("restart_ordinary_cleanup_clean", value)
            self.assertEqual(aggregate.primary_performance_exclusion(value), expected)


if __name__ == "__main__":
    unittest.main()
