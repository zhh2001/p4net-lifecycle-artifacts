"""Reject inconsistent calibration inputs before any native side effects."""

import copy
import unittest
from unittest.mock import Mock, patch

from harness.observer_config import validate_calibration

from harness_tests.test_measure import metadata


def configuration():
    return {
        "mode": "pilot",
        "clock_domain": "observer-monotonic",
        "duration_ns": 10_000_000_000,
        "interval_ns": 100_000_000,
        "metadata": metadata(),
        "observer_profile": "S",
        "attempt_id": "attempt-1",
    }


class ConfigurationTests(unittest.TestCase):
    def test_all_profiles_validate_without_sampling_and_detach_metadata(self):
        unexpected = Mock(side_effect=AssertionError("unexpected side effect"))
        manifest = {
            "run_id": "synthetic-run",
            "groups": 1,
            "configuration_profile": "matched-v1",
        }
        with (
            patch("time.monotonic_ns", unexpected),
            patch("subprocess.Popen", unexpected),
            patch("harness.resources.read_sample", unexpected),
        ):
            for profile in ("B", "T", "S"):
                value = {**configuration(), "observer_profile": profile}
                detached = validate_calibration(value, manifest)
                self.assertEqual(detached, value)
                detached["metadata"]["switches"] = 10
                self.assertEqual(value["metadata"]["switches"], 1)
        unexpected.assert_not_called()

    def test_invalid_modes_identity_and_schedule_fail_validation(self):
        cases = [
            {"mode": "formal"},
            {"mode": "synthetic-validation"},
            {"observer_profile": "unknown"},
            {"observer_profile": True},
            {"attempt_id": ""},
            {"attempt_id": "bad\nidentity"},
            {"attempt_id": "x" * 257},
            {"attempt_id": 1},
            {"duration_ns": True},
            {"interval_ns": 0},
            {"interval_ns": 20_000_000_000},
            {"clock_domain": " "},
            {"metadata": {**metadata(), "input_lock_sha256": "invalid"}},
        ]
        for override in cases:
            with self.subTest(override=override), self.assertRaises(ValueError):
                validate_calibration({**configuration(), **override})

    def test_fields_are_exact_and_inputs_are_not_mutated_on_failure(self):
        original = configuration()
        before = copy.deepcopy(original)
        with self.assertRaises(ValueError):
            validate_calibration({**original, "collection_authorized": True})
        for name in original:
            missing = {key: value for key, value in original.items() if key != name}
            with self.subTest(missing=name), self.assertRaises(ValueError):
                validate_calibration(missing)
        self.assertEqual(original, before)

    def test_manifest_condition_mismatch_is_rejected(self):
        manifest = {
            "run_id": "synthetic-run",
            "groups": 1,
            "configuration_profile": "matched-v1",
        }
        for change in (
            {"run_id": "another"},
            {"groups": 16},
            {"configuration_profile": "native"},
            {"episode_fault": "normal-control"},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_calibration(configuration(), {**manifest, **change})
