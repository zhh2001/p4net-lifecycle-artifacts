"""Keep native preflight ahead of claims and preserve published interruption outcomes."""

import json
import unittest
from unittest.mock import Mock

from harness import observer_campaign as campaign_module
from harness.campaign_executor import _write_new

from harness_tests import test_observer_campaign_inputs as bindings


class NativeFixture:
    mode = "pilot"

    def __init__(self):
        self.preflight = Mock()
        self.calls = []

    def __call__(self, attempt):
        self.calls.append(attempt.metadata["planned_id"])
        response = campaign_module.SyntheticBackend()(attempt)
        response["measurement"].update(mode="pilot", performance_samples=True)
        return response


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.fixture = bindings.ObserverBindingTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.base = self.fixture.base
        self.output = self.base / "journal"
        self.binding = self.fixture.build(mode="pilot")

    def campaign(self):
        return campaign_module.Campaign(self.output, self.binding, base=self.base)

    def test_qualification_observation_mapping_preserves_campaign_identity(self):
        original = {"phase": "qualification", "session": 0, "run_id": "run"}
        runtime = campaign_module.observation_metadata(original)
        self.assertEqual(runtime, {**original, "session": 1, "campaign_session": 0})
        self.assertEqual(campaign_module.observation_metadata(runtime), runtime)
        self.assertEqual(original["session"], 0)
        for session in (1, 2, 3):
            metadata = {"phase": "calibration", "session": session}
            self.assertEqual(campaign_module.observation_metadata(metadata), metadata)
        with self.assertRaises(ValueError):
            campaign_module.observation_metadata({"phase": "qualification", "session": True})

    def test_preflight_runs_before_any_claim(self):
        backend = NativeFixture()

        def check(output, binding):
            self.assertEqual(output, self.output)
            self.assertEqual(binding, self.binding)
            self.assertEqual(list((output / "attempts").iterdir()), [])

        backend.preflight.side_effect = check
        with self.campaign() as campaign:
            report = campaign.run(
                backend, phase="qualification", limit=1, collection_authorized=True
            )
        backend.preflight.assert_called_once()
        self.assertEqual(len(backend.calls), 1)
        self.assertEqual(report["attempt_status_counts"], {"completed": 1})

    def test_unauthorized_native_run_does_not_call_preflight_or_claim(self):
        backend = NativeFixture()
        with self.campaign() as campaign, self.assertRaises(PermissionError):
            campaign.run(backend, phase="qualification")
        backend.preflight.assert_not_called()
        self.assertEqual(backend.calls, [])
        self.assertEqual(list((self.output / "attempts").iterdir()), [])

    def test_preflight_failure_does_not_reconcile_or_start_partial_claim(self):
        backend = NativeFixture()
        backend.preflight.side_effect = ValueError("changed environment")
        with self.campaign() as campaign:
            planned = next(iter(campaign.entries))
            directory = self.output / "attempts" / planned / "0001"
            directory.mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, "changed environment"):
                campaign.run(backend, phase="qualification", collection_authorized=True)
        self.assertEqual(backend.calls, [])
        self.assertFalse((directory / "result.json").exists())

    def test_native_backend_without_preflight_is_rejected(self):
        class MissingPreflight:
            mode = "pilot"

            def __call__(self, attempt):
                raise AssertionError("unexpected backend invocation")

        with self.campaign() as campaign, self.assertRaisesRegex(ValueError, "preflight"):
            campaign.run(MissingPreflight(), phase="qualification", collection_authorized=True)
        self.assertEqual(list((self.output / "attempts").iterdir()), [])

    def test_published_native_success_survives_interrupt_and_is_not_reexecuted(self):
        class Interrupted(NativeFixture):
            def __call__(self, attempt):
                response = super().__call__(attempt)
                _write_new(attempt.directory / "backend-result.json", response)
                raise KeyboardInterrupt

        backend = Interrupted()
        with self.campaign() as campaign, self.assertRaises(KeyboardInterrupt):
            campaign.run(backend, phase="qualification", collection_authorized=True)
        result = next((self.output / "attempts").glob("*/*/result.json"))
        frozen = result.read_bytes()
        self.assertEqual(json.loads(frozen)["status"], "completed")
        with self.campaign() as campaign:
            campaign.reconcile()
        self.assertEqual(result.read_bytes(), frozen)
        self.assertEqual(len(backend.calls), 1)

    def test_invalid_measurement_at_interrupt_retains_known_native_success(self):
        class InvalidInterrupted(NativeFixture):
            def __call__(self, attempt):
                _write_new(
                    attempt.directory / "backend-result.json", {"native_result": {"ok": True}}
                )
                raise KeyboardInterrupt

        with self.campaign() as campaign, self.assertRaises(KeyboardInterrupt):
            campaign.run(InvalidInterrupted(), phase="qualification", collection_authorized=True)
        path = next((self.output / "attempts").glob("*/*/measurement.json"))
        record = json.loads(path.read_bytes())
        self.assertEqual(record["status"], "completed")
        self.assertFalse(record["qualified"])
        self.assertEqual(record["metrics"], {})

    def test_terminal_resume_rechecks_environment_without_backend_execution(self):
        backend = NativeFixture()
        with self.campaign() as campaign:
            campaign.run(backend, phase="qualification", collection_authorized=True)
        self.assertEqual(len(backend.calls), 3)
        with self.campaign() as campaign:
            report = campaign.run(backend, phase="qualification", collection_authorized=True)
        self.assertEqual(len(backend.calls), 3)
        self.assertEqual(backend.preflight.call_count, 2)
        self.assertEqual(report["invocation"]["executed_attempt_ids"], [])

    def test_corrupted_backend_result_does_not_replace_the_original_interrupt(self):
        class CorruptInterrupted(NativeFixture):
            def __call__(self, attempt):
                (attempt.directory / "backend-result.json").write_text("incomplete JSON")
                raise KeyboardInterrupt("requested stop")

        with self.campaign() as campaign, self.assertRaises(KeyboardInterrupt) as caught:
            campaign.run(CorruptInterrupted(), phase="qualification", collection_authorized=True)
        self.assertEqual(str(caught.exception), "requested stop")
        self.assertIsInstance(caught.exception.__cause__, ValueError)
        path = next((self.output / "attempts").glob("*/*/backend-result.json"))
        self.assertEqual(path.read_text(), "incomplete JSON")
        self.assertFalse((path.parent / "result.json").exists())
