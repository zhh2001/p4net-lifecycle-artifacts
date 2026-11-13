"""Check native observer routing with retained fixtures and mocked dispatches."""

import copy
import json
import unittest
import uuid
from unittest.mock import patch

from harness import observer_calibration_plan
from harness import observer_campaign as campaigns
from harness import observer_campaign_inputs as inputs
from harness import observer_campaign_native as native
from harness.campaign_executor import _json, _write_new
from harness.observer_config import validate_calibration

from harness_tests import test_campaign_native_adapter as fixtures


class PilotFixture(campaigns.SyntheticBackend):
    mode = "pilot"

    def preflight(self, output, binding):
        pass

    def __call__(self, attempt):
        value = super().__call__(attempt)
        value["measurement"]["performance_samples"] = True
        return value


class ObserverNativeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.CampaignNativeAdapterTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.base = self.fixture.base
        self.output = self.fixture.output
        self.plan = observer_calibration_plan.generate()
        fixtures.fixtures.write(self.fixture.plan_path, self.plan)
        control = _json(self.fixture.control)
        control["campaign"]["sha256"] = fixtures.fixtures.digest(self.fixture.plan_path)
        fixtures.fixtures.write(self.fixture.control, control)
        inventory = patch.object(
            inputs, "runtime_sources", return_value=sorted((self.base / "harness").glob("*.py"))
        )
        inventory.start()
        self.addCleanup(inventory.stop)
        self.binding = inputs.build_binding(
            self.fixture.plan_path,
            self.fixture.control,
            self.fixture.dependency,
            self.fixture.sources,
            mode="pilot",
            base=self.base,
        )
        with campaigns.Campaign(self.output, self.binding, base=self.base):
            pass
        self.dispatch = patch.object(
            native.observer_dispatch, "run_calibrated", return_value={"fixture": "dispatch"}
        )
        self.launch = self.dispatch.start()
        self.addCleanup(self.dispatch.stop)
        self.adapter = patch.object(native, "_adapt", side_effect=self.adapt)
        self.convert = self.adapter.start()
        self.addCleanup(self.adapter.stop)
        self.backend = native.NativeObserverBackend(base=self.base)

    @staticmethod
    def adapt(dispatch, metadata, *, artifacts):
        return {
            "measurement": {**metadata, "status": "completed"},
            "native_result": {"ok": True},
            "dispatch_result": dispatch,
        }

    def prepare(self):
        self.backend.preflight(self.output, self.binding)
        return self.backend

    def predecessors(self, stages):
        with campaigns.Campaign(self.output, self.binding, base=self.base) as journal:
            for stage in stages:
                path = self.output / "gates" / f"qualification-stage{stage}" / "0001.json"
                if not path.exists():
                    journal.run(PilotFixture(), phase="qualification", collection_authorized=True)
                    journal.review_gate(
                        f"qualification-stage{stage}", qualified=True, reason="fixture verified"
                    )

    def attempt(self, *, tool="p4net", profile="S", phase="qualification", stage=1, switches=1):
        if phase == "calibration":
            self.predecessors((1, 2, 3))
        else:
            self.predecessors(range(1, stage))
        row = next(
            row
            for row in self.plan[phase + "_schedule"]
            if row["tool"] == tool
            and row["observer_profile"] == profile
            and (row["stage"] == stage if phase == "qualification" else row["switches"] == switches)
        )
        metadata = campaigns.metadata_for(self.plan, self.binding, phase, row, 1, uuid.uuid4().hex)
        directory = self.output / "attempts" / metadata["planned_id"] / "0001"
        directory.mkdir(parents=True)
        proofs = []
        for gate in campaigns.required_gates(self.plan, phase, row):
            path = self.output / "gates" / gate / "0001.json"
            proofs.append(
                {"gate_id": gate, "review_number": 1, "sha256": fixtures.fixtures.digest(path)}
            )
        started = {
            "schema_version": 1,
            "record_type": "observer-attempt-start",
            "metadata": metadata,
            "entry": row,
            "gate_reviews": proofs,
            "previous_attempt_id": None,
            "input_lock_sha256": self.binding["input_lock_sha256"],
            "mode": "pilot",
            "performance_samples": True,
        }
        _write_new(directory / "started.json", started)
        return campaigns.Attempt(directory, started)

    def test_preflight_checks_all_frozen_native_environments_and_detaches_binding(self):
        self.prepare()
        self.fixture.verify_environment.assert_called_once()
        self.assertEqual(
            self.fixture.verify_environment.call_args.kwargs["labels"],
            ("p4net310", "p4utils310", "tutorial310"),
        )
        self.assertEqual(self.backend.binding, self.binding)
        self.binding["profiles"][0]["label"] = "mutated"
        self.assertNotEqual(self.backend.binding, self.binding)
        self.launch.assert_not_called()

    def test_call_requires_preflight_before_any_dispatch_or_manifest_creation(self):
        attempt = self.attempt()
        with self.assertRaises(RuntimeError):
            self.backend(attempt)
        self.fixture.create.assert_not_called()
        self.launch.assert_not_called()

    def test_all_tools_and_profiles_reach_bound_worker_and_calibrated_dispatch(self):
        self.prepare()
        for tool, (label, worker) in native.TREATMENTS.items():
            for profile in ("B", "T", "S"):
                with self.subTest(tool=tool, profile=profile):
                    attempt = self.attempt(tool=tool, profile=profile, phase="calibration")
                    result = self.backend(attempt)
                    args, kwargs = self.launch.call_args
                    environment = _json(self.fixture.environments[label])
                    self.assertEqual(
                        args[1], self.fixture.environments[label].parent / environment["executable"]
                    )
                    self.assertEqual(args[2], worker)
                    self.assertTrue(kwargs["collection_authorized"])
                    configuration = kwargs["calibration"]
                    self.assertEqual(configuration["observer_profile"], profile)
                    self.assertEqual(configuration["attempt_id"], attempt.metadata["attempt_id"])
                    self.assertEqual(configuration["metadata"], attempt.metadata)
                    self.assertEqual(
                        configuration["metadata"]["input_lock_sha256"],
                        self.binding["input_lock_sha256"],
                    )
                    self.assertEqual(configuration["duration_ns"], 10_000_000_000)
                    self.assertEqual(configuration["interval_ns"], 100_000_000)
                    manifest = _json(args[0])
                    self.assertEqual(manifest["run_id"], attempt.metadata["run_id"])
                    self.assertNotIn("episode_fault", manifest)
                    self.assertTrue(result["native_result"]["ok"])
                    self.convert.assert_called_with(
                        {"fixture": "dispatch"}, attempt.metadata, artifacts=attempt.artifacts
                    )

    def test_normal_recovery_control_is_one_bound_four_switch_episode(self):
        self.prepare()
        for tool in native.TREATMENTS:
            attempt = self.attempt(tool=tool, stage=2)
            self.backend(attempt)
            manifest = _json(self.launch.call_args.args[0])
            self.assertEqual(manifest["episode_fault"], "normal-control")
            self.assertEqual(manifest["groups"], 4)
            self.assertEqual(
                self.launch.call_args.kwargs["calibration"]["metadata"]["workload"], "fault"
            )

    def test_qualification_uses_positive_observation_session_and_retains_campaign_identity(self):
        self.prepare()
        attempt = self.attempt()
        self.assertEqual(attempt.metadata["session"], 0)
        self.backend(attempt)
        configuration = self.launch.call_args.kwargs["calibration"]
        self.assertEqual(
            configuration["metadata"], campaigns.observation_metadata(attempt.metadata)
        )
        self.assertEqual(configuration["metadata"]["session"], 1)
        self.assertEqual(configuration["metadata"]["campaign_session"], 0)
        self.assertEqual(attempt.metadata["session"], 0)
        self.assertEqual(
            validate_calibration(configuration, _json(self.launch.call_args.args[0])), configuration
        )
        self.convert.assert_called_with(
            {"fixture": "dispatch"}, attempt.metadata, artifacts=attempt.artifacts
        )

    def test_preflight_failure_clears_preceding_success(self):
        self.prepare()
        self.fixture.verify_environment.side_effect = ValueError("dependency changed")
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertIsNone(self.backend.binding)
        self.assertIsNone(self.backend.output)
        with self.assertRaises(RuntimeError):
            self.backend(self.attempt())

    def test_preflight_rejects_nonroot_mode_and_foreign_journal(self):
        with (
            patch("harness.campaign_executor.os.geteuid", return_value=1000),
            self.assertRaises(PermissionError),
        ):
            self.prepare()
        synthetic = copy.deepcopy(self.binding)
        synthetic["mode"] = "synthetic-validation"
        with self.assertRaises(ValueError):
            self.backend.preflight(self.output, synthetic)
        with self.assertRaises(OSError):
            self.backend.preflight(self.base / "missing-journal", self.binding)
        self.launch.assert_not_called()

    def test_effective_tool_change_after_preflight_prevents_dispatch(self):
        self.prepare()
        attempt = self.attempt()
        self.fixture.lookup.side_effect = lambda name: "/different/" + name
        with self.assertRaises(ValueError):
            self.backend(attempt)
        self.fixture.create.assert_not_called()
        self.launch.assert_not_called()

    def test_changed_bound_input_after_preflight_prevents_artifacts(self):
        self.prepare()
        attempt = self.attempt()
        self.fixture.sources[0].write_text("changed")
        with self.assertRaises(ValueError):
            self.backend(attempt)
        self.assertFalse(attempt.artifacts.exists())

    def test_claim_foreign_identity_or_unpublished_changes_are_rejected(self):
        self.prepare()
        attempt = self.attempt()
        changed = copy.deepcopy(attempt.started)
        changed["metadata"]["observer_profile"] = "B"
        with self.assertRaises(ValueError):
            self.backend(campaigns.Attempt(attempt.directory, changed))
        with self.assertRaises(ValueError):
            self.backend(campaigns.Attempt(self.base / "outside", attempt.started))
        self.fixture.create.assert_not_called()

    def test_changed_gate_review_cannot_authorize_dispatch(self):
        self.prepare()
        attempt = self.attempt(phase="calibration", profile="B")
        path = self.output / "gates/qualification-stage1/0001.json"
        path.write_text(path.read_text() + "\n")
        with self.assertRaises(ValueError):
            self.backend(attempt)
        self.assertFalse(attempt.artifacts.exists())

    def test_outcome_or_artifact_presence_prevents_same_attempt_relaunch(self):
        self.prepare()
        attempt = self.attempt()
        attempt.artifacts.mkdir()
        with self.assertRaises(FileExistsError):
            self.backend(attempt)
        self.launch.assert_not_called()

    def test_replaced_journal_binding_after_preflight_prevents_dispatch(self):
        self.prepare()
        attempt = self.attempt()
        path = self.output / "observer-binding.json"
        changed = _json(path)
        changed["input_lock_sha256"] = "f" * 64
        path.write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, "journal binding changed"):
            self.backend(attempt)
        self.assertFalse(attempt.artifacts.exists())

    def test_worker_version_and_executable_identity_are_checked(self):
        self.prepare()
        original = native._json
        attempt = self.attempt()
        environment_path = self.fixture.environments["p4net310"]
        for override in ({"version_info": [3, 12, 3]}, {"executable": "foreign/python"}):

            def read(path, override=override):
                value = original(path)
                return {**value, **override} if path == environment_path else value

            with patch.object(native, "_json", side_effect=read), self.assertRaises(ValueError):
                self.backend(attempt)
        self.assertFalse(attempt.artifacts.exists())

    def test_interruption_retains_validated_published_backend_result_then_propagates(self):
        self.prepare()
        attempt = self.attempt()

        def interrupt(*args, **kwargs):
            _write_new(attempt.artifacts / "observer-dispatch.json", {"fixture": "interrupted"})
            raise KeyboardInterrupt()

        self.launch.side_effect = interrupt
        with self.assertRaises(KeyboardInterrupt):
            self.backend(attempt)
        result = _json(attempt.directory / "backend-result.json")
        self.assertTrue(result["native_result"]["ok"])
        self.assertEqual(result["measurement"]["run_id"], attempt.metadata["run_id"])

    def test_interruption_without_validated_artifact_does_not_invent_backend_result(self):
        self.prepare()
        attempt = self.attempt()
        self.launch.side_effect = SystemExit(2)
        with self.assertRaises(SystemExit):
            self.backend(attempt)
        self.assertFalse((attempt.directory / "backend-result.json").exists())

    def test_invalid_interrupted_dispatch_does_not_replace_original_interruption(self):
        self.prepare()
        attempt = self.attempt()

        def interrupt(*args, **kwargs):
            _write_new(attempt.artifacts / "observer-dispatch.json", {"fixture": "invalid"})
            raise KeyboardInterrupt()

        self.launch.side_effect = interrupt
        self.convert.side_effect = ValueError("dispatch identity differs")
        with self.assertRaises(KeyboardInterrupt):
            self.backend(attempt)
        self.assertFalse((attempt.directory / "backend-result.json").exists())

    def test_dispatch_exception_propagates_without_a_fabricated_response(self):
        self.prepare()
        attempt = self.attempt()
        self.launch.side_effect = RuntimeError("dispatch setup failed")
        with self.assertRaisesRegex(RuntimeError, "dispatch setup failed"):
            self.backend(attempt)
        self.convert.assert_not_called()
        self.assertFalse((attempt.directory / "backend-result.json").exists())

    def test_conversion_failure_and_dispatch_error_propagate_for_journal_handling(self):
        self.prepare()
        attempt = self.attempt()
        self.convert.side_effect = ValueError("invalid artifact chain")
        with self.assertRaises(ValueError):
            self.backend(attempt)
