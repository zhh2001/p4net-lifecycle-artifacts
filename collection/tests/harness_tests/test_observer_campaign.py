"""Exercise immutable observer claims, reviews, recovery, and explicit retries."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from harness import observer_calibration_plan
from harness import observer_campaign as campaigns

from harness_tests import test_observer_campaign_inputs as bindings


def read(path):
    return json.loads(path.read_text())


class RecordingBackend(campaigns.SyntheticBackend):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.calls = []

    def __call__(self, attempt):
        self.calls.append(attempt)
        return super().__call__(attempt)


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.fixture = bindings.ObserverBindingTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.allocation = observer_calibration_plan.generate()
        self.fixture.save_plan()
        self.base = self.fixture.base
        self.plan = self.fixture.allocation
        self.binding = self.fixture.build()
        self.output = self.base / "observer-journal"
        for name in (
            "subprocess.Popen",
            "subprocess.run",
            "socket.socket",
            "time.monotonic_ns",
            "time.sleep",
            "harness.resources.read_sample",
            "harness.observer_dispatch.run_calibrated",
        ):
            blocker = patch(name, side_effect=AssertionError(f"unexpected live operation: {name}"))
            blocker.start()
            self.addCleanup(blocker.stop)

    def campaign(self, output=None, binding=None):
        return campaigns.Campaign(output or self.output, binding or self.binding, base=self.base)

    def planned(self, phase="qualification", index=0):
        key = "planned_parent_id" if phase == "qualification" else "planned_task_id"
        return self.plan[phase + "_schedule"][index][key]

    def directory(self, planned=None, number=1):
        return self.output / "attempts" / (planned or self.planned()) / f"{number:04}"

    def run_one(self, backend=None):
        backend = backend or RecordingBackend()
        with self.campaign() as campaign:
            report = campaign.run(backend, phase="qualification", limit=1)
        return report, backend

    def qualify(self, campaign, backend):
        for stage in (1, 2, 3):
            campaign.run(backend, phase="qualification")
            campaign.review_gate(
                f"qualification-stage{stage}", qualified=True, reason="fixture valid"
            )

    def fingerprint(self, path):
        stat = path.stat()
        return hashlib.sha256(path.read_bytes()).hexdigest(), stat.st_ino, stat.st_mtime_ns

    def test_stages_and_initial_calibration_wiring_require_explicit_review(self):
        backend = RecordingBackend()
        with self.campaign() as campaign:
            report = campaign.run(backend, phase="qualification")
            self.assertEqual(len(backend.calls), 3)
            self.assertIsNotNone(report["invocation"]["blocked_by_gate"])
            campaign.run(backend, phase="qualification")
            self.assertEqual(len(backend.calls), 3)
            campaign.review_gate("qualification-stage1", qualified=True, reason="reviewed")
            campaign.run(backend, phase="qualification")
            self.assertEqual(len(backend.calls), 6)
            campaign.review_gate("qualification-stage2", qualified=True, reason="reviewed")
            campaign.run(backend, phase="qualification")
            campaign.review_gate("qualification-stage3", qualified=True, reason="reviewed")
            first = campaign.run(backend, phase="calibration", session=1)
            self.assertEqual(len(first["invocation"]["executed_attempt_ids"]), 9)
            campaign.run(backend, phase="calibration", session=1)
            self.assertEqual(len(backend.calls), 18)
            campaign.review_gate("calibration-wiring", qualified=True, reason="reviewed")
            report = campaign.run(backend, phase="calibration", session=1)
            self.assertEqual(report["planned_units_with_attempts"], 99)
            self.assertFalse(report["performance_samples"])

    def test_full_synthetic_plan_retains_279_distinct_planned_units(self):
        backend = RecordingBackend()
        with self.campaign() as campaign:
            self.qualify(campaign, backend)
            campaign.run(backend, phase="calibration", session=1)
            campaign.review_gate("calibration-wiring", qualified=True, reason="fixture valid")
            for session in (1, 2, 3):
                report = campaign.run(backend, phase="calibration", session=session)
        self.assertEqual(len(backend.calls), 279)
        self.assertEqual(report["attempt_status_counts"], {"completed": 279})
        self.assertEqual(report["unattempted_planned_ids"], [])
        self.assertEqual(len({attempt.metadata["run_id"] for attempt in backend.calls}), 279)
        self.assertEqual(
            {attempt.metadata["tool"] for attempt in backend.calls},
            {"p4net", "p4utils", "tutorial-components"},
        )

    def test_resume_preserves_terminal_bytes_and_never_reruns_first_attempt(self):
        self.run_one()
        terminal = self.directory() / "result.json"
        before = self.fingerprint(terminal)
        backend = RecordingBackend()
        with self.campaign() as campaign:
            campaign.run(backend, phase="qualification", limit=1)
        self.assertEqual(len(backend.calls), 1)
        self.assertNotEqual(backend.calls[0].metadata["planned_id"], self.planned())
        self.assertEqual(self.fingerprint(terminal), before)

    def test_failed_first_attempt_and_explicit_retry_remain_separate(self):
        planned = self.planned()
        backend = RecordingBackend({planned: "failed"})
        self.run_one(backend)
        before = self.fingerprint(self.directory() / "result.json")
        backend.outcomes.clear()
        with self.campaign() as campaign:
            report = campaign.run(backend, phase="qualification", retry=[planned])
        self.assertEqual(len(backend.calls), 2)
        self.assertEqual([row["status"] for row in report["attempts"]], ["failed", "completed"])
        self.assertEqual(self.fingerprint(self.directory() / "result.json"), before)
        self.assertNotEqual(
            read(self.directory() / "started.json")["metadata"]["run_id"],
            read(self.directory(number=2) / "started.json")["metadata"]["run_id"],
        )
        self.assertEqual(
            read(self.directory(number=2) / "started.json")["previous_attempt_id"],
            f"{planned}--a0001",
        )

    def test_review_of_explicit_retry_can_advance_without_changing_first_result(self):
        planned = self.planned()
        backend = RecordingBackend({planned: "failed"})
        with self.campaign() as campaign:
            campaign.run(backend, phase="qualification")
            campaign.review_gate("qualification-stage1", qualified=False, reason="diagnosed")
            backend.outcomes.clear()
            campaign.run(backend, phase="qualification")
            campaign.run(backend, phase="qualification", retry=[planned])
            with self.assertRaises(ValueError):
                campaign.review_gate("qualification-stage1", qualified=True, reason="first failed")
            review = campaign.review_gate(
                "qualification-stage1",
                qualified=True,
                reason="explicit retry reviewed",
                selection="latest-attempt",
            )
            self.assertEqual(review["review_number"], 2)
            self.assertEqual(
                next(row for row in review["attempts"] if row["planned_id"] == planned)[
                    "attempt_number"
                ],
                2,
            )
            report = campaign.run(backend, phase="qualification")
            self.assertEqual(len(report["invocation"]["executed_attempt_ids"]), 3)
        self.assertEqual(read(self.directory() / "result.json")["status"], "failed")

    def test_historical_latest_review_remains_valid_after_another_retry(self):
        backend = RecordingBackend()
        with self.campaign() as campaign:
            campaign.run(backend, phase="qualification")
            campaign.review_gate(
                "qualification-stage1",
                qualified=True,
                reason="initial latest",
                selection="latest-attempt",
            )
            review = self.output / "gates/qualification-stage1/0001.json"
            before = self.fingerprint(review)
            campaign.run(backend, phase="qualification", retry=[self.planned()])
        with self.campaign() as campaign:
            report = campaign.run(backend, phase="qualification")
        self.assertEqual(self.fingerprint(review), before)
        self.assertEqual(len(report["invocation"]["executed_attempt_ids"]), 3)

    def test_later_rejection_blocks_new_claims_but_not_old_pinned_claims(self):
        backend = RecordingBackend()
        with self.campaign() as campaign:
            campaign.run(backend, phase="qualification")
            campaign.review_gate("qualification-stage1", qualified=True, reason="initial valid")
            campaign.run(backend, phase="qualification", limit=1)
            campaign.review_gate(
                "qualification-stage1", qualified=False, reason="additional diagnosis"
            )
            report = campaign.run(backend, phase="qualification")
            self.assertEqual(report["invocation"]["executed_attempt_ids"], [])
            self.assertEqual(campaign.report()["planned_units_with_attempts"], 4)

    def test_missing_metric_blocks_health_review_but_preserves_other_metrics(self):
        planned = self.planned()
        backend = RecordingBackend(missing_metrics={planned: ["observer_pss_bytes"]})
        with self.campaign() as campaign:
            campaign.run(backend, phase="qualification")
            with self.assertRaises(ValueError):
                campaign.review_gate("qualification-stage1", qualified=True, reason="missing")
        measurement = read(self.directory() / "measurement.json")
        self.assertEqual(measurement["status"], "completed")
        self.assertFalse(measurement["qualified"])
        self.assertEqual(
            set(measurement["metrics"]), set(campaigns.REFERENCE_METRICS) - {"observer_pss_bytes"}
        )

    def test_missing_reference_keeps_native_completion_without_zero_metrics(self):
        self.run_one(RecordingBackend(unavailable=[self.planned()]))
        measurement = read(self.directory() / "measurement.json")
        self.assertEqual(measurement["status"], "completed")
        self.assertEqual(measurement["metrics"], {})
        self.assertEqual(measurement["reference_status"], "incomplete")

    def test_invalid_measurement_does_not_rewrite_explicit_native_success(self):
        backend = Mock(mode="synthetic-validation", return_value={"native_result": {"ok": True}})
        self.run_one(backend)
        measurement = read(self.directory() / "measurement.json")
        self.assertEqual(measurement["status"], "completed")
        self.assertFalse(measurement["qualified"])
        self.assertEqual(measurement["metrics"], {})

    def test_timeout_is_terminal_and_not_automatically_retried(self):
        backend = Mock(mode="synthetic-validation", side_effect=TimeoutError("fixture timeout"))
        self.run_one(backend)
        self.assertEqual(read(self.directory() / "result.json")["status"], "timeout")
        with self.campaign() as campaign:
            campaign.reconcile()
        backend.assert_called_once()

    def test_keyboard_interrupt_is_recorded_then_propagated(self):
        backend = Mock(mode="synthetic-validation", side_effect=KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt), self.campaign() as campaign:
            campaign.run(backend, phase="qualification")
        terminal = read(self.directory() / "result.json")
        self.assertEqual(terminal["status"], "blocked")
        self.assertIn("KeyboardInterrupt", terminal["reason"])

    def test_reconcile_empty_claim_does_not_create_a_run_or_launch_worker(self):
        with self.campaign() as campaign:
            self.directory().mkdir(parents=True)
            campaign.reconcile()
        result = read(self.directory() / "result.json")
        self.assertIsNone(result["run_id"])
        self.assertIsNone(result["measurement"])
        self.assertEqual(result["status"], "blocked")

    def test_reconcile_started_claim_without_outcome_keeps_missing_metrics(self):
        self.run_one()
        for name in ("measurement.json", "backend-result.json", "result.json"):
            (self.directory() / name).unlink()
        with self.campaign() as campaign:
            campaign.reconcile()
        measurement = read(self.directory() / "measurement.json")
        self.assertEqual(measurement["status"], "blocked")
        self.assertEqual(measurement["metrics"], {})

    def test_reconcile_backend_and_measurement_publications_without_rerunning(self):
        for retained in ("backend-result.json", "measurement.json"):
            with self.subTest(retained=retained), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "journal"
                backend = RecordingBackend()
                with self.campaign(output) as campaign:
                    campaign.run(backend, phase="qualification", limit=1)
                directory = output / "attempts" / self.planned() / "0001"
                (directory / "result.json").unlink()
                if retained == "backend-result.json":
                    (directory / "measurement.json").unlink()
                before = self.fingerprint(directory / retained)
                with self.campaign(output) as campaign:
                    campaign.reconcile()
                self.assertEqual(self.fingerprint(directory / retained), before)
                self.assertEqual(read(directory / "result.json")["status"], "completed")
                self.assertEqual(len(backend.calls), 1)

    def test_review_requires_complete_qualified_selected_coverage(self):
        with self.campaign() as campaign:
            with self.assertRaises(ValueError):
                campaign.review_gate("qualification-stage1", qualified=True, reason="unfinished")
            for selection in ("", "automatic"):
                with self.assertRaises(ValueError):
                    campaign.review_gate(
                        "qualification-stage1",
                        qualified=False,
                        reason="diagnosis",
                        selection=selection,
                    )

    def test_changed_terminal_or_review_reference_is_rejected(self):
        backend = RecordingBackend()
        with self.campaign() as campaign:
            campaign.run(backend, phase="qualification")
            campaign.review_gate("qualification-stage1", qualified=True, reason="valid")
        terminal = self.directory() / "result.json"
        original = terminal.read_bytes()
        terminal.write_bytes(original + b" ")
        with self.assertRaises(ValueError), self.campaign():
            pass
        terminal.write_bytes(original)
        review = self.output / "gates/qualification-stage1/0001.json"
        value = read(review)
        value["attempts"][0]["sha256"] = "0" * 64
        review.write_text(json.dumps(value))
        with self.assertRaises(ValueError), self.campaign():
            pass

    def test_claim_requires_exact_pinned_positive_gate_proofs(self):
        backend = RecordingBackend()
        with self.campaign() as campaign:
            campaign.run(backend, phase="qualification")
            campaign.review_gate("qualification-stage1", qualified=True, reason="valid")
            campaign.run(backend, phase="qualification", limit=1)
        started = self.directory(self.planned(index=3)) / "started.json"
        value = read(started)
        self.assertEqual(value["gate_reviews"][0]["gate_id"], "qualification-stage1")
        value["gate_reviews"] = []
        started.write_text(json.dumps(value))
        with self.assertRaises(ValueError), self.campaign():
            pass

    def test_duplicate_run_identity_and_missing_ordinals_are_rejected(self):
        self.run_one()
        source = self.directory()
        later = source.parent / "0003"
        later.mkdir()
        with self.assertRaises(ValueError), self.campaign():
            pass
        later.rmdir()
        with self.campaign() as campaign:
            campaign.run(RecordingBackend(), phase="qualification", limit=1)
        second = self.directory(self.planned(index=1)) / "started.json"
        value = read(second)
        value["metadata"]["run_id"] = read(source / "started.json")["metadata"]["run_id"]
        second.write_text(json.dumps(value))
        with self.assertRaises(ValueError), self.campaign():
            pass

    def test_changed_measurement_checksum_and_symlinks_are_rejected(self):
        self.run_one()
        path = self.directory() / "measurement.json"
        original = path.read_bytes()
        path.write_bytes(original + b" ")
        with self.assertRaises(ValueError), self.campaign():
            pass
        path.unlink()
        target = self.base / "linked.json"
        target.write_bytes(original)
        path.symlink_to(target)
        with self.assertRaises(ValueError), self.campaign():
            pass

    def test_context_lock_prevents_concurrent_campaign_writers(self):
        with self.campaign(), self.assertRaises(BlockingIOError), self.campaign():
            pass

    def test_invalid_invocation_and_retry_never_call_backend(self):
        backend = RecordingBackend()
        cases = (
            {"phase": "unknown"},
            {"phase": "qualification", "session": 1},
            {"phase": "calibration", "session": True},
            {"phase": "calibration", "session": 4},
            {"phase": "qualification", "limit": 0},
            {"phase": "qualification", "retry": ["unknown"]},
            {"phase": "qualification", "retry": [self.planned()]},
            {"phase": "qualification", "retry": [self.planned(), self.planned()]},
        )
        with self.campaign() as campaign:
            for arguments in cases:
                with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                    campaign.run(backend, **arguments)
        self.assertEqual(backend.calls, [])

    def test_empty_parent_directory_does_not_authorize_an_explicit_retry(self):
        backend = RecordingBackend()
        with self.campaign() as campaign:
            (self.output / "attempts" / self.planned()).mkdir()
            with self.assertRaisesRegex(ValueError, "preceding attempt"):
                campaign.run(backend, phase="qualification", retry=[self.planned()])
            self.assertEqual(backend.calls, [])
            self.assertEqual(campaign.report()["planned_units_with_attempts"], 0)

    def test_mode_mismatch_and_unauthorized_pilot_precede_claims(self):
        with self.campaign() as campaign:
            with self.assertRaises(ValueError):
                campaign.run(Mock(mode="pilot"), phase="qualification")
            campaign.binding["mode"] = "pilot"
            with self.assertRaises(PermissionError):
                campaign.run(Mock(mode="pilot"), phase="qualification")
        self.assertEqual(list((self.output / "attempts").iterdir()), [])

    def test_read_only_records_need_no_current_runtime_or_recovery(self):
        self.run_one()
        paths = [path for path in self.output.rglob("*.json") if path.is_file()]
        before = {path: self.fingerprint(path) for path in paths}
        self.fixture.core.write_text("evolved runtime")
        with (
            patch.object(campaigns, "verify_binding", side_effect=AssertionError("live verify")),
            patch.object(campaigns, "_write_new", side_effect=AssertionError("write")),
        ):
            records = campaigns.read_records(self.output, base=self.base)
        self.assertEqual(len(records["attempts"]), 1)
        self.assertEqual(len(records["input_hashes"]), 5)
        self.assertEqual({path: self.fingerprint(path) for path in paths}, before)

    def test_measurement_contract_rejects_nonfinite_bool_and_incomplete_metrics(self):
        self.run_one()
        value = read(self.directory() / "measurement.json")
        metadata = read(self.directory() / "started.json")["metadata"]
        for metrics in (
            {"cost": True},
            {"cost": float("nan")},
            {"cost": float("inf")},
            {"observer_body_wall_ns": -1},
        ):
            with self.subTest(metrics=metrics), self.assertRaises(ValueError):
                campaigns.validate_measurement(
                    {**value, "metrics": metrics}, metadata, "synthetic-validation"
                )
        with self.assertRaises(ValueError):
            campaigns.validate_measurement(
                {**value, "reference_status": "incomplete"}, metadata, "synthetic-validation"
            )
