"""Exercise campaign execution and recovery using temporary synthetic records."""

import copy
import hashlib
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from harness import campaign, campaign_executor, campaign_inputs


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n")
    return path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


class RecordingBackend(campaign_executor.SyntheticBackend):
    def __init__(self, outcomes=None):
        super().__init__(outcomes)
        self.calls = []

    def __call__(self, attempt):
        self.calls.append(attempt)
        return super().__call__(attempt)


class CampaignExecutorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.output = self.base / "output"
        self.plan = campaign.generate(sessions=1, repetitions_per_session=1)
        self.plan_path = write(self.base / "plans" / "campaign.json", self.plan)
        self.source = write(self.base / "harness" / "worker.py", {"source": "synthetic fixture"})
        self.workload = self.base / "harness" / "workloads" / "l3.p4"
        self.workload.parent.mkdir()
        self.workload.write_text("synthetic P4 fixture\n")
        self.launcher = write(self.base / "harness" / "bin" / "simple_switch_grpc", {})
        self.environment = write(self.base / "deps" / "tool" / "environment.json", {})
        self.tools = write(self.base / "deps" / "tools.json", {})
        self.mininet = write(self.base / "deps" / "mininet.json", {})
        self.artifact = write(self.base / "fixture.whl", {"package": "synthetic fixture"})
        self.dependency = write(
            self.base / "deps" / "manifest.json",
            {
                "environment_files": {"tool": "tool/environment.json"},
                "tools_file": "tools.json",
                "mininet_source_file": "mininet.json",
                "artifacts": {"tool": {"path": "../fixture.whl", "sha256": digest(self.artifact)}},
            },
        )
        self.control = write(
            self.base / "frozen-control.json",
            {
                "campaign": {"path": "plans/campaign.json", "sha256": digest(self.plan_path)},
                "dependency_freeze": {
                    "path": "deps/manifest.json",
                    "sha256": digest(self.dependency),
                },
                "sources": {
                    str(path.relative_to(self.base)): digest(path)
                    for path in (self.source, self.workload, self.launcher)
                },
            },
        )
        self.binding = campaign_inputs.build_binding(
            self.plan_path,
            self.control,
            self.dependency,
            [self.source, self.workload, self.launcher],
            mode="synthetic-validation",
            base=self.base,
        )
        for name in (
            "subprocess.run",
            "subprocess.Popen",
            "socket.socket",
            "harness.isolation.run_isolated",
            "harness.measure.sample_window",
            "harness.measure.time.monotonic_ns",
            "harness.resources.read_sample",
            "harness.campaign_executor.NativeBackend.__init__",
        ):
            blocker = patch(name, side_effect=AssertionError(f"unexpected live operation: {name}"))
            blocker.start()
            self.addCleanup(blocker.stop)

    def executor(self, output=None):
        return campaign_executor.Campaign(output or self.output, self.binding, base=self.base)

    def planned(self, phase="scale", index=0):
        key = "planned_case_id" if phase == "scale" else "planned_episode_id"
        return self.plan[phase + "_schedule"][index][key]

    def directory(self, planned=None, number=1, output=None):
        return (output or self.output) / "attempts" / (planned or self.planned()) / f"{number:04}"

    def run_one(self, *, output=None, backend=None):
        backend = backend or RecordingBackend()
        with self.executor(output) as executor:
            report = executor.run("scale", 1, backend, limit=1)
        return report, backend, self.directory(output=output)

    def test_complete_schedule_keeps_one_measurement_per_scale_run_or_parent_episode(self):
        backend = RecordingBackend()
        with self.executor() as executor:
            scale = executor.run("scale", 1, backend)
            report = executor.run("fault", 1, backend)
        self.assertEqual(scale["attempt_status_counts"], {"completed": 15})
        self.assertEqual(report["attempt_status_counts"], {"completed": 33})
        self.assertEqual(report["planned_units"], 33)
        self.assertEqual(report["planned_units_with_attempts"], 33)
        self.assertEqual(report["unattempted_planned_ids"], [])
        self.assertFalse(report["performance_samples"])
        self.assertEqual(len(backend.calls), 33)
        self.assertEqual(len(list(self.output.glob("attempts/*/*/measurement.json"))), 33)
        episodes = [attempt for attempt in backend.calls if attempt.metadata["workload"] == "fault"]
        self.assertEqual(len(episodes), 18)
        self.assertEqual(
            len(
                {
                    value
                    for attempt in episodes
                    for value in attempt.metadata["planned_execution_ids"]
                }
            ),
            36,
        )
        self.assertEqual(len({attempt.metadata["run_id"] for attempt in backend.calls}), 33)
        for attempt in backend.calls:
            metadata = attempt.metadata
            phase = metadata["workload"]
            expected = next(
                entry
                for entry in self.plan[phase + "_schedule"]
                if entry["planned_case_id" if phase == "scale" else "planned_episode_id"]
                == metadata["planned_id"]
            )
            for field in ("tool", "switches", "matched_block", "sequence"):
                self.assertEqual(metadata[field], expected[field])
            self.assertEqual(metadata["fault"], expected.get("fault"))
            self.assertEqual(metadata["input_lock_sha256"], self.binding["input_lock_sha256"])
            self.assertEqual(metadata["session"], 1)
            self.assertEqual(metadata["python"], "3.10.20")
            self.assertEqual(metadata["configuration_profile"], "matched-v1")
            self.assertEqual(metadata["attempt_number"], 1)
            self.assertRegex(metadata["run_id"], r"^[a-f0-9]{32}$")
            self.assertEqual(attempt.artifacts, attempt.directory / "artifacts")
            record = read(attempt.directory / "measurement.json")
            self.assertEqual(record["mode"], "synthetic-validation")
            self.assertFalse(record["performance_samples"])
            self.assertTrue(all(record[key] == value for key, value in metadata.items()))
            metadata["run_id"] = "changed copy"
            self.assertNotEqual(attempt.metadata["run_id"], metadata["run_id"])

    def test_resume_skips_every_terminal_status_without_replacing_records(self):
        statuses = ("completed", "failed", "timeout", "blocked")
        outcomes = {self.planned(index=i): statuses[i % 4] for i in range(15)}
        self.run_one(backend=RecordingBackend(outcomes))
        with self.executor() as executor:
            executor.run("scale", 1, RecordingBackend(outcomes))
        paths = list(self.output.glob("attempts/*/*/*.json"))
        originals = {path: path.read_bytes() for path in paths}
        backend = RecordingBackend()
        with self.executor() as executor:
            report = executor.run("scale", 1, backend)
        self.assertEqual(backend.calls, [])
        self.assertEqual(report["invocation"]["executed_attempt_ids"], [])
        self.assertEqual(set(report["attempt_status_counts"]), set(statuses))
        self.assertEqual({path: path.read_bytes() for path in paths}, originals)

    def test_explicit_retry_allocates_new_uuid_and_ordinal_preserving_history(self):
        planned = self.planned()
        self.run_one(backend=RecordingBackend({planned: "failed"}))
        first = self.directory()
        before = {path.name: path.read_bytes() for path in first.iterdir() if path.is_file()}
        backend = RecordingBackend()
        with self.executor() as executor:
            report = executor.run("scale", 1, backend, retry=[planned])
        self.assertEqual(len(backend.calls), 1)
        second = self.directory(number=2)
        initial, retried = read(first / "started.json"), read(second / "started.json")
        self.assertNotEqual(initial["metadata"]["run_id"], retried["metadata"]["run_id"])
        self.assertEqual(retried["metadata"]["attempt_number"], 2)
        self.assertEqual(retried["previous_attempt_id"], initial["metadata"]["attempt_id"])
        self.assertEqual(report["planned_units_with_attempts"], 1)
        self.assertEqual(report["attempt_status_counts"], {"failed": 1, "completed": 1})
        self.assertEqual(
            {path.name: path.read_bytes() for path in first.iterdir() if path.is_file()}, before
        )
        self.assertIn("not independent", report["analysis_selection"])

    def test_keyboard_interrupt_persists_blocked_attempt_before_propagating(self):
        class InterruptedBackend(RecordingBackend):
            def __call__(self, attempt):
                self.calls.append(attempt)
                raise KeyboardInterrupt

        backend = InterruptedBackend()
        with self.executor() as executor:
            with self.assertRaises(KeyboardInterrupt):
                executor.run("scale", 1, backend)
            report = executor.report()
        self.assertEqual(len(backend.calls), 1)
        self.assertEqual(report["attempt_status_counts"], {"blocked": 1})
        record = read(self.directory() / "measurement.json")
        self.assertEqual(record["status"], "blocked")
        self.assertEqual(record["metrics"], {})
        self.assertIn("KeyboardInterrupt", record["reason"])
        resumed = RecordingBackend()
        with self.executor() as executor:
            executor.run("scale", 1, resumed, limit=1)
        self.assertNotEqual(resumed.calls[0].metadata["planned_id"], self.planned())

    def test_unfinished_started_claim_becomes_blocked_and_is_skipped(self):
        _, _, directory = self.run_one()
        started = (directory / "started.json").read_bytes()
        for name in ("result.json", "measurement.json", "backend-result.json"):
            (directory / name).unlink()
        backend = RecordingBackend()
        with self.executor() as executor:
            executor.reconcile()
            self.assertEqual(executor.report()["attempt_status_counts"], {"blocked": 1})
            executor.run("scale", 1, backend, limit=1)
        self.assertEqual((directory / "started.json").read_bytes(), started)
        self.assertEqual(read(directory / "measurement.json")["metrics"], {})
        self.assertNotEqual(backend.calls[0].metadata["planned_id"], self.planned())
        self.assertFalse(self.directory(number=2).exists())

    def test_published_measurement_without_terminal_is_recovered_without_reexecution(self):
        _, _, directory = self.run_one()
        original = (directory / "measurement.json").read_bytes()
        (directory / "result.json").unlink()
        backend = RecordingBackend()
        with self.executor() as executor:
            executor.reconcile()
            recovered = executor.report()["attempts"][0]
            executor.run("scale", 1, backend, limit=1)
        self.assertEqual(recovered["status"], "completed")
        self.assertEqual(recovered["reason"], "recovered-published-measurement")
        self.assertEqual((directory / "measurement.json").read_bytes(), original)
        self.assertNotEqual(backend.calls[0].metadata["planned_id"], self.planned())

    def test_orphan_directory_before_started_record_is_retained_as_blocked(self):
        with self.executor() as executor:
            directory = self.directory()
            directory.mkdir(parents=True)
            scratch = directory / "unpublished.txt"
            scratch.write_text("interrupted preparation\n")
            executor.reconcile()
            terminal = executor.report()["attempts"][0]
            backend = RecordingBackend()
            executor.run("scale", 1, backend, limit=1)
        self.assertEqual(terminal["status"], "blocked")
        self.assertIsNone(terminal["run_id"])
        self.assertIsNone(terminal["measurement"])
        self.assertEqual(terminal["reason"], "interrupted-before-start-record")
        self.assertEqual(scratch.read_text(), "interrupted preparation\n")
        self.assertNotEqual(backend.calls[0].metadata["planned_id"], self.planned())

    def test_input_drift_aborts_before_any_backend_call_or_claim(self):
        backend = RecordingBackend()
        with self.executor() as executor:
            self.workload.write_text("changed frozen source\n")
            with self.assertRaisesRegex(ValueError, "input file hash differs"):
                executor.run("scale", 1, backend)
        self.assertEqual(backend.calls, [])
        self.assertEqual(list((self.output / "attempts").iterdir()), [])

    def test_wrong_backend_identity_retains_raw_failure_and_has_no_accepted_metrics(self):
        class WrongIdentityBackend(RecordingBackend):
            def __call__(self, attempt):
                response = dict(super().__call__(attempt))
                response["measurement"]["run_id"] = "f" * 32
                response["measurement"]["metrics"] = {"invented_metric": 999}
                response["native_result"] = {"raw_failure_fixture": "retained"}
                return response

        report, _, directory = self.run_one(backend=WrongIdentityBackend())
        self.assertEqual(report["attempt_status_counts"], {"failed": 1})
        record = read(directory / "measurement.json")
        raw = read(directory / "backend-result.json")
        self.assertEqual(record["metrics"], {})
        self.assertNotEqual(record["run_id"], raw["measurement"]["run_id"])
        self.assertEqual(raw["measurement"]["metrics"], {"invented_metric": 999})
        self.assertEqual(raw["native_result"], {"raw_failure_fixture": "retained"})

    def test_backend_exceptions_retain_failed_or_timeout_outcomes_with_missing_metrics(self):
        for index, error in enumerate(
            (RuntimeError("fixture failure"), TimeoutError("fixture timeout"))
        ):
            with self.subTest(error=type(error).__name__):
                backend = RecordingBackend()
                with patch.object(RecordingBackend, "__call__", side_effect=error):
                    report, _, directory = self.run_one(
                        output=self.base / f"exception-{index}", backend=backend
                    )
                expected = "timeout" if isinstance(error, TimeoutError) else "failed"
                self.assertEqual(report["attempt_status_counts"], {expected: 1})
                record = read(directory / "measurement.json")
                self.assertEqual(record["metrics"], {})
                self.assertIn(str(error), record["reason"])

    def test_advisory_lock_rejects_duplicate_executor_and_leaves_owner_usable(self):
        with self.executor() as first:
            with self.assertRaises(BlockingIOError), self.executor():
                self.fail("duplicate lock was accepted")
            report = first.run("scale", 1, RecordingBackend(), limit=1)
        self.assertEqual(report["attempt_status_counts"], {"completed": 1})
        with self.executor() as resumed:
            self.assertEqual(resumed.report()["attempt_status_counts"], {"completed": 1})

    def test_context_lock_and_binding_mode_are_required_before_execution(self):
        executor = self.executor()
        with self.assertRaisesRegex(RuntimeError, "context lock"):
            executor.run("scale", 1, RecordingBackend())
        backend = RecordingBackend()
        backend.mode = "pilot"
        with executor, self.assertRaisesRegex(ValueError, "mode differs"):
            executor.run("scale", 1, backend)
        self.assertEqual(backend.calls, [])

    def test_reconciliation_requires_active_context_lock(self):
        self.run_one()
        executor = self.executor()
        with self.assertRaisesRegex(RuntimeError, "lock"):
            executor.reconcile()
        with executor:
            executor.reconcile()
        with self.assertRaisesRegex(RuntimeError, "lock"):
            executor.reconcile()

    def test_all_history_is_validated_before_any_interrupted_claim_is_recovered(self):
        with self.executor() as executor:
            executor.run("scale", 1, RecordingBackend(), limit=2)
        directories = sorted(self.output.glob("attempts/*/0001"))
        unfinished, corrupted = directories
        for name in ("result.json", "measurement.json", "backend-result.json"):
            (unfinished / name).unlink()
        terminal = read(corrupted / "result.json")
        terminal["run_id"] = "f" * 32
        write(corrupted / "result.json", terminal)
        before = {
            str(path.relative_to(self.output)): digest(path)
            for path in self.output.glob("attempts/*/*/*.json")
        }
        backend = RecordingBackend()
        with self.executor() as executor, self.assertRaises(ValueError):
            executor.run("scale", 1, backend)
        self.assertEqual(backend.calls, [])
        self.assertEqual(
            {
                str(path.relative_to(self.output)): digest(path)
                for path in self.output.glob("attempts/*/*/*.json")
            },
            before,
        )
        self.assertFalse((unfinished / "result.json").exists())

    def test_invalid_retry_prerequisite_is_rejected_before_recovery_writes(self):
        _, _, directory = self.run_one()
        for name in ("result.json", "measurement.json", "backend-result.json"):
            (directory / name).unlink()
        backend = RecordingBackend()
        with self.executor() as executor, self.assertRaisesRegex(ValueError, "preceding attempt"):
            executor.run("scale", 1, backend, retry=[self.planned(index=1)])
        self.assertFalse((directory / "result.json").exists())
        self.assertFalse((directory / "measurement.json").exists())
        self.assertEqual(backend.calls, [])

    def test_attempt_root_symlink_is_rejected_before_writing_to_its_target(self):
        with self.executor():
            pass
        target = self.base / "external-attempts"
        (self.output / "attempts").rename(target)
        (self.output / "attempts").symlink_to(target, target_is_directory=True)
        with self.assertRaises(ValueError), self.executor():
            self.fail("attempt root symlink was accepted")
        self.assertEqual(list(target.iterdir()), [])

    def test_noncanonical_and_gapped_attempt_ordinals_are_refused(self):
        self.run_one()
        directory = self.directory()
        for name in ("00001", "0002"):
            with self.subTest(name=name):
                moved = directory.with_name(name)
                directory.rename(moved)
                backend = RecordingBackend()
                with self.executor() as executor, self.assertRaises(ValueError):
                    executor.run("scale", 1, backend)
                self.assertEqual(backend.calls, [])
                moved.rename(directory)

    def test_invalid_phase_session_retry_and_limit_reject_without_backend_execution(self):
        backend = RecordingBackend()
        options = [
            ("unknown", 1, {}),
            ("scale", True, {}),
            ("scale", 1.0, {}),
            ("scale", 0, {}),
            ("scale", 2, {}),
            ("scale", 1, {"limit": True}),
            ("scale", 1, {"limit": 0}),
            ("scale", 1, {"retry": self.planned()}),
            ("scale", 1, {"retry": [self.planned(), self.planned()]}),
            ("scale", 1, {"retry": [self.planned("fault")]}),
            ("scale", 1, {"retry": [self.planned()]}),
        ]
        with self.executor() as executor:
            for phase, session, arguments in options:
                with (
                    self.subTest(arguments=(phase, session, arguments)),
                    self.assertRaises(ValueError),
                ):
                    executor.run(phase, session, backend, **arguments)
        self.assertEqual(backend.calls, [])
        self.assertEqual(list((self.output / "attempts").iterdir()), [])

    def test_invalid_plan_types_do_not_pass_by_numeric_equality(self):
        cases = [
            ("schema_version", True),
            ("allocation", []),
            ("scale_schedule", {}),
        ]
        for key, invalid in cases:
            with self.subTest(key=key):
                changed = copy.deepcopy(self.plan)
                changed[key] = invalid
                with self.assertRaises(ValueError):
                    campaign_executor.validate_plan(changed)
        for phase in ("scale", "fault"):
            for key in ("sequence", "session", "repetition_within_session", "switches", "hosts"):
                with self.subTest(phase=phase, key=key):
                    changed = copy.deepcopy(self.plan)
                    changed[phase + "_schedule"][0][key] = float(
                        changed[phase + "_schedule"][0][key]
                    )
                    with self.assertRaises(ValueError):
                        campaign_executor.validate_plan(changed)
        changed = copy.deepcopy(self.plan)
        changed["fault_schedule"][0]["executions"][0]["planned_execution_id"] = "changed"
        with self.assertRaises(ValueError):
            campaign_executor.validate_plan(changed)

    def test_terminal_identity_corruption_is_refused_before_resume(self):
        self.run_one()
        path = self.directory() / "result.json"
        original = path.read_bytes()
        for field, invalid in (
            ("run_id", "f" * 32),
            ("attempt_number", True),
            ("planned_id", "other"),
        ):
            with self.subTest(field=field):
                terminal = json.loads(original)
                terminal[field] = invalid
                write(path, terminal)
                backend = RecordingBackend()
                with self.executor() as executor, self.assertRaises(ValueError):
                    executor.run("scale", 1, backend)
                self.assertEqual(backend.calls, [])
                path.write_bytes(original)

    def test_measurement_content_and_published_checksum_corruption_are_refused(self):
        self.run_one()
        directory = self.directory()
        terminal = directory / "result.json"
        measurement = directory / "measurement.json"
        original_terminal, original_measurement = terminal.read_bytes(), measurement.read_bytes()
        for field in ("content", "checksum", "path"):
            with self.subTest(field=field):
                if field == "content":
                    measurement.write_bytes(original_measurement + b" ")
                else:
                    changed = json.loads(original_terminal)
                    changed["measurement"]["sha256" if field == "checksum" else "path"] = (
                        "0" * 64 if field == "checksum" else "../different.json"
                    )
                    write(terminal, changed)
                backend = RecordingBackend()
                with self.executor() as executor, self.assertRaises(ValueError):
                    executor.run("scale", 1, backend)
                self.assertEqual(backend.calls, [])
                terminal.write_bytes(original_terminal)
                measurement.write_bytes(original_measurement)

    def test_raw_backend_checksum_corruption_is_refused_before_resume(self):
        self.run_one()
        raw = self.directory() / "backend-result.json"
        raw.write_bytes(raw.read_bytes() + b" ")
        backend = RecordingBackend()
        with self.executor() as executor, self.assertRaisesRegex(ValueError, "backend outcome"):
            executor.run("scale", 1, backend)
        self.assertEqual(backend.calls, [])

    def test_duplicate_json_keys_and_nonfinite_terminal_values_are_refused(self):
        self.run_one()
        terminal = self.directory() / "result.json"
        original = terminal.read_text()
        changed = [
            original.replace(
                '"status": "completed"', '"status": "completed", "status": "completed"'
            ),
            original.rstrip()[:-1] + ', "untrusted_extra": NaN}\n',
        ]
        for index, value in enumerate(changed):
            with self.subTest(index=index):
                terminal.write_text(value)
                with self.executor() as executor, self.assertRaises(ValueError):
                    executor.run("scale", 1, RecordingBackend())
                terminal.write_text(original)

    def test_publication_write_failures_leave_recoverable_claims_without_duplicate_execution(self):
        original_write = campaign_executor._write_new
        for filename in ("started.json", "measurement.json", "result.json"):
            with self.subTest(filename=filename):
                output = self.base / ("publication-" + filename)
                backend = RecordingBackend()

                def failing_write(path, value, target=filename):
                    if path.name == target:
                        raise OSError("synthetic publication failure")
                    return original_write(path, value)

                with (
                    self.executor(output) as executor,
                    patch.object(campaign_executor, "_write_new", side_effect=failing_write),
                    self.assertRaisesRegex(OSError, "synthetic publication failure"),
                ):
                    executor.run("scale", 1, backend, limit=1)
                directory = self.directory(output=output)
                self.assertTrue(directory.is_dir())
                self.assertFalse((directory / "result.json").exists())
                resumed = RecordingBackend()
                with self.executor(output) as executor:
                    executor.reconcile()
                    report = executor.report()
                    executor.run("scale", 1, resumed, limit=1)
                expected = "blocked" if filename == "started.json" else "completed"
                self.assertEqual(report["attempt_status_counts"], {expected: 1})
                self.assertNotEqual(resumed.calls[0].metadata["planned_id"], self.planned())
                self.assertFalse(self.directory(output=output, number=2).exists())

    def test_cli_defaults_to_synthetic_execution(self):
        arguments = [
            "harness.campaign_executor",
            "--plan",
            str(self.plan_path),
            "--control",
            str(self.control),
            "--dependencies",
            str(self.dependency),
            "--output",
            str(self.output),
            "--phase",
            "scale",
            "--session",
            "1",
            "--limit",
            "1",
        ]
        stdout = io.StringIO()
        with (
            patch.object(sys, "argv", arguments),
            patch.object(campaign_executor, "PAPER", self.base),
            redirect_stdout(stdout),
        ):
            campaign_executor.main()
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["attempt_status_counts"], {"completed": 1})
        self.assertFalse(report["performance_samples"])
        record = read(self.directory() / "measurement.json")
        self.assertEqual(record["mode"], "synthetic-validation")

    def test_backend_cannot_replace_the_durable_claim_by_mutating_its_context(self):
        class MutatingBackend(RecordingBackend):
            def __call__(self, attempt):
                attempt.started["metadata"]["session"] = 2
                return super().__call__(attempt)

        report, _, directory = self.run_one(backend=MutatingBackend())
        self.assertEqual(report["attempt_status_counts"], {"failed": 1})
        record = read(directory / "measurement.json")
        self.assertEqual(record["session"], 1)
        self.assertEqual(record["metrics"], {})
        self.assertEqual(read(directory / "started.json")["metadata"]["session"], 1)
        self.assertEqual(read(directory / "backend-result.json")["measurement"]["session"], 2)

    def test_interrupted_invocation_includes_the_started_attempt(self):
        class InterruptedBackend(RecordingBackend):
            def __call__(self, attempt):
                raise KeyboardInterrupt

        with self.executor() as executor, self.assertRaises(KeyboardInterrupt):
            executor.run("scale", 1, InterruptedBackend(), limit=1)
        (report_path,) = self.output.glob("execution-report-*.json")
        report = read(report_path)
        started = read(self.directory() / "started.json")
        self.assertEqual(
            report["invocation"]["executed_attempt_ids"], [started["metadata"]["attempt_id"]]
        )
        self.assertEqual(report["attempt_status_counts"], {"blocked": 1})


if __name__ == "__main__":
    unittest.main()
