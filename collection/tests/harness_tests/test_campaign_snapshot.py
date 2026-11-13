"""Check immutable campaign reads, historical inputs, and journal corruption."""

import copy
import fcntl
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import campaign, campaign_executor, campaign_inputs, campaign_snapshot


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n")
    return path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rehash(snapshot):
    payload = {key: value for key, value in snapshot.items() if key != "snapshot_sha256"}
    snapshot["snapshot_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


class CampaignSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.output = self.base / "output"
        self.plan = campaign.generate(sessions=1, repetitions_per_session=1)
        self.plan_path = write(self.base / "campaign.json", self.plan)
        self.source = write(self.base / "worker.py", {"fixture": "source"})
        write(self.base / "deps" / "environment.json", {})
        write(self.base / "deps" / "tools.json", {})
        write(self.base / "deps" / "mininet.json", {})
        artifact = write(self.base / "fixture.whl", {})
        dependency = write(
            self.base / "deps" / "manifest.json",
            {
                "environment_files": {"tool": "environment.json"},
                "tools_file": "tools.json",
                "mininet_source_file": "mininet.json",
                "artifacts": {"tool": {"path": "../fixture.whl", "sha256": digest(artifact)}},
            },
        )
        control = write(
            self.base / "control.json",
            {
                "campaign": {"path": "campaign.json", "sha256": digest(self.plan_path)},
                "dependency_freeze": {
                    "path": "deps/manifest.json",
                    "sha256": digest(dependency),
                },
                "sources": {},
            },
        )
        self.binding = campaign_inputs.build_binding(
            self.plan_path,
            control,
            dependency,
            [self.source],
            mode="synthetic-validation",
            base=self.base,
        )
        for name in (
            "subprocess.run",
            "subprocess.Popen",
            "socket.socket",
            "harness.isolation.run_isolated",
            "harness.measure.sample_window",
            "harness.resources.read_sample",
        ):
            blocker = patch(name, side_effect=AssertionError(f"unexpected live operation: {name}"))
            blocker.start()
            self.addCleanup(blocker.stop)

    def executor(self):
        return campaign_executor.Campaign(self.output, self.binding, base=self.base)

    def run_one(self, *, status="completed"):
        planned = self.plan["scale_schedule"][0]["planned_case_id"]
        with self.executor() as executor:
            executor.run("scale", 1, campaign_executor.SyntheticBackend({planned: status}), limit=1)
        return self.output / "attempts" / planned / "0001"

    def load(self, **kwargs):
        return campaign_snapshot.load_snapshot(self.output, base=self.base, **kwargs)

    def byte_tree(self):
        return {
            str(path.relative_to(self.output)): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in self.output.rglob("*")
            if path.is_file()
        }

    def test_completed_snapshot_preserves_all_bytes_and_hashes(self):
        directory = self.run_one()
        before = self.byte_tree()
        result = self.load()
        self.assertEqual(self.byte_tree(), before)
        self.assertEqual(result["record_type"], "campaign-snapshot")
        self.assertEqual(result["attempts"][0]["state"], "completed")
        self.assertEqual(result["attempts"][0]["measurement"]["status"], "completed")
        self.assertEqual(len(result["unattempted_planned_ids"]), 32)
        self.assertEqual(len(result["input_hashes"]), 6)
        for path, expected in result["input_hashes"].items():
            self.assertEqual(digest(Path(path)), expected)
        payload = {key: value for key, value in result.items() if key != "snapshot_sha256"}
        self.assertEqual(
            hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            ).hexdigest(),
            result["snapshot_sha256"],
        )
        self.assertEqual(result, self.load())
        self.assertIn(str(directory / "result.json"), result["input_hashes"])

    def test_current_sources_and_deleted_runtime_dependencies_do_not_invalidate_history(self):
        self.run_one()
        self.source.write_text("changed source\n")
        for path in (self.base / "deps").rglob("*.json"):
            path.unlink()
        with patch(
            "harness.campaign_inputs.verify_binding", side_effect=AssertionError("live verify")
        ):
            result = self.load()
        self.assertEqual(result["binding"], self.binding)
        self.assertEqual(result["attempts"][0]["state"], "completed")

    def test_unfinished_claim_is_not_recovered_or_promoted(self):
        directory = self.run_one()
        (directory / "result.json").unlink()
        before = self.byte_tree()
        result = self.load()
        self.assertEqual(result["attempts"][0]["state"], "unfinalized")
        self.assertEqual(result["attempts"][0]["measurement"]["status"], "completed")
        self.assertEqual(self.byte_tree(), before)
        self.assertFalse((directory / "result.json").exists())

    def test_unfinished_start_only_and_no_start_directories_are_retained(self):
        directory = self.run_one()
        for name in ("measurement.json", "backend-result.json", "result.json"):
            (directory / name).unlink()
        second_planned = self.plan["scale_schedule"][1]["planned_case_id"]
        second = self.output / "attempts" / second_planned / "0001"
        second.mkdir(parents=True)
        attempts = self.load()["attempts"]
        by_planned = {row["planned_id"]: row for row in attempts}
        self.assertEqual([row["state"] for row in attempts], ["unfinalized", "unfinalized"])
        self.assertIsNotNone(by_planned[directory.parent.name]["run_id"])
        self.assertIsNone(by_planned[second_planned]["run_id"])

    def test_reconciled_orphan_retains_blocked_without_measurement(self):
        with self.executor() as executor:
            planned = self.plan["scale_schedule"][0]["planned_case_id"]
            directory = self.output / "attempts" / planned / "0001"
            directory.mkdir(parents=True)
            executor.reconcile()
        result = self.load()["attempts"][0]
        self.assertEqual(result["state"], "blocked")
        self.assertIsNone(result["run_id"])
        self.assertIsNone(result["measurement"])

    def test_empty_journal_preserves_full_planned_denominator(self):
        with self.executor():
            pass
        result = self.load()
        self.assertEqual(result["attempts"], [])
        self.assertEqual(len(result["unattempted_planned_ids"]), 33)

    def test_attempts_order_numerically_and_keep_distinct_uuid_claims(self):
        self.run_one(status="failed")
        planned = self.plan["scale_schedule"][0]["planned_case_id"]
        for _ in range(2):
            with self.executor() as executor:
                executor.run("scale", 1, campaign_executor.SyntheticBackend(), retry=[planned])
        rows = self.load()["attempts"]
        self.assertEqual([row["attempt_number"] for row in rows], [1, 2, 3])
        self.assertEqual([row["state"] for row in rows], ["failed", "completed", "completed"])
        self.assertEqual(len({row["run_id"] for row in rows}), 3)

    def test_active_executor_lock_refuses_snapshot_without_writes(self):
        self.run_one()
        before = self.byte_tree()
        with (self.output / ".executor.lock").open("rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(ValueError, "being executed"):
                self.load()
        self.assertEqual(self.byte_tree(), before)

    def test_missing_lock_is_not_created(self):
        self.run_one()
        lock = self.output / ".executor.lock"
        lock.unlink()
        with self.assertRaisesRegex(ValueError, "existing regular executor lock"):
            self.load()
        self.assertFalse(lock.exists())

    def test_absent_output_is_not_created(self):
        with self.assertRaisesRegex(ValueError, "existing real directory"):
            self.load()
        self.assertFalse(self.output.exists())

    def test_expected_pins_are_checked(self):
        self.run_one()
        self.load(
            expected_plan_sha256=digest(self.plan_path).upper(),
            expected_input_lock_sha256=self.binding["input_lock_sha256"],
        )
        for kwargs in (
            {"expected_plan_sha256": "f" * 64},
            {"expected_input_lock_sha256": "f" * 64},
            {"expected_plan_sha256": "invalid"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.load(**kwargs)

    def test_changed_plan_or_binding_is_rejected(self):
        self.run_one()
        self.plan_path.write_text(self.plan_path.read_text() + "\n")
        with self.assertRaisesRegex(ValueError, "plan checksum"):
            self.load()
        write(self.plan_path, self.plan)
        binding = copy.deepcopy(self.binding)
        binding["mode"] = "formal"
        write(self.output / "campaign-binding.json", binding)
        with self.assertRaises(ValueError):
            self.load()

    def test_terminal_record_and_measurement_corruption_are_rejected(self):
        directory = self.run_one()
        for filename, field, value in (
            ("result.json", "status", "timeout"),
            ("result.json", "attempt_number", True),
            ("result.json", "run_id", "0" * 32),
            ("measurement.json", "metrics", {"fabricated": 20}),
            ("backend-result.json", "native_result", {"changed": True}),
            ("started.json", "previous_attempt_id", "wrong"),
        ):
            path = directory / filename
            original = path.read_bytes()
            record = json.loads(original)
            record[field] = value
            write(path, record)
            with self.subTest(filename=filename, field=field), self.assertRaises(ValueError):
                self.load()
            path.write_bytes(original)

    def test_duplicate_or_nonfinite_json_is_rejected(self):
        directory = self.run_one()
        path = directory / "result.json"
        for text in (
            '{"status":"completed","status":"failed"}',
            '{"value":NaN}',
            '{"value":1e999}',
            "[]",
        ):
            path.write_text(text)
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.load()

    def test_symlinks_in_journal_are_rejected(self):
        directory = self.run_one()
        for path in (
            self.output / ".executor.lock",
            self.output / "attempts",
            directory,
            directory / "measurement.json",
        ):
            original = path.with_name(path.name + ".original")
            path.rename(original)
            path.symlink_to(original, target_is_directory=original.is_dir())
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.load()
            path.unlink()
            original.rename(path)

    def test_missing_ordinals_and_unknown_planned_units_are_rejected(self):
        directory = self.run_one()
        directory.rename(directory.with_name("0002"))
        with self.assertRaisesRegex(ValueError, "missing ordinals"):
            self.load()
        directory.with_name("0002").rename(directory)
        parent = directory.parent
        parent.rename(parent.with_name("unknown-planned-id"))
        with self.assertRaisesRegex(ValueError, "unknown planned"):
            self.load()

    def test_outcomes_without_start_or_terminal_measurement_are_rejected(self):
        directory = self.run_one()
        start = (directory / "started.json").read_bytes()
        (directory / "started.json").unlink()
        with self.assertRaisesRegex(ValueError, "without a preceding start"):
            self.load()
        (directory / "started.json").write_bytes(start)
        (directory / "measurement.json").unlink()
        with self.assertRaisesRegex(ValueError, "missing its measurement"):
            self.load()

    def test_duplicate_uuid_is_rejected_even_for_unfinished_claims(self):
        self.run_one()
        with self.executor() as executor:
            executor.run("scale", 1, campaign_executor.SyntheticBackend(), limit=1)
        starts = sorted(self.output.glob("attempts/*/*/started.json"))
        first, second = (json.loads(path.read_text()) for path in starts)
        second["metadata"]["run_id"] = first["metadata"]["run_id"]
        write(starts[1], second)
        for name in ("result.json", "measurement.json", "backend-result.json"):
            (starts[1].parent / name).unlink()
        with self.assertRaisesRegex(ValueError, "duplicate run_id"):
            self.load()

    def test_in_memory_validation_never_reopens_input_files(self):
        self.run_one()
        snapshot = self.load()
        with patch.object(Path, "read_bytes", side_effect=AssertionError("unexpected file read")):
            campaign_snapshot.validate_snapshot(snapshot)

    def test_in_memory_changes_require_new_snapshot_digest(self):
        self.run_one()
        snapshot = self.load()
        snapshot["attempts"][0]["state"] = "failed"
        with self.assertRaisesRegex(ValueError, "snapshot checksum"):
            campaign_snapshot.validate_snapshot(snapshot)

    def test_rehashed_invalid_in_memory_identities_are_rejected(self):
        self.run_one()
        original = self.load()
        for field, value in (
            ("planned_id", "unknown"),
            ("attempt_number", True),
            ("attempt_id", "changed"),
            ("directory", "../other"),
            ("state", "timeout"),
            ("reason", []),
            ("run_id", None),
            ("run_id", "invalid"),
            ("measurement", None),
        ):
            snapshot = copy.deepcopy(original)
            snapshot["attempts"][0][field] = value
            rehash(snapshot)
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                campaign_snapshot.validate_snapshot(snapshot)

    def test_rehashed_invalid_missing_population_and_evidence_are_rejected(self):
        self.run_one()
        original = self.load()
        for field, value in (
            ("schema_version", True),
            ("attempts", {}),
            ("unattempted_planned_ids", []),
            ("input_hashes", {"relative.json": "a" * 64}),
            ("input_hashes", {"/absolute.json": "a" * 64}),
        ):
            snapshot = copy.deepcopy(original)
            snapshot[field] = value
            rehash(snapshot)
            with self.subTest(field=field), self.assertRaises(ValueError):
                campaign_snapshot.validate_snapshot(snapshot)

    def test_terminal_metadata_must_match_plan_even_when_checksums_are_repaired(self):
        directory = self.run_one()
        measurement = json.loads((directory / "measurement.json").read_text())
        measurement["matched_block"] = "another-block"
        write(directory / "measurement.json", measurement)
        terminal = json.loads((directory / "result.json").read_text())
        terminal["measurement"]["sha256"] = digest(directory / "measurement.json")
        write(directory / "result.json", terminal)
        with self.assertRaisesRegex(ValueError, "measurement identity"):
            self.load()

    def test_retry_cannot_follow_unfinalized_predecessor(self):
        directory = self.run_one()
        planned = directory.parent.name
        with self.executor() as executor:
            executor.run("scale", 1, campaign_executor.SyntheticBackend(), retry=[planned])
        snapshot = self.load()
        snapshot["attempts"][0]["state"] = "unfinalized"
        rehash(snapshot)
        with self.assertRaisesRegex(ValueError, "unfinalized predecessor"):
            campaign_snapshot.validate_snapshot(snapshot)
        (directory / "result.json").unlink()
        with self.assertRaisesRegex(ValueError, "unfinalized predecessor"):
            self.load()


if __name__ == "__main__":
    unittest.main()
