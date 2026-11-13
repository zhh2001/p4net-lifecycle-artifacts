"""Check planned denominators, independent profile pairs, and read-only history."""

import copy
import hashlib
import json
import unittest

from harness import observer_calibration_plan
from harness import observer_campaign as execution
from harness import observer_campaign_analysis as analysis

from harness_tests import test_observer_campaign_inputs as bindings


def seal(snapshot):
    snapshot.pop("snapshot_sha256", None)
    snapshot["snapshot_sha256"] = hashlib.sha256(analysis._canonical(snapshot)).hexdigest()
    return snapshot


def synthetic_snapshot(*, populated=True):
    plan = observer_calibration_plan.generate()
    attempts = []
    if populated:
        for row in plan["calibration_schedule"]:
            planned = row["planned_task_id"]
            value = {"B": 10, "T": 12, "S": 20}[row["observer_profile"]]
            attempts.append(
                {
                    "directory": f"attempts/{planned}/0001",
                    "started": {"metadata": {"attempt_id": f"{planned}--a0001"}},
                    "result": {"status": "completed", "attempt_id": f"{planned}--a0001"},
                    "measurement": {
                        "metrics": {"observer_body_wall_ns": value, "observer_cpu_seconds": value},
                        "qualified": True,
                    },
                }
            )
    return seal(
        {
            "schema_version": 1,
            "record_type": "observer-campaign-snapshot",
            "read_only": True,
            "mode": "synthetic-validation",
            "performance_samples": False,
            "binding": {"input_lock_sha256": "a" * 64},
            "plan": plan,
            "attempts": attempts,
            "gate_reviews": [],
            "input_hashes": {},
        }
    )


class CoverageTests(unittest.TestCase):
    def summary(self, snapshot, **kwargs):
        return analysis.summarize_snapshot(snapshot, selection="first-attempt", **kwargs)

    def test_empty_history_keeps_all_planned_denominators_and_missing_metrics(self):
        report = self.summary(synthetic_snapshot(populated=False), expected_metrics=["wall"])
        self.assertEqual(report["overall"]["planned_units"], 270)
        self.assertEqual(report["overall"]["state_counts"]["unattempted"], 270)
        self.assertFalse(report["overall"]["all_planned_terminal"])
        self.assertEqual(len(report["groups"]), 18)
        self.assertEqual(len(report["contrasts"]), 18)
        self.assertTrue(all(group["overall"]["planned_units"] == 15 for group in report["groups"]))
        self.assertIsNone(report["overall"]["metrics"]["wall"]["median"])
        self.assertEqual(report["overall"]["metrics"]["wall"]["n"], 0)

    def test_full_plan_has_ninety_blocks_and_fifteen_pairs_per_tool_scale(self):
        report = self.summary(synthetic_snapshot())
        self.assertEqual(report["overall"]["state_counts"]["completed"], 270)
        self.assertTrue(report["overall"]["all_planned_terminal"])
        self.assertEqual(report["complete_profile_blocks"], 90)
        for contrast in report["contrasts"]:
            metric = contrast["metrics"]["observer_body_wall_ns"]
            self.assertEqual(metric["eligible_pairs"], 15)
            self.assertEqual(metric["session_counts"], {"1": 5, "2": 5, "3": 5})
            expected = {"S-B": 10, "S-T": 8, "T-B": 2}[contrast["contrast"]]
            self.assertTrue(all(row["difference"] == expected for row in metric["differences"]))
        self.assertEqual(
            {group["key"]["tool"] for group in report["groups"]},
            {"p4net", "p4utils", "tutorial-components"},
        )

    def test_missing_sampled_metric_does_not_remove_timestamp_boundary_pair(self):
        snapshot = synthetic_snapshot()
        index = next(
            i
            for i, row in enumerate(snapshot["plan"]["calibration_schedule"])
            if row["observer_profile"] == "S"
        )
        row = snapshot["plan"]["calibration_schedule"][index]
        snapshot["attempts"][index]["measurement"]["metrics"].pop("observer_cpu_seconds")
        snapshot["attempts"][index]["measurement"]["qualified"] = False
        report = self.summary(seal(snapshot))
        matched = [
            item
            for item in report["contrasts"]
            if item["tool"] == row["tool"] and item["switches"] == row["switches"]
        ]
        for contrast in matched:
            expected = 15 if contrast["contrast"] == "T-B" else 14
            self.assertEqual(
                contrast["metrics"]["observer_cpu_seconds"]["eligible_pairs"], expected
            )
            self.assertEqual(contrast["metrics"]["observer_body_wall_ns"]["eligible_pairs"], 15)
        self.assertEqual(report["overall"]["state_counts"]["completed"], 270)
        self.assertEqual(report["overall"]["measurement_qualified_units"], 269)
        self.assertEqual(report["complete_profile_blocks"], 90)
        self.assertEqual(report["metric_complete_profile_blocks"]["observer_cpu_seconds"], 89)

    def test_retry_success_remains_supplementary_to_first_failure(self):
        snapshot = synthetic_snapshot()
        original = snapshot["attempts"][0]
        retry = copy.deepcopy(original)
        retry["directory"] = retry["directory"][:-4] + "0002"
        retry["result"]["attempt_id"] = retry["result"]["attempt_id"][:-4] + "0002"
        snapshot["attempts"].append(retry)
        original["result"]["status"] = "failed"
        original["measurement"].update(metrics={}, qualified=False)
        seal(snapshot)
        primary = self.summary(snapshot)
        latest = analysis.summarize_snapshot(snapshot, selection="latest-attempt")
        self.assertEqual(primary["overall"]["state_counts"]["failed"], 1)
        self.assertEqual(primary["overall"]["state_counts"]["completed"], 269)
        self.assertEqual(latest["overall"]["state_counts"]["completed"], 270)
        self.assertEqual(primary["analysis_role"], "primary")
        self.assertEqual(latest["analysis_role"], "supplementary")
        self.assertEqual(sum(map(len, primary["attempt_history"].values())), 271)

    def test_unfinalized_measurement_does_not_supply_an_observed_value(self):
        snapshot = synthetic_snapshot()
        snapshot["attempts"][0]["result"] = None
        report = self.summary(seal(snapshot))
        self.assertEqual(report["overall"]["state_counts"]["unfinalized"], 1)
        self.assertEqual(report["overall"]["metrics"]["observer_body_wall_ns"]["n"], 269)

    def test_session_and_qualification_scope_are_distinct(self):
        snapshot = synthetic_snapshot()
        report = self.summary(snapshot, sessions=[2])
        self.assertEqual(report["overall"]["planned_units"], 90)
        self.assertTrue(
            all(
                item["metrics"]["observer_body_wall_ns"]["planned_pairs"] == 5
                for item in report["contrasts"]
            )
        )
        qualification = self.summary(snapshot, phase="qualification")
        self.assertEqual(qualification["overall"]["planned_units"], 9)
        self.assertEqual(qualification["overall"]["state_counts"]["unattempted"], 9)
        self.assertEqual(qualification["contrasts"], [])

    def test_invalid_selection_scope_and_changed_snapshot_are_rejected(self):
        snapshot = synthetic_snapshot(populated=False)
        for kwargs in (
            {"sessions": [True]},
            {"sessions": [1, 1]},
            {"sessions": []},
            {"phase": "qualification", "sessions": [1]},
            {"expected_metrics": "wall"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.summary(snapshot, **kwargs)
        with self.assertRaises(ValueError):
            analysis.summarize_snapshot(snapshot, selection="automatic")
        snapshot["read_only"] = False
        with self.assertRaises(ValueError):
            self.summary(snapshot)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.fixture = bindings.ObserverBindingTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.base = self.fixture.base
        self.output = self.base / "journal"
        self.binding = self.fixture.build()
        with execution.Campaign(self.output, self.binding, base=self.base):
            pass

    def census(self):
        return {
            str(path): (
                hashlib.sha256(path.read_bytes()).hexdigest(),
                path.stat().st_mtime_ns,
                path.stat().st_ino,
            )
            for path in self.output.rglob("*")
            if path.is_file()
        }

    def test_reader_preserves_bytes_mtime_and_inode(self):
        before = self.census()
        first = analysis.load_snapshot(self.output, base=self.base)
        second = analysis.load_snapshot(self.output, base=self.base)
        self.assertEqual(first, second)
        self.assertEqual(before, self.census())

    def test_historical_read_does_not_require_current_runtime_or_original_plan(self):
        self.fixture.plan.unlink()
        self.fixture.core.write_text("evolved source")
        snapshot = analysis.load_snapshot(self.output, base=self.base)
        self.assertEqual(len(snapshot["plan"]["qualification_schedule"]), 9)
        with self.assertRaises((ValueError, OSError)):
            execution.Campaign(self.output, self.binding, base=self.base)

    def test_reader_refuses_active_writer_and_does_not_create_a_missing_journal(self):
        with (
            execution.Campaign(self.output, self.binding, base=self.base),
            self.assertRaises(RuntimeError),
        ):
            analysis.load_snapshot(self.output, base=self.base)
        missing = self.base / "missing"
        with self.assertRaises(ValueError):
            analysis.load_snapshot(missing, base=self.base)
        self.assertFalse(missing.exists())

    def test_partial_claim_remains_unfinalized_without_recovery(self):
        planned = self.fixture.allocation["qualification_schedule"][0]["planned_parent_id"]
        directory = self.output / "attempts" / planned / "0001"
        directory.mkdir(parents=True)
        before = self.census()
        snapshot = analysis.load_snapshot(self.output, base=self.base)
        report = analysis.summarize_snapshot(
            snapshot, selection="first-attempt", phase="qualification"
        )
        self.assertEqual(report["overall"]["state_counts"]["unfinalized"], 1)
        self.assertEqual(before, self.census())
        self.assertFalse((directory / "result.json").exists())

    def test_modified_terminal_measurement_is_rejected(self):
        with execution.Campaign(self.output, self.binding, base=self.base) as campaign:
            campaign.run(execution.SyntheticBackend(), phase="qualification", limit=1)
        path = next((self.output / "attempts").glob("*/*/measurement.json"))
        value = json.loads(path.read_text())
        value["metrics"]["observer_body_wall_ns"] += 1
        path.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            analysis.load_snapshot(self.output, base=self.base)
