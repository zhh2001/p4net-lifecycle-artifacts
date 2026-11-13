"""Check allocation, blocking, recovery units, and non-overwriting plan output."""

import json
import tempfile
import unittest
from collections import Counter, defaultdict
from pathlib import Path

from harness.campaign import FAULTS, SCALES, TOOLS, generate, write_plan


class AllocationTests(unittest.TestCase):
    def test_default_counts_distinguish_episodes_from_worker_executions(self) -> None:
        plan = generate()
        summary = plan["summary"]
        self.assertEqual(len(plan["scale_schedule"]), 450)
        self.assertEqual(len(plan["fault_schedule"]), 540)
        self.assertEqual(summary["fault_injected_episodes"], 450)
        self.assertEqual(summary["fault_control_episodes"], 90)
        self.assertEqual(summary["fault_worker_executions"], 1080)
        self.assertEqual(summary["scheduled_worker_executions"], 1530)
        self.assertEqual(summary["independent_replication_units"], 990)
        self.assertEqual(summary["per_tool"]["scheduled_worker_executions"], 510)

    def test_every_tool_and_scale_has_ten_repetitions_per_session(self) -> None:
        plan = generate()
        counts = Counter(
            (row["tool"], row["switches"], row["session"]) for row in plan["scale_schedule"]
        )
        self.assertEqual(len(counts), len(TOOLS) * len(SCALES) * 3)
        self.assertEqual(set(counts.values()), {10})
        self.assertTrue(all(row["hosts"] == 2 * row["switches"] for row in plan["scale_schedule"]))

    def test_matched_blocks_contain_each_tool_once(self) -> None:
        expected = {item["tool"] for item in TOOLS}
        plan = generate(sessions=2, repetitions_per_session=2)
        for schedule in (plan["scale_schedule"], plan["fault_schedule"]):
            blocks = defaultdict(list)
            for row in schedule:
                blocks[row["matched_block"]].append(row["tool"])
            for tools in blocks.values():
                self.assertEqual(len(tools), len(expected))
                self.assertEqual(set(tools), expected)

    def test_normal_control_is_single_condition_not_repeated_for_each_fault(self) -> None:
        rows = generate()["fault_schedule"]
        controls = [row for row in rows if row["fault"] == "normal-control"]
        counts = Counter(row["tool"] for row in controls)
        self.assertEqual(len(controls), 90)
        self.assertEqual(set(counts.values()), {30})
        self.assertEqual(len({row["fault"] for row in rows}), len(FAULTS) + 1)

    def test_recovery_stays_in_same_isolation_and_has_distinct_planned_execution_ids(self) -> None:
        plan = generate(sessions=1, repetitions_per_session=1)
        identifiers = [row["planned_case_id"] for row in plan["scale_schedule"]]
        for row in plan["fault_schedule"]:
            self.assertEqual(row["switches"], 4)
            self.assertEqual(row["isolation_scope"], "same-outer-isolation-for-entire-episode")
            self.assertEqual(
                row["restart_configuration"], "same-node-names-addresses-and-service-ports"
            )
            self.assertEqual(len(row["executions"]), 2)
            self.assertEqual(row["executions"][1]["role"], "next-valid-restart")
            identifiers.append(row["planned_episode_id"])
            identifiers.extend(item["planned_execution_id"] for item in row["executions"])
        self.assertEqual(len(identifiers), len(set(identifiers)))

    def test_schedules_are_reproducible_and_seed_changes_order_not_allocation(self) -> None:
        first = generate(seed=42, sessions=1, repetitions_per_session=2)
        self.assertEqual(first, generate(seed=42, sessions=1, repetitions_per_session=2))
        second = generate(seed=43, sessions=1, repetitions_per_session=2)
        self.assertNotEqual(first["scale_schedule"], second["scale_schedule"])
        for phase, identity in (
            ("scale_schedule", "planned_case_id"),
            ("fault_schedule", "planned_episode_id"),
        ):
            self.assertEqual(
                {row[identity] for row in first[phase]}, {row[identity] for row in second[phase]}
            )
        self.assertEqual(first["summary"], second["summary"])

    def test_schedule_is_planned_and_has_no_fabricated_run_results(self) -> None:
        plan = generate(sessions=1, repetitions_per_session=1)
        self.assertEqual(plan["primary_configuration_selection"], "user-confirmed-matched-v1")
        self.assertTrue(plan["campaign_runner_implemented"])
        self.assertTrue(plan["native_measurement_integration_implemented"])
        self.assertFalse(plan["performance_samples"])
        self.assertEqual(plan["execution_status"], "planned")
        for row in (*plan["scale_schedule"], *plan["fault_schedule"]):
            self.assertEqual(row["configuration_profile"], "matched-v1")
            self.assertEqual(row["execution_status"], "planned")
            self.assertNotIn("run_id", row)
            self.assertNotIn("result", row)
        self.assertTrue(
            all(item["status"].startswith("pending-") for item in plan["secondary_build_modes"])
        )

    def test_custom_session_allocation_has_no_hidden_extra_repetition_factor(self) -> None:
        plan = generate(sessions=2, repetitions_per_session=4)
        self.assertEqual(plan["allocation"]["repetitions_per_condition"], 8)
        self.assertEqual(len(plan["scale_schedule"]), 5 * 3 * 8)
        self.assertEqual(len(plan["fault_schedule"]), 6 * 3 * 8)

    def test_editing_returned_metadata_does_not_change_later_plans(self) -> None:
        plan = generate(sessions=1, repetitions_per_session=1)
        plan["tools"][0]["version"] = "edited"
        second = generate(sessions=1, repetitions_per_session=1)
        self.assertEqual(second["tools"][0]["version"], "1.8.0")

    def test_invalid_allocation_values_are_rejected(self) -> None:
        for kwargs in (
            {"seed": True},
            {"seed": -1},
            {"seed": 2**63},
            {"sessions": 0},
            {"sessions": True},
            {"repetitions_per_session": -2},
            {"repetitions_per_session": 1.5},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                generate(**kwargs)


class PlanOutputTests(unittest.TestCase):
    def test_new_file_and_directory_outputs_preserve_existing_records(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = generate(sessions=1, repetitions_per_session=1)
            direct = write_plan(root / "direct.json", plan)
            nested = write_plan(root / "new-directory", plan)
            self.assertEqual(json.loads(direct.read_text()), plan)
            self.assertEqual(json.loads(nested.read_text()), plan)
            original = direct.read_bytes()
            with self.assertRaises(FileExistsError):
                write_plan(direct, {"replacement": True})
            self.assertEqual(direct.read_bytes(), original)
            with self.assertRaises(FileExistsError):
                write_plan(nested.parent, plan)


if __name__ == "__main__":
    unittest.main()
