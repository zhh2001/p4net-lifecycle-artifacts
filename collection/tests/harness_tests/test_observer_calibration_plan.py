"""Check offline profile balance, qualification stages, and draft-only controls."""

import copy
import hashlib
import io
import json
import tempfile
import unittest
from collections import Counter, defaultdict
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from harness import campaign
from harness import observer_calibration_plan as allocation


class ObserverCalibrationPlanTests(unittest.TestCase):
    def test_candidate_counts_and_nonexecution_controls_are_explicit(self):
        plan = allocation.generate()
        self.assertEqual(
            plan["summary"],
            {
                "qualification_parent_units": 9,
                "qualification_windows": 12,
                "calibration_tasks": 270,
                "calibration_matched_blocks": 90,
            },
        )
        self.assertFalse(plan["runtime_ready"])
        self.assertFalse(plan["collection_authorized"])
        self.assertFalse(plan["performance_samples"])
        self.assertEqual(plan["execution_status"], "planned-not-executable")
        self.assertNotIn("input_lock_sha256", plan)
        self.assertEqual(plan["seed_scope"], "allocation ordering only")
        for row in [*plan["calibration_schedule"], *plan["qualification_schedule"]]:
            self.assertEqual(row["execution_status"], "planned-not-executable")
            self.assertFalse({"run_id", "metrics", "result", "attempt_id"} & row.keys())

    def test_all_profiles_share_hold_and_functional_checks(self):
        profiles = {row["profile"]: row for row in allocation.generate()["profiles"]}
        for profile in profiles.values():
            self.assertEqual(profile["hold_duration_ns"], 10_000_000_000)
            self.assertEqual(profile["hold_anchor"], profiles["B"]["hold_anchor"])
            self.assertTrue(profile["boundary_and_target_checks"])
            self.assertTrue(profile["ordinary_audit_and_cleanup"])
            self.assertTrue(profile["external_reference_required"])
            self.assertFalse(profile["runtime_ready"])
        self.assertFalse(profiles["B"]["internal_recorder"])
        self.assertTrue(profiles["T"]["internal_recorder"])
        self.assertFalse(profiles["T"]["resource_sampler"])
        self.assertTrue(profiles["S"]["resource_sampler"])
        self.assertEqual(profiles["S"]["sampling_interval_ns"], 100_000_000)
        self.assertEqual(profiles["S"]["expected_resource_endpoints"], 101)

    def test_triplets_are_contiguous_unique_and_pairable(self):
        rows = allocation.generate()["calibration_schedule"]
        self.assertEqual([row["sequence"] for row in rows], list(range(1, 271)))
        self.assertEqual(len({row["planned_task_id"] for row in rows}), 270)
        for start in range(0, len(rows), 3):
            triplet = rows[start : start + 3]
            self.assertEqual(len({row["matched_block"] for row in triplet}), 1)
            self.assertEqual({row["observer_profile"] for row in triplet}, {"B", "T", "S"})
            self.assertEqual([row["position_within_block"] for row in triplet], [1, 2, 3])
            self.assertEqual(
                [row["observer_profile"] for row in triplet], triplet[0]["profile_order"]
            )
            self.assertEqual(
                len(
                    {
                        (row["session"], row["tool"], row["switches"], row["block"])
                        for row in triplet
                    }
                ),
                1,
            )

    def test_permutation_and_position_balance_hold_for_every_tool_and_scale(self):
        for seed in (allocation.DEFAULT_SEED, 0, 77, 2**63 - 1):
            rows = allocation.generate(seed)["calibration_schedule"]
            permutations = defaultdict(Counter)
            positions = defaultdict(Counter)
            within_session = defaultdict(set)
            for row in rows:
                condition = row["tool"], row["switches"]
                positions[condition][row["observer_profile"], row["position_within_block"]] += 1
                if row["position_within_block"] == 1:
                    order = tuple(row["profile_order"])
                    permutations[condition][order] += 1
                    within_session[(*condition, row["session"])].add(order)
            self.assertEqual(len(permutations), 6)
            for counts in permutations.values():
                self.assertEqual(len(counts), 6)
                self.assertEqual(sorted(counts.values()), [2, 2, 2, 3, 3, 3])
            for counts in positions.values():
                self.assertEqual(len(counts), 9)
                self.assertEqual(set(counts.values()), {5})
            self.assertEqual(set(map(len, within_session.values())), {5})

    def test_first_live_qualification_has_three_gated_stages_and_twelve_windows(self):
        rows = allocation.generate()["qualification_schedule"]
        self.assertEqual(len({row["planned_parent_id"] for row in rows}), 9)
        self.assertEqual([row["stage"] for row in rows], [1] * 3 + [2] * 3 + [3] * 3)
        for stage, switches, expected in ((1, 1, 1), (2, 4, 2), (3, 16, 1)):
            selected = [row for row in rows if row["stage"] == stage]
            self.assertEqual(
                {row["tool"] for row in selected}, {row["tool"] for row in campaign.TOOLS}
            )
            self.assertEqual({row["switches"] for row in selected}, {switches})
            self.assertEqual({row["observer_profile"] for row in selected}, {"S"})
            self.assertEqual({len(row["expected_windows"]) for row in selected}, {expected})
            self.assertEqual(
                {row["requires_preceding_stage_qualified"] for row in selected}, {stage > 1}
            )
        self.assertEqual({row["fault"] for row in rows if row["stage"] == 2}, {"normal-control"})

    def test_scope_selection_omits_calibration_without_changing_qualification(self):
        full = allocation.generate()
        qualification = allocation.generate(scope="qualification-only")
        self.assertEqual(qualification["qualification_schedule"], full["qualification_schedule"])
        self.assertEqual(qualification["calibration_schedule"], [])
        self.assertIsNone(qualification["calibration_allocation"])
        self.assertIsNone(qualification["initial_calibration_wiring_gate"])
        self.assertEqual(qualification["summary"]["calibration_tasks"], 0)
        self.assertFalse(qualification["runtime_ready"])
        allocation.validate_plan(qualification)

    def test_initial_calibration_gate_is_three_complete_triplets_inside_the_total(self):
        for seed in (allocation.DEFAULT_SEED, 0, 77):
            plan = allocation.generate(seed)
            rows = plan["calibration_schedule"]
            initial = rows[:9]
            gate = plan["initial_calibration_wiring_gate"]
            self.assertEqual(gate["tasks"], 9)
            self.assertEqual(len(rows), 270)
            self.assertEqual(len({row["planned_task_id"] for row in rows}), 270)
            self.assertEqual({row["session"] for row in initial}, {1})
            self.assertEqual({row["switches"] for row in initial}, {1})
            self.assertEqual({row["block"] for row in initial}, {1})
            self.assertEqual(
                Counter((row["tool"], row["observer_profile"]) for row in initial),
                Counter(
                    (tool["tool"], profile)
                    for tool in campaign.TOOLS
                    for profile in ("B", "T", "S")
                ),
            )
            self.assertEqual(gate["planned_task_ids"], [row["planned_task_id"] for row in initial])
            self.assertEqual(
                gate["matched_block_ids"], [row["matched_block"] for row in initial[::3]]
            )
            self.assertTrue(gate["later_tasks_require_gate_qualified"])
            self.assertTrue(gate["first_attempts_remain_in_calibration_denominator"])
            self.assertIn("unattempted", gate["failure_policy"])
            self.assertIn("no automatic retry", gate["failure_policy"])
            self.assertTrue(
                set(gate["planned_task_ids"]).isdisjoint(row["planned_task_id"] for row in rows[9:])
            )

    def test_seed_changes_order_while_retaining_allocation_and_original_formal_plan(self):
        formal = campaign.generate()
        before = json.dumps(formal, sort_keys=True)
        first, other = allocation.generate(), allocation.generate(89)
        self.assertEqual(first, allocation.generate())
        self.assertNotEqual(first["calibration_schedule"], other["calibration_schedule"])
        self.assertEqual(
            {row["planned_task_id"] for row in first["calibration_schedule"]},
            {row["planned_task_id"] for row in other["calibration_schedule"]},
        )
        self.assertEqual(first["summary"], other["summary"])
        first["tools"][0]["tool"] = "draft-only-edit"
        self.assertEqual(json.dumps(formal, sort_keys=True), before)
        self.assertEqual(campaign.generate(), formal)
        self.assertEqual(formal["summary"]["independent_replication_units"], 990)
        self.assertFalse(first["formal_allocation"]["changed"])

    def test_tampering_cannot_be_hidden_by_recomputing_allocation_hash(self):
        plan = allocation.generate()
        for change in ("runtime", "authorization", "row", "hold"):
            edited = copy.deepcopy(plan)
            if change == "runtime":
                edited["runtime_ready"] = True
            elif change == "authorization":
                edited["collection_authorized"] = True
            elif change == "row":
                edited["calibration_schedule"][0]["observer_profile"] = "unexpected"
            else:
                edited["profiles"][0]["hold_duration_ns"] = 0
            edited["plan_sha256"] = hashlib.sha256(
                allocation._canonical(
                    {key: value for key, value in edited.items() if key != "plan_sha256"}
                )
            ).hexdigest()
            with self.subTest(change=change), self.assertRaises(ValueError):
                allocation.validate_plan(edited)
        allocation.validate_plan(plan)

    def test_invalid_seed_scope_and_plan_types_are_rejected(self):
        for seed in (True, False, -1, 2**63, 1.5, "5", None):
            with self.subTest(seed=seed), self.assertRaises(ValueError):
                allocation.generate(seed)
        for scope in ("pilot", "formal", "", None, True):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                allocation.generate(scope=scope)
        for value in (None, [], {}, {"seed": 3, "scope": "unknown"}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                allocation.validate_plan(value)

    def test_output_is_exclusive_and_round_trips_without_changing_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "draft.json"
            plan = allocation.generate()
            before = copy.deepcopy(plan)
            allocation.write_plan(path, plan)
            self.assertEqual(json.loads(path.read_text()), plan)
            contents = path.read_bytes()
            with self.assertRaises(FileExistsError):
                allocation.write_plan(path, plan)
            self.assertEqual(path.read_bytes(), contents)
            self.assertEqual(plan, before)

    def test_cli_has_no_execution_mode_and_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qualification.json"
            args = ["--output", str(path), "--scope", "qualification-only"]
            allocation.main(args)
            self.assertEqual(json.loads(path.read_text())["summary"]["qualification_windows"], 12)
            contents = path.read_bytes()
            for arguments in (args, [*args, "--native"]):
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    allocation.main(arguments)
            self.assertEqual(path.read_bytes(), contents)

    def test_generation_never_touches_live_execution_clock_entropy_or_sampler(self):
        def fail(*args, **kwargs):
            raise AssertionError("unexpected live operation")

        with (
            patch("subprocess.run", side_effect=fail),
            patch("subprocess.Popen", side_effect=fail),
            patch("socket.socket", side_effect=fail),
            patch("time.monotonic_ns", side_effect=fail),
            patch("time.time", side_effect=fail),
            patch("os.urandom", side_effect=fail),
            patch("harness.measure.Recorder", side_effect=fail),
            patch("harness.measure.sample_window", side_effect=fail),
            patch("harness.isolation.run_isolated", side_effect=fail),
        ):
            for scope in allocation.SCOPES:
                plan = allocation.generate(scope=scope)
                allocation.validate_plan(plan)
