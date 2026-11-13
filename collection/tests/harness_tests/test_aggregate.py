"""Check run-level outcome denominators and offline distribution summaries."""

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

from harness import aggregate


def record(run_id="run-1", **changes):
    value = {
        "schema_version": 1,
        "record_type": "measurement-record",
        "mode": "synthetic-validation",
        "performance_samples": False,
        "run_id": run_id,
        "session": 1,
        "tool": "p4net",
        "python": "3.10.20",
        "input_lock_sha256": "a" * 64,
        "workload": "scale",
        "switches": 4,
        "configuration_profile": "matched-v1",
        "build_mode": "native-source-cold",
        "fault": None,
        "status": "completed",
        "metrics": {"task_to_ready_ns": 100},
    }
    value.update(changes)
    return value


class SummaryTests(unittest.TestCase):
    def test_failures_remain_in_denominator_but_not_completed_timing_distribution(self):
        rows = [
            record("done-1", metrics={"task_to_ready_ns": 10}),
            record("done-2", metrics={"task_to_ready_ns": 30}),
            record("failed", status="failed", metrics={"task_to_ready_ns": 9000}),
            record("timeout", status="timeout", metrics={}),
            record("blocked", status="blocked", metrics={}),
        ]
        result = aggregate.summarize(rows, "synthetic-validation")
        overall = result["groups"][0]["overall"]
        self.assertEqual(overall["total_runs"], 5)
        self.assertEqual(
            overall["status_counts"], {"completed": 2, "failed": 1, "timeout": 1, "blocked": 1}
        )
        self.assertEqual(overall["completion_proportion"], 0.4)
        self.assertEqual(
            overall["metrics"]["task_to_ready_ns"],
            {"n": 2, "missing_completed": 0, "q1": 15, "median": 20, "q3": 25, "iqr": 10},
        )
        self.assertEqual(
            overall["incomplete_runs"][0],
            {"input_index": 2, "run_id": "failed", "status": "failed", "session": 1},
        )
        self.assertEqual(overall["run_ids"], [row["run_id"] for row in rows])
        self.assertEqual(result["denominator"], "observed-records")

    def test_missing_metrics_are_not_zero_and_raw_samples_are_not_repetitions(self):
        rows = [
            record("sampled", metrics={"idle_worker_cpu_percent": 40}, raw_samples=[1] * 100),
            record("missing", metrics={}),
            record("failed", status="failed", metrics={"only_failed_ns": 20}),
        ]
        overall = aggregate.summarize(rows, "synthetic-validation")["groups"][0]["overall"]
        cpu = overall["metrics"]["idle_worker_cpu_percent"]
        self.assertEqual((cpu["n"], cpu["missing_completed"], cpu["median"]), (1, 1, 40))
        failed = overall["metrics"]["only_failed_ns"]
        self.assertEqual((failed["n"], failed["missing_completed"]), (0, 2))
        self.assertIsNone(failed["median"])
        self.assertEqual(overall["total_runs"], 3)

    def test_session_strata_preserve_all_observed_outcomes(self):
        rows = [
            record("s1", session=1),
            record("s2", session=2, status="timeout", metrics={}),
        ]
        group = aggregate.summarize(rows, "synthetic-validation")["groups"][0]
        self.assertEqual(group["overall"]["status_counts"]["timeout"], 1)
        self.assertEqual([row["session"] for row in group["sessions"]], [1, 2])
        self.assertEqual(group["sessions"][1]["completion_proportion"], 0)

    def test_expected_metrics_remain_visible_when_every_value_is_missing(self):
        result = aggregate.summarize(
            [record("complete", metrics={}), record("failed", status="failed", metrics={})],
            "synthetic-validation",
            expected_metrics=["idle_worker_cpu_percent"],
        )
        group = result["groups"][0]
        expected = {
            "n": 0,
            "missing_completed": 1,
            "q1": None,
            "median": None,
            "q3": None,
            "iqr": None,
        }
        self.assertEqual(group["overall"]["metrics"]["idle_worker_cpu_percent"], expected)
        self.assertEqual(group["sessions"][0]["metrics"]["idle_worker_cpu_percent"], expected)
        self.assertEqual(result["expected_metrics"], ["idle_worker_cpu_percent"])
        for names in ("cpu", [None], [""]):
            with self.subTest(names=names), self.assertRaises(ValueError):
                aggregate.summarize([record()], "synthetic-validation", expected_metrics=names)

    def test_session_without_a_metric_keeps_the_group_metric_as_missing(self):
        result = aggregate.summarize(
            [record("with", session=1), record("without", session=2, metrics={})],
            "synthetic-validation",
        )
        session = result["groups"][0]["sessions"][1]
        self.assertEqual(session["metrics"]["task_to_ready_ns"]["missing_completed"], 1)
        self.assertEqual(session["metrics"]["task_to_ready_ns"]["n"], 0)

    def test_native_outcomes_have_independent_denominators_without_status_inference(self):
        rows = [
            record(
                "complete-failed-recovery",
                ordinary_stop_timeout=True,
                recovery_success=False,
                framework_complete=True,
                ordinary_cleanup_clean=False,
                restart_ordinary_stop_timeout=True,
                restart_ordinary_cleanup_clean=False,
            ),
            record(
                "failed-recovered",
                ordinary_stop_timeout=False,
                status="failed",
                recovery_success=True,
                framework_complete=False,
                ordinary_cleanup_clean=True,
                restart_ordinary_stop_timeout=False,
                restart_ordinary_cleanup_clean=True,
                session=2,
            ),
            record("missing", recovery_success=None),
        ]
        result = aggregate.summarize(rows, "synthetic-validation")
        overall = result["groups"][0]["overall"]
        expected = {
            "true": 1,
            "false": 1,
            "missing": 1,
            "observed_denominator": 2,
            "true_proportion": 0.5,
        }
        for name in aggregate.NATIVE_OUTCOMES:
            self.assertEqual(overall["native_outcomes"][name], expected)
        first_session = result["groups"][0]["sessions"][0]
        self.assertEqual(
            first_session["native_outcomes"]["recovery_success"],
            {
                "true": 0,
                "false": 1,
                "missing": 1,
                "observed_denominator": 1,
                "true_proportion": 0,
            },
        )
        second_session = result["groups"][0]["sessions"][1]
        self.assertEqual(second_session["native_outcomes"]["recovery_success"]["true"], 1)
        self.assertEqual(overall["status_counts"]["completed"], 2)
        self.assertIn("separate denominators", result["status_meaning"])

    def test_missing_native_outcomes_remain_unobserved(self):
        overall = aggregate.summarize([record()], "synthetic-validation")["groups"][0]["overall"]
        for value in overall["native_outcomes"].values():
            self.assertEqual(
                value,
                {
                    "true": 0,
                    "false": 0,
                    "missing": 1,
                    "observed_denominator": 0,
                    "true_proportion": None,
                },
            )

    def test_environment_input_lock_and_conditions_remain_separate(self):
        rows = [record()]
        variants = [
            {"tool": "p4utils"},
            {"python": "3.12.3"},
            {"input_lock_sha256": "b" * 64},
            {"switches": 8},
            {"build_mode": "common-precompiled"},
            {"workload": "fault", "fault": "kill-bmv2"},
        ]
        rows.extend(record(f"variant-{i}", **change) for i, change in enumerate(variants))
        result = aggregate.summarize(rows, "synthetic-validation")
        self.assertEqual(len(result["groups"]), 7)
        fault = next(group for group in result["groups"] if group["condition"]["fault"])
        self.assertEqual(fault["replication_unit"], "episode")

    def test_equivalent_digest_case_is_canonicalized_without_mutating_records(self):
        rows = [record(), record("upper", input_lock_sha256="A" * 64)]
        before = copy.deepcopy(rows)
        result = aggregate.summarize(rows, "synthetic-validation")
        self.assertEqual(len(result["groups"]), 1)
        self.assertEqual(result["groups"][0]["condition"]["input_lock_sha256"], "a" * 64)
        self.assertEqual(rows, before)

    def test_quantile_interpolation_is_fixed_for_small_populations(self):
        self.assertEqual(aggregate.quantile([90, 10, 30, 50], 0.25), 25)
        self.assertEqual(aggregate.quantile([90, 10, 30, 50], 0.75), 60)
        self.assertEqual(aggregate.quantile([7], 0.25), 7)
        for probability in (-1, 2, True, float("nan"), float("inf")):
            with self.subTest(probability=probability), self.assertRaises(ValueError):
                aggregate.quantile([1], probability)
        with self.assertRaises(ValueError):
            aggregate.quantile([], 0.5)

    def test_pilot_and_formal_records_require_real_sample_mode(self):
        for mode in ("pilot", "formal"):
            with self.subTest(mode=mode):
                result = aggregate.summarize([record(mode=mode, performance_samples=True)], mode)
                self.assertTrue(result["performance_samples"])
        synthetic = aggregate.summarize([record()], "synthetic-validation")
        self.assertFalse(synthetic["performance_samples"])
        self.assertIn("confidence intervals", synthetic["inference_pending"])


class ValidationTests(unittest.TestCase):
    def test_shared_record_validator_rejects_invalid_mode_and_contract(self):
        self.assertIsNone(aggregate.validate_record(record(), "synthetic-validation"))
        for mode, changes in (("other", {}), ("synthetic-validation", {"session": 0})):
            with self.subTest(mode=mode, changes=changes), self.assertRaises(ValueError):
                aggregate.validate_record(record(**changes), mode)

    def test_native_outcome_values_cannot_be_coerced_to_bool(self):
        for name in aggregate.NATIVE_OUTCOMES:
            for value in (0, 1, "true", [], {}):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    aggregate.validate_record(record(**{name: value}), "synthetic-validation")

    def test_invalid_fields_and_missing_required_fields_are_rejected(self):
        variants = [
            {"schema_version": True},
            {"record_type": "process-resource-sample"},
            {"run_id": " "},
            {"session": 0},
            {"session": True},
            {"switches": -1},
            {"python": ""},
            {"input_lock_sha256": "z" * 64},
            {"input_lock_sha256": "a" * 63},
            {"tool": []},
            {"build_mode": ""},
            {"workload": "other"},
            {"configuration_profile": "native"},
            {"fault": ""},
            {"status": "skipped"},
            {"metrics": []},
            {"metrics": {"": 1}},
            {"metrics": {"value": None}},
            {"metrics": {"value": True}},
            {"metrics": {"value": -1}},
            {"metrics": {"value": float("nan")}},
            {"metrics": {"value": float("inf")}},
            {"metrics": {"value": 10**400}},
        ]
        for change in variants:
            with self.subTest(change=change), self.assertRaises(ValueError):
                aggregate.summarize([record(**change)], "synthetic-validation")
        for key in record():
            changed = record()
            del changed[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                aggregate.summarize([changed], "synthetic-validation")

    def test_duplicate_ids_and_mixed_modes_cannot_enter_a_summary(self):
        cases = [
            [record(), record()],
            [record(), record("formal", mode="formal", performance_samples=True)],
            [record(performance_samples=True)],
            [record(performance_samples=0)],
            [record(mode="pilot")],
        ]
        for rows in cases:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                aggregate.summarize(rows, "synthetic-validation")
        with self.assertRaises(ValueError):
            aggregate.summarize([], "synthetic-validation")
        with self.assertRaises(ValueError):
            aggregate.summarize([record()], "other")


class OutputTests(unittest.TestCase):
    def test_cli_accepts_record_forms_and_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = [root / f"input-{i}.json" for i in range(3)]
            forms = [record("one"), [record("two")], {"records": [record("three")]}]
            for path, data in zip(paths, forms, strict=True):
                path.write_text(json.dumps(data))
            output = root / "nested/summary.json"
            arguments = [
                "--mode",
                "synthetic-validation",
                "--output",
                str(output),
                *map(str, paths),
            ]
            aggregate.main(arguments)
            original = output.read_bytes()
            result = json.loads(original)
            self.assertEqual(result["total_records"], 3)
            self.assertEqual(len(result["input_files"]), 3)
            self.assertEqual(result["input_files"][0]["records"], 1)
            self.assertFalse(result["performance_samples"])
            expected_output = root / "with-expected.json"
            aggregate.main(
                [
                    "--mode",
                    "synthetic-validation",
                    "--output",
                    str(expected_output),
                    "--expected-metric",
                    "idle_bmv2_cpu_percent",
                    *map(str, paths),
                ]
            )
            expected = json.loads(expected_output.read_text())
            missing = expected["groups"][0]["overall"]["metrics"]["idle_bmv2_cpu_percent"]
            self.assertEqual((missing["n"], missing["missing_completed"]), (0, 3))
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                aggregate.main(arguments)
            self.assertEqual(output.read_bytes(), original)

    def test_cli_rejects_nonfinite_json_before_creating_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "bad.json"
            source.write_text(json.dumps(record(metrics={"metric": float("nan")})))
            output = root / "summary.json"
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                aggregate.main(
                    ["--mode", "synthetic-validation", "--output", str(output), str(source)]
                )
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
