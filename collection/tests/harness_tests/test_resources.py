"""Exercise resource records with synthetic procfs and deterministic clocks."""

from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import resources


def stat(
    *, pid: int = 20, start: int = 900, user: int = 11, system: int = 7, state: str = "S"
) -> str:
    fields = [state] + ["0"] * 23
    fields[11:15] = [str(user), str(system), "10000", "20000"]
    fields[19] = str(start)
    return f"{pid} (worker (with) spaces)) " + " ".join(fields)


def memory() -> str:
    return (
        "00400000-00c00000 ---p 00000000 00:00 0 [rollup]\nRss: 8 kB\nPss: 5 kB\nPss_Anon: 4 kB\n"
    )


class FakeClock:
    def __init__(self, start: int = 1000, step: int = 200) -> None:
        self.next = start
        self.step = step

    def __call__(self) -> int:
        value = self.next
        self.next += self.step
        return value


class ParserTests(unittest.TestCase):
    def test_stat_handles_comm_parentheses_and_excludes_child_cpu(self) -> None:
        result = resources.parse_stat(stat())
        self.assertEqual(result["name"], "worker (with) spaces)")
        self.assertEqual(result["pid"], 20)
        self.assertEqual(result["start_ticks"], 900)
        self.assertEqual(result["cpu_ticks"], 18)

    def test_invalid_stat_data_is_rejected(self) -> None:
        for text in ("", "20 (worker) S 0", stat(user=-1), stat(pid=0), stat(start=-1)):
            with self.subTest(text=text), self.assertRaises(ValueError):
                resources.parse_stat(text)

    def test_memory_uses_exact_rss_and_pss_fields_and_binary_kilobytes(self) -> None:
        self.assertEqual(
            resources.parse_smaps_rollup(memory()), {"rss_bytes": 8192, "pss_bytes": 5120}
        )

    def test_missing_duplicate_negative_or_wrong_unit_memory_is_rejected(self) -> None:
        for text in (
            "Rss: 8 kB\n",
            memory() + "Pss: 3 kB\n",
            memory().replace("8 kB", "-8 kB"),
            memory().replace("5 kB", "5 MB"),
            memory().replace("5 kB", "invalid kB"),
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                resources.parse_smaps_rollup(text)

    def test_targets_require_valid_identity_and_separate_roles(self) -> None:
        for args in ((True, 900, "worker"), (0, 900, "worker"), (20, -1, "worker"), (20, 9, "all")):
            with self.subTest(args=args), self.assertRaises(ValueError):
                resources.ProcessTarget(*args)
        self.assertNotEqual(
            resources.ProcessTarget(20, 900, "worker"),
            resources.ProcessTarget(20, 900, "bmv2"),
        )


class ReadTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.process = self.root / "20"
        self.process.mkdir()
        (self.process / "stat").write_text(stat())
        (self.process / "smaps_rollup").write_text(memory())
        self.target = resources.ProcessTarget(20, 900, "worker")

    def read(self, clock=None):
        return resources.read_sample(
            self.target,
            proc_root=self.root,
            clock_ns=clock or FakeClock(),
            clock_domain="fixture-monotonic",
        )

    def test_complete_sample_has_identity_units_and_bounded_midpoint(self) -> None:
        result = self.read()
        self.assertTrue(result["ok"])
        self.assertEqual(result["target"], {"pid": 20, "start_ticks": 900, "role": "worker"})
        self.assertEqual(result["record_type"], "process-resource-sample")
        self.assertEqual(result["sample_start_ns"], 1000)
        self.assertEqual(result["cpu_midpoint_ns"], 1100)
        self.assertEqual(result["sample_end_ns"], 1400)
        self.assertEqual(result["cpu_ticks"], 18)
        self.assertEqual(result["rss_bytes"], 8192)
        self.assertEqual(result["pss_bytes"], 5120)

    def test_missing_memory_retains_target_and_does_not_impute_zero(self) -> None:
        (self.process / "smaps_rollup").unlink()
        result = self.read()
        self.assertFalse(result["ok"])
        self.assertEqual(result["target"]["pid"], 20)
        self.assertEqual(result["error"]["type"], "FileNotFoundError")
        for key in ("cpu_ticks", "rss_bytes", "pss_bytes"):
            self.assertNotIn(key, result)

    def test_wrong_identity_or_exited_state_is_not_a_sample(self) -> None:
        for text in (stat(pid=21), stat(start=901), stat(state="Z"), stat(state="X")):
            (self.process / "stat").write_text(text)
            with self.subTest(text=text):
                result = self.read()
                self.assertFalse(result["ok"])
                self.assertNotIn("rss_bytes", result)

    def test_pid_reuse_or_exit_during_memory_read_invalidates_the_whole_sample(self) -> None:
        original = Path.read_text
        for changed in (stat(start=901), stat(state="Z"), stat(user=1)):
            (self.process / "stat").write_text(stat())

            def read(path, *args, changed=changed, **kwargs):
                text = original(path, *args, **kwargs)
                if path.name == "smaps_rollup":
                    (self.process / "stat").write_text(changed)
                return text

            with patch.object(Path, "read_text", read), self.subTest(changed=changed):
                result = self.read()
            self.assertFalse(result["ok"])
            self.assertNotIn("cpu_ticks", result)
            self.assertNotIn("pss_bytes", result)

    def test_permission_errors_are_explicit(self) -> None:
        with patch.object(Path, "read_text", side_effect=PermissionError("fixture denied")):
            result = self.read()
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["type"], "PermissionError")

    def test_backward_clock_is_invalid(self) -> None:
        result = self.read(clock=FakeClock(start=1000, step=-100))
        self.assertFalse(result["ok"])
        self.assertIn("clock", result["error"]["message"])


def sample(midpoint: int, *, user: int = 0, system: int = 0) -> dict:
    return {
        "record_type": "process-resource-sample",
        "target": {"pid": 20, "start_ticks": 900, "role": "bmv2"},
        "clock_domain": "fixture-monotonic",
        "sample_start_ns": midpoint - 10,
        "sample_end_ns": midpoint + 10,
        "cpu_midpoint_ns": midpoint,
        "user_ticks": user,
        "system_ticks": system,
        "cpu_ticks": user + system,
        "ok": True,
    }


class IntervalTests(unittest.TestCase):
    def test_cpu_uses_elapsed_time_and_can_exceed_one_cpu(self) -> None:
        previous = sample(1_000_000_000, user=10, system=2)
        current = sample(2_000_000_000, user=160, system=52)
        result = resources.cpu_interval(previous, current, clock_ticks=100)
        self.assertTrue(result["ok"])
        self.assertEqual(result["wall_ns"], 1_000_000_000)
        self.assertEqual(result["cpu_ticks"], 200)
        self.assertEqual(result["cpu_percent"], 200.0)

    def test_real_zero_usage_is_distinct_from_a_missing_sample(self) -> None:
        previous = sample(1000)
        current = sample(2000)
        self.assertEqual(
            resources.cpu_interval(previous, current, clock_ticks=100)["cpu_percent"], 0
        )
        failed = {**current, "ok": False, "error": {"type": "FileNotFoundError"}}
        result = resources.cpu_interval(previous, failed, clock_ticks=100)
        self.assertFalse(result["ok"])
        self.assertNotIn("cpu_percent", result)

    def test_identity_role_clock_and_counter_changes_are_rejected(self) -> None:
        previous = sample(1_000_000, user=10, system=5)
        current = sample(2_000_000, user=15, system=10)
        variants = []
        for key, value in (("pid", 21), ("start_ticks", 901), ("role", "worker")):
            changed = copy.deepcopy(current)
            changed["target"][key] = value
            variants.append(changed)
        variants.extend(
            [
                {**current, "clock_domain": "another-clock"},
                {**current, "cpu_midpoint_ns": 0},
                {**current, "sample_start_ns": 0, "cpu_midpoint_ns": 1_000_000},
                {**current, "user_ticks": 9, "cpu_ticks": 19},
                {**current, "cpu_ticks": 999},
            ]
        )
        for changed in variants:
            with self.subTest(changed=changed):
                result = resources.cpu_interval(previous, changed, clock_ticks=100)
                self.assertFalse(result["ok"])
                self.assertNotIn("cpu_percent", result)

    def test_invalid_tick_frequency_is_rejected(self) -> None:
        for value in (0, -1, True, float("nan")):
            with self.subTest(value=value):
                result = resources.cpu_interval(sample(1000), sample(2000), clock_ticks=value)
                self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
