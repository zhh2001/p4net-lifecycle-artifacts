import json
import os
from unittest.mock import patch

from overhead.model import NAMESPACES, Context, Identity
from overhead.proc import ProcReader
from overhead.simulation import run

from .support import Fixture


class ProcTests(Fixture):
    def make_process(self, pid, parent=0, inner=None, start=10):
        root = self.output / "proc"
        directory = root / str(pid)
        (directory / "ns").mkdir(parents=True)
        (root / "sys/kernel/random").mkdir(parents=True, exist_ok=True)
        (root / "sys/kernel/random/boot_id").write_text("boot")
        fields = ["S"] + ["0"] * 19
        fields[1] = str(parent)
        fields[11] = "11"
        fields[12] = "7"
        fields[13] = "99999"
        fields[14] = "88888"
        fields[19] = str(start)
        (directory / "stat").write_text(f"{pid} (worker (strange) name) " + " ".join(fields))
        (directory / "status").write_text(f"NSpid:\t{pid}\t{pid if inner is None else inner}\n")
        (directory / "smaps_rollup").write_text("Rss: 8 kB\nPss: 4 kB\nPss_Anon: 3 kB\n")
        for i, name in enumerate(NAMESPACES):
            (directory / "ns" / name).symlink_to(f"{name}:[{100 + i}]")
        return root

    def test_own_cpu_does_not_include_waited_children(self):
        root = self.make_process(100)
        reader = ProcReader(root)
        value = reader.cpu(reader.identity(100))
        self.assertEqual(
            (value["user_ticks"], value["system_ticks"], value["cpu_ticks"]), (11, 7, 18)
        )

    def test_memory_has_exact_fields_and_byte_units(self):
        root = self.make_process(100)
        reader = ProcReader(root)
        value = reader.memory(reader.identity(100))
        self.assertEqual((value["rss_bytes"], value["pss_bytes"]), (8192, 4096))

    def test_one_malformed_memory_field_keeps_the_other(self):
        root = self.make_process(100)
        (root / "100/smaps_rollup").write_text("Rss: 8 kB\nPss: invalid kB\n")
        reader = ProcReader(root)
        value = reader.memory(reader.identity(100))
        self.assertEqual(value["rss_bytes"], 8192)
        self.assertNotIn("pss_bytes", value)

    def test_pid_reuse_during_cpu_read_is_rejected(self):
        root = self.make_process(100)
        reader = ProcReader(root)
        identity = reader.identity(100)
        values = identity.as_dict()
        values["start_ticks"] = 11
        with (
            patch.object(reader, "identity", side_effect=[identity, Identity.from_dict(values)]),
            self.assertRaises(ProcessLookupError),
        ):
            reader.cpu(identity)

    def test_boot_or_namespace_change_is_rejected(self):
        root = self.make_process(100)
        reader = ProcReader(root)
        identity = reader.identity(100)
        (root / "sys/kernel/random/boot_id").write_text("other")
        with self.assertRaises(ProcessLookupError):
            reader.memory(identity)

    def test_namespace_pid_maps_to_the_direct_child(self):
        root = self.make_process(100, 0, 1)
        self.make_process(200, 100, 2, 11)
        reader = ProcReader(root)
        parent = reader.identity(100)
        inner = reader.identity(200).as_dict()
        inner["pid"] = 2
        self.assertEqual(reader.resolve_child(parent, Identity.from_dict(inner)).pid, 200)

    def test_grandchild_does_not_satisfy_direct_child_mapping(self):
        root = self.make_process(100, 0, 1)
        self.make_process(200, 999, 2, 11)
        reader = ProcReader(root)
        parent = reader.identity(100)
        inner = reader.identity(200)
        with self.assertRaises(ProcessLookupError):
            reader.resolve_child(parent, inner)

    def test_own_cpu_path_reads_self(self):
        pid = os.getpid()
        root = self.make_process(pid)
        (root / "self").symlink_to(str(pid))
        reader = ProcReader(root)
        self.assertEqual(reader.cpu(reader.identity(pid), self_read=True)["cpu_ticks"], 18)


class ProcessIntegrationTests(Fixture):
    def test_all_profiles_and_tool_identities_use_real_synthetic_processes(self):
        for tool in ("p4net", "p4utils", "tutorial-components"):
            for profile in ("native", "off", "stages", "detail"):
                with self.subTest(tool=tool, profile=profile):
                    directory = self.output / (tool + "-" + profile)
                    result = run(directory, Context("run-" + profile, "a1", tool, profile))
                    self.assertTrue(result["measurement_complete"], result["issues"])
                    self.assertTrue(result["native_result"]["ok"])
                    self.assertFalse(result["context"]["performance_samples"])
                    self.assertEqual(
                        result["worker_end"]["cpu"]["identity"]["namespace_pid"],
                        result["reference"]["endpoints"]["worker_identity"]["namespace_pid"],
                    )
                    self.assertEqual(result["worker_end"]["native_outcome"]["exit_code"], 0)
                    trace = directory / "diagnostic-trace.jsonl"
                    self.assertEqual(trace.exists(), profile != "native")
                    if trace.exists():
                        stages = [
                            json.loads(line)["stage"]
                            for line in trace.read_text().splitlines()
                            if json.loads(line)["kind"] == "begin"
                        ]
                        self.assertEqual("task.detail" in stages, profile == "detail")
                        self.assertEqual(
                            "worker.workflow" in stages, profile in ("stages", "detail")
                        )

    def test_native_exceptions_exit_statuses_and_interruptions_are_retained(self):
        for behavior, expected in (("raise", 1), ("exit", 7), ("interrupt", -2)):
            for profile in ("native", "detail"):
                with self.subTest(behavior=behavior, profile=profile):
                    directory = self.output / (behavior + "-" + profile)
                    result = run(
                        directory,
                        Context("failure-" + behavior, "a1", "p4net", profile),
                        behavior=behavior,
                    )
                    self.assertEqual(result["native_result"]["worker_returncode"], expected)
                    self.assertFalse(result["native_result"]["ok"])
                    self.assertFalse(result["primary_performance_eligible"])
                    end = json.loads((directory / "worker-cpu-end.json").read_text())
                    self.assertEqual(end["native_outcome"]["status"], "raised")

    def test_synthetic_cli_cannot_switch_to_a_native_worker_module(self):
        import sys

        from overhead.entry import main

        manifest = self.output / "entry.json"
        value = {
            "schema_version": 1,
            "record_type": "synthetic-diagnostic-entry",
            "context": self.context.as_dict(),
            "entry": {"module": "harness.worker", "source": "/tmp/native.py", "sha256": "0" * 64},
            "arguments": [],
            "output": str(self.output / "end.json"),
        }
        manifest.write_text(json.dumps(value))
        with (
            patch.object(sys, "argv", ["entry", "--synthetic-config", str(manifest)]),
            self.assertRaises(ValueError),
        ):
            main()
        self.assertFalse((self.output / "end.json").exists())


class TransportProcessTests(Fixture):
    def test_lost_ready_or_final_ack_keeps_the_native_result(self):
        for checkpoint in ("ref_ready", "ref_complete"):
            with self.subTest(checkpoint=checkpoint):
                result = run(
                    self.output / checkpoint,
                    Context("lost-" + checkpoint, "a1", "p4net", "detail"),
                    drop_checkpoint=checkpoint,
                )
                self.assertTrue(result["native_result"]["ok"])
                self.assertFalse(result["primary_performance_eligible"])
                self.assertFalse(result["measurement_complete"])
                self.assertTrue(
                    any(issue["metric"] == "reference_transport" for issue in result["issues"])
                )


class BeginGateProcessTests(Fixture):
    def test_lost_begin_ack_does_not_launch_a_worker(self):
        directory = self.output / "begin-loss"
        result = run(
            directory, Context("lost-begin", "a1", "p4net", "native"), drop_checkpoint="ref_begin"
        )
        self.assertIsNone(result["native_result"])
        self.assertFalse(result["measurement_complete"])
        self.assertFalse((directory / "worker-entry.json").exists())
