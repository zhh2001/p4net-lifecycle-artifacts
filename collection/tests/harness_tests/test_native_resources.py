"""Identify only live task processes from synthetic procfs and launch records."""

import json
import tempfile
import unittest
from pathlib import Path

from harness.native_resources import select_targets


class TargetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.proc = self.root / "proc"
        self.output = self.root / "run"
        self.launches = self.output / "bmv2-launches"
        self.launches.mkdir(parents=True)
        self.worker = {"pid": 10, "start_ticks": 5}
        self.process(10, 5, ["python", "-m", "worker"], ppid=1)

    def process(self, pid, start, argv, *, ppid=10, pgrp=10, state="S"):
        directory = self.proc / str(pid)
        directory.mkdir(parents=True, exist_ok=True)
        fields = ["0"] * 50
        fields[0], fields[1], fields[2], fields[19] = state, str(ppid), str(pgrp), str(start)
        (directory / "stat").write_text(f"{pid} (process) " + " ".join(fields))
        (directory / "cmdline").write_bytes(("\0".join(argv) + "\0").encode())

    def manifest(self, groups=2):
        manifest = {
            "groups": groups,
            "output_dir": str(self.output),
            "switch_names": [f"r123abcs{i}" for i in range(groups)],
            "service_ports": list(range(30000, 30000 + 2 * groups)),
        }
        for i, switch in enumerate(manifest["switch_names"]):
            argv = [
                "/bin/simple_switch_grpc",
                "-i",
                f"1@{switch}-eth1",
                "-i",
                f"2@{switch}-eth2",
                "--device-id",
                str(i),
                "--thrift-port",
                str(30001 + 2 * i),
                "program.json",
                "--",
                "--grpc-server-addr",
                f"127.0.0.1:{30000 + 2 * i}",
            ]
            self.launch(i + 20, argv)
        return manifest

    def launch(self, pid, argv):
        self.process(pid, pid + 100, argv)
        (self.launches / f"launch-{pid}.json").write_text(
            json.dumps(
                {
                    "pid": pid,
                    "query": False,
                    "status": "prepared",
                    "effective_argv": argv,
                }
            )
        )

    def select(self, manifest):
        return select_targets(manifest, self.worker, {}, proc_root=self.proc)

    def test_helpers_and_host_shells_are_not_bmv2_targets(self):
        manifest = self.manifest()
        self.process(40, 140, ["bash"])
        self.process(41, 141, ["p4c", "program.p4"])
        targets = self.select(manifest)
        self.assertEqual(
            [(item.pid, item.role) for item in targets],
            [(10, "worker"), (20, "bmv2"), (21, "bmv2")],
        )
        self.assertEqual(targets[1].start_ticks, 120)

    def test_all_sixteen_switches_are_required(self):
        manifest = self.manifest(16)
        self.assertEqual(len(self.select(manifest)), 17)
        (self.launches / "launch-35.json").unlink()
        with self.assertRaisesRegex(ValueError, "cover"):
            self.select(manifest)

    def test_reused_worker_pid_is_rejected(self):
        manifest = self.manifest()
        self.process(10, 6, ["python"], ppid=1)
        with self.assertRaisesRegex(ProcessLookupError, "worker identity"):
            self.select(manifest)

    def test_exited_switch_is_rejected(self):
        manifest = self.manifest()
        self.process(20, 120, ["simple_switch_grpc"], state="Z")
        with self.assertRaises(ProcessLookupError):
            self.select(manifest)

    def test_changed_command_cannot_reuse_a_launch_record(self):
        manifest = self.manifest()
        self.process(20, 121, ["bash"])
        with self.assertRaisesRegex(ValueError, "command"):
            self.select(manifest)

    def test_unrelated_group_and_ancestry_cannot_supply_a_target(self):
        manifest = self.manifest()
        launch = json.loads((self.launches / "launch-20.json").read_text())
        self.process(20, 120, launch["effective_argv"], ppid=1, pgrp=99)
        with self.assertRaisesRegex(ValueError, "ownership"):
            self.select(manifest)

    def test_descendant_in_another_group_remains_identifiable(self):
        manifest = self.manifest()
        self.process(40, 140, ["bash"])
        launch = json.loads((self.launches / "launch-20.json").read_text())
        self.process(20, 120, launch["effective_argv"], ppid=40, pgrp=99)
        self.assertEqual(len(self.select(manifest)), 3)

    def test_duplicate_device_id_is_rejected(self):
        manifest = self.manifest()
        argv = json.loads((self.launches / "launch-20.json").read_text())["effective_argv"]
        self.launch(21, argv)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.select(manifest)

    def test_wrong_ports_and_interfaces_are_rejected(self):
        for change in ("port", "interface"):
            with self.subTest(change=change):
                manifest = self.manifest()
                argv = json.loads((self.launches / "launch-20.json").read_text())["effective_argv"]
                if change == "port":
                    argv[-1] = "127.0.0.1:40000"
                else:
                    argv[2] = "1@unrelated-eth1"
                self.launch(20, argv)
                with self.assertRaises(ValueError):
                    self.select(manifest)

    def test_selector_never_reads_memory_files(self):
        manifest = self.manifest()
        self.assertFalse(any(self.proc.rglob("smaps_rollup")))
        self.assertEqual(len(self.select(manifest)), 3)

    def test_identity_selection_does_not_parse_cpu_counter_fields(self):
        manifest = self.manifest()
        for path in self.proc.glob("*/stat"):
            head, tail = path.read_text().rsplit(")", 1)
            fields = tail.split()
            fields[11] = fields[12] = "not-a-cpu-counter"
            path.write_text(head + ") " + " ".join(fields))
        self.assertEqual(len(self.select(manifest)), 3)
