"""Check task equivalence and compiler failures without native network setup."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from harness import spec
from harness.worker_tutorial import compile_task, configure_task, populate_network


class TutorialAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        path = spec.create(Path(self.temp.name) / "trial", groups=2)
        self.manifest = spec.load(path)

    def test_public_components_receive_identical_hosts_ports_and_pipeline(self) -> None:
        network = MagicMock()
        components = {"P4RuntimeSwitch": object(), "P4Host": object()}
        program = Path("/trial/compiled/l3.json")
        with patch("harness.worker_tutorial.shutil.which", return_value="/bin/simple_switch_grpc"):
            populate_network(network, components, self.manifest, program)
        self.assertEqual(network.addSwitch.call_count, 2)
        self.assertEqual(network.addHost.call_count, 4)
        self.assertEqual(network.addLink.call_count, 4)
        self.assertLess(len(network.addSwitch.return_value.nanomsg.removeprefix("ipc://")), 100)
        self.assertTrue(network.addSwitch.return_value.nanomsg.startswith("ipc:///tmp/"))
        for i, call in enumerate(network.addSwitch.call_args_list):
            self.assertEqual(call.args[0], self.manifest["switch_names"][i])
            self.assertEqual(call.kwargs["grpc_port"], self.manifest["service_ports"][2 * i])
            self.assertEqual(call.kwargs["json_path"], str(program))
            self.assertFalse(call.kwargs["pcap_dump"])
        for row, call in zip(
            spec.task_rows(self.manifest), network.addHost.call_args_list, strict=True
        ):
            self.assertEqual(call.args[0], row["host"])
            self.assertEqual(call.kwargs["ip"], row["ip"] + "/24")
            self.assertEqual(call.kwargs["mac"], row["mac"])

    def test_table_values_and_neighbors_match_shared_task(self) -> None:
        network = MagicMock()
        network.get.return_value.defaultIntf.return_value = "eth0"
        network.get.return_value.pexec.return_value = ("", "", 0)
        helper = MagicMock()
        connections = [MagicMock(), MagicMock()]
        configure_task(network, helper, connections, self.manifest)
        self.assertEqual([c.WriteTableEntry.call_count for c in connections], [2, 2])
        for row, call in zip(
            spec.task_rows(self.manifest), helper.buildTableEntry.call_args_list, strict=True
        ):
            self.assertEqual(call.kwargs["match_fields"], {"hdr.ipv4.dstAddr": (row["ip"], 32)})
            self.assertEqual(call.kwargs["action_params"]["port"], row["port"])
            self.assertEqual(call.kwargs["action_params"]["src_mac"], row["switch_mac"])
        for call in network.get.return_value.pexec.call_args_list:
            self.assertIn("eth0", call.args[0])

    def test_neighbor_failure_is_not_accepted_as_readiness(self) -> None:
        network = MagicMock()
        network.get.return_value.pexec.return_value = ("", "permission denied", 1)
        with self.assertRaisesRegex(RuntimeError, "neighbor configuration failed"):
            configure_task(network, MagicMock(), [MagicMock(), MagicMock()], self.manifest)

    def test_failed_compiler_preserves_output_and_error(self) -> None:
        completed = subprocess.CompletedProcess([], 1, stdout=b"details", stderr=b"invalid input")
        with (
            patch("harness.worker_tutorial.subprocess.run", return_value=completed),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            compile_task(self.manifest)
        folder = Path(self.manifest["output_dir"]) / "compiler"
        self.assertEqual((folder / "stderr.log").read_bytes(), b"invalid input")
        command = json.loads((folder / "command.json").read_text())
        self.assertEqual(command[0], "p4c")
        self.assertIn(self.manifest["p4_source"], command)

    def test_missing_compiler_artifacts_are_rejected(self) -> None:
        completed = subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")
        with (
            patch("harness.worker_tutorial.subprocess.run", return_value=completed),
            self.assertRaisesRegex(RuntimeError, "nonempty"),
        ):
            compile_task(self.manifest)


if __name__ == "__main__":
    unittest.main()
