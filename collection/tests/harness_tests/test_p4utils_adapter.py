"""Check the P4-Utils task mapping without creating native network resources."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from harness import spec
from harness.worker_p4utils import configure, program


class P4UtilsAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.manifest = spec.load(spec.create(Path(self.temporary.name) / "trial", groups=2))

    def test_explicit_topology_preserves_task_addresses_and_ports(self) -> None:
        network = MagicMock()
        returned = configure(self.manifest, factory=lambda: network)
        self.assertIs(returned, network)
        self.assertEqual(network.addP4RuntimeSwitch.call_count, 2)
        self.assertEqual(network.addHost.call_count, 4)
        self.assertEqual(network.addLink.call_count, 4)
        switches = network.addP4RuntimeSwitch.call_args_list
        self.assertEqual([call.kwargs["device_id"] for call in switches], [0, 1])
        self.assertEqual(
            [call.kwargs["grpc_port"] for call in switches], self.manifest["service_ports"][::2]
        )
        self.assertTrue(all(call.kwargs["pcap_dump"] is False for call in switches))
        for row, call in zip(
            spec.task_rows(self.manifest), network.addLink.call_args_list, strict=True
        ):
            self.assertEqual(call.args, (row["host"], row["switch"]))
            self.assertEqual(call.kwargs["port1"], 0)
            self.assertEqual(call.kwargs["port2"], row["port"])
            self.assertEqual(call.kwargs["addr1"], row["mac"])
            self.assertEqual(call.kwargs["params1"]["ip"], row["ip"] + "/24")
        network.startNetwork.assert_not_called()
        network.disableArpTables.assert_called_once()
        network.disableGwArp.assert_called_once()

    def test_table_mapping_uses_client_api_and_retains_controllers(self) -> None:
        network = MagicMock()
        network.getNode.side_effect = lambda name: {
            "json_path": name + ".json",
            "p4rt_path": name + ".txt",
        }
        controllers = []
        built = []

        def factory(**kwargs):
            controller = MagicMock()
            controller.table_add.return_value = True
            built.append((kwargs, controller))
            return controller

        program(network, self.manifest, controllers, factory=factory)
        self.assertEqual(controllers, [entry[1] for entry in built])
        for index, (_kwargs, controller) in enumerate(built):
            rows = spec.task_rows(self.manifest)[2 * index : 2 * index + 2]
            for row, call in zip(rows, controller.table_add.call_args_list, strict=True):
                self.assertEqual(
                    call.args,
                    (
                        "L3Ingress.ipv4_lpm",
                        "L3Ingress.forward",
                        [row["ip"] + "/32"],
                        [row["mac"], row["switch_mac"], str(row["port"])],
                    ),
                )

    def test_suppressed_client_failure_cannot_be_reported_as_success(self) -> None:
        network = MagicMock()
        network.getNode.return_value = {"json_path": "program.json", "p4rt_path": "program.txt"}
        controller = MagicMock()
        controller.table_add.return_value = None
        retained = []
        with self.assertRaisesRegex(RuntimeError, "rejected"):
            program(network, self.manifest, retained, factory=lambda **kwargs: controller)
        self.assertEqual(retained, [controller])


if __name__ == "__main__":
    unittest.main()
