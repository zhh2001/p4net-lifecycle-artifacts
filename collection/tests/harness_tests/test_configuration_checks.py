"""Check scale selection before any native task or output mutation."""

import json
import tempfile
import unittest
from pathlib import Path

from harness import settings, spec
from harness.bmv2_launcher import POLICY
from harness.configuration_checks import inspect_trial


class ScaleSelectionTests(unittest.TestCase):
    def test_per_switch_mappings_cannot_be_replaced_by_another_valid_port(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = spec.create(Path(directory) / "trial", 2, configuration_profile=settings.MATCHED)
            manifest = spec.load(path)
            output = path.parent
            hosts = [
                {
                    "host": row["host"],
                    "ipv4": [row["ip"] + "/24"],
                    "mac": row["mac"],
                    "mtu": 1500,
                    "offloads": {"rx": False, "tx": False, "sg": False},
                    "ipv6_disabled": dict.fromkeys(("all", "default", "lo", "interface"), True),
                }
                for row in spec.task_rows(manifest)
            ]
            (output / "host-settings.json").write_text(
                json.dumps(
                    {
                        "configuration_profile": settings.MATCHED,
                        "performance_samples": False,
                        "hosts": hosts,
                    }
                )
            )
            launches = output / "bmv2-launches"
            launches.mkdir()
            originals = []
            for i, switch in enumerate(manifest["switch_names"]):
                argv = [
                    "simple_switch_grpc",
                    "--device-id",
                    str(i),
                    "-i",
                    f"1@{switch}-eth1",
                    "-i",
                    f"2@{switch}-eth2",
                    "--thrift-port",
                    str(manifest["service_ports"][2 * i + 1]),
                    "--log-console",
                    "-L",
                    "info",
                    "--",
                    "--grpc-server-addr",
                    f"127.0.0.1:{manifest['service_ports'][2 * i]}",
                ]
                originals.append(argv)

            def save(first):
                processes = []
                for i, argv in enumerate((first, originals[1])):
                    record = {
                        "query": False,
                        "policy": POLICY,
                        "status": "prepared",
                        "pid": 100 + i,
                        "effective_argv": argv,
                    }
                    (launches / f"{i}.json").write_text(json.dumps(record))
                    processes.append({"pid": 100 + i, "cmdline": argv})
                (output / "inventory-ready.json").write_text(json.dumps({"processes": processes}))

            save(originals[0])
            self.assertTrue(inspect_trial(path)["device_port_interface_mapping_verified"])
            for flag, replacement in (
                ("--grpc-server-addr", f"127.0.0.1:{manifest['service_ports'][2]}"),
                ("--thrift-port", str(manifest["service_ports"][3])),
                ("--device-id", "1"),
                ("-i", f"1@{manifest['switch_names'][1]}-eth1"),
            ):
                changed = originals[0].copy()
                changed[changed.index(flag) + 1] = replacement
                save(changed)
                with self.subTest(flag=flag), self.assertRaises(AssertionError):
                    inspect_trial(path)
            for extra in (
                ["--interface", "3@unexpected"],
                ["--interface=3@unexpected"],
                ["-i3@unexpected"],
            ):
                changed = originals[0].copy()
                changed[changed.index("--") : changed.index("--")] = extra
                save(changed)
                with self.subTest(extra=extra), self.assertRaises(AssertionError):
                    inspect_trial(path)

            save(originals[0])
            (output / "inventory-ready.json").unlink()
            targets = [
                {"pid": 50, "start_ticks": 7, "role": "worker"},
                {"pid": 100, "start_ticks": 8, "role": "bmv2"},
                {"pid": 101, "start_ticks": 9, "role": "bmv2"},
            ]
            checked = inspect_trial(path, verified_targets=targets)
            self.assertEqual(checked["procfs_evidence"], "validated-native-boundary-targets")
            self.assertTrue(checked["device_port_interface_mapping_verified"])
            targets[1]["pid"] = 999
            with self.assertRaises(AssertionError):
                inspect_trial(path, verified_targets=targets)


if __name__ == "__main__":
    unittest.main()
