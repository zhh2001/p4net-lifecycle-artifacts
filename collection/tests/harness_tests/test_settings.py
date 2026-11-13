"""Validate measured host postconditions rather than successful command exit."""

import json
import subprocess
import unittest

from harness import settings


class SettingsTests(unittest.TestCase):
    def test_offload_parser_distinguishes_parent_and_subfeature(self) -> None:
        values = settings.parse_features(
            "rx-checksumming: off [fixed]\n"
            "tx-checksumming: off\n\ttx-checksum-ip-generic: on [fixed]\n"
            "scatter-gather: off\n"
        )
        self.assertEqual(values, {"rx": False, "tx": False, "sg": False})

    def test_incomplete_and_unknown_reports_are_rejected(self) -> None:
        for text in ("rx-checksumming: off\n", "rx-checksumming: unknown\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                settings.parse_features(text)

    def test_successful_commands_cannot_conceal_wrong_postconditions(self) -> None:
        row = {"host": "host", "ip": "10.231.0.1", "mac": "02:77:00:00:00:01"}
        for mtu in (1500, 9000):

            def run(argv, mtu=mtu):
                text = ""
                if argv[:3] == ["ip", "-j", "addr"]:
                    text = json.dumps(
                        [
                            {
                                "ifname": "eth0",
                                "mtu": mtu,
                                "address": row["mac"],
                                "addr_info": [
                                    {"family": "inet", "local": row["ip"], "prefixlen": 24}
                                ],
                            }
                        ]
                    )
                elif argv[:2] == ["ethtool", "-k"]:
                    text = "rx-checksumming: off\ntx-checksumming: off\nscatter-gather: off\n"
                elif argv[:2] == ["sysctl", "-n"]:
                    text = "1\n1\n1\n1\n"
                return subprocess.CompletedProcess(argv, 0, text.encode(), b"")

            if mtu == 1500:
                self.assertEqual(settings.configure_host(row, "eth0", run)["mtu"], 1500)
            else:
                with self.assertRaisesRegex(RuntimeError, "postconditions"):
                    settings.configure_host(row, "eth0", run)

    def test_profile_and_packet_arguments_are_explicit(self) -> None:
        self.assertFalse(settings.matched({}))
        self.assertTrue(settings.matched({"configuration_profile": "matched-v1"}))
        with self.assertRaises(ValueError):
            settings.matched({"configuration_profile": "unknown"})
        self.assertEqual(
            settings.ping_command("10.0.0.1"),
            ["ping", "-n", "-c", "1", "-W", "2", "-w", "4", "10.0.0.1"],
        )
