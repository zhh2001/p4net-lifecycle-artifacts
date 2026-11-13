"""Check protocol routing and the namespace boundary before native execution."""

import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from harness import events, isolation


class EventTests(unittest.TestCase):
    def test_library_stdout_cannot_corrupt_protocol(self) -> None:
        protocol, library = io.StringIO(), io.StringIO()
        with patch.object(events, "PROTOCOL_OUT", protocol), redirect_stdout(library):
            print("library diagnostic")
            events.emit({"run_id": "trial"}, "starting")
        self.assertEqual(json.loads(protocol.getvalue())["event"], "starting")
        self.assertEqual(library.getvalue(), "library diagnostic\n")

    def test_stop_and_eof_are_accepted_but_other_commands_are_rejected(self) -> None:
        for text in ('{"command":"stop"}\n', ""):
            with patch("sys.stdin", io.StringIO(text)):
                events.read_stop()
        with (
            patch("sys.stdin", io.StringIO('{"command":"start"}\n')),
            self.assertRaises(ValueError),
        ):
            events.read_stop()


class IsolationTests(unittest.TestCase):
    def test_mount_setup_cannot_run_in_the_parent_namespaces(self) -> None:
        expected = {key: f"{key}:[1]" for key in isolation.NAMESPACES}
        with (
            patch.object(isolation, "namespace_ids", return_value=expected),
            patch("harness.isolation.os.getpid", return_value=1),
            self.assertRaisesRegex(RuntimeError, "all private"),
        ):
            isolation.require_private(expected)

    def test_mount_setup_requires_pid_namespace_init(self) -> None:
        expected = {key: f"{key}:[1]" for key in isolation.NAMESPACES}
        with (
            patch("harness.isolation.os.getpid", return_value=200),
            self.assertRaisesRegex(RuntimeError, "init process"),
        ):
            isolation.require_private(expected)

    def test_worker_interpreter_path_keeps_its_virtual_environment(self) -> None:
        command = isolation.isolated_command(
            Path("/tmp/manifest.json"), Path("/tmp/venv/bin/python"), "harness.worker"
        )
        self.assertIn("--kill-child=KILL", command)
        self.assertIn("--net", command)
        self.assertNotIn("--map-root-user", command)
        self.assertEqual(command[command.index("--python") + 1], "/tmp/venv/bin/python")


if __name__ == "__main__":
    unittest.main()
