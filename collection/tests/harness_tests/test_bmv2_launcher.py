"""Check controlled BMv2 options without launching a network process."""

from __future__ import annotations

import errno
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from harness.bmv2_launcher import ArgumentError, normalize, run


class NormalizeTests(unittest.TestCase):
    def test_task_parameters_and_target_order_are_preserved(self) -> None:
        args = [
            "--device-id",
            "0",
            "-i",
            "1@rs0-eth1",
            "--thrift-port",
            "12345",
            "--nanolog",
            "ipc:///tmp/nanolog",
            "program.json",
            "--log-console",
            "--",
            "--grpc-server-addr",
            "0.0.0.0:12346",
            "--cpu-port",
            "255",
        ]
        result = normalize(args)
        self.assertEqual(
            result,
            [
                "--device-id",
                "0",
                "-i",
                "1@rs0-eth1",
                "--thrift-port",
                "12345",
                "--log-console",
                "-L",
                "info",
                "program.json",
                "--",
                "--grpc-server-addr",
                "127.0.0.1:12346",
                "--cpu-port",
                "255",
            ],
        )

    def test_p4net_console_flush_is_removed(self) -> None:
        self.assertEqual(
            normalize(["--log-console", "--log-flush", "-L", "debug", "p.json"]),
            ["--log-console", "-L", "info", "p.json"],
        )

    def test_grpc_bind_is_local_and_preserves_the_allocated_port(self) -> None:
        result = normalize(["p.json", "--", "--grpc-server-addr=0.0.0.0:50051"])
        self.assertEqual(result[-2:], ["--grpc-server-addr", "127.0.0.1:50051"])
        for value in ("10.0.0.1:50051", "127.0.0.1:0", "127.0.0.1:NaN"):
            with self.subTest(value=value), self.assertRaises(ArgumentError):
                normalize(["p.json", "--", "--grpc-server-addr", value])

    def test_file_logging_is_replaced_by_console_logging(self) -> None:
        result = normalize(["--log-file=/tmp/output.log", "--log-flush", "p.json"])
        self.assertEqual(result, ["--log-console", "-L", "info", "p.json"])

    def test_optional_pcap_forms_are_disabled(self) -> None:
        for args in (
            ["--pcap=/tmp/pcaps", "p.json"],
            ["--pcap", "/tmp/pcaps", "p.json"],
            ["p.json", "--pcap"],
            ["p.json", "--pcap="],
        ):
            with self.subTest(args=args):
                self.assertEqual(normalize(args), ["--log-console", "-L", "info", "p.json"])

    def test_queries_are_forwarded_without_policy_options(self) -> None:
        for flag in ("--help", "-h", "--version", "-v", "--json-version"):
            self.assertEqual(normalize([flag]), [flag])

    def test_unknown_and_misplaced_options_fail(self) -> None:
        for args in (
            ["--unknown", "p.json"],
            ["--grpc-server-addr", "localhost:1", "p.json"],
            ["p.json", "--", "--log-console"],
            ["p.json", "--", "free-value"],
        ):
            with self.subTest(args=args), self.assertRaises(ArgumentError):
                normalize(args)

    def test_duplicate_and_conflicting_options_fail(self) -> None:
        for args in (
            ["--log-console", "--log-console", "p.json"],
            ["--log-file", "x", "--log-console", "p.json"],
            ["-L", "info", "--log-level=info", "p.json"],
            ["-i", "1@a", "--interface", "1@b", "p.json"],
            ["--device-id", "0", "--device-id", "1", "p.json"],
            ["p.json", "--", "--cpu-port", "1", "--cpu-port", "2"],
        ):
            with self.subTest(args=args), self.assertRaises(ArgumentError):
                normalize(args)

    def test_incomplete_and_invalid_policy_values_fail(self) -> None:
        for args in (
            ["p.json", "--nanolog"],
            ["--log-level=", "p.json"],
            ["--log-level", "verbose", "p.json"],
            ["--log-console=yes", "p.json"],
            ["p.json", "--", "--grpc-server-addr"],
        ):
            with self.subTest(args=args), self.assertRaises(ArgumentError):
                normalize(args)

    def test_explicit_none_nanolog_is_not_forwarded_as_a_transport(self) -> None:
        self.assertEqual(
            normalize(["--nanolog", "none", "p.json"]), ["--log-console", "-L", "info", "p.json"]
        )

    def test_no_pipeline_mode_and_attached_short_values(self) -> None:
        self.assertEqual(
            normalize(["-i1@veth0", "-Ltrace", "--no-p4"]),
            ["-i1@veth0", "--no-p4", "--log-console", "-L", "info"],
        )
        with self.assertRaises(ArgumentError):
            normalize(["--no-p4", "p.json"])

    def test_multiple_configuration_paths_and_separators_fail(self) -> None:
        for args in ([], ["a.json", "b.json"], ["p.json", "--", "--"]):
            with self.subTest(args=args), self.assertRaises(ArgumentError):
                normalize(args)


class LauncherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.env = {
            "P4NET_STUDY_RUN_DIR": str(self.directory),
            "P4NET_STUDY_BMV2_REAL": "/missing/simple_switch_grpc",
        }

    def record(self) -> dict:
        (path,) = (self.directory / "bmv2-launches").glob("*.json")
        return json.loads(path.read_text())

    def test_exec_failure_preserves_requested_and_effective_argv(self) -> None:
        with (
            patch(
                "harness.bmv2_launcher.os.execve",
                side_effect=FileNotFoundError(errno.ENOENT, "binary unavailable"),
            ) as execute,
            redirect_stderr(io.StringIO()),
        ):
            code = run(["--nanolog", "ipc:///tmp/log", "p.json"], self.env)
        self.assertEqual(code, 127)
        record = self.record()
        self.assertEqual(record["status"], "exec_failed")
        self.assertEqual(record["requested_argv"], ["--nanolog", "ipc:///tmp/log", "p.json"])
        self.assertEqual(
            record["effective_argv"],
            ["/missing/simple_switch_grpc", "--log-console", "-L", "info", "p.json"],
        )
        self.assertEqual(execute.call_args.args[0], "/missing/simple_switch_grpc")
        self.assertEqual(execute.call_args.args[2], self.env)

    def test_argument_rejection_is_recorded_without_exec(self) -> None:
        with patch("harness.bmv2_launcher.os.execve") as execute, redirect_stderr(io.StringIO()):
            self.assertEqual(run(["--invalid", "p.json"], self.env), 2)
        execute.assert_not_called()
        self.assertEqual(self.record()["status"], "rejected")

    def test_existing_launch_record_cannot_be_overwritten(self) -> None:
        with (
            patch(
                "harness.bmv2_launcher.os.execve",
                side_effect=PermissionError(errno.EACCES, "permission denied"),
            ),
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(run(["p.json"], self.env), 126)
        before = self.record()
        with redirect_stderr(io.StringIO()):
            self.assertEqual(run(["other.json"], self.env), 2)
        self.assertEqual(self.record(), before)

    def test_missing_run_directory_prevents_launch(self) -> None:
        with patch("harness.bmv2_launcher.os.execve") as execute, redirect_stderr(io.StringIO()):
            self.assertEqual(run(["p.json"], {}), 2)
        execute.assert_not_called()

    def test_query_record_is_distinguished(self) -> None:
        with (
            patch(
                "harness.bmv2_launcher.os.execve",
                side_effect=FileNotFoundError(errno.ENOENT, "binary unavailable"),
            ),
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(run(["--version"], self.env), 127)
        self.assertTrue(self.record()["query"])
        self.assertEqual(
            self.record()["effective_argv"], ["/missing/simple_switch_grpc", "--version"]
        )


if __name__ == "__main__":
    unittest.main()
