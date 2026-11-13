"""Check descriptor transport and failure publication using synthetic parent probes."""

import copy
import fcntl
import json
import os
import signal
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from harness import observer_dispatch as dispatch
from harness import spec
from harness.observer_reference import ObserverIdentity, encode_message

from harness_tests.test_measure import metadata


class SocketChannelTests(unittest.TestCase):
    def setUp(self):
        self.left, self.right = socket.socketpair()
        self.addCleanup(self.left.close)
        self.addCleanup(self.right.close)
        self.channel = dispatch.SocketChannel(self.left, deadline=time.monotonic() + 5)

    def test_round_trip_uses_bounded_utf8_frames(self):
        message = {"value": "reference 中文", "number": 1}
        self.channel.send(message)
        self.assertEqual(self.right.recv(4096), encode_message(message))
        self.right.sendall(encode_message(message))
        self.assertEqual(self.channel.receive(), message)

    def test_multiple_frames_keep_their_boundaries(self):
        self.right.sendall(encode_message({"one": 1}) + encode_message({"two": 2}))
        self.assertEqual(self.channel.receive(), {"one": 1})
        self.assertEqual(self.channel.receive(), {"two": 2})

    def test_fragmented_frame_rechecks_the_absolute_deadline(self):
        sock = Mock()
        sock.recv.side_effect = [b'{"ok":', b"true}", b"\n"]
        clock = Mock(side_effect=[10, 10, 11, 11, 12, 12, 13])
        channel = dispatch.SocketChannel(sock, deadline=20, clock=clock)
        self.assertEqual(channel.receive(), {"ok": True})
        self.assertEqual([item.args[0] for item in sock.settimeout.call_args_list], [10, 9, 8])

    def test_partial_frame_eof_has_no_invented_message(self):
        self.right.sendall(b'{"partial":')
        self.right.close()
        with self.assertRaises(EOFError):
            self.channel.receive()

    def test_overlong_frame_is_rejected_without_waiting_for_newline(self):
        self.right.sendall(b"x" * 4097)
        with self.assertRaises(ValueError):
            self.channel.receive()

    def test_deadline_expiry_precedes_io_and_rejects_buffered_frames(self):
        sock = Mock()
        channel = dispatch.SocketChannel(sock, deadline=1, clock=lambda: 2)
        channel.buffer.extend(encode_message({"ready": True}))
        with self.assertRaises(TimeoutError):
            channel.receive()
        with self.assertRaises(TimeoutError):
            channel.send({"ready": True})
        sock.recv.assert_not_called()
        sock.sendall.assert_not_called()

    def test_partial_frame_cannot_extend_the_deadline(self):
        sock = Mock()
        sock.recv.return_value = b"{"
        clock = Mock(side_effect=[0, 0, 11])
        channel = dispatch.SocketChannel(sock, deadline=10, clock=clock)
        with self.assertRaises(TimeoutError):
            channel.receive()
        self.assertEqual(sock.recv.call_count, 1)

    def test_invalid_deadline_or_clock_is_rejected(self):
        for value in (True, float("inf"), float("nan"), "20"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                dispatch.SocketChannel(self.left, deadline=value)
        channel = dispatch.SocketChannel(self.left, deadline=20, clock=lambda: float("nan"))
        with self.assertRaises(ValueError):
            channel.receive()

    def test_invalid_json_and_duplicate_keys_are_rejected(self):
        self.right.sendall(b'{"x":1,"x":2}\n')
        with self.assertRaises(ValueError):
            self.channel.receive()


class DispatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.manifest_path = spec.create(self.base / "run", configuration_profile="matched-v1")
        self.manifest = spec.load(self.manifest_path)
        values = metadata()
        values["run_id"] = self.manifest["run_id"]
        self.configuration = {
            "mode": "pilot",
            "clock_domain": "synthetic-parent-test",
            "duration_ns": 10_000_000_000,
            "interval_ns": 100_000_000,
            "metadata": values,
            "observer_profile": "S",
            "attempt_id": "attempt-1",
        }
        self.namespaces = {"pid": "pid:[12]", "net": "net:[13]", "mnt": "mnt:[14]"}
        self.identity = ObserverIdentity(4322, 100, self.namespaces)
        self.proc = Mock(pid=4321, returncode=None)
        self.proc.poll.side_effect = lambda: self.proc.returncode
        self.native_ok = True
        self.returncode = 0
        self.messages = [
            {
                "schema_version": 1,
                "record_type": "observer-reference-checkpoint",
                "run_id": self.manifest["run_id"],
                "attempt_id": "attempt-1",
                "observer_profile": "S",
                "boundary": boundary,
                "sequence": index,
                "namespaces": self.namespaces,
            }
            for index, boundary in enumerate(dispatch.BOUNDARIES)
        ]
        self.channel = Mock()
        self.channel.remaining.return_value = 20
        self.channel.receive.side_effect = self.receive
        self.pairs = []
        original_socketpair = socket.socketpair

        def pair():
            sockets = original_socketpair()
            self.pairs.append(sockets)
            return sockets

        self.mock("socket.socketpair", side_effect=pair)
        self.mock("isolation.environment_for", return_value={"SYNTHETIC": "1"})
        self.command = self.mock("isolation.isolated_command", return_value=["fixture-unshare"])
        self.launch = self.mock("subprocess.Popen", side_effect=self.spawn)
        self.mock("_outer_start_ticks", return_value=99)
        self.discover = self.mock("discover_observer", return_value=self.identity)
        self.mock("SocketChannel", return_value=self.channel)
        self.cpu = self.mock("read_observer_cpu", side_effect=self.cpu_endpoint)
        self.memory = self.mock(
            "read_observer_memory",
            return_value={
                "observer": self.identity.as_dict(),
                "rss_bytes": 4096,
                "pss_bytes": 2048,
            },
        )
        self.mock("time.monotonic", return_value=100.0)
        self.ns = 0
        self.mock("time.monotonic_ns", side_effect=self.clock)
        self.mock("time.process_time_ns", return_value=0)
        self.mock("os.sysconf", return_value=100)
        self.proc.wait.side_effect = self.wait

    def mock(self, name, **kwargs):
        replacement = patch(f"harness.observer_dispatch.{name}", **kwargs)
        value = replacement.start()
        self.addCleanup(replacement.stop)
        return value

    def clock(self):
        self.ns += 1
        return self.ns

    def cpu_endpoint(self, identity):
        return {"observer": identity.as_dict(), "user_ticks": 1, "system_ticks": 0, "cpu_ticks": 1}

    def spawn(self, *args, **kwargs):
        self.assertEqual(
            [item.name for item in self.manifest_path.parent.iterdir()],
            [self.manifest_path.name],
        )
        lock_path, log_path = dispatch.control_paths(self.manifest_path)
        self.assertTrue(lock_path.is_file())
        self.assertTrue(log_path.is_file())
        self.assertEqual(kwargs["stdout"].name, str(log_path))
        self.assertEqual(kwargs["pass_fds"], (self.pairs[-1][1].fileno(),))
        os.fstat(kwargs["pass_fds"][0])
        self.assertTrue(kwargs["start_new_session"])
        return self.proc

    def wait(self, timeout=None):
        self.proc.returncode = self.returncode
        return self.returncode

    def receive(self):
        message = self.messages.pop(0)
        if message["boundary"] == "ref_complete":
            self.write_child()
        return message

    def write_child(self):
        child = {
            "schema_version": 1,
            "record_type": "observer-calibration-child-result",
            "run_id": self.manifest["run_id"],
            "attempt_id": "attempt-1",
            "observer_profile": "S",
            "mode": "pilot",
            "performance_samples": True,
            "native_result": {"ok": self.native_ok},
            "reference_primary_acknowledged": True,
        }
        (self.manifest_path.parent / "observer-child-result.json").write_text(json.dumps(child))

    def run_attempt(self, path=None, **kwargs):
        arguments = {
            "calibration": self.configuration,
            "collection_authorized": True,
            "timeout": 30,
        }
        arguments.update(kwargs)
        result = dispatch.run_calibrated(
            self.manifest_path if path is None else path,
            Path("/fixture/python"),
            "fixture.worker",
            **arguments,
        )
        for pair in self.pairs:
            self.assertEqual([sock.fileno() for sock in pair], [-1, -1])
        return result

    def test_success_inherits_one_descriptor_and_binds_separate_sidecar(self):
        result = self.run_attempt()
        self.assertEqual(result["dispatch_status"], "completed")
        self.assertTrue(result["native_ok"])
        self.assertFalse(result["inner_pid_numbers_consumed"])
        self.assertEqual(self.command.call_args.kwargs["reference_deadline"], 130.0)
        self.discover.assert_called_once_with(4321, self.namespaces, outer_start_ticks=99)
        self.assertEqual(self.cpu.call_count, 2)
        self.memory.assert_called_once_with(self.identity)
        self.proc.send_signal.assert_not_called()
        record = json.loads((self.manifest_path.parent / "observer-reference.json").read_bytes())
        self.assertEqual(record["child_result"], result["child_result"])
        self.assertEqual(
            result, json.loads((self.manifest_path.parent / "observer-dispatch.json").read_bytes())
        )
        self.assertEqual(result["log"], str(dispatch.control_paths(self.manifest_path)[1]))

    def test_control_paths_are_outside_output_and_distinct_for_sibling_runs(self):
        lock, log = dispatch.control_paths(self.manifest_path)
        directory = self.manifest_path.parent
        self.assertEqual(lock, directory.parent / f".{directory.name}-observer-dispatch.lock")
        self.assertEqual(log, directory.parent / f"{directory.name}-observer-isolation.log")
        other = dispatch.control_paths(directory.parent / "other" / self.manifest_path.name)
        self.assertTrue(set((lock, log)).isdisjoint(other))
        self.assertEqual(lock.parent, directory.parent)
        self.assertEqual(log.parent, directory.parent)

    def test_manifest_aliases_share_canonical_control_identity(self):
        directory_alias = self.base / "run-alias"
        directory_alias.symlink_to(self.manifest_path.parent, target_is_directory=True)
        file_alias = self.base / "manifest-alias.json"
        file_alias.symlink_to(self.manifest_path)
        expected = dispatch.control_paths(self.manifest_path)
        for path in (
            self.manifest_path,
            directory_alias / self.manifest_path.name,
            file_alias,
            Path(os.path.relpath(self.manifest_path)),
        ):
            with self.subTest(path=path):
                self.assertEqual(dispatch.control_paths(path), expected)

    def test_directory_alias_cannot_bypass_canonical_lock(self):
        directory_alias = self.base / "run-alias"
        directory_alias.symlink_to(self.manifest_path.parent, target_is_directory=True)
        lock_path, _ = dispatch.control_paths(self.manifest_path)
        with lock_path.open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(RuntimeError, "another dispatcher"):
                self.run_attempt(directory_alias / self.manifest_path.name)
        self.launch.assert_not_called()

    def test_directory_alias_cannot_bypass_canonical_log(self):
        directory_alias = self.base / "run-alias"
        directory_alias.symlink_to(self.manifest_path.parent, target_is_directory=True)
        _, log_path = dispatch.control_paths(self.manifest_path)
        log_path.write_text("preserve canonical log")
        with self.assertRaises(FileExistsError):
            self.run_attempt(directory_alias / self.manifest_path.name)
        self.launch.assert_not_called()
        self.assertEqual(log_path.read_text(), "preserve canonical log")

    def test_manifest_file_alias_uses_canonical_command_and_artifacts(self):
        file_alias = self.base / "manifest-alias.json"
        file_alias.symlink_to(self.manifest_path)
        result = self.run_attempt(file_alias)
        self.assertEqual(result["dispatch_status"], "completed")
        self.assertEqual(self.command.call_args.args[0], self.manifest_path.resolve())
        directory = self.manifest_path.resolve().parent
        self.assertEqual(
            result["child_result"]["path"], str(directory / "observer-child-result.json")
        )
        self.assertEqual(
            result["calibration_terminal"]["path"],
            str(directory / "observer-calibration-result.json"),
        )
        self.assertEqual(result["log"], str(dispatch.control_paths(self.manifest_path)[1]))
        for name in (
            "observer-child-result.json",
            "observer-reference.json",
            "observer-calibration-result.json",
            "observer-dispatch.json",
        ):
            self.assertTrue((directory / name).is_file())
            self.assertFalse((file_alias.parent / name).exists())

    def test_native_failure_is_not_changed_by_successful_transport(self):
        self.native_ok = False
        self.returncode = 1
        result = self.run_attempt()
        self.assertEqual(result["dispatch_status"], "completed")
        self.assertFalse(result["native_ok"])

    def test_authorization_rejects_truthy_values_before_any_launch_or_probe(self):
        for authorization in (False, 1, "yes", None):
            with self.subTest(authorization=authorization), self.assertRaises(PermissionError):
                self.run_attempt(collection_authorized=authorization)
        self.launch.assert_not_called()
        self.discover.assert_not_called()
        self.cpu.assert_not_called()
        self.assertEqual(self.pairs, [])

    def test_preexisting_result_cannot_launch_another_attempt(self):
        result = self.manifest_path.parent / "result.json"
        result.write_text("preserve")
        with self.assertRaises(FileExistsError):
            self.run_attempt()
        self.launch.assert_not_called()
        self.assertEqual(result.read_text(), "preserve")

    def test_early_isolation_or_primary_artifact_prevents_relaunch(self):
        directory = self.manifest_path.parent
        for artifact in (
            directory / "primary-outcome.json",
            directory.parent / f"{directory.name}-isolation.json",
        ):
            artifact.write_text("preserve")
            with self.subTest(artifact=artifact.name), self.assertRaises(FileExistsError):
                self.run_attempt()
            self.assertEqual(artifact.read_text(), "preserve")
            artifact.unlink()
        self.launch.assert_not_called()

    def test_concurrent_owner_prevents_duplicate_launch(self):
        lock_path, _ = dispatch.control_paths(self.manifest_path)
        with lock_path.open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(RuntimeError, "another dispatcher"):
                self.run_attempt()
        self.launch.assert_not_called()

    def test_existing_external_lock_alone_does_not_count_as_a_prior_outcome(self):
        lock, _ = dispatch.control_paths(self.manifest_path)
        lock.write_text("")
        result = self.run_attempt()
        self.assertEqual(result["dispatch_status"], "completed")
        self.launch.assert_called_once()

    def test_external_log_prevents_relaunch_without_entering_native_output(self):
        _, log = dispatch.control_paths(self.manifest_path)
        log.write_text("preserve previous control log")
        with self.assertRaises(FileExistsError):
            self.run_attempt()
        self.launch.assert_not_called()
        self.assertEqual(log.read_text(), "preserve previous control log")
        self.assertEqual(list(self.manifest_path.parent.iterdir()), [self.manifest_path])

    def test_external_log_symlink_is_not_followed_or_replaced(self):
        _, log = dispatch.control_paths(self.manifest_path)
        target = self.base / "unrelated.log"
        target.write_text("preserve unrelated output")
        log.symlink_to(target)
        with self.assertRaises(FileExistsError):
            self.run_attempt()
        self.launch.assert_not_called()
        self.assertTrue(log.is_symlink())
        self.assertEqual(target.read_text(), "preserve unrelated output")

    def test_external_lock_symlink_is_not_followed(self):
        lock, _ = dispatch.control_paths(self.manifest_path)
        target = self.base / "unrelated.lock"
        target.write_text("preserve unrelated lock")
        lock.symlink_to(target)
        with self.assertRaises(OSError):
            self.run_attempt()
        self.launch.assert_not_called()
        self.assertTrue(lock.is_symlink())
        self.assertEqual(target.read_text(), "preserve unrelated lock")

    def test_legacy_control_and_unknown_files_cannot_bypass_fresh_directory_check(self):
        for name in (".observer-dispatch.lock", "observer-isolation.log", "unexpected.json"):
            path = self.manifest_path.parent / name
            path.write_text("preserve")
            with self.subTest(name=name), self.assertRaises(FileExistsError):
                self.run_attempt()
            self.assertEqual(path.read_text(), "preserve")
            path.unlink()
        self.launch.assert_not_called()

    def test_unknown_directory_or_dangling_symlink_cannot_launch(self):
        directory = self.manifest_path.parent / "unexpected-directory"
        directory.mkdir()
        with self.assertRaises(FileExistsError):
            self.run_attempt()
        directory.rmdir()
        link = self.manifest_path.parent / "unexpected-link"
        link.symlink_to(self.base / "missing")
        with self.assertRaises(FileExistsError):
            self.run_attempt()
        self.launch.assert_not_called()
        self.assertTrue(link.is_symlink())

    def test_invalid_timeout_cannot_launch(self):
        with self.assertRaises(ValueError):
            self.run_attempt(timeout=float("nan"))
        self.launch.assert_not_called()

    def test_invalid_initial_binding_cannot_authorize_pid_discovery(self):
        self.messages[0]["attempt_id"] = "different"
        result = self.run_attempt()
        self.assertEqual(result["dispatch_status"], "failed")
        self.discover.assert_not_called()
        self.cpu.assert_not_called()
        self.proc.send_signal.assert_called_once_with(signal.SIGTERM)

    def test_channel_eof_reaps_only_the_owned_outer_process(self):
        self.channel.receive.side_effect = EOFError("closed")
        result = self.run_attempt()
        self.assertEqual(result["dispatch_status"], "failed")
        self.assertIsNone(result["native_ok"])
        self.assertFalse(result["native_outcome_available"])
        self.proc.send_signal.assert_called_once_with(signal.SIGTERM)

    def test_timeout_escalates_termination_without_using_inner_pid(self):
        self.channel.receive.side_effect = TimeoutError("expired")
        self.proc.wait.side_effect = [subprocess.TimeoutExpired("fixture", 5), -9]
        result = self.run_attempt()
        self.assertEqual(result["dispatch_status"], "timeout")
        self.proc.send_signal.assert_called_once_with(signal.SIGTERM)
        self.proc.kill.assert_called_once_with()
        self.assertEqual(
            [call.kwargs["timeout"] for call in self.proc.wait.call_args_list], [5, 10]
        )

    def test_incomplete_reference_keeps_already_published_native_success(self):
        count = 0

        def receive():
            nonlocal count
            count += 1
            if count == 3:
                self.write_child()
                raise EOFError("closed before complete")
            return self.messages.pop(0)

        self.channel.receive.side_effect = receive
        result = self.run_attempt()
        self.assertEqual(result["dispatch_status"], "failed")
        self.assertTrue(result["native_ok"])
        terminal = json.loads(
            (self.manifest_path.parent / "observer-calibration-result.json").read_bytes()
        )
        self.assertEqual(terminal["reference_status"], "incomplete")
        self.assertIsNone(terminal["reference_sidecar"])
        self.assertFalse((self.manifest_path.parent / "observer-reference.json").exists())

    def test_interruption_is_persisted_and_reraised(self):
        self.channel.receive.side_effect = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.run_attempt()
        record = json.loads((self.manifest_path.parent / "observer-dispatch.json").read_bytes())
        self.assertEqual(record["dispatch_status"], "interrupted")
        self.proc.send_signal.assert_called_once_with(signal.SIGTERM)
        for pair in self.pairs:
            self.assertEqual([sock.fileno() for sock in pair], [-1, -1])

    def test_outer_exit_disagreement_remains_a_dispatch_failure(self):
        self.returncode = 99
        result = self.run_attempt()
        self.assertEqual(result["dispatch_status"], "failed")
        self.assertTrue(result["native_ok"])
        self.assertIsNotNone(result["calibration_terminal"])

    def test_launch_failure_closes_sockets_and_retains_no_native_outcome(self):
        self.launch.side_effect = OSError("launch failed")
        result = self.run_attempt()
        self.assertEqual(result["dispatch_status"], "failed")
        self.assertIsNone(result["outer_pid"])
        self.assertFalse(result["native_outcome_available"])

    def test_environment_failure_is_persisted_before_launch(self):
        self.mock("isolation.environment_for", side_effect=RuntimeError("missing BMv2 wrapper"))
        result = self.run_attempt()
        self.assertEqual(result["dispatch_status"], "failed")
        self.assertIsNone(result["outer_launch_ns"])
        self.assertIsNone(result["outer_exit_ns"])
        self.assertIsNone(result["outer_lifetime_ns"])
        self.assertFalse(result["native_outcome_available"])
        self.assertEqual(self.pairs, [])
        self.launch.assert_not_called()
        self.cpu.assert_not_called()

    def test_socket_creation_failure_is_persisted_before_launch(self):
        self.mock("socket.socketpair", side_effect=OSError("no descriptors"))
        result = self.run_attempt()
        self.assertEqual(result["dispatch_status"], "failed")
        self.assertIsNone(result["outer_launch_ns"])
        self.assertIsNone(result["outer_exit_ns"])
        self.assertFalse(result["native_outcome_available"])
        self.launch.assert_not_called()

    def test_unreaped_process_does_not_receive_a_fabricated_exit_timestamp(self):
        self.channel.receive.side_effect = TimeoutError("expired")
        self.proc.wait.side_effect = [
            subprocess.TimeoutExpired("fixture", 5),
            subprocess.TimeoutExpired("fixture", 10),
        ]
        result = self.run_attempt()
        self.assertEqual(result["dispatch_status"], "timeout")
        self.assertIsNone(result["outer_returncode"])
        self.assertIsNone(result["outer_exit_ns"])
        self.assertIsNone(result["outer_lifetime_ns"])
        self.assertTrue(result["cleanup_issues"])
        self.proc.kill.assert_called_once_with()

    def ordinary_before_failure(self, *, ok=True, run_id=None, corrupt_envelope=False):
        original = self.receive

        def receive():
            if self.messages[0]["boundary"] != "ref_complete":
                return original()
            ordinary = {
                "schema_version": 1,
                "run_id": self.manifest["run_id"] if run_id is None else run_id,
                "mode": "correctness-check",
                "performance_samples": False,
                "ok": ok,
            }
            (self.manifest_path.parent / "result.json").write_text(json.dumps(ordinary))
            if corrupt_envelope:
                (self.manifest_path.parent / "observer-child-result.json").write_text("{}")
            raise EOFError("envelope publication failed")

        self.channel.receive.side_effect = receive

    def test_raw_native_result_survives_a_missing_calibration_envelope(self):
        self.ordinary_before_failure()
        result = self.run_attempt()
        self.assertEqual(result["dispatch_status"], "failed")
        self.assertTrue(result["native_outcome_available"])
        self.assertTrue(result["native_ok"])
        self.assertEqual(result["native_result_source"]["kind"], "ordinary-result")
        self.assertEqual(
            result["native_result_source"]["path"], str(self.manifest_path.parent / "result.json")
        )
        self.assertIsNone(result["child_result"])
        self.assertIsNone(result["calibration_terminal"])
        self.assertFalse((self.manifest_path.parent / "observer-reference.json").exists())

    def test_raw_native_failure_is_preserved_without_an_envelope(self):
        self.ordinary_before_failure(ok=False)
        result = self.run_attempt()
        self.assertTrue(result["native_outcome_available"])
        self.assertFalse(result["native_ok"])
        self.assertEqual(result["dispatch_status"], "failed")

    def test_corrupt_calibration_envelope_does_not_hide_valid_ordinary_result(self):
        self.ordinary_before_failure(corrupt_envelope=True)
        result = self.run_attempt()
        self.assertTrue(result["native_ok"])
        self.assertEqual(result["native_result_source"]["kind"], "ordinary-result")
        self.assertIsNone(result["child_result"])
        self.assertIsNone(result["calibration_terminal"])
        self.assertIsNotNone(result["publication_error"])

    def test_foreign_raw_result_is_not_used_as_the_native_outcome(self):
        self.ordinary_before_failure(run_id="different-run")
        result = self.run_attempt()
        self.assertFalse(result["native_outcome_available"])
        self.assertIsNone(result["native_ok"])
        self.assertIsNone(result["native_result_source"])
        self.assertIsNotNone(result["native_result_error"])

    def test_ordinary_result_requires_integer_schema_and_boolean_outcome(self):
        raw = self.manifest_path.parent / "ordinary-fixture.json"
        valid = {"schema_version": 1, "run_id": self.manifest["run_id"], "ok": True}
        for values in ({"schema_version": True}, {"ok": 1}, {"schema_version": 2}):
            raw.write_text(json.dumps({**valid, **values}))
            with self.subTest(values=values), self.assertRaises(ValueError):
                dispatch._ordinary_result(raw, self.manifest["run_id"])
        for content in (
            '{"schema_version":1,"schema_version":1}',
            json.dumps({**valid, "invalid": float("nan")}),
        ):
            raw.write_text(content)
            with self.assertRaises(ValueError):
                dispatch._ordinary_result(raw, self.manifest["run_id"])

    def test_pid_discovery_failure_never_samples_an_unverified_identity(self):
        self.discover.side_effect = ProcessLookupError("identity changed")
        result = self.run_attempt()
        self.assertEqual(result["dispatch_status"], "failed")
        self.cpu.assert_not_called()
        self.memory.assert_not_called()

    def test_recorded_attempt_cannot_automatically_run_again(self):
        first = copy.deepcopy(self.run_attempt())
        with self.assertRaises(FileExistsError):
            self.run_attempt()
        self.assertEqual(self.launch.call_count, 1)
        self.assertEqual(
            first, json.loads((self.manifest_path.parent / "observer-dispatch.json").read_bytes())
        )
