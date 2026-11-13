"""Check fixture ownership, command probing, and recovery observation boundaries."""

import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from harness import episode, events, faults, spec


def clean(manifest):
    return {
        "run_id": manifest["run_id"],
        "prefix": manifest["prefix"],
        "processes": [],
        "namespaces": [],
        "interfaces": [],
        "listeners": [],
        "snapshot_errors": [],
        "root_interface_inventory": [],
        "observed_namespace_ids": [],
    }


class FixtureTests(unittest.TestCase):
    def test_reused_pid_cannot_receive_fault_signal(self) -> None:
        with (
            patch.object(faults, "require_enclosure"),
            patch.object(faults, "process_identity", return_value={"pid": 22, "start_ticks": 8}),
            patch.object(faults.os, "kill") as send,
        ):
            with self.assertRaises(ProcessLookupError):
                faults.signal_verified({"pid": 22, "start_ticks": 7}, signal.SIGKILL)
            send.assert_not_called()

    def test_switch_lookup_requires_owned_listener(self) -> None:
        manifest = {"switch_names": ["r123abcs0"], "service_ports": [50051, 9090]}
        state = {
            "processes": [
                {
                    "pid": 22,
                    "start_ticks": 7,
                    "cmdline": ["/bin/simple_switch_grpc", "-i", "1@r123abcs0-eth1"],
                }
            ],
            "listeners": [{"local_port": 50051, "owners": [{"pid": 99, "start_ticks": 7}]}],
        }
        with self.assertRaisesRegex(RuntimeError, "ownership"):
            faults.identify_first_switch(state, manifest)
        state["listeners"][0]["owners"] = [{"pid": 22, "start_ticks": 7}]
        with patch.object(faults, "process_identity", return_value={"pid": 22, "start_ticks": 7}):
            self.assertEqual(faults.identify_first_switch(state, manifest)["pid"], 22)

    def test_endpoint_rule_is_exact_and_never_flushes(self) -> None:
        snapshot = {}
        with patch.object(
            faults, "identify_first_switch", return_value={"pid": 22, "start_ticks": 7}
        ):
            blocker = faults.EndpointBlocker(
                {"run_id": "episode", "service_ports": [50051]}, snapshot
            )
        replies = [subprocess.CompletedProcess([], code, "", "") for code in (1, 0, 0, 0)]
        with (
            patch.object(faults, "require_enclosure"),
            patch.object(blocker, "_command", side_effect=replies) as run,
        ):
            blocker.install()
            blocker.release()
            blocker.release()
        self.assertEqual([c.args[0] for c in run.call_args_list], ["-C", "-A", "-C", "-D"])
        self.assertIn("127.0.0.1", blocker.rule)
        self.assertEqual(blocker.rule[blocker.rule.index("--dport") + 1], "50051")
        self.assertNotIn("-F", blocker.rule)

    def test_same_name_with_new_namespace_inode_is_not_inherited(self) -> None:
        state = clean({"run_id": "episode", "prefix": "r123abc"})
        state["namespaces"] = [{"name": "r123abca0", "netns": "net:[10]"}]
        ledger = episode.signatures(state)
        self.assertTrue(episode.allowed_restart(state, ledger))
        state["namespaces"][0]["netns"] = "net:[11]"
        self.assertFalse(episode.allowed_restart(state, ledger))
        state["snapshot_errors"] = ["uncertain"]
        self.assertFalse(episode.allowed_restart(state, ledger))

    def test_unlinked_name_does_not_change_namespace_object_identity(self) -> None:
        state = clean({"run_id": "episode", "prefix": "r123abc"})
        state["namespaces"] = [{"name": "r123abca0", "netns": "net:[10]"}]
        ledger = episode.signatures(state)
        state["namespaces"][0]["name"] = None
        self.assertTrue(episode.allowed_restart(state, ledger))

    def test_kill_probe_requires_old_identity_to_exit(self) -> None:
        identity = {"pid": 22, "start_ticks": 7}
        with (
            patch.object(faults, "process_identity", side_effect=[identity, None]),
            patch.object(faults.time, "sleep") as pause,
        ):
            self.assertTrue(faults.confirm_exit(identity)["exit_confirmed"])
            pause.assert_called_once()

    def test_process_exit_confirmation_has_a_bound(self) -> None:
        identity = {"pid": 22, "start_ticks": 7}
        with (
            patch.object(faults, "process_identity", return_value=identity),
            patch.object(faults.time, "monotonic", side_effect=[0, 4]),
            self.assertRaises(TimeoutError),
        ):
            faults.confirm_exit(identity)


class CommandTests(unittest.TestCase):
    def test_failed_probe_is_returned_and_next_command_can_stop(self) -> None:
        stream = io.StringIO()
        command = '{"command":"probe","request_id":"read-1"}\n{"command":"stop"}\n'
        with patch("sys.stdin", io.StringIO(command)), patch.object(events, "PROTOCOL_OUT", stream):

            def fail():
                raise RuntimeError("existing channel unavailable")

            events.serve_commands({"run_id": "task"}, fail)
        response = json.loads(stream.getvalue())
        self.assertEqual(response["request_id"], "read-1")
        self.assertFalse(response["ok"])
        self.assertEqual(response["error_type"], "RuntimeError")

    def test_unknown_commands_are_not_probe_requests(self) -> None:
        with (
            patch("sys.stdin", io.StringIO('{"command":"reconnect"}\n')),
            self.assertRaises(ValueError),
        ):
            events.serve_commands({"run_id": "task"}, lambda: {"entries": 2})

    def test_read_uses_existing_stub_and_native_deadline(self) -> None:
        stub = MagicMock()
        stub.Read.return_value = [MagicMock(entities=[1, 2])]
        result = events.bounded_read(stub)
        self.assertEqual(result, {"entries": 2})
        self.assertEqual(stub.Read.call_args.kwargs, {"timeout": 2.0})
        request = stub.Read.call_args.args[0]
        self.assertEqual(request.device_id, 0)
        self.assertTrue(request.entities[0].HasField("table_entry"))


class RunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = spec.create(
            Path(self.temp.name) / "episode", configuration_profile="matched-v1"
        )
        self.manifest = spec.load(self.path)
        self.manifest["episode_fault"] = "normal-control"
        self.path.write_text(json.dumps(self.manifest))

    def execute(self, capture=clean):
        with (
            patch.object(faults, "require_enclosure"),
            patch.object(episode.audit, "capture", side_effect=capture),
        ):
            return episode.run_episode(
                self.path, Path(sys.executable), "harness_tests.fixtures.episode_worker"
            )

    def test_restart_reuses_resources_in_same_namespace_with_new_process(self) -> None:
        result = self.execute()
        self.assertTrue(result["framework_complete"] and result["recovery_success"])
        initial = json.loads((self.path.parent / "initial/manifest.json").read_text())
        restart = json.loads((self.path.parent / "restart/manifest.json").read_text())
        for key in ("prefix", "host_names", "switch_names", "service_ports", "p4_source"):
            self.assertEqual(initial[key], restart[key])
        self.assertNotEqual(initial["run_id"], restart["run_id"])
        self.assertTrue((self.path.parent / "primary-outcome.json").exists())
        self.assertTrue((self.path.parent / "initial/inventory-ordinary-after.json").exists())

    def test_queued_ready_is_consumed_before_startup_signal(self) -> None:
        attempt = object.__new__(episode.Attempt)
        attempt.manifest = self.manifest
        attempt.started = False
        attempt.identity = {"pid": 99999, "start_ticks": 1}
        attempt.proc = SimpleNamespace(pid=99999, poll=lambda: None)
        attempt.result = {"ready": False, "checks": [], "error": None, "stopped": False}
        attempt.events = io.StringIO()
        registry = {**self.manifest, "owned_processes": [], "namespace_ids": []}
        state = clean(self.manifest)
        state["interfaces"] = [{"ifname": self.manifest["prefix"] + "-eth0", "link_type": "ether"}]
        attempt.episode = SimpleNamespace(manifest=registry, snapshot=lambda: state)
        hosts = self.manifest["host_names"]
        checks = [
            {"src": hosts[0], "dst": hosts[1], "ok": True},
            {"src": hosts[1], "dst": hosts[0], "ok": True},
        ]
        read_fd, write_fd = os.pipe()
        messages = [
            {
                "schema_version": 1,
                "run_id": self.manifest["run_id"],
                "event": kind,
                **({"checks": checks} if kind == "ready" else {}),
            }
            for kind in ("starting", "inventory", "ready")
        ]
        os.write(write_fd, ("\n".join(json.dumps(m) for m in messages) + "\n").encode())
        os.close(write_fd)
        with os.fdopen(read_fd, "rb", buffering=0) as stream:
            attempt.reader = episode.supervisor.EventReader(stream)
            try:
                with patch.object(faults, "signal_verified") as send:
                    self.assertIsNone(attempt.wait_ready(interrupt=True))
                    send.assert_not_called()
                self.assertTrue(attempt.result["ready"])
            finally:
                attempt.reader.close()

    def test_existing_episode_cannot_be_overwritten(self) -> None:
        target = self.path.parent / "primary-outcome.json"
        target.write_text("previous observation")
        with self.assertRaises(FileExistsError):
            self.execute()
        self.assertEqual(target.read_text(), "previous observation")

    def test_protocol_failure_saves_original_scene_before_safety(self) -> None:
        self.manifest["test_behavior"] = "bad-json"
        self.path.write_text(json.dumps(self.manifest))
        result = self.execute()
        self.assertFalse(result["ok"])
        self.assertIn("framework_error", result)
        self.assertTrue((self.path.parent / "initial/inventory-ordinary-after.json").exists())
        self.assertTrue((self.path.parent / "primary-outcome.json").exists())

    def test_generic_rescue_cannot_promote_native_recovery(self) -> None:
        phase = {"dirty": False, "rescued": False}

        def capture(manifest):
            snapshot = clean(manifest)
            if manifest.get("worker_identity"):
                phase["dirty"] = True
            if phase["dirty"] and not phase["rescued"]:
                snapshot["interfaces"] = [
                    {"ifname": manifest["prefix"] + "-extra", "ifindex": 99, "namespace": "root"}
                ]
            return snapshot

        def rescue(*args):
            phase["rescued"] = True
            return [{"action": "test-rescue"}]

        with patch.object(episode.supervisor, "_rescue", side_effect=rescue):
            result = self.execute(capture)
        self.assertTrue(result["ok"] and result["safety_after_clean"])
        self.assertFalse(result["recovery_success"])
        primary = json.loads((self.path.parent / "primary-outcome.json").read_text())
        self.assertFalse(primary["recovery_success"])
        self.assertNotIn("safety_actions", primary)
