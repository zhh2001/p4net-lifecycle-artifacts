"""Exercise worker protocol failures without native network resources."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.supervisor import (
    EventReader,
    ProtocolError,
    _remember_event,
    _remember_namespaces,
    _remember_snapshot,
    _rescue,
    _signal_identity,
    run,
    snapshot_clean,
    validate_event,
    validate_ready,
    validate_task_ready,
)


def clean_snapshot() -> dict:
    return {
        key: [] for key in ("processes", "namespaces", "interfaces", "listeners", "snapshot_errors")
    }


class EventReaderTests(unittest.TestCase):
    def read_bytes(self, data: bytes, limit: int = 4096) -> dict | None:
        read_fd, write_fd = os.pipe()
        with os.fdopen(read_fd, "rb", buffering=0) as stream:
            os.write(write_fd, data)
            os.close(write_fd)
            reader = EventReader(stream, max_event_bytes=limit)
            try:
                return reader.read(time.monotonic() + 1)
            finally:
                reader.close()

    def test_valid_line(self) -> None:
        self.assertEqual(self.read_bytes(b'{"event":"ready"}\n'), {"event": "ready"})

    def test_invalid_json(self) -> None:
        with self.assertRaises(ProtocolError):
            self.read_bytes(b"{broken}\n")

    def test_nonfinite_json(self) -> None:
        with self.assertRaises(ProtocolError):
            self.read_bytes(b'{"value":NaN}\n')

    def test_object_required(self) -> None:
        with self.assertRaises(ProtocolError):
            self.read_bytes(b"[]\n")

    def test_unterminated_event(self) -> None:
        with self.assertRaisesRegex(ProtocolError, "incomplete"):
            self.read_bytes(b'{"event":"ready"}')

    def test_size_limit(self) -> None:
        with self.assertRaisesRegex(ProtocolError, "size limit"):
            self.read_bytes(b'{"value":"long content"}\n', limit=8)

    def test_partial_line_has_deadline(self) -> None:
        read_fd, write_fd = os.pipe()
        try:
            with os.fdopen(read_fd, "rb", buffering=0) as stream:
                os.write(write_fd, b'{"event":')
                reader = EventReader(stream)
                try:
                    with self.assertRaises(TimeoutError):
                        reader.read(time.monotonic() + 0.02)
                finally:
                    reader.close()
        finally:
            os.close(write_fd)


class ValidationTests(unittest.TestCase):
    def test_event_run_and_schema(self) -> None:
        for event in (
            {"schema_version": True, "run_id": "r1", "event": "ready"},
            {"schema_version": 1, "run_id": "other", "event": "ready"},
            {"schema_version": 1, "run_id": "r1", "event": "unknown"},
        ):
            with self.assertRaises(ProtocolError):
                validate_event(event, "r1")

    def test_ready_requires_true_nonempty_checks(self) -> None:
        for checks in (
            [],
            None,
            [{"src": "a", "dst": "b", "ok": 1}],
            [{"src": "a", "dst": "b", "ok": False}],
        ):
            with self.assertRaises(ProtocolError):
                validate_ready({"checks": checks})

    def test_missing_audit_lists_are_not_clean(self) -> None:
        self.assertFalse(snapshot_clean({}))
        self.assertTrue(snapshot_clean(clean_snapshot()))

    def test_root_namespace_cannot_be_adopted(self) -> None:
        manifest: dict = {"namespace_ids": []}
        _remember_namespaces(manifest, [os.readlink("/proc/self/ns/net"), "net:[123]"])
        self.assertEqual(manifest["namespace_ids"], ["net:[123]"])
        with self.assertRaises(ProtocolError):
            _remember_namespaces(manifest, ["arbitrary"])

    def test_directional_coverage_must_be_complete_without_duplicates(self) -> None:
        manifest = {"host_names": ["a", "b", "c", "d"]}
        checks = [
            {"src": src, "dst": dst, "ok": True}
            for src, dst in (("a", "b"), ("b", "a"), ("c", "d"), ("d", "c"))
        ]
        self.assertEqual(validate_task_ready({"checks": checks}, manifest), checks)
        with self.assertRaises(ProtocolError):
            validate_task_ready({"checks": checks[:-1]}, manifest)
        with self.assertRaises(ProtocolError):
            validate_task_ready({"checks": [*checks[:-1], checks[0]]}, manifest)

    def test_reused_pid_is_not_signaled(self) -> None:
        identity = {"pid": 12345, "start_ticks": 42}
        with (
            patch(
                "harness.supervisor.process_identity",
                return_value={"pid": 12345, "start_ticks": 43},
            ),
            patch("harness.supervisor.os.kill") as kill,
        ):
            actions: list = []
            _signal_identity(identity, signal.SIGTERM, actions)
            kill.assert_not_called()
            self.assertEqual(actions, [])

    def test_rescue_does_not_delete_unrelated_names(self) -> None:
        snapshot = clean_snapshot()
        snapshot["interfaces"] = [{"ifname": "other0", "namespace": "root"}]
        snapshot["namespaces"] = [{"name": "unrelated"}]
        manifest = {"prefix": "r123abc", "owned_processes": [], "namespace_ids": []}
        with patch("harness.supervisor.subprocess.run") as command:
            self.assertEqual(_rescue(manifest, snapshot), [])
            command.assert_not_called()

    def test_marker_only_observer_is_not_granted_signal_authority(self) -> None:
        identity = {"pid": 12345, "start_ticks": 42}
        for reasons in (["output_path"], ["namespace"], ["candidate_descendant"]):
            manifest = {
                "prefix": "r123abc",
                "owned_processes": [],
                "namespace_ids": [],
                "worker_identity": {"pid": 9876, "start_ticks": 10},
            }
            snapshot = clean_snapshot()
            snapshot["processes"] = [{**identity, "ownership": reasons}]
            with (
                patch("harness.supervisor.process_identity", return_value=identity),
                patch("harness.supervisor.os.getpgid", return_value=5555),
                patch("harness.supervisor._signal_identity") as send_signal,
            ):
                self.assertEqual(_rescue(manifest, snapshot), [])
                send_signal.assert_not_called()
            self.assertEqual(manifest["owned_processes"], [])
            self.assertFalse(snapshot_clean(snapshot))

    def test_independent_ancestry_grants_signal_authority(self) -> None:
        for reason in ("worker_descendant", "trusted_descendant"):
            manifest: dict = {"owned_processes": [], "namespace_ids": []}
            snapshot = clean_snapshot()
            snapshot["processes"] = [{"pid": 12345, "start_ticks": 42, "ownership": [reason]}]
            _remember_snapshot(manifest, snapshot)
            self.assertEqual(manifest["owned_processes"], [{"pid": 12345, "start_ticks": 42}])

    def test_current_identity_in_worker_group_grants_signal_authority(self) -> None:
        identity = {"pid": 12345, "start_ticks": 42}
        manifest = {
            "owned_processes": [],
            "namespace_ids": [],
            "worker_identity": {"pid": 9876, "start_ticks": 10},
        }
        snapshot = clean_snapshot()
        snapshot["processes"] = [{**identity, "ownership": ["output_path"]}]
        with (
            patch("harness.supervisor.process_identity", return_value=identity),
            patch("harness.supervisor.os.getpgid", return_value=9876),
        ):
            _remember_snapshot(manifest, snapshot)
        self.assertEqual(manifest["owned_processes"], [identity])

    def test_unverified_event_identity_cannot_gain_signal_authority(self) -> None:
        identity = {"pid": 12345, "start_ticks": 42}
        manifest: dict = {"owned_processes": [], "namespace_ids": []}
        with patch("harness.supervisor.process_identity", return_value=None):
            _remember_event(manifest, {"owned_processes": [identity]}, 9876)
        self.assertEqual(manifest["owned_processes"], [])
        with (
            patch("harness.supervisor.process_identity", return_value=identity),
            patch("harness.supervisor.os.getpgid", return_value=5555),
            self.assertRaisesRegex(ProtocolError, "outside"),
        ):
            _remember_event(manifest, {"owned_processes": [identity]}, 9876)


class SupervisorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name) / "run"
        self.directory.mkdir()
        self.manifest = self.directory / "manifest.json"
        self.manifest.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "run_id": "test-run",
                    "prefix": "r123abc",
                    "groups": 1,
                    "host_names": ["r123abca", "r123abcb"],
                    "switch_names": ["r123abcs"],
                    "service_ports": [30001, 30002],
                    "p4_source": str(Path(__file__).resolve()),
                    "output_dir": str(self.directory),
                }
            )
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def event(self, kind: str, **kwargs: object) -> dict:
        return {"schema_version": 1, "run_id": "test-run", "event": kind, **kwargs}

    def script(self, events: list[dict], after_stop: list[dict] | None = None) -> str:
        after = [self.event("stopped")] if after_stop is None else after_stop
        return (
            "import json,sys\n"
            f"events={events!r}\n"
            "for event in events: print(json.dumps(event),flush=True)\n"
            "sys.stdin.readline()\n"
            f"events={after!r}\n"
            "for event in events: print(json.dumps(event),flush=True)\n"
        )

    def execute(self, code: str, audit=None) -> dict:
        return run(
            self.manifest,
            worker_command=[sys.executable, "-c", code],
            ready_timeout=1,
            stop_timeout=0.2,
            audit_fn=audit or (lambda manifest: clean_snapshot()),
        )

    def ready(self) -> dict:
        return self.event(
            "ready",
            checks=[
                {"src": "r123abca", "dst": "r123abcb", "ok": True},
                {"src": "r123abcb", "dst": "r123abca", "ok": True},
            ],
        )

    def test_normal_worker(self) -> None:
        result = self.execute(self.script([self.event("starting"), self.ready()]))
        self.assertTrue(result["ok"])
        self.assertTrue(result["cleanup"]["after_clean"])
        self.assertFalse(result["performance_samples"])
        self.assertTrue((self.directory / "inventory-ready.json").is_file())

    def test_worker_exit_before_readiness(self) -> None:
        result = self.execute("pass")
        self.assertFalse(result["ok"])
        self.assertEqual(result["worker_returncode"], 0)

    def test_worker_exit_closes_parent_pipes(self) -> None:
        original = subprocess.Popen
        children = []

        def spawn(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child

        with patch("harness.supervisor.subprocess.Popen", side_effect=spawn):
            self.execute("pass")
        self.assertTrue(children[0].stdin.closed)
        self.assertTrue(children[0].stdout.closed)

    def test_bad_json_preserves_failure(self) -> None:
        result = self.execute("print('{broken}',flush=True)")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["type"], "ProtocolError")

    def test_failed_ping_cannot_be_ready(self) -> None:
        event = self.event("ready", checks=[{"src": "a", "dst": "b", "ok": False}])
        result = self.execute(self.script([self.event("starting"), event]))
        self.assertFalse(result["ready"])
        self.assertFalse(result["ok"])

    def test_duplicate_ready_is_failure(self) -> None:
        result = self.execute(self.script([self.event("starting"), self.ready(), self.ready()]))
        self.assertFalse(result["ok"])
        self.assertIn("duplicated", result["error"]["message"])

    def test_event_after_stopped_is_failure(self) -> None:
        result = self.execute(
            self.script(
                [self.event("starting"), self.ready()],
                [self.event("stopped"), self.event("inventory")],
            )
        )
        self.assertFalse(result["ok"])
        self.assertIn("after stopped", result["error"]["message"])

    def test_missing_stopped_is_failure(self) -> None:
        result = self.execute(self.script([self.event("starting"), self.ready()], []))
        self.assertFalse(result["ok"])

    def test_error_event_is_failure(self) -> None:
        result = self.execute(
            self.script([self.event("starting"), self.event("error", message="broken")])
        )
        self.assertFalse(result["ok"])
        self.assertIn("broken", result["error"]["message"])

    def test_inventory_before_starting_is_failure(self) -> None:
        result = self.execute(
            self.script([self.event("inventory"), self.event("starting"), self.ready()])
        )
        self.assertFalse(result["ok"])
        self.assertIn("precedes starting", result["error"]["message"])

    def test_audit_failure_refuses_launch(self) -> None:
        snapshot = clean_snapshot()
        snapshot["snapshot_errors"] = ["permission denied"]
        with patch("harness.supervisor.subprocess.Popen") as launch:
            result = self.execute("pass", audit=lambda manifest: snapshot)
            launch.assert_not_called()
        self.assertFalse(result["ok"])
        self.assertTrue(result["cleanup"]["not_started"])

    def test_rescue_cannot_turn_residual_failure_into_success(self) -> None:
        calls = 0

        def audit(manifest: dict) -> dict:
            nonlocal calls
            calls += 1
            snapshot = clean_snapshot()
            if calls == 3:
                snapshot["interfaces"] = [{"ifname": "r123abc-eth1", "namespace": "root"}]
            return snapshot

        with patch("harness.supervisor._rescue", return_value=[{"action": "test-rescue"}]):
            result = self.execute(self.script([self.event("starting"), self.ready()]), audit=audit)
        self.assertFalse(result["ok"])
        self.assertFalse(result["cleanup"]["after_clean"])
        self.assertTrue(result["cleanup"]["after_rescue_clean"])
        before_rescue = json.loads((self.directory / "inventory-after.json").read_text())
        self.assertEqual(len(before_rescue["interfaces"]), 1)

    def test_root_interface_comparison_is_applied_before_and_after_rescue(self) -> None:
        def audit(manifest: dict) -> dict:
            return {**clean_snapshot(), "root_interface_inventory": []}

        comparisons = 0

        def compare(before: dict, after: dict) -> dict:
            nonlocal comparisons
            comparisons += 1
            return {**after, "snapshot_errors": ["unattributed temporary veth"]}

        with (
            patch("harness.audit.compare_root_interfaces", side_effect=compare),
            patch("harness.supervisor._rescue", return_value=[]),
        ):
            result = self.execute(self.script([self.event("starting"), self.ready()]), audit=audit)
        self.assertEqual(comparisons, 2)
        self.assertFalse(result["ok"])
        self.assertFalse(result["cleanup"]["after_clean"])
        self.assertFalse(result["cleanup"]["after_rescue_clean"])

    def test_output_records_cannot_be_overwritten(self) -> None:
        (self.directory / "result.json").write_text("existing")
        with self.assertRaises(FileExistsError):
            self.execute("pass")
        self.assertEqual((self.directory / "result.json").read_text(), "existing")

    def test_invalid_deadline_is_rejected(self) -> None:
        for timeout in (0, -1, float("nan"), float("inf"), True):
            with self.assertRaises(ValueError):
                run(self.manifest, ready_timeout=timeout)


if __name__ == "__main__":
    unittest.main()
