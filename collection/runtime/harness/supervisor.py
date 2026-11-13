"""Supervise one correctness-check worker without collecting performance data."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import selectors
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path
from typing import IO, Any

from harness.native_measurement import Observation

MAX_EVENT_BYTES = 1024 * 1024
RESOURCE_KEYS = ("processes", "namespaces", "interfaces", "listeners", "snapshot_errors")
EVENTS = {"starting", "inventory", "ready", "stopped", "error"}
Snapshot = dict[str, Any]


class ProtocolError(RuntimeError):
    """The worker did not follow the check-mode event protocol."""


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def process_identity(pid: int) -> dict[str, int] | None:
    """Return a live process identity without treating a reused PID as ownership."""
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        return None
    fields = text.rsplit(")", 1)[1].split()
    if fields[0] in {"Z", "X", "x"}:
        return None
    return {"pid": pid, "start_ticks": int(fields[19])}


def _positive_timeout(value: float, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite positive number")
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a finite positive number")
    return float(value)


class EventReader:
    """Read bounded JSON lines with a deadline, including partial-line stalls."""

    def __init__(
        self,
        stream: IO[bytes],
        max_event_bytes: int = MAX_EVENT_BYTES,
        *,
        clock_ns: Callable[[], int | None] | None = None,
    ) -> None:
        self.stream = stream
        self.max_event_bytes = max_event_bytes
        self.buffer = bytearray()
        self.selector = selectors.DefaultSelector()
        self.selector.register(stream, selectors.EVENT_READ)
        self.eof = False
        self.clock_ns = clock_ns
        self.last_received_ns: int | None = None

    def close(self) -> None:
        self.selector.close()

    def read(self, deadline: float) -> dict[str, Any] | None:
        while True:
            end = self.buffer.find(b"\n")
            if end >= 0:
                if end > self.max_event_bytes:
                    raise ProtocolError("worker event exceeds the size limit")
                line = bytes(self.buffer[:end])
                del self.buffer[: end + 1]
                # Observe a complete line before JSON decoding and protocol checks.
                self.last_received_ns = self.clock_ns() if self.clock_ns is not None else None
                try:
                    event = json.loads(
                        line,
                        parse_constant=lambda value: _invalid_constant(value),
                    )
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                    raise ProtocolError(f"invalid worker JSON: {exc}") from exc
                if not isinstance(event, dict):
                    raise ProtocolError("worker event must be a JSON object")
                return event
            if len(self.buffer) > self.max_event_bytes:
                raise ProtocolError("worker event exceeds the size limit")
            if self.eof:
                if self.buffer:
                    raise ProtocolError("worker closed stdout with an incomplete event")
                return None
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self.selector.select(remaining):
                raise TimeoutError("worker event deadline exceeded")
            data = os.read(self.stream.fileno(), 65536)
            if data:
                self.buffer.extend(data)
            else:
                self.eof = True


def _invalid_constant(value: str) -> None:
    raise ValueError(f"nonfinite JSON value: {value}")


def validate_event(event: dict[str, Any], run_id: str) -> str:
    if event.get("schema_version") != 1 or isinstance(event.get("schema_version"), bool):
        raise ProtocolError("worker event has an unsupported schema version")
    if event.get("run_id") != run_id:
        raise ProtocolError("worker event identifies a different run")
    kind = event.get("event")
    if not isinstance(kind, str) or kind not in EVENTS:
        raise ProtocolError(f"unknown worker event: {kind!r}")
    return kind


def validate_ready(event: dict[str, Any]) -> list[dict[str, Any]]:
    checks = event.get("checks")
    if not isinstance(checks, list) or not checks:
        raise ProtocolError("ready requires nonempty connectivity checks")
    for check in checks:
        if (
            not isinstance(check, dict)
            or check.get("ok") is not True
            or not isinstance(check.get("src"), str)
            or not check["src"]
            or not isinstance(check.get("dst"), str)
            or not check["dst"]
        ):
            raise ProtocolError("ready contains an invalid or failed connectivity check")
    return checks


def validate_task_ready(event: Snapshot, manifest: Snapshot) -> list[Snapshot]:
    checks = validate_ready(event)
    hosts = manifest["host_names"]
    expected = {
        pair
        for index in range(0, len(hosts), 2)
        for pair in ((hosts[index], hosts[index + 1]), (hosts[index + 1], hosts[index]))
    }
    actual = [(check["src"], check["dst"]) for check in checks]
    if len(actual) != len(expected) or set(actual) != expected:
        raise ProtocolError("ready does not contain each required directional check exactly once")
    return checks


def snapshot_clean(snapshot: Snapshot) -> bool:
    return all(
        key in snapshot and isinstance(snapshot[key], list) and not snapshot[key]
        for key in RESOURCE_KEYS
    )


def _capture(capture: Callable[[Snapshot], Snapshot], manifest: Snapshot) -> Snapshot:
    try:
        snapshot = capture(manifest)
        if not isinstance(snapshot, dict):
            raise TypeError("audit snapshot is not an object")
        missing = [key for key in RESOURCE_KEYS if not isinstance(snapshot.get(key), list)]
        if missing:
            raise TypeError(f"audit snapshot has invalid resource lists: {missing}")
        return snapshot
    except Exception as exc:
        return {
            **{key: [] for key in RESOURCE_KEYS},
            "snapshot_errors": [{"type": type(exc).__name__, "message": str(exc)}],
        }


def _compare_final_interfaces(before: Snapshot, after: Snapshot) -> Snapshot:
    if "root_interface_inventory" not in before or "root_interface_inventory" not in after:
        return after
    try:
        from .audit import compare_root_interfaces

        return compare_root_interfaces(before, after)
    except Exception as exc:
        result = dict(after)
        result["snapshot_errors"] = [
            *after["snapshot_errors"],
            {"type": "InterfaceComparisonError", "message": str(exc)},
        ]
        return result


def _remember_snapshot(manifest: Snapshot, snapshot: Snapshot) -> None:
    known = {(item["pid"], item["start_ticks"]) for item in manifest["owned_processes"]}
    for item in snapshot.get("processes", []):
        if not isinstance(item, dict):
            continue
        identity = (item.get("pid"), item.get("start_ticks"))
        if not all(
            isinstance(part, int) and not isinstance(part, bool) and part > 0 for part in identity
        ):
            continue
        if identity not in known and _trusted_snapshot_process(manifest, item):
            manifest["owned_processes"].append({"pid": identity[0], "start_ticks": identity[1]})
            known.add(identity)
    _remember_namespaces(manifest, snapshot.get("observed_namespace_ids", []))


def _trusted_snapshot_process(manifest: Snapshot, item: Snapshot) -> bool:
    """Grant signal authority from ancestry or the controlled process group."""
    if item["pid"] == os.getpid():
        return False
    ownership = item.get("ownership", [])
    if isinstance(ownership, str):
        ownership = [ownership]
    if isinstance(ownership, list) and any(
        value in ("worker_descendant", "trusted_descendant") for value in ownership
    ):
        return True
    worker = manifest.get("worker_identity")
    if not worker:
        return False
    identity = {"pid": item["pid"], "start_ticks": item["start_ticks"]}
    if process_identity(item["pid"]) != identity:
        return False
    try:
        return bool(os.getpgid(item["pid"]) == worker["pid"])
    except ProcessLookupError:
        return False


def _remember_namespaces(manifest: Snapshot, values: Any) -> None:
    if not isinstance(values, list):
        raise ProtocolError("observed_namespace_ids must be a list")
    root_namespace = os.readlink("/proc/self/ns/net")
    namespace_ids = set(manifest.get("namespace_ids", []))
    for value in values:
        if not isinstance(value, str) or not re.fullmatch(r"net:\[[0-9]+\]", value):
            raise ProtocolError("observed namespace identity must have the form net:[number]")
        if value != root_namespace:
            namespace_ids.add(value)
    manifest["namespace_ids"] = sorted(namespace_ids)


def _remember_event(manifest: Snapshot, event: Snapshot, worker_pid: int) -> None:
    _remember_namespaces(manifest, event.get("observed_namespace_ids", []))
    owned = event.get("owned_processes", [])
    if not isinstance(owned, list):
        raise ProtocolError("owned_processes must be a list")
    for item in owned:
        if not isinstance(item, dict):
            raise ProtocolError("owned process identity must be an object")
        pid, start = item.get("pid"), item.get("start_ticks")
        if (
            not isinstance(pid, int)
            or isinstance(pid, bool)
            or pid <= 0
            or not isinstance(start, int)
            or isinstance(start, bool)
            or start <= 0
        ):
            raise ProtocolError("owned process identity must contain positive integers")
        current = process_identity(pid)
        if current is None:
            continue
        if current != {"pid": pid, "start_ticks": start}:
            raise ProtocolError("owned process PID has a different identity")
        try:
            if os.getpgid(pid) != worker_pid:
                raise ProtocolError("reported process is outside the worker process group")
        except ProcessLookupError:
            continue
        identity = {"pid": pid, "start_ticks": start}
        if identity not in manifest["owned_processes"]:
            manifest["owned_processes"].append(identity)


def _same_process(identity: Snapshot) -> bool:
    return identity.get("pid") != os.getpid() and process_identity(identity["pid"]) == identity


def _signal_identity(identity: Snapshot, sig: signal.Signals, actions: list[Snapshot]) -> None:
    try:
        if not _same_process(identity):
            return
        os.kill(identity["pid"], sig)
        actions.append({"action": "signal", "signal": sig.name, **identity})
    except ProcessLookupError:
        pass
    except OSError as exc:
        actions.append({"action": "signal_error", **identity, "error": str(exc)})


def _request_stop(proc: subprocess.Popen[bytes], actions: list[Snapshot]) -> None:
    if proc.stdin is not None and not proc.stdin.closed:
        try:
            proc.stdin.write(b'{"command":"stop"}\n')
            proc.stdin.flush()
            actions.append({"action": "request_stop"})
        except (BrokenPipeError, OSError) as exc:
            actions.append({"action": "stop_request_error", "error": str(exc)})
        finally:
            proc.stdin.close()


def _stop_worker(
    proc: subprocess.Popen[bytes], manifest: Snapshot, timeout: float, actions: list[Snapshot]
) -> bool:
    """Finish teardown, returning whether an escalation was required."""
    if proc.poll() is not None:
        return False
    _request_stop(proc, actions)
    try:
        proc.wait(timeout=timeout)
        return False
    except subprocess.TimeoutExpired:
        pass
    identity = manifest.get("worker_identity")
    if identity:
        _signal_identity(identity, signal.SIGTERM, actions)
    try:
        proc.wait(timeout=min(timeout, 5.0))
    except subprocess.TimeoutExpired:
        members = manifest["owned_processes"]
        if identity:
            members = [identity, *members]
        for member in members:
            try:
                if _same_process(member) and os.getpgid(member["pid"]) == proc.pid:
                    os.killpg(proc.pid, signal.SIGKILL)
                    actions.append({"action": "kill_worker_group", "pgid": proc.pid})
                    break
            except ProcessLookupError:
                continue
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            actions.append({"action": "worker_reap_failed", "pid": proc.pid})
    return True


def _resource_name(item: Any) -> str | None:
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        value = item.get("name", item.get("ifname"))
        if isinstance(value, str):
            return value
    return None


def _rescue(manifest: Snapshot, snapshot: Snapshot) -> list[Snapshot]:
    """Remove only identities and names attributed to the current run."""
    actions: list[Snapshot] = []
    _remember_snapshot(manifest, snapshot)
    for identity in manifest["owned_processes"]:
        _signal_identity(identity, signal.SIGTERM, actions)
    live = [item for item in manifest["owned_processes"] if _same_process(item)]
    deadline = time.monotonic() + 2.0
    while live and time.monotonic() < deadline:
        time.sleep(0.05)
        live = [item for item in live if _same_process(item)]
    for identity in live:
        _signal_identity(identity, signal.SIGKILL, actions)
    prefix = manifest["prefix"]
    for kind in ("interfaces", "namespaces"):
        for item in snapshot.get(kind, []):
            name = _resource_name(item)
            if name is None or not name.startswith(prefix):
                continue
            if kind == "namespaces":
                command = ["ip", "netns", "delete", name]
            else:
                namespace = item.get("namespace") if isinstance(item, dict) else None
                if namespace not in (None, "root"):
                    if not isinstance(namespace, str) or not namespace.startswith(prefix):
                        continue
                    command = ["ip", "-n", namespace, "link", "delete", name]
                else:
                    command = ["ip", "link", "delete", name]
            try:
                done = subprocess.run(command, capture_output=True, text=True, timeout=5)
                actions.append(
                    {
                        "action": "rescue_resource",
                        "command": command,
                        "returncode": done.returncode,
                        "stderr": done.stderr,
                    }
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                actions.append(
                    {"action": "rescue_resource_error", "command": command, "error": str(exc)}
                )
    return actions


def _load_manifest(path: Path) -> Snapshot:
    manifest = json.loads(path.read_text())
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != 1
        or isinstance(manifest.get("schema_version"), bool)
    ):
        raise ValueError("manifest schema_version must be 1")
    if not isinstance(manifest.get("run_id"), str) or not manifest["run_id"]:
        raise ValueError("manifest run_id must be a nonempty string")
    prefix = manifest.get("prefix")
    if not isinstance(prefix, str) or not re.fullmatch(r"[a-z][a-z0-9]{5,9}", prefix):
        raise ValueError("manifest prefix must contain 6 to 10 lowercase letters/digits")
    for key in ("host_names", "switch_names"):
        names = manifest.get(key)
        if not isinstance(names, list) or not names:
            raise ValueError(f"manifest {key} must be a nonempty list")
        if any(
            not isinstance(name, str)
            or not name.startswith(prefix)
            or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,11}", name)
            for name in names
        ):
            raise ValueError(f"manifest {key} must contain run-prefixed node names")
    groups = manifest.get("groups")
    if isinstance(groups, bool) or not isinstance(groups, int) or groups <= 0:
        raise ValueError("manifest groups must be a positive integer")
    if len(manifest["host_names"]) != 2 * groups or len(manifest["switch_names"]) != groups:
        raise ValueError("manifest must have two hosts and one switch per group")
    all_names = manifest["host_names"] + manifest["switch_names"]
    if len(set(all_names)) != len(all_names):
        raise ValueError("manifest node names must be unique")
    out = Path(manifest["output_dir"]).resolve()
    if path.resolve().parent != out:
        raise ValueError("manifest must be stored directly in output_dir")
    if any(item.name != path.name for item in out.iterdir()):
        raise FileExistsError("output_dir already contains run records")
    manifest["output_dir"] = str(out)
    manifest["owned_processes"] = []
    manifest["namespace_ids"] = []
    manifest.pop("worker_identity", None)
    return manifest


def run(
    manifest_path: Path,
    worker_module: str = "harness.worker",
    ready_timeout: float = 120,
    stop_timeout: float = 30,
    *,
    worker_command: Sequence[str] | None = None,
    audit_fn: Callable[[Snapshot], Snapshot] | None = None,
    observation: Observation | None = None,
) -> Snapshot:
    ready_timeout = _positive_timeout(ready_timeout, "ready_timeout")
    stop_timeout = _positive_timeout(stop_timeout, "stop_timeout")
    manifest = _load_manifest(Path(manifest_path))
    if observation is not None:
        observation.bind(manifest)
    directory = Path(manifest["output_dir"])
    if audit_fn is None:
        from .audit import capture

        audit_fn = capture
    result: Snapshot = {
        "schema_version": 1,
        "run_id": manifest["run_id"],
        "mode": "correctness-check",
        "performance_samples": False,
        "ok": False,
        "status": "failed",
        "ready": False,
        "checks": [],
        "worker_returncode": None,
        "error": None,
        "cleanup": {"after_clean": False, "rescue_attempted": False},
    }
    actions: list[Snapshot] = []
    proc: subprocess.Popen[bytes] | None = None
    reader: EventReader | None = None
    stop_requested = False
    stopped = False
    ordinary_deadline: float | None = None

    def request_stop(worker: subprocess.Popen[bytes]) -> None:
        nonlocal stop_requested, ordinary_deadline
        if stop_requested:
            return
        if worker.poll() is not None:
            if observation is not None:
                observation.mark("worker_exit")
            return
        stop_requested = True
        if observation is not None:
            observation.mark("stop_request")
        ordinary_deadline = time.monotonic() + stop_timeout
        old_actions = len(actions)
        _request_stop(worker, actions)
        if observation is not None:
            sent = any(item["action"] == "request_stop" for item in actions[old_actions:])
            observation.mark("stop_sent" if sent else "stop_failed")

    if observation is not None and observation.recorder is not None:
        result["mode"] = observation.recorder.mode
        result["performance_samples"] = observation.performance_samples

    with (directory / "events.jsonl").open("w", encoding="utf-8") as events:

        def record(origin: str, payload: Snapshot) -> None:
            events.write(
                json.dumps(
                    {
                        "recorded_at": datetime.now().astimezone().isoformat(),
                        "origin": origin,
                        "payload": payload,
                    },
                    allow_nan=False,
                )
                + "\n"
            )
            events.flush()

        before = _capture(audit_fn, manifest)
        write_json(directory / "inventory-before.json", before)
        if not snapshot_clean(before):
            result["error"] = {
                "type": "PreexistingResources",
                "message": "initial audit is not clean",
            }
            result["cleanup"]["not_started"] = True
            if observation is not None:
                result["observation"] = observation.finish(result)
            write_json(directory / "result.json", result)
            return result
        with (directory / "worker.log").open("wb") as log:
            try:
                command = (
                    list(worker_command)
                    if worker_command is not None
                    else [
                        sys.executable,
                        "-m",
                        worker_module,
                        "--manifest",
                        str(Path(manifest_path).resolve()),
                    ]
                )
                if observation is not None:
                    observation.mark("worker_launch")
                proc = subprocess.Popen(
                    command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=log,
                    start_new_session=True,
                    bufsize=0,
                    cwd=Path(__file__).resolve().parents[1],
                )
                identity = process_identity(proc.pid)
                if identity is not None:
                    manifest["worker_identity"] = identity
                record("supervisor", {"event": "launched", "pid": proc.pid, "command": command})
                assert proc.stdout is not None
                reader = EventReader(
                    proc.stdout, clock_ns=observation.clock_ns if observation is not None else None
                )
                deadline = time.monotonic() + ready_timeout
                starting = False
                while True:
                    event = reader.read(deadline)
                    if event is None:
                        break
                    if observation is not None:
                        observation.received(event, observed_ns=reader.last_received_ns)
                    record("worker", event)
                    kind = validate_event(event, manifest["run_id"])
                    if stopped:
                        raise ProtocolError("worker emitted an event after stopped")
                    _remember_event(manifest, event, proc.pid)
                    if kind == "starting":
                        if starting or result["ready"]:
                            raise ProtocolError("starting event is duplicated or out of order")
                        starting = True
                    elif kind == "inventory":
                        if not starting:
                            raise ProtocolError("inventory precedes starting")
                    elif kind == "error":
                        raise ProtocolError(
                            f"worker reported an error: {event.get('message', event)}"
                        )
                    elif kind == "ready":
                        if not starting or result["ready"]:
                            raise ProtocolError("ready event is duplicated or precedes starting")
                        result["checks"] = validate_task_ready(event, manifest)
                        result["ready"] = True
                        if observation is not None:
                            observation.ready(manifest, manifest.get("worker_identity", {}), event)
                        ready = _capture(audit_fn, manifest)
                        _remember_snapshot(manifest, ready)
                        write_json(directory / "inventory-ready.json", ready)
                        if ready["snapshot_errors"]:
                            raise RuntimeError("ready resource audit is incomplete")
                        request_stop(proc)
                        deadline = ordinary_deadline or time.monotonic() + stop_timeout
                    elif kind == "stopped":
                        if not result["ready"]:
                            raise ProtocolError("worker stopped before readiness")
                        stopped = True
                proc.wait(timeout=stop_timeout)
                if observation is not None:
                    observation.mark("worker_exit")
                result["worker_returncode"] = proc.returncode
                if not result["ready"] or not stopped or proc.returncode != 0:
                    raise ProtocolError("worker exited without successful ready/stopped completion")
            except BaseException as exc:
                result["error"] = {"type": type(exc).__name__, "message": str(exc)}
                record("supervisor", {"event": "failed", **result["error"]})
            finally:
                safety_started = False
                if observation is not None and proc is not None:
                    if proc.poll() is None:
                        request_stop(proc)
                        try:
                            proc.wait(timeout=max(0, (ordinary_deadline or 0) - time.monotonic()))
                        except subprocess.TimeoutExpired:
                            result["ordinary_stop_timeout"] = True
                    if proc.poll() is not None:
                        observation.mark("worker_exit")
                    observation.mark("ordinary_audit_start")
                    ordinary = _compare_final_interfaces(before, _capture(audit_fn, manifest))
                    observation.mark("ordinary_audit_end")
                    try:
                        _remember_snapshot(manifest, ordinary)
                        write_json(directory / "inventory-ordinary-after.json", ordinary)
                    except Exception as exc:
                        observation.issue("save ordinary inventory", exc)
                    result["cleanup"]["ordinary_after_clean"] = snapshot_clean(ordinary)
                    observation.checkpoint(
                        directory / "measurement-primary.json",
                        {
                            **result,
                            "ok": result["error"] is None
                            and result["ready"]
                            and stopped
                            and proc.returncode == 0
                            and snapshot_clean(ordinary),
                        },
                    )
                    if proc.poll() is None:
                        observation.mark("safety_start")
                        safety_started = True
                if proc is not None:
                    escalated = _stop_worker(proc, manifest, stop_timeout, actions)
                    result["worker_returncode"] = proc.poll()
                    if escalated and result["error"] is None:
                        result["error"] = {
                            "type": "ShutdownEscalation",
                            "message": "worker required escalation",
                        }
                    if proc.stdout is not None:
                        proc.stdout.close()
                    if proc.stdin is not None and not proc.stdin.closed:
                        proc.stdin.close()
                if reader is not None:
                    reader.close()
                after = _compare_final_interfaces(before, _capture(audit_fn, manifest))
                write_json(directory / "inventory-after.json", after)
                result["cleanup"]["after_clean"] = snapshot_clean(after)
                if not snapshot_clean(after):
                    if result["error"] is None:
                        result["error"] = {
                            "type": "ResidualResources",
                            "message": "resources remain or the final audit is incomplete",
                        }
                    result["cleanup"]["rescue_attempted"] = True
                    if observation is not None and not safety_started:
                        observation.mark("safety_start")
                        safety_started = True
                    actions.extend(_rescue(manifest, after))
                    after_rescue = _compare_final_interfaces(before, _capture(audit_fn, manifest))
                    write_json(directory / "inventory-after-rescue.json", after_rescue)
                    result["cleanup"]["after_rescue_clean"] = snapshot_clean(after_rescue)
                result["cleanup"]["actions"] = actions
                result["ok"] = result["error"] is None and snapshot_clean(after)
                result["status"] = "passed" if result["ok"] else "failed"
                if observation is not None:
                    if safety_started:
                        observation.mark("safety_end")
                    result["observation"] = observation.finish(result)
                write_json(directory / "result.json", result)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--worker-module", default="harness.worker")
    parser.add_argument("--ready-timeout", default=120.0, type=float)
    parser.add_argument("--stop-timeout", default=30.0, type=float)
    args = parser.parse_args(argv)
    try:
        result = run(args.manifest, args.worker_module, args.ready_timeout, args.stop_timeout)
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f"{type(exc).__name__}: {exc}\n")
    print(json.dumps(result, allow_nan=False))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
