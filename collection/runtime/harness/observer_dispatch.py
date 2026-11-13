"""Dispatch a calibrated observer through one bounded namespace reference socket."""

from __future__ import annotations

import fcntl
import hashlib
import math
import os
import signal
import socket
import subprocess
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from pathlib import Path
from typing import Any

from harness import isolation, observer_runtime
from harness.campaign_executor import _json
from harness.observer_reference import (
    BOUNDARIES,
    MAX_FRAME_BYTES,
    ParentReference,
    _binding,
    _check_message,
    _namespaces,
    decode_message,
    discover_observer,
    encode_message,
    read_observer_cpu,
    read_observer_memory,
)
from harness.resources import parse_stat
from harness.spec import load


class SocketChannel:
    """Bound every frame read and write by the same absolute monotonic deadline."""

    def __init__(
        self,
        sock: socket.socket,
        *,
        deadline: float,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if isinstance(deadline, bool) or not isinstance(deadline, (int, float)):
            raise ValueError("reference deadline must be a finite monotonic time")
        if not math.isfinite(deadline):
            raise ValueError("reference deadline must be a finite monotonic time")
        if clock is not None and not callable(clock):
            raise ValueError("reference clock must be callable")
        self.sock, self.deadline = sock, float(deadline)
        self.clock = time.monotonic if clock is None else clock
        self.buffer = bytearray()

    def remaining(self) -> float:
        current = self.clock()
        if isinstance(current, bool) or not isinstance(current, (int, float)):
            raise ValueError("reference clock must return a finite monotonic time")
        remaining = self.deadline - current
        if not math.isfinite(remaining):
            raise ValueError("reference clock must return a finite monotonic time")
        if remaining <= 0:
            raise TimeoutError("observer reference deadline expired")
        return remaining

    def send(self, value: Mapping[str, Any]) -> None:
        frame = encode_message(value)
        self.sock.settimeout(self.remaining())
        self.sock.sendall(frame)

    def receive(self) -> dict[str, Any]:
        while True:
            self.remaining()
            newline = self.buffer.find(b"\n")
            if newline >= 0:
                frame = bytes(self.buffer[: newline + 1])
                del self.buffer[: newline + 1]
                return decode_message(frame)
            if len(self.buffer) >= MAX_FRAME_BYTES:
                raise ValueError("reference frame exceeds the bounded newline limit")
            self.sock.settimeout(self.remaining())
            chunk = self.sock.recv(MAX_FRAME_BYTES + 1 - len(self.buffer))
            if not chunk:
                raise EOFError("observer reference channel closed before the next checkpoint")
            self.buffer.extend(chunk)


def _outer_start_ticks(pid: int) -> int:
    if type(pid) is not int or pid < 2:
        raise ValueError("the owned outer process requires a host PID")
    value = parse_stat((Path("/proc") / str(pid) / "stat").read_text())
    if value["pid"] != pid or value["state"] in {"Z", "X", "x"}:
        raise ProcessLookupError("outer process exited before reference discovery")
    return int(value["start_ticks"])


def _stop_owned(proc: subprocess.Popen[Any]) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    if proc.poll() is not None:
        proc.wait()
        return issues
    with suppress(ProcessLookupError):
        proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        with suppress(ProcessLookupError):
            proc.kill()
        try:
            proc.wait(timeout=10)
        except Exception as exc:
            issues.append({"type": type(exc).__name__, "message": str(exc)})
    return issues


def _pointer(path: Path) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("a published regular calibration artifact is required")
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def _child(path: Path, binding: Mapping[str, str]) -> dict[str, Any]:
    _pointer(path)
    value = _json(path)
    if (
        not isinstance(value, dict)
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("record_type") != "observer-calibration-child-result"
        or value.get("mode") != "pilot"
        or value.get("performance_samples") is not True
        or any(value.get(key) != expected for key, expected in binding.items())
        or not isinstance(value.get("native_result"), dict)
        or type(value["native_result"].get("ok")) is not bool
    ):
        raise ValueError("published child result differs from the calibrated attempt")
    return value


def _ordinary_result(path: Path, run_id: str) -> dict[str, Any]:
    _pointer(path)
    value = _json(path)
    if (
        not isinstance(value, dict)
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("run_id") != run_id
        or type(value.get("ok")) is not bool
    ):
        raise ValueError("ordinary result does not identify this native task")
    return value


def control_paths(path: Path) -> tuple[Path, Path]:
    """Keep parent control files beside the canonical native output directory."""
    directory = path.resolve().parent
    return (
        directory.parent / f".{directory.name}-observer-dispatch.lock",
        directory.parent / f"{directory.name}-observer-isolation.log",
    )


def run_calibrated(
    path: Path,
    python: Path,
    worker: str,
    *,
    calibration: Mapping[str, Any],
    timeout: float | None = None,
    collection_authorized: bool = False,
) -> dict[str, Any]:
    """Run one explicitly authorized attempt and retain transport failures separately."""
    if collection_authorized is not True:
        raise PermissionError("observer calibration collection has not been authorized")
    from harness.observer_config import validate_calibration
    from harness.supervisor import _positive_timeout

    path = path.resolve()
    manifest = load(path)
    configuration = validate_calibration(calibration, manifest)
    timeout = _positive_timeout(
        (360 if "episode_fault" in manifest else 210) if timeout is None else timeout,
        "observer outer watchdog",
    )
    lock_path, _ = control_paths(path)
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("another dispatcher owns this calibration attempt") from None
        return _run_locked(path, python, worker, configuration, manifest, timeout)


def _run_locked(
    path: Path,
    python: Path,
    worker: str,
    configuration: Mapping[str, Any],
    manifest: Mapping[str, Any],
    timeout: float,
) -> dict[str, Any]:
    binding = _binding(
        manifest["run_id"], configuration["attempt_id"], configuration["observer_profile"]
    )
    directory = path.parent
    child_path = directory / "observer-child-result.json"
    sidecar_path = directory / "observer-reference.json"
    terminal_path = directory / "observer-calibration-result.json"
    dispatch_path = directory / "observer-dispatch.json"
    _, log_path = control_paths(path)
    for artifact in (
        child_path,
        sidecar_path,
        terminal_path,
        dispatch_path,
        log_path,
        directory / "result.json",
        directory / "measurement-primary.json",
        directory / "primary-outcome.json",
        directory.parent / f"{directory.name}-isolation.json",
    ):
        if os.path.lexists(artifact):
            raise FileExistsError(f"calibration attempt already has an artifact: {artifact}")
    if any(item.name != path.name for item in directory.iterdir()):
        raise FileExistsError("calibration output directory already contains run records")
    launched_ns: int | None = None
    exited_ns: int | None = None
    proc: subprocess.Popen[Any] | None = None
    reference: ParentReference | None = None
    error: BaseException | None = None
    cleanup_issues: list[dict[str, str]] = []
    terminal: dict[str, Any] | None = None
    parent_socket: socket.socket | None = None
    child_socket: socket.socket | None = None
    try:
        environment = isolation.environment_for(manifest)
        deadline = time.monotonic() + timeout
        parent_socket, child_socket = socket.socketpair()
        with log_path.open("x") as log:
            try:
                command = isolation.isolated_command(
                    path,
                    python.absolute(),
                    worker,
                    observer_calibration=configuration,
                    reference_fd=child_socket.fileno(),
                    reference_deadline=deadline,
                )
                launched_ns = time.monotonic_ns()
                proc = subprocess.Popen(
                    command,
                    cwd=isolation.PAPER,
                    env=environment,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                    pass_fds=(child_socket.fileno(),),
                )
            finally:
                child_socket.close()
            outer_ticks = _outer_start_ticks(proc.pid)
            channel = SocketChannel(parent_socket, deadline=deadline)
            first = channel.receive()
            namespaces = _namespaces(first.get("namespaces"))
            _check_message(first, binding, namespaces, BOUNDARIES[0], 0)
            identity = discover_observer(proc.pid, namespaces, outer_start_ticks=outer_ticks)
            reference = ParentReference(
                identity,
                run_id=binding["run_id"],
                attempt_id=binding["attempt_id"],
                profile=binding["observer_profile"],
                mode="pilot",
                clock_ns=time.monotonic_ns,
                monitor_cpu_ns=time.process_time_ns,
                clock_ticks=os.sysconf("SC_CLK_TCK"),
                read_cpu=read_observer_cpu,
                read_memory=read_observer_memory,
                send_ack=channel.send,
            )
            reference.handle(first)
            while reference.index < len(BOUNDARIES):
                reference.handle(channel.receive())
            code = proc.wait(timeout=channel.remaining())
            exited_ns = time.monotonic_ns()
            child = _child(child_path, binding)
            expected_code = 0 if child["native_result"]["ok"] else 1
            if code != expected_code:
                raise RuntimeError("outer exit status disagrees with the native child result")
    except BaseException as exc:
        error = exc
        if reference is not None and reference.index < len(BOUNDARIES):
            reference.failed = True
    finally:
        if parent_socket is not None:
            parent_socket.close()
        if child_socket is not None:
            child_socket.close()
        if proc is not None:
            try:
                cleanup_issues = _stop_owned(proc)
            except BaseException as exc:
                cleanup_issues.append({"type": type(exc).__name__, "message": str(exc)})
                if error is None:
                    error = exc
            if exited_ns is None and proc.returncode is not None:
                exited_ns = time.monotonic_ns()
    child_result = None
    child_pointer = None
    publication_error = None
    native_ok = None
    native_source = None
    native_result_error = None
    if child_path.is_file() and not child_path.is_symlink():
        try:
            child_result = _child(child_path, binding)
            child_pointer = _pointer(child_path)
            native_ok = child_result["native_result"]["ok"]
            native_source = {"kind": "child-envelope", **child_pointer}
            if reference is not None:
                terminal = observer_runtime.publish_terminal(
                    terminal_path, child_path, sidecar_path, reference
                )
        except Exception as exc:
            publication_error = {"type": type(exc).__name__, "message": str(exc)}
            if error is None:
                error = exc
    ordinary_path = directory / "result.json"
    if native_source is None and os.path.lexists(ordinary_path):
        try:
            ordinary = _ordinary_result(ordinary_path, binding["run_id"])
            native_ok = ordinary["ok"]
            native_source = {"kind": "ordinary-result", **_pointer(ordinary_path)}
        except Exception as exc:
            native_result_error = {"type": type(exc).__name__, "message": str(exc)}
    if error is None and (terminal is None or cleanup_issues):
        error = RuntimeError(
            "calibration dispatch lacks a terminal record or a reaped outer process"
        )
    status = (
        "interrupted"
        if isinstance(error, (KeyboardInterrupt, SystemExit))
        else "timeout"
        if isinstance(error, (TimeoutError, subprocess.TimeoutExpired))
        else "failed"
        if error is not None
        else "completed"
    )
    result = {
        "schema_version": 1,
        "record_type": "observer-calibration-dispatch-record",
        **binding,
        "mode": "pilot",
        "performance_samples": True,
        "dispatch_status": status,
        "native_outcome_available": native_source is not None,
        "native_ok": native_ok,
        "native_result_source": native_source,
        "native_result_error": native_result_error,
        "child_result": child_pointer,
        "calibration_terminal": _pointer(terminal_path) if terminal is not None else None,
        "outer_pid": proc.pid if proc is not None else None,
        "outer_returncode": proc.returncode if proc is not None else None,
        "outer_launch_ns": launched_ns,
        "outer_exit_ns": exited_ns,
        "outer_lifetime_ns": (
            exited_ns - launched_ns if launched_ns is not None and exited_ns is not None else None
        ),
        "cleanup_issues": cleanup_issues,
        "publication_error": publication_error,
        "error": {"type": type(error).__name__, "message": str(error)}
        if error is not None
        else None,
        "inner_pid_numbers_consumed": False,
        "log": str(log_path),
    }
    observer_runtime._publish(dispatch_path, result)
    if isinstance(error, (KeyboardInterrupt, SystemExit)):
        raise error
    return result
