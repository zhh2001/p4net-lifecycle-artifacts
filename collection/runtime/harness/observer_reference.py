"""Exchange bounded observer checkpoints and collect identity-checked reference endpoints."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, BinaryIO

from harness.resources import parse_smaps_rollup, parse_stat

NAMESPACE_KINDS = ("pid", "net", "mnt")
BOUNDARIES = ("ref_begin", "ref_primary_published", "ref_complete")
MAX_FRAME_BYTES = 4096
IDENTITY_KEYS = ("run_id", "attempt_id", "observer_profile")
MESSAGE_KEYS = {
    "schema_version",
    "record_type",
    "boundary",
    "sequence",
    "namespaces",
    *IDENTITY_KEYS,
}


def _integer(value: Any, name: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name} must be an integer of at least {minimum}")
    return value


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ValueError(f"{name} must be a nonempty string of at most 256 characters")
    if any(ord(character) < 32 for character in value):
        raise ValueError(f"{name} cannot contain control characters")
    return value


def _namespaces(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != set(NAMESPACE_KINDS):
        raise ValueError("exactly PID, network, and mount namespace identities are required")
    result = {}
    for kind in NAMESPACE_KINDS:
        item = value[kind]
        if not isinstance(item, str) or not re.fullmatch(rf"{kind}:\[[0-9]+\]", item):
            raise ValueError("invalid namespace identity")
        result[kind] = item
    return result


def _binding(run_id: Any, attempt_id: Any, profile: Any) -> dict[str, str]:
    if profile not in ("B", "T", "S"):
        raise ValueError("observer profile must be B, T, or S")
    return {
        "run_id": _text(run_id, "run_id"),
        "attempt_id": _text(attempt_id, "attempt_id"),
        "observer_profile": profile,
    }


@dataclass(frozen=True)
class ObserverIdentity:
    host_pid: int
    start_ticks: int
    namespaces: Mapping[str, str]

    def __post_init__(self) -> None:
        _integer(self.host_pid, "observer host PID", minimum=2)
        _integer(self.start_ticks, "observer start ticks")
        object.__setattr__(self, "namespaces", MappingProxyType(_namespaces(self.namespaces)))

    def as_dict(self) -> dict[str, Any]:
        return {
            "host_pid": self.host_pid,
            "start_ticks": self.start_ticks,
            "namespaces": dict(self.namespaces),
        }


def _stat_view(pid: int, proc_root: Path) -> dict[str, Any]:
    raw = (proc_root / str(pid) / "stat").read_text()
    value = parse_stat(raw)
    if value["pid"] != pid or value["state"] in {"Z", "X", "x"}:
        raise ProcessLookupError("observer process has exited or changed")
    value["ppid"] = _integer(int(raw.rsplit(")", 1)[1].split()[1]), "parent PID")
    return value


def _view(pid: int, proc_root: Path) -> dict[str, Any]:
    value = _stat_view(pid, proc_root)
    value["namespaces"] = {
        kind: os.readlink(proc_root / str(pid) / "ns" / kind) for kind in NAMESPACE_KINDS
    }
    return value


def _verify(identity: ObserverIdentity, proc_root: Path) -> dict[str, Any]:
    value = _view(identity.host_pid, proc_root)
    if value["start_ticks"] != identity.start_ticks or value["namespaces"] != dict(
        identity.namespaces
    ):
        raise ProcessLookupError("observer PID identity or namespace membership changed")
    return value


def discover_observer(
    outer_pid: int,
    expected_namespaces: Mapping[str, str],
    *,
    proc_root: Path = Path("/proc"),
    outer_start_ticks: int | None = None,
) -> ObserverIdentity:
    """Find a unique descendant namespace init and lock its host identity."""
    _integer(outer_pid, "outer PID", minimum=2)
    expected = _namespaces(expected_namespaces)
    outer = _view(outer_pid, proc_root)
    if outer_start_ticks is not None:
        _integer(outer_start_ticks, "outer start ticks")
        if outer["start_ticks"] != outer_start_ticks:
            raise ProcessLookupError("outer process identity changed")
    views = {outer_pid: outer}
    for path in proc_root.iterdir():
        if not path.name.isdecimal() or int(path.name) == outer_pid:
            continue
        try:
            views[int(path.name)] = _stat_view(int(path.name), proc_root)
        except (OSError, ValueError):
            continue
    candidates = []
    for pid, initial in views.items():
        if pid == outer_pid:
            continue
        view = initial
        parent, visited = view["ppid"], {pid}
        while parent != outer_pid and parent in views and parent not in visited:
            visited.add(parent)
            parent = views[parent]["ppid"]
        if parent != outer_pid:
            continue
        try:
            view = _view(pid, proc_root)
        except (FileNotFoundError, ProcessLookupError):
            continue
        if view["start_ticks"] != initial["start_ticks"] or view["ppid"] != initial["ppid"]:
            raise ProcessLookupError("descendant process changed during discovery")
        if view["namespaces"] != expected:
            continue
        status = (proc_root / str(pid) / "status").read_text().splitlines()
        namespace_pids = [row.split()[1:] for row in status if row.startswith("NSpid:")]
        if len(namespace_pids) != 1 or len(namespace_pids[0]) < 2:
            continue
        values = namespace_pids[0]
        if (
            all(item.isdecimal() and int(item) > 0 for item in values)
            and int(values[0]) == pid
            and int(values[-1]) == 1
        ):
            candidates.append(ObserverIdentity(pid, view["start_ticks"], expected))
    after = _view(outer_pid, proc_root)
    if after["start_ticks"] != outer["start_ticks"] or after["namespaces"] != outer["namespaces"]:
        raise ProcessLookupError("outer process identity changed during discovery")
    if len(candidates) != 1:
        raise ValueError("a unique observer namespace init was not found in the outer process tree")
    _verify(candidates[0], proc_root)
    return candidates[0]


def read_observer_cpu(
    identity: ObserverIdentity, *, proc_root: Path = Path("/proc")
) -> dict[str, Any]:
    """Read only the observer's own counters between two identity checks."""
    before = _verify(identity, proc_root)
    after = _verify(identity, proc_root)
    if any(after[key] < before[key] for key in ("user_ticks", "system_ticks")):
        raise ValueError("observer CPU counters decreased during the read")
    return {
        "observer": identity.as_dict(),
        **{key: before[key] for key in ("user_ticks", "system_ticks", "cpu_ticks")},
    }


def read_observer_memory(
    identity: ObserverIdentity, *, proc_root: Path = Path("/proc")
) -> dict[str, Any]:
    """Read one endpoint RSS/PSS observation with no timing or CPU summary."""
    _verify(identity, proc_root)
    values = parse_smaps_rollup((proc_root / str(identity.host_pid) / "smaps_rollup").read_text())
    _verify(identity, proc_root)
    return {
        "observer": identity.as_dict(),
        **values,
        "scope": "post-final-publication endpoint; not peak or time average",
    }


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for name, value in items:
        if name in result:
            raise ValueError("duplicate reference message field")
        result[name] = value
    return result


def encode_message(value: Mapping[str, Any]) -> bytes:
    result = (
        json.dumps(dict(value), sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        + b"\n"
    )
    if len(result) > MAX_FRAME_BYTES:
        raise ValueError("reference message is too long")
    return result


def decode_message(value: bytes) -> dict[str, Any]:
    if not isinstance(value, bytes) or not value.endswith(b"\n") or value.count(b"\n") != 1:
        raise ValueError("reference message requires exactly one newline-terminated frame")
    if len(value) > MAX_FRAME_BYTES:
        raise ValueError("reference message is too long")
    try:
        result = json.loads(
            value.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid UTF-8 reference JSON") from exc
    if not isinstance(result, dict):
        raise ValueError("reference message must be an object")
    return result


class LineChannel:
    """Use bounded binary file streams; the transport owner supplies timeout policy."""

    def __init__(self, reader: BinaryIO, writer: BinaryIO) -> None:
        self.reader, self.writer = reader, writer

    def send(self, value: Mapping[str, Any]) -> None:
        frame = encode_message(value)
        written = self.writer.write(frame)
        if written != len(frame):
            raise OSError("short reference message write")
        self.writer.flush()

    def receive(self) -> dict[str, Any]:
        frame = self.reader.readline(MAX_FRAME_BYTES + 1)
        if not frame:
            raise EOFError("reference channel closed before acknowledgment")
        return decode_message(frame)


def _message(
    binding: Mapping[str, str],
    namespaces: Mapping[str, str],
    boundary: str,
    sequence: int,
    *,
    ack: bool = False,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "record_type": "observer-reference-ack" if ack else "observer-reference-checkpoint",
        **binding,
        "boundary": boundary,
        "sequence": sequence,
        "namespaces": dict(namespaces),
    }


def _check_message(
    value: Mapping[str, Any],
    binding: Mapping[str, str],
    namespaces: Mapping[str, str],
    boundary: str,
    sequence: int,
    *,
    ack: bool = False,
) -> None:
    expected = _message(binding, namespaces, boundary, sequence, ack=ack)
    if set(value) != MESSAGE_KEYS or json.dumps(dict(value), sort_keys=True) != json.dumps(
        expected, sort_keys=True
    ):
        raise ValueError("reference message order, identity, or schema differs")


class ChildReference:
    """Pause the observer at the three acknowledged publication boundaries."""

    def __init__(
        self,
        *,
        run_id: str,
        attempt_id: str,
        profile: str,
        namespaces: Mapping[str, str],
        send: Callable[[Mapping[str, Any]], None],
        receive: Callable[[], Mapping[str, Any]],
    ) -> None:
        self.binding = _binding(run_id, attempt_id, profile)
        self.namespaces = _namespaces(namespaces)
        if not callable(send) or not callable(receive):
            raise ValueError("explicit reference send and receive functions are required")
        self.send, self.receive = send, receive
        self.index = 0
        self.failed = False

    def checkpoint(self, boundary: str) -> None:
        if self.failed:
            raise ValueError("reference child checkpoint is already failed")
        try:
            if self.index >= len(BOUNDARIES) or boundary != BOUNDARIES[self.index]:
                raise ValueError("reference child checkpoint is out of order or complete")
            self.send(_message(self.binding, self.namespaces, boundary, self.index))
            response = self.receive()
            _check_message(response, self.binding, self.namespaces, boundary, self.index, ack=True)
        except BaseException:
            self.failed = True
            raise
        self.index += 1


class ParentReference:
    """Collect independent endpoint records; all clocks and readers are explicit."""

    def __init__(
        self,
        identity: ObserverIdentity,
        *,
        run_id: str,
        attempt_id: str,
        profile: str,
        clock_ns: Callable[[], int],
        monitor_cpu_ns: Callable[[], int],
        clock_ticks: int,
        read_cpu: Callable[[ObserverIdentity], Mapping[str, Any]],
        read_memory: Callable[[ObserverIdentity], Mapping[str, Any]],
        send_ack: Callable[[Mapping[str, Any]], None],
        mode: str = "synthetic-validation",
    ) -> None:
        if mode not in ("synthetic-validation", "pilot"):
            raise ValueError("reference mode must be synthetic-validation or pilot")
        if not isinstance(identity, ObserverIdentity):
            raise ValueError("a validated observer identity is required")
        if not all(
            callable(item) for item in (clock_ns, monitor_cpu_ns, read_cpu, read_memory, send_ack)
        ):
            raise ValueError(
                "explicit reference clocks, readers, and acknowledgment sender are required"
            )
        self.identity, self.binding = identity, _binding(run_id, attempt_id, profile)
        self.clock, self.monitor_cpu = clock_ns, monitor_cpu_ns
        self.clock_ticks = _integer(clock_ticks, "clock ticks", minimum=1)
        self.read_cpu, self.read_memory, self.send_ack = read_cpu, read_memory, send_ack
        self.mode, self.index, self.failed = mode, 0, False
        self.previous_clock = self.previous_monitor = -1
        self.events: list[dict[str, Any]] = []
        self.cpu_start: dict[str, Any] | None = None
        self.cpu_end: dict[str, Any] | None = None
        self.memory: dict[str, Any] | None = None
        self.wall_start: int | None = None
        self.wall_end: int | None = None
        self.monitor_start: int | None = None
        self.monitor_end: int | None = None

    def _now(self) -> int:
        value = _integer(self.clock(), "reference clock")
        if value < self.previous_clock:
            raise ValueError("reference clock moved backward")
        self.previous_clock = value
        return value

    def _monitor(self) -> int:
        value = _integer(self.monitor_cpu(), "reference process CPU")
        if value < self.previous_monitor:
            raise ValueError("reference process CPU moved backward")
        self.previous_monitor = value
        return value

    def _cpu(self) -> dict[str, Any]:
        value = copy.deepcopy(dict(self.read_cpu(self.identity)))
        if value.get("observer") != self.identity.as_dict():
            raise ValueError("CPU endpoint identifies another observer")
        for name in ("user_ticks", "system_ticks", "cpu_ticks"):
            _integer(value.get(name), name)
        if value["cpu_ticks"] != value["user_ticks"] + value["system_ticks"]:
            raise ValueError("observer CPU total differs from its own counters")
        return value

    def handle(self, value: Mapping[str, Any]) -> None:
        if self.failed:
            raise ValueError("reference parent is failed")
        try:
            if self.index >= len(BOUNDARIES):
                raise ValueError("reference parent is complete")
            boundary = BOUNDARIES[self.index]
            _check_message(value, self.binding, self.identity.namespaces, boundary, self.index)
            ack = _message(self.binding, self.identity.namespaces, boundary, self.index, ack=True)
            received = self._now()
            event: dict[str, Any] = {"boundary": boundary, "received_ns": received}
            if boundary == "ref_begin":
                self.monitor_start = self._monitor()
                self.cpu_start = self._cpu()
                event["cpu_probe_end_ns"] = self._now()
                self.wall_start = self._now()
                event["start_ack_ns"] = self.wall_start
            elif boundary == "ref_complete":
                self.wall_end = received
                self.cpu_end = self._cpu()
                assert self.cpu_start is not None
                if any(
                    self.cpu_end[name] < self.cpu_start[name]
                    for name in ("user_ticks", "system_ticks")
                ):
                    raise ValueError("observer CPU counters decreased across endpoints")
                event["cpu_probe_end_ns"] = self._now()
                event["memory_probe_start_ns"] = self._now()
                memory = copy.deepcopy(dict(self.read_memory(self.identity)))
                if memory.get("observer") != self.identity.as_dict():
                    raise ValueError("memory endpoint identifies another observer")
                _integer(memory.get("rss_bytes"), "observer RSS")
                _integer(memory.get("pss_bytes"), "observer PSS")
                self.memory = memory
                event["memory_probe_end_ns"] = self._now()
            self.send_ack(ack)
            event["ack_sent_ns"] = self._now()
            if boundary == "ref_complete":
                self.monitor_end = self._monitor()
            self.events.append(event)
            self.index += 1
        except BaseException:
            self.failed = True
            raise

    def record(self) -> dict[str, Any]:
        if self.failed or self.index != len(BOUNDARIES):
            raise ValueError("reference endpoints are incomplete")
        assert self.cpu_start is not None and self.cpu_end is not None
        assert self.wall_start is not None and self.wall_end is not None
        assert self.monitor_start is not None and self.monitor_end is not None
        delta = self.cpu_end["cpu_ticks"] - self.cpu_start["cpu_ticks"]
        return {
            "schema_version": 1,
            "record_type": "observer-reference-record",
            **self.binding,
            "mode": self.mode,
            "performance_samples": self.mode == "pilot",
            "observer": self.identity.as_dict(),
            "clock_ticks": self.clock_ticks,
            "observer_cpu_resolution_seconds": 1 / self.clock_ticks,
            "wall_start_ns": self.wall_start,
            "wall_end_ns": self.wall_end,
            "observer_body_wall_ns": self.wall_end - self.wall_start,
            "observer_cpu_delta_ticks": delta,
            "observer_cpu_seconds": delta / self.clock_ticks,
            "observer_cpu_start": copy.deepcopy(self.cpu_start),
            "observer_cpu_end": copy.deepcopy(self.cpu_end),
            "observer_memory_endpoint": copy.deepcopy(self.memory),
            "reference_process_cpu_ns": self.monitor_end - self.monitor_start,
            "reference_events": copy.deepcopy(self.events),
            "reference_cost_subtracted": False,
            "memory_scope": "post-final-publication endpoint; not peak or time average",
        }

    def publish_sidecar(self, path: Path, child_result: Path) -> dict[str, Any]:
        record = self.record()
        if child_result.is_symlink() or not child_result.is_file():
            raise ValueError("an already-published regular child result is required")
        content = child_result.read_bytes()
        child = json.loads(content, object_pairs_hook=_pairs)
        if (
            not isinstance(child, dict)
            or type(child.get("schema_version")) is not int
            or child.get("schema_version") != 1
            or child.get("record_type") != "observer-calibration-child-result"
            or child.get("mode") != self.mode
            or child.get("performance_samples") is not (self.mode == "pilot")
            or any(child.get(key) != value for key, value in self.binding.items())
        ):
            raise ValueError("child result schema, mode, or identity differs from its reference")
        record["child_result"] = {
            "path": str(child_result),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        if child_result.read_bytes() != content:
            raise ValueError("child result changed during reference binding")
        from harness.campaign_executor import _write_new

        _write_new(path, record)
        return record
