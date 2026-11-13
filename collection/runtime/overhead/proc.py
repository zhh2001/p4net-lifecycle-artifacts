"""Read own CPU counters and memory between immutable process-identity checks."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from harness.resources import parse_stat

from overhead.model import NAMESPACES, Identity, integer


class ProcReader:
    def __init__(self, root: Path = Path("/proc"), *, clock: Callable[[], int] = time.monotonic_ns):
        self.root, self.clock = root, clock

    def identity(self, pid: int) -> Identity:
        directory = self.root / str(integer(pid, "pid", 1))
        stat = parse_stat((directory / "stat").read_text())
        if stat["pid"] != pid or stat["state"] in {"Z", "X", "x"}:
            raise ProcessLookupError("process exited or changed")
        status = (directory / "status").read_text().splitlines()
        rows = [row.split()[1:] for row in status if row.startswith("NSpid:")]
        if len(rows) != 1 or not rows[0] or not all(item.isdecimal() for item in rows[0]):
            raise ValueError("namespace PID mapping is unavailable")
        identity = Identity(
            pid,
            int(rows[0][-1]),
            stat["start_ticks"],
            (self.root / "sys/kernel/random/boot_id").read_text().strip(),
            {name: os.readlink(directory / "ns" / name) for name in NAMESPACES},
        )
        after = parse_stat((directory / "stat").read_text())
        if (after["pid"], after["start_ticks"]) != (pid, identity.start_ticks) or after[
            "state"
        ] in {"Z", "X", "x"}:
            raise ProcessLookupError("process changed during identity read")
        return identity

    def verify(self, identity: Identity) -> None:
        if self.identity(identity.pid) != identity:
            raise ProcessLookupError("process identity changed")

    def cpu(self, identity: Identity, *, self_read: bool = False) -> dict[str, Any]:
        started = integer(self.clock(), "CPU read start")
        self.verify(identity)
        if self_read and identity.pid != os.getpid():
            raise ValueError("own CPU read requires the current process")
        path = self.root / "self/stat" if self_read else self.root / str(identity.pid) / "stat"
        stat = parse_stat(path.read_text())
        if (stat["pid"], stat["start_ticks"]) != (identity.pid, identity.start_ticks):
            raise ProcessLookupError("CPU endpoint identifies another process")
        self.verify(identity)
        ended = integer(self.clock(), "CPU read end")
        if ended < started:
            raise ValueError("CPU endpoint clock moved backward")
        return {
            "identity": identity.as_dict(),
            "user_ticks": stat["user_ticks"],
            "system_ticks": stat["system_ticks"],
            "cpu_ticks": stat["cpu_ticks"],
            "clock_ticks": integer(os.sysconf("SC_CLK_TCK"), "clock ticks", 1),
            "read_start_ns": started,
            "read_end_ns": ended,
        }

    def memory(self, identity: Identity) -> dict[str, Any]:
        started = integer(self.clock(), "memory read start")
        self.verify(identity)
        raw = (self.root / str(identity.pid) / "smaps_rollup").read_text()
        memory: dict[str, Any] = {}
        unavailable = {}
        for field in ("Rss", "Pss"):
            lines = [
                line.partition(":")[2].split()
                for line in raw.splitlines()
                if line.partition(":")[0] == field
            ]
            key = field.lower() + "_bytes"
            try:
                if len(lines) != 1 or len(lines[0]) != 2 or lines[0][1] != "kB":
                    raise ValueError("missing, duplicate, or invalid memory field")
                memory[key] = integer(int(lines[0][0]), key) * 1024
            except ValueError as exc:
                unavailable[key] = str(exc)
        memory["unavailable_fields"] = unavailable
        self.verify(identity)
        ended = integer(self.clock(), "memory read end")
        if ended < started:
            raise ValueError("memory endpoint clock moved backward")
        return {
            "identity": identity.as_dict(),
            **memory,
            "read_start_ns": started,
            "read_end_ns": ended,
        }

    def resolve_child(self, supervisor: Identity, child: Identity) -> Identity:
        self.verify(supervisor)
        candidates = []
        for directory in self.root.iterdir():
            if not directory.name.isdecimal():
                continue
            try:
                raw = (directory / "stat").read_text()
                if int(raw.rsplit(")", 1)[1].split()[1]) != supervisor.pid:
                    continue
                current = self.identity(int(directory.name))
                if current.same_process(child):
                    candidates.append(current)
            except (FileNotFoundError, ProcessLookupError):
                continue
        self.verify(supervisor)
        if len(candidates) != 1:
            raise ProcessLookupError("a unique direct worker child was not found")
        return candidates[0]
