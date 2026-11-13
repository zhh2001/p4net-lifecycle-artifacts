"""Identity-checked procfs samples and per-process CPU intervals."""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ProcessTarget:
    pid: int
    start_ticks: int
    role: str

    def __post_init__(self) -> None:
        _integer(self.pid, "pid", minimum=1)
        _integer(self.start_ticks, "start_ticks")
        if not isinstance(self.role, str) or self.role not in {"worker", "bmv2"}:
            raise ValueError("role must be worker or bmv2")


def _integer(value: Any, name: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name} must be an integer of at least {minimum}")
    return value


def parse_stat(text: str) -> dict[str, Any]:
    """Read the process's own CPU counters, excluding child CPU fields."""
    head, tail = text.rsplit(")", 1)
    pid, name = head.split("(", 1)
    fields = tail.split()
    if len(fields) < 20 or len(fields[0]) != 1:
        raise ValueError("incomplete process stat")
    result: dict[str, Any] = {
        "pid": _integer(int(pid.strip()), "pid", minimum=1),
        "name": name,
        "state": fields[0],
        "user_ticks": _integer(int(fields[11]), "user_ticks"),
        "system_ticks": _integer(int(fields[12]), "system_ticks"),
        "start_ticks": _integer(int(fields[19]), "start_ticks"),
    }
    result["cpu_ticks"] = result["user_ticks"] + result["system_ticks"]
    return result


def parse_smaps_rollup(text: str) -> dict[str, int]:
    """Convert the exact Rss and Pss fields from procfs kB to bytes."""
    result = {}
    for line in text.splitlines():
        name, separator, payload = line.partition(":")
        if not separator or name not in {"Rss", "Pss"}:
            continue
        key = name.lower() + "_bytes"
        fields = payload.split()
        if key in result or len(fields) != 2 or fields[1] != "kB":
            raise ValueError(f"invalid or duplicate smaps_rollup {name}")
        result[key] = _integer(int(fields[0]), name) * 1024
    if result.keys() != {"rss_bytes", "pss_bytes"}:
        raise ValueError("smaps_rollup must contain Rss and Pss")
    return result


def _verify(record: Mapping[str, Any], target: ProcessTarget) -> None:
    if record["pid"] != target.pid or record["start_ticks"] != target.start_ticks:
        raise ValueError("process identity changed")
    if record["state"] in {"Z", "X", "x"}:
        raise ProcessLookupError("process has exited")


def _failure(record: dict[str, Any], exc: Exception) -> dict[str, Any]:
    return {
        **record,
        "ok": False,
        "error": {"type": type(exc).__name__, "message": str(exc)},
    }


def read_sample(
    target: ProcessTarget,
    *,
    proc_root: Path = Path("/proc"),
    clock_ns: Callable[[], int] = time.monotonic_ns,
    clock_domain: str = "monotonic_ns",
) -> dict[str, Any]:
    """Read stat and memory between two checks of the same live identity."""
    if not isinstance(clock_domain, str) or not clock_domain:
        raise ValueError("clock_domain must be a nonempty string")
    started = _integer(clock_ns(), "sample_start_ns")
    record: dict[str, Any] = {
        "record_type": "process-resource-sample",
        "target": asdict(target),
        "clock_domain": clock_domain,
        "sample_start_ns": started,
    }
    ended: int | None = None
    try:
        directory = proc_root / str(target.pid)
        before = parse_stat((directory / "stat").read_text())
        cpu_read_end = _integer(clock_ns(), "cpu_read_end_ns")
        _verify(before, target)
        memory = parse_smaps_rollup((directory / "smaps_rollup").read_text())
        after = parse_stat((directory / "stat").read_text())
        _verify(after, target)
        if any(after[key] < before[key] for key in ("user_ticks", "system_ticks")):
            raise ValueError("CPU counters decreased during the sample")
        ended = _integer(clock_ns(), "sample_end_ns")
        if not started <= cpu_read_end <= ended:
            raise ValueError("sample clock moved backward")
        return {
            **record,
            "sample_end_ns": ended,
            "cpu_midpoint_ns": (started + cpu_read_end) // 2,
            "cpu_read_end_ns": cpu_read_end,
            "ok": True,
            **{key: before[key] for key in ("user_ticks", "system_ticks", "cpu_ticks")},
            **memory,
        }
    except (OSError, ValueError) as exc:
        if ended is None:
            ended = _integer(clock_ns(), "sample_end_ns")
        record["sample_end_ns"] = ended
        return _failure(record, exc)


def _valid_sample(sample: Mapping[str, Any]) -> tuple[dict[str, Any], int, int]:
    if sample.get("record_type") != "process-resource-sample" or sample.get("ok") is not True:
        raise ValueError("CPU interval requires two successful resource samples")
    target = asdict(ProcessTarget(**sample["target"]))
    start = _integer(sample["sample_start_ns"], "sample_start_ns")
    end = _integer(sample["sample_end_ns"], "sample_end_ns")
    midpoint = _integer(sample["cpu_midpoint_ns"], "cpu_midpoint_ns")
    if not start <= midpoint <= end:
        raise ValueError("CPU midpoint lies outside the sample bounds")
    user = _integer(sample["user_ticks"], "user_ticks")
    system = _integer(sample["system_ticks"], "system_ticks")
    ticks = _integer(sample["cpu_ticks"], "cpu_ticks")
    if ticks != user + system:
        raise ValueError("CPU total differs from user plus system ticks")
    return target, midpoint, ticks


def cpu_interval(
    previous: Mapping[str, Any], current: Mapping[str, Any], *, clock_ticks: int
) -> dict[str, Any]:
    """Compute CPU use for one identity; 100 percent means one logical CPU."""
    record: dict[str, Any] = {
        "record_type": "process-cpu-interval",
        "target": current.get("target"),
        "clock_domain": current.get("clock_domain"),
    }
    try:
        frequency = _integer(clock_ticks, "clock_ticks", minimum=1)
        old_target, old_time, old_ticks = _valid_sample(previous)
        new_target, new_time, new_ticks = _valid_sample(current)
        if old_target != new_target:
            raise ValueError("CPU interval process identity or role changed")
        domain = current.get("clock_domain")
        if not isinstance(domain, str) or not domain or domain != previous.get("clock_domain"):
            raise ValueError("CPU interval clock domains differ or are missing")
        if new_time <= old_time:
            raise ValueError("CPU interval needs increasing observation times")
        if any(current[key] < previous[key] for key in ("user_ticks", "system_ticks")):
            raise ValueError("CPU counters decreased between samples")
        wall = new_time - old_time
        ticks = new_ticks - old_ticks
        percent = ticks * 100_000_000_000 / (frequency * wall)
        if not math.isfinite(percent):
            raise ValueError("CPU percentage is not finite")
        return {
            **record,
            "ok": True,
            "interval_start_ns": old_time,
            "interval_end_ns": new_time,
            "wall_ns": wall,
            "cpu_ticks": ticks,
            "clock_ticks": frequency,
            "cpu_percent": percent,
        }
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        return _failure(record, exc)
