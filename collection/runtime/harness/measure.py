"""Lifecycle markers and bounded idle sampling for one study execution."""

from __future__ import annotations

import copy
import json
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict
from itertools import pairwise
from pathlib import Path
from typing import Any

from harness.aggregate import validate_record
from harness.resources import ProcessTarget, cpu_interval, read_sample

DEFAULT_WINDOW_NS = 10_000_000_000
DEFAULT_INTERVAL_NS = 100_000_000
MODES = {"synthetic-validation", "pilot", "formal"}
RUNTIME_FAULTS = {"sigint-startup", "kill-bmv2", "drop-control"}
PREREQUISITES = {
    "condition_ready": (),
    "worker_launch": (),
    "ready_received": ("worker_launch",),
    "stop_request": ("worker_launch",),
    "stop_sent": ("stop_request",),
    "stop_failed": ("stop_request",),
    "worker_exit": ("worker_launch",),
    "ordinary_audit_start": ("worker_launch",),
    "ordinary_audit_end": ("ordinary_audit_start",),
    "intervention_start": ("worker_launch",),
    "intervention_applied": ("intervention_start",),
    "intervention_failed": ("intervention_start",),
    "exit_confirmed": ("intervention_applied",),
    "restart_launch": ("worker_exit", "ordinary_audit_end"),
    "restart_ready_received": ("restart_launch",),
    "safety_start": ("worker_launch",),
    "safety_end": ("safety_start",),
}


def _ns(value: Any, name: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < int(positive):
        raise ValueError(f"{name} must be a {'positive' if positive else 'nonnegative'} integer")
    return value


class Recorder:
    """Capture observer timestamps before validation, logging, or audit work."""

    def __init__(
        self,
        metadata: Mapping[str, Any],
        *,
        mode: str,
        clock_domain: str,
        clock_ns: Callable[[], int] | None = None,
    ) -> None:
        if mode not in MODES or not isinstance(clock_domain, str) or not clock_domain:
            raise ValueError("a known mode and explicit clock domain are required")
        if clock_ns is None and mode == "synthetic-validation":
            raise ValueError("synthetic records require an explicit test clock")
        self.metadata = copy.deepcopy(dict(metadata))
        for key in (
            "schema_version",
            "record_type",
            "mode",
            "performance_samples",
            "markers",
            "metrics",
        ):
            if key in self.metadata:
                raise ValueError(f"metadata cannot override {key}")
        self.mode = mode
        self.clock_domain = clock_domain
        validate_record(
            {
                **self.metadata,
                "schema_version": 1,
                "record_type": "measurement-record",
                "mode": mode,
                "performance_samples": mode != "synthetic-validation",
                "status": "blocked",
                "metrics": {},
            },
            mode,
        )
        self.clock_ns = time.monotonic_ns if clock_ns is None else clock_ns
        self.markers: dict[str, int] = {}
        self.validated_ready: set[str] = set()
        self.windows: dict[str, dict[str, Any]] = {}
        self.closed = False

    def mark(self, name: str, *, observed_ns: int | None = None) -> int:
        if self.closed or name not in PREREQUISITES or name in self.markers:
            raise ValueError("closed recorder, unknown marker, or duplicate marker")
        if "safety_start" in self.markers and name != "safety_end":
            raise ValueError("ordinary timing cannot continue after safety escalation")
        if any(prior not in self.markers for prior in PREREQUISITES[name]):
            raise ValueError(f"missing prerequisite for {name}")
        if name == "condition_ready" and "worker_launch" in self.markers:
            raise ValueError("a startup condition must precede the initial launch")
        if (
            name == "ready_received"
            and {"stop_request", "worker_exit", "ordinary_audit_start", "restart_launch"}
            & self.markers.keys()
        ):
            raise ValueError("initial readiness cannot follow teardown or exit")
        if (
            name
            in {
                "stop_request",
                "stop_sent",
                "stop_failed",
                "intervention_start",
                "intervention_applied",
                "intervention_failed",
            }
            and "worker_exit" in self.markers
        ):
            raise ValueError("cannot send commands or interventions to an exited worker")
        if name == "intervention_start" and "stop_request" in self.markers:
            raise ValueError("intervention cannot begin after teardown was requested")
        if (
            name == "intervention_start"
            and self.metadata.get("fault") in {"kill-bmv2", "drop-control"}
            and "ready_received" not in self.validated_ready
        ):
            raise ValueError("running-switch faults require validated readiness")
        if (
            name in {"stop_sent", "stop_failed"}
            and {"stop_sent", "stop_failed"} & self.markers.keys()
        ):
            raise ValueError("stop delivery already has an outcome")
        if (
            name in {"intervention_applied", "intervention_failed"}
            and {"intervention_applied", "intervention_failed"} & self.markers.keys()
        ):
            raise ValueError("intervention already has an outcome")
        value = _ns(self.clock_ns() if observed_ns is None else observed_ns, name)
        if self.markers and value < max(self.markers.values()):
            raise ValueError("observer clock moved backward")
        self.markers[name] = value
        return value

    def accept_ready(self, *, restart: bool = False) -> None:
        marker = "restart_ready_received" if restart else "ready_received"
        if self.closed or marker not in self.markers or "safety_start" in self.markers:
            raise ValueError("readiness requires a received event before safety escalation")
        self.validated_ready.add(marker)

    def attach_window(self, window: Mapping[str, Any], *, restart: bool = False) -> None:
        name = "restart" if restart else "initial"
        ready = "restart_ready_received" if restart else "ready_received"
        if self.closed or "safety_start" in self.markers or ready not in self.validated_ready:
            raise ValueError("idle sampling requires validated readiness before safety escalation")
        if name in self.windows:
            raise ValueError("an idle window is already attached")
        if window.get("clock_domain") != self.clock_domain:
            raise ValueError("idle window clock domain differs")
        if window.get("record_type") != "idle-resource-window" or window.get("mode") != self.mode:
            raise ValueError("idle window has a different record type or mode")
        targets = window.get("targets", [])
        if (
            sum(target.get("role") == "worker" for target in targets) != 1
            or sum(target.get("role") == "bmv2" for target in targets) != self.metadata["switches"]
        ):
            raise ValueError("idle window does not cover the expected worker and switches")
        if window.get("performance_samples") is not (self.mode != "synthetic-validation"):
            raise ValueError("idle window mode differs")
        if window.get("window_start_ns", -1) < self.markers[ready]:
            raise ValueError("idle window precedes readiness")
        if (
            not restart
            and "stop_request" in self.markers
            and window.get("window_end_ns", -1) > self.markers["stop_request"]
        ):
            raise ValueError("idle window overlaps shutdown")
        self.windows[name] = copy.deepcopy(dict(window))

    def finish(self, status: str, **outcome: Any) -> dict[str, Any]:
        if self.closed or status not in {"completed", "failed", "timeout", "blocked"}:
            raise ValueError("closed recorder or invalid execution status")
        if set(outcome) & (
            self.metadata.keys()
            | {
                "markers",
                "metrics",
                "mode",
                "status",
                "performance_samples",
                "record_type",
                "schema_version",
                "clock_domain",
                "resource_windows",
                "measurement_issues",
            }
        ):
            raise ValueError("outcome cannot override record fields")
        metrics: dict[str, int | float] = {}
        issues = []

        def duration(metric: str, begin: str, end: str) -> None:
            if begin in self.markers and end in self.markers:
                value = self.markers[end] - self.markers[begin]
                if value >= 0:
                    metrics[metric] = value

        if "ready_received" in self.validated_ready:
            duration("task_to_ready_ns", "worker_launch", "ready_received")
        if "restart_ready_received" in self.validated_ready:
            duration("restart_task_to_ready_ns", "restart_launch", "restart_ready_received")
            fault = self.metadata.get("fault")
            if fault in RUNTIME_FAULTS:
                duration(
                    "fault_to_restart_ready_ns", "intervention_applied", "restart_ready_received"
                )
            elif fault in {"invalid-p4", "occupied-grpc"}:
                duration(
                    "initial_launch_to_restart_ready_ns", "worker_launch", "restart_ready_received"
                )
            elif fault == "normal-control":
                duration("stop_to_restart_ready_ns", "stop_request", "restart_ready_received")
        if "stop_sent" in self.markers:
            order = list(self.markers)
            exited_before_audit = "worker_exit" in self.markers and (
                "ordinary_audit_start" not in self.markers
                or order.index("worker_exit") < order.index("ordinary_audit_start")
            )
            if exited_before_audit:
                duration("stop_to_exit_ns", "stop_request", "worker_exit")
            if exited_before_audit and "ordinary_audit_start" in self.markers:
                duration("stop_to_audit_ns", "stop_request", "ordinary_audit_end")
                duration("exit_to_audit_ns", "worker_exit", "ordinary_audit_end")
            elif (
                "ordinary_audit_end" in self.markers
                and outcome.get("ordinary_stop_timeout") is not True
            ):
                issues.append("ordinary audit completed without a prior observed worker exit")
        duration("ordinary_audit_ns", "ordinary_audit_start", "ordinary_audit_end")
        for phase, window in self.windows.items():
            if (
                phase == "initial"
                and self.markers.get("stop_request", window["window_end_ns"])
                < window["window_end_ns"]
            ):
                issues.append("idle window overlaps shutdown")
                continue
            if window.get("complete") is not True:
                issues.append(f"{phase} idle window is incomplete")
                continue
            for role, role_metrics in window["role_metrics"].items():
                for key, value in role_metrics.items():
                    prefix = "idle" if phase == "initial" else "restart_idle"
                    metrics[f"{prefix}_{role}_{key}"] = value
        if status == "completed" and not self.validated_ready:
            issues.append("completed execution lacks validated readiness timing")
        record = {
            **self.metadata,
            "schema_version": 1,
            "record_type": "measurement-record",
            "mode": self.mode,
            "performance_samples": self.mode != "synthetic-validation",
            "clock_domain": self.clock_domain,
            "status": status,
            "markers": dict(self.markers),
            "validated_ready": sorted(self.validated_ready),
            "metrics": metrics,
            "resource_windows": copy.deepcopy(self.windows),
            "measurement_issues": issues,
            **outcome,
        }
        json.dumps(record, allow_nan=False)
        validate_record(record, self.mode)
        self.closed = True
        return record


def sample_window(
    targets: Sequence[ProcessTarget],
    *,
    mode: str,
    clock_domain: str,
    clock_ticks: int,
    duration_ns: int = DEFAULT_WINDOW_NS,
    interval_ns: int = DEFAULT_INTERVAL_NS,
    proc_root: Path = Path("/proc"),
    clock_ns: Callable[[], int] = time.monotonic_ns,
    sleep: Callable[[float], None] = time.sleep,
    read: Callable[..., dict[str, Any]] = read_sample,
    start_ns: int | None = None,
) -> dict[str, Any]:
    """Sample a fixed target set on a deadline schedule; keep every failed read."""
    _ns(duration_ns, "duration_ns", positive=True)
    _ns(interval_ns, "interval_ns", positive=True)
    _ns(clock_ticks, "clock_ticks", positive=True)
    if interval_ns > duration_ns or mode not in MODES or not clock_domain:
        raise ValueError("invalid idle sampling configuration")
    if (
        mode == "synthetic-validation"
        and read is read_sample
        and proc_root.resolve() == Path("/proc")
    ):
        raise ValueError("synthetic validation cannot sample live procfs")
    targets = tuple(targets)
    if not targets or sum(target.role == "worker" for target in targets) != 1:
        raise ValueError("one worker and its BMv2 targets are required")
    if len({target.pid for target in targets}) != len(targets):
        raise ValueError("target PID is duplicated")
    if not any(target.role == "bmv2" for target in targets):
        raise ValueError("BMv2 targets are missing")
    entered = _ns(clock_ns(), "window_start_ns")
    started = entered if start_ns is None else _ns(start_ns, "start_ns")
    deadline = started + duration_ns
    if start_ns is not None and entered >= deadline:
        raise ValueError("sampling anchor has expired")
    rounds = []
    next_due = started
    missed = 0
    if start_ns is not None and entered >= started + interval_ns:
        while next_due < entered and next_due < deadline:
            missed += 1
            next_due = min(next_due + interval_ns, deadline)
    previous_end = entered
    while True:
        now = _ns(clock_ns(), "sample_round_ns")
        if now < previous_end:
            raise ValueError("sampler clock moved backward")
        if now < next_due:
            sleep((next_due - now) / 1_000_000_000)
            if start_ns is not None:
                after_sleep = _ns(clock_ns(), "sample_wake_ns")
                if after_sleep <= now:
                    raise ValueError("sampling wait did not advance its clock")
                while after_sleep < next_due:
                    sleep((next_due - after_sleep) / 1_000_000_000)
                    after = _ns(clock_ns(), "sample_wake_ns")
                    if after <= after_sleep:
                        raise ValueError("sampling wait did not advance its clock")
                    after_sleep = after
                now = after_sleep
        rounds.append(
            [
                read(target, proc_root=proc_root, clock_ns=clock_ns, clock_domain=clock_domain)
                for target in targets
            ]
        )
        ended = _ns(clock_ns(), "sample_round_end_ns")
        if ended < now:
            raise ValueError("sampler clock moved backward")
        previous_end = ended
        if next_due == deadline:
            break
        next_due = min(next_due + interval_ns, deadline)
        while next_due < ended and next_due < deadline:
            missed += 1
            next_due = min(next_due + interval_ns, deadline)
    role_metrics: dict[str, dict[str, float]] = {}
    errors = []
    for index, target in enumerate(targets):
        samples = [row[index] for row in rounds]
        intervals = [cpu_interval(a, b, clock_ticks=clock_ticks) for a, b in pairwise(samples)]
        if any(
            sample.get("ok") is not True
            or sample.get("target") != asdict(target)
            or sample.get("clock_domain") != clock_domain
            for sample in samples
        ) or any(interval.get("ok") is not True for interval in intervals):
            errors.append(
                {"target": asdict(target), "error": "missing or invalid process observations"}
            )
            continue
        wall = sum(interval["wall_ns"] for interval in intervals)
        values = {
            "cpu_percent": sum(interval["cpu_ticks"] for interval in intervals)
            * 100_000_000_000
            / (clock_ticks * wall),
        }
        for key in ("rss_bytes", "pss_bytes"):
            values[key] = (
                sum(
                    (a[key] + b[key]) / 2 * interval["wall_ns"]
                    for (a, b), interval in zip(pairwise(samples), intervals, strict=True)
                )
                / wall
            )
        totals = role_metrics.setdefault(target.role, dict.fromkeys(values, 0.0))
        for key, value in values.items():
            totals[key] += value
    complete = not errors and missed == 0
    return {
        "record_type": "idle-resource-window",
        "mode": mode,
        "performance_samples": mode != "synthetic-validation",
        "clock_domain": clock_domain,
        "window_start_ns": started,
        "window_end_ns": ended,
        "scheduled_end_ns": deadline,
        "overrun_ns": max(0, ended - deadline),
        "requested_duration_ns": duration_ns,
        "requested_interval_ns": interval_ns,
        "clock_ticks": clock_ticks,
        "targets": [asdict(target) for target in targets],
        "rounds": rounds,
        "missed_deadlines": missed,
        "complete": complete,
        "errors": errors,
        "role_metrics": role_metrics if complete else {},
        "memory_summary": "Time-weighted trapezoidal mean per process, then sum by role",
        "cpu_summary": "Sum of each process's CPU delta / actual observation span",
        "window_boundary": "Endpoint is scheduled; window_end follows its completed reads",
    }


def write_record(path: Path, record: Mapping[str, Any]) -> None:
    payload = json.dumps(record, indent=2, allow_nan=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as stream:
        stream.write(payload)
