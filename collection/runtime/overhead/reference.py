"""Collect external endpoints and keep metric failures separate from native outcomes."""

from __future__ import annotations

import copy
import time
from collections.abc import Callable
from typing import Any

from overhead.model import Context, Identity, integer
from overhead.proc import ProcReader
from overhead.wire import TRANSITIONS, check


def cpu_endpoint(value: dict[str, Any], identity: Identity) -> dict[str, Any]:
    result = copy.deepcopy(value)
    if Identity.from_dict(result["identity"]) != identity:
        raise ProcessLookupError("CPU endpoint identity differs")
    for key in ("user_ticks", "system_ticks", "cpu_ticks", "read_start_ns", "read_end_ns"):
        integer(result[key], key)
    integer(result["clock_ticks"], "clock ticks", 1)
    if (
        result["cpu_ticks"] != result["user_ticks"] + result["system_ticks"]
        or result["read_end_ns"] < result["read_start_ns"]
    ):
        raise ValueError("invalid own CPU counters or read order")
    return result


def memory_endpoint(value: dict[str, Any], identity: Identity) -> dict[str, Any]:
    result = copy.deepcopy(value)
    if Identity.from_dict(result["identity"]) != identity:
        raise ProcessLookupError("memory endpoint identity differs")
    for key in ("read_start_ns", "read_end_ns"):
        integer(result[key], key)
    unavailable = dict(result.get("unavailable_fields", {}))
    for key in ("rss_bytes", "pss_bytes"):
        try:
            integer(result[key], key)
        except (ValueError, KeyError) as exc:
            result.pop(key, None)
            unavailable[key] = str(exc)
    result["unavailable_fields"] = unavailable
    if result["read_end_ns"] < result["read_start_ns"]:
        raise ValueError("memory read order differs")
    return result


class ParentReference:
    def __init__(
        self,
        context: Context,
        supervisor: Identity,
        send_ack: Callable[[dict[str, Any]], None],
        *,
        reader: ProcReader | None = None,
        clock: Callable[[], int] = time.monotonic_ns,
        process_cpu: Callable[[], int] = time.process_time_ns,
    ):
        self.context, self.supervisor, self.send_ack = context, supervisor, send_ack
        self.reader = ProcReader() if reader is None else reader
        self.clock, self.process_cpu = clock, process_cpu
        self.history: list[str] = []
        self.events: list[dict[str, Any]] = []
        self.issues: list[dict[str, str]] = []
        self.endpoints: dict[str, Any] = {}
        self.failed = False
        self.previous_clock = -1

    def now(self) -> int:
        value = integer(self.clock(), "reference clock")
        if value < self.previous_clock:
            raise ValueError("reference clock moved backward")
        self.previous_clock = value
        return value

    def metric(self, name: str, read: Callable[[], dict[str, Any]]) -> None:
        started = self.now()
        try:
            value = read()
            self.endpoints[name] = value
            for field, reason in value.get("unavailable_fields", {}).items():
                self.issues.append(
                    {"metric": name + "." + field, "type": "ValueError", "message": reason}
                )
        except (OSError, ValueError, KeyError, TypeError) as exc:
            self.issues.append({"metric": name, "type": type(exc).__name__, "message": str(exc)})
        self.events.append({"probe": name, "start_ns": started, "end_ns": self.now()})

    def handle(self, value: dict[str, Any]) -> None:
        if self.failed:
            raise RuntimeError("reference already failed")
        try:
            check(value, self.context, self.supervisor)
            previous = self.history[-1] if self.history else None
            boundary = value["boundary"]
            if value["sequence"] != len(self.history) + 1 or boundary not in TRANSITIONS[previous]:
                raise ValueError("reference order or sequence differs")
            self.reader.verify(self.supervisor)
            received = self.now()
            payload = value["payload"]
            if boundary == "ref_begin":
                if payload:
                    raise ValueError("begin payload must be empty")
                try:
                    self.endpoints["reference_cpu_begin_ns"] = integer(
                        self.process_cpu(), "reference CPU"
                    )
                except (ValueError, OSError) as exc:
                    self.issues.append(
                        {
                            "metric": "reference_own_cpu_ns",
                            "type": type(exc).__name__,
                            "message": str(exc),
                        }
                    )
                self.metric(
                    "supervisor_cpu_begin",
                    lambda: cpu_endpoint(self.reader.cpu(self.supervisor), self.supervisor),
                )
                self.endpoints["body_start_ns"] = self.now()
            elif boundary == "ref_ready":
                if set(payload) != {"worker", "hold_anchor_ns", "hold_deadline_ns"}:
                    raise ValueError("ready payload differs")
                anchor = integer(payload["hold_anchor_ns"], "hold anchor")
                deadline = integer(payload["hold_deadline_ns"], "hold deadline")
                if deadline <= anchor or anchor > received:
                    raise ValueError("invalid ready hold boundaries")
                child = Identity.from_dict(payload["worker"])
                worker = self.reader.resolve_child(self.supervisor, child)
                self.endpoints["worker_identity"] = worker.as_dict()
                self.endpoints["hold_anchor_ns"] = anchor
                self.endpoints["hold_deadline_ns"] = deadline
                self.metric(
                    "worker_cpu_ready", lambda: cpu_endpoint(self.reader.cpu(worker), worker)
                )
                self.metric(
                    "worker_memory_ready",
                    lambda: memory_endpoint(self.reader.memory(worker), worker),
                )
            elif boundary == "ref_primary_published":
                if set(payload) != {"primary"}:
                    raise ValueError("primary payload differs")
                self.endpoints["primary_pointer"] = copy.deepcopy(payload["primary"])
            else:
                if set(payload) != {"child"}:
                    raise ValueError("complete payload differs")
                self.endpoints["body_end_ns"] = received
                self.endpoints["child_pointer"] = copy.deepcopy(payload["child"])

                def end_cpu() -> dict[str, Any]:
                    endpoint = cpu_endpoint(self.reader.cpu(self.supervisor), self.supervisor)
                    first = self.endpoints.get("supervisor_cpu_begin")
                    if first is not None and (
                        endpoint["clock_ticks"] != first["clock_ticks"]
                        or any(endpoint[key] < first[key] for key in ("user_ticks", "system_ticks"))
                    ):
                        raise ValueError("supervisor CPU counters decreased or changed units")
                    return endpoint

                self.metric("supervisor_cpu_end", end_cpu)
                self.metric(
                    "supervisor_memory_end",
                    lambda: memory_endpoint(self.reader.memory(self.supervisor), self.supervisor),
                )
                try:
                    self.endpoints["reference_cpu_end_ns"] = integer(
                        self.process_cpu(), "reference CPU"
                    )
                except (ValueError, OSError) as exc:
                    self.issues.append(
                        {
                            "metric": "reference_own_cpu_ns",
                            "type": type(exc).__name__,
                            "message": str(exc),
                        }
                    )
            self.send_ack({**value, "record_type": "diagnostic-reference-ack"})
            self.history.append(boundary)
            self.events.append(
                {"boundary": boundary, "received_ns": received, "acknowledged_ns": self.now()}
            )
        except BaseException:
            self.failed = True
            raise

    def result(self) -> dict[str, Any]:
        endpoints = copy.deepcopy(self.endpoints)
        metrics = {}
        if "body_end_ns" in endpoints and "body_start_ns" in endpoints:
            metrics["reference_body_wall_ns"] = (
                endpoints["body_end_ns"] - endpoints["body_start_ns"]
            )
        if all(key in endpoints for key in ("supervisor_cpu_begin", "supervisor_cpu_end")):
            first, last = endpoints["supervisor_cpu_begin"], endpoints["supervisor_cpu_end"]
            if first["clock_ticks"] != last["clock_ticks"] or any(
                last[k] < first[k] for k in ("user_ticks", "system_ticks")
            ):
                raise ValueError("supervisor CPU endpoints are inconsistent")
            metrics["supervisor_cpu_ticks"] = last["cpu_ticks"] - first["cpu_ticks"]
        issues = copy.deepcopy(self.issues)
        if all(key in endpoints for key in ("reference_cpu_begin_ns", "reference_cpu_end_ns")):
            if endpoints["reference_cpu_end_ns"] < endpoints["reference_cpu_begin_ns"]:
                issues.append(
                    {
                        "metric": "reference_own_cpu_ns",
                        "type": "ValueError",
                        "message": "reference CPU clock moved backward",
                    }
                )
            else:
                metrics["reference_own_cpu_ns"] = (
                    endpoints["reference_cpu_end_ns"] - endpoints["reference_cpu_begin_ns"]
                )
        return {
            "schema_version": 1,
            "record_type": "diagnostic-reference-endpoints",
            "context": self.context.as_dict(),
            "history": list(self.history),
            "transport_complete": bool(
                self.history and self.history[-1] == "ref_complete" and not self.failed
            ),
            "endpoints": endpoints,
            "metrics": metrics,
            "issues": issues,
            "events": copy.deepcopy(self.events),
        }
