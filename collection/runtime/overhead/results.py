"""Bind published child data and worker CPU endpoints to the external reference."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

from overhead.model import Context, Identity, integer
from overhead.publication import pointer, publish
from overhead.reference import ParentReference, cpu_endpoint


def read_bound(path: Path, expected: dict[str, str], context: Context, kind: str) -> dict[str, Any]:
    if pointer(path) != expected:
        raise ValueError("published artifact pointer differs")

    def finite_number(raw: str) -> float:
        value = float(raw)
        if not math.isfinite(value):
            raise ValueError("published value is not finite")
        return value

    def invalid_constant(raw: str) -> Any:
        raise ValueError("published value is not finite: " + raw)

    value: dict[str, Any] = json.loads(
        path.read_text(), parse_float=finite_number, parse_constant=invalid_constant
    )
    type(context).from_dict(value["context"])
    if (
        pointer(path) != expected
        or value["context"] != context.as_dict()
        or value["record_type"] != kind
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
    ):
        raise ValueError("published artifact identity differs")
    return value


def worker_end(
    path: Path, context: Context, worker: Identity, ready: dict[str, Any] | None
) -> dict[str, Any]:
    ref = pointer(path)
    data = read_bound(path, ref, context, "diagnostic-worker-cpu-end")
    inner = Identity.from_dict(data["worker_identity"])
    if not worker.same_process(inner) or inner.pid != inner.namespace_pid:
        raise ProcessLookupError("worker end identity differs from the observed worker")
    cpu = cpu_endpoint(data["cpu"], inner)
    if (
        data["scope"] != "process-start-through-selected-entry-completion"
        or data["interpreter_finalization_included"] is not False
    ):
        raise ValueError("worker CPU end scope differs")
    if integer(data["before_own_publication_ns"], "end publication boundary") < cpu["read_end_ns"]:
        raise ValueError("worker end publication precedes its CPU read")
    if ready is not None:
        ready = cpu_endpoint(ready, worker)
        if cpu["read_start_ns"] < ready["read_end_ns"]:
            raise ValueError("worker end CPU read precedes readiness")
    if ready is not None and (
        cpu["clock_ticks"] != ready["clock_ticks"]
        or any(cpu[k] < ready[k] for k in ("user_ticks", "system_ticks"))
    ):
        raise ValueError("worker CPU end counters precede readiness")
    return {"pointer": ref, "cpu": cpu, "native_outcome": data["native_outcome"]}


def finalize(
    reference: ParentReference,
    output: Path,
    *,
    outer_span: dict[str, int] | None = None,
    external_issues: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    raw = reference.result()
    context = reference.context
    issues = list(raw["issues"]) + ([] if external_issues is None else external_issues)
    endpoints = raw["endpoints"]
    metrics = dict(raw["metrics"])
    native = None
    eligible = False
    child = None
    try:
        child = read_bound(
            output / "child.json",
            endpoints["child_pointer"],
            context,
            "diagnostic-calibration-child",
        )
        primary = read_bound(
            output / "primary.json",
            endpoints["primary_pointer"],
            context,
            "diagnostic-calibration-primary",
        )
        if (
            child["primary"] != endpoints["primary_pointer"]
            or child["native_result"] != primary["native_result"]
            or child["native_outcome"] != primary["native_outcome"]
            or child["markers"] != primary["markers"]
            or child["hold"] != primary["hold"]
        ):
            raise ValueError("child and primary native outcomes differ")
        native = child["native_result"]
        hold = child["hold"]
        hold_valid = (
            isinstance(hold, dict)
            and hold.get("complete") is True
            and integer(hold["scheduled_end_ns"], "hold end")
            - integer(hold["anchor_ns"], "hold start")
            == integer(hold["requested_duration_ns"], "hold duration", 1)
            and integer(hold["callback_end_ns"], "hold completion") >= hold["scheduled_end_ns"]
            and integer(hold["extension_ns"], "hold extension")
            == hold["callback_end_ns"] - hold["scheduled_end_ns"]
        )
        if hold_valid:
            hold_valid = hold["anchor_ns"] == endpoints.get("hold_anchor_ns") and hold[
                "scheduled_end_ns"
            ] == endpoints.get("hold_deadline_ns")
        eligible = (
            raw["transport_complete"]
            and isinstance(native, dict)
            and native.get("ok") is True
            and native.get("ready") is True
            and type(native.get("worker_returncode")) is int
            and native.get("worker_returncode") == 0
            and native.get("cleanup", {}).get("ordinary_after_clean") is True
            and native.get("cleanup", {}).get("rescue_attempted") is False
            and hold_valid
            and not child["issues"]
        )
        markers = child["markers"]
        for name, left, right in (
            ("startup_wall_ns", "worker_launch", "validated_ready"),
            ("ordinary_stop_wall_ns", "stop_request", "worker_exit"),
        ):
            if left in markers and right in markers:
                delta = integer(markers[right], right) - integer(markers[left], left)
                if delta < 0:
                    raise ValueError("lifecycle timestamp order differs")
                metrics[name] = delta
    except (OSError, ValueError, KeyError, TypeError) as exc:
        issues.append({"metric": "publication", "type": type(exc).__name__, "message": str(exc)})
        eligible = False
    if "worker_cpu_ready" in endpoints:
        metrics["worker_cpu_ready_ticks"] = endpoints["worker_cpu_ready"]["cpu_ticks"]
    for endpoint, prefix in (
        ("worker_memory_ready", "worker_ready"),
        ("supervisor_memory_end", "supervisor_end"),
    ):
        if endpoint in endpoints:
            for name in ("rss_bytes", "pss_bytes"):
                if name in endpoints[endpoint]:
                    metrics[prefix + "_" + name] = endpoints[endpoint][name]
    if native is None and "child_pointer" not in endpoints:
        for filename, kind in (
            ("child.json", "diagnostic-calibration-child"),
            ("primary.json", "diagnostic-calibration-primary"),
        ):
            try:
                saved = read_bound(output / filename, pointer(output / filename), context, kind)
                native = saved["native_result"]
                break
            except (OSError, ValueError, KeyError, TypeError):
                continue
    if outer_span is not None:
        if set(outer_span) != {"start_ns", "end_ns"}:
            raise ValueError("outer interval fields differ")
        start = integer(outer_span["start_ns"], "outer start")
        end_time = integer(outer_span["end_ns"], "outer end")
        if end_time < start:
            raise ValueError("outer interval moved backward")
        metrics["outer_process_wall_ns"] = end_time - start
    end = None
    try:
        worker = Identity.from_dict(endpoints["worker_identity"])
        end = worker_end(
            output / "worker-cpu-end.json", context, worker, endpoints.get("worker_cpu_ready")
        )
        metrics["worker_cpu_end_ticks"] = end["cpu"]["cpu_ticks"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        issues.append(
            {"metric": "worker_cpu_end_ticks", "type": type(exc).__name__, "message": str(exc)}
        )
    required = {
        "reference_body_wall_ns",
        "outer_process_wall_ns",
        "supervisor_cpu_ticks",
        "startup_wall_ns",
        "ordinary_stop_wall_ns",
        "worker_cpu_ready_ticks",
        "worker_cpu_end_ticks",
        "worker_ready_rss_bytes",
        "worker_ready_pss_bytes",
        "supervisor_end_rss_bytes",
        "supervisor_end_pss_bytes",
    }
    receipt = {
        "schema_version": 1,
        "record_type": "diagnostic-calibration-reference-result",
        "context": context.as_dict(),
        "native_result": native,
        "primary_performance_eligible": eligible,
        "measurement_complete": eligible and not issues and required.issubset(metrics),
        "outer_span": outer_span,
        "metrics": metrics if eligible else {},
        "raw_validated_metrics": metrics,
        "reference": raw,
        "worker_end": end,
        "issues": issues,
        "child": pointer(output / "child.json") if child is not None else None,
    }
    publish(output / "reference-result.json", receipt)
    return receipt
