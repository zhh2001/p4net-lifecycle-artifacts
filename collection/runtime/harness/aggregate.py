"""Summarize completed measurement records without launching or sampling workloads."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

MODES = ("synthetic-validation", "native-validation", "pilot", "formal")
STATUSES = ("completed", "failed", "timeout", "blocked")
NATIVE_OUTCOMES = (
    "recovery_success",
    "ordinary_cleanup_clean",
    "framework_complete",
    "ordinary_stop_timeout",
    "restart_ordinary_stop_timeout",
    "restart_ordinary_cleanup_clean",
)
PERFORMANCE_FIELDS = {
    "markers",
    "resource_windows",
    "clock_domain",
    "clock_ticks",
    "samples",
    "sample_count",
    "role_metrics",
    "window_start_ns",
    "window_end_ns",
    "duration_ns",
    "interval_ns",
    "elapsed_ns",
    "observed_ns",
    "timestamp_ns",
    "cpu_ticks",
    "user_ticks",
    "system_ticks",
    "rss_bytes",
    "pss_bytes",
}
GROUP_KEYS = (
    "tool",
    "python",
    "input_lock_sha256",
    "workload",
    "switches",
    "configuration_profile",
    "build_mode",
    "fault",
)


def _text(value: Any, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")


def _positive_integer(value: Any, name: str) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _metric(value: Any, name: str) -> None:
    if type(value) not in (int, float) or value < 0:
        raise ValueError(f"metric {name!r} must be a finite nonnegative number")
    try:
        finite = math.isfinite(value)
    except OverflowError:
        finite = False
    if not finite:
        raise ValueError(f"metric {name!r} must be a finite nonnegative number")


def _native_validation(record: dict[str, Any], index: int) -> None:
    """Keep functional native records free of performance observations."""

    def inspect(value: Any, *, root: bool = False) -> None:
        if isinstance(value, dict):
            for name, item in value.items():
                if name in PERFORMANCE_FIELDS or (name == "metrics" and (not root or item != {})):
                    raise ValueError(
                        f"record {index} native-validation cannot contain performance field {name}"
                    )
                if name == "performance_samples" and item is not False:
                    raise ValueError(
                        f"record {index} native-validation cannot contain performance samples"
                    )
                inspect(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                inspect(item)

    inspect(record, root=True)


def _validate(record: Any, mode: str, index: int) -> None:
    if not isinstance(record, dict):
        raise ValueError(f"record {index} must be an object")
    required = {
        "schema_version",
        "record_type",
        "mode",
        "performance_samples",
        "run_id",
        "session",
        *GROUP_KEYS,
        "status",
        "metrics",
    }
    if missing := required - record.keys():
        raise ValueError(f"record {index} is missing fields: {', '.join(sorted(missing))}")
    if type(record["schema_version"]) is not int or record["schema_version"] != 1:
        raise ValueError(f"record {index} has an unsupported schema_version")
    if record["record_type"] != "measurement-record":
        raise ValueError(f"record {index} is not a measurement-record")
    if record["mode"] != mode:
        raise ValueError(f"record {index} mode differs from the requested mode")
    expected_samples = mode in {"pilot", "formal"}
    if (
        type(record["performance_samples"]) is not bool
        or record["performance_samples"] != expected_samples
    ):
        raise ValueError(f"record {index} performance_samples is inconsistent with mode")
    for name in ("run_id", "tool", "python", "build_mode"):
        _text(record[name], name)
    if not isinstance(record["input_lock_sha256"], str) or not re.fullmatch(
        r"[a-fA-F0-9]{64}", record["input_lock_sha256"]
    ):
        raise ValueError(f"record {index} input_lock_sha256 must contain 64 hexadecimal digits")
    for name in ("session", "switches"):
        _positive_integer(record[name], name)
    if record["workload"] not in ("scale", "fault"):
        raise ValueError(f"record {index} has an invalid workload")
    if record["configuration_profile"] != "matched-v1":
        raise ValueError(f"record {index} has an unsupported configuration_profile")
    if record["fault"] is not None:
        _text(record["fault"], "fault")
    if record["status"] not in STATUSES:
        raise ValueError(f"record {index} has an invalid status")
    for name in NATIVE_OUTCOMES:
        if record.get(name) is not None and type(record[name]) is not bool:
            raise ValueError(f"record {index} {name} must be bool or None")
    if "measurement_issues" in record and not isinstance(record["measurement_issues"], list):
        raise ValueError(f"record {index} measurement_issues must be a list")
    if not isinstance(record["metrics"], dict):
        raise ValueError(f"record {index} metrics must be an object")
    for name, value in record["metrics"].items():
        _text(name, "metric name")
        _metric(value, name)
    if mode == "native-validation":
        _native_validation(record, index)


def validate_record(record: dict[str, Any], mode: str) -> None:
    """Validate one record against the shared measurement contract."""
    if mode not in MODES:
        raise ValueError("mode must be synthetic-validation, native-validation, pilot, or formal")
    _validate(record, mode, 0)


def primary_performance_exclusion(record: Mapping[str, Any]) -> str | None:
    """Keep native outcomes visible while identifying unusable performance records."""
    if record.get("status") != "completed":
        return "not-completed"
    if any(
        record.get(name) is not None and type(record[name]) is not bool for name in NATIVE_OUTCOMES
    ):
        return "invalid-native-outcome"
    issues = record.get("measurement_issues", [])
    if not isinstance(issues, list):
        return "invalid-measurement-issues"
    if any(
        record.get(name) is True
        for name in ("ordinary_stop_timeout", "restart_ordinary_stop_timeout")
    ):
        return "ordinary-stop-timeout"
    if any(
        record.get(name) is False
        for name in ("ordinary_cleanup_clean", "restart_ordinary_cleanup_clean")
    ):
        return "ordinary-cleanup-incomplete"
    if issues:
        return "measurement-issues"
    return None


def primary_performance_eligible(record: Mapping[str, Any]) -> bool:
    """Return whether a completed record can contribute primary performance values."""
    return primary_performance_exclusion(record) is None


def quantile(values: Sequence[int | float], probability: float) -> int | float:
    """Linearly interpolate at position (n - 1) * probability in sorted values."""
    if not values:
        raise ValueError("quantile requires at least one value")
    if type(probability) not in (int, float) or not 0 <= probability <= 1:
        raise ValueError("probability must be between zero and one")
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _summarize_rows(
    rows: list[tuple[int, dict[str, Any]]], metric_names: set[str]
) -> dict[str, Any]:
    counts = {status: 0 for status in STATUSES}
    for _, record in rows:
        counts[record["status"]] += 1
    completed = [record for _, record in rows if record["status"] == "completed"]
    metrics = {}
    for name in sorted(metric_names):
        values = [
            record["metrics"][name]
            for record in completed
            if primary_performance_eligible(record) and name in record["metrics"]
        ]
        q1 = quantile(values, 0.25) if values else None
        q3 = quantile(values, 0.75) if values else None
        metrics[name] = {
            "n": len(values),
            "missing_completed": len(completed) - len(values),
            "q1": q1,
            "median": quantile(values, 0.5) if values else None,
            "q3": q3,
            "iqr": q3 - q1 if q1 is not None and q3 is not None else None,
        }
    native_outcomes = {}
    for name in NATIVE_OUTCOMES:
        true = sum(record.get(name) is True for _, record in rows)
        false = sum(record.get(name) is False for _, record in rows)
        observed = true + false
        native_outcomes[name] = {
            "true": true,
            "false": false,
            "missing": len(rows) - observed,
            "observed_denominator": observed,
            "true_proportion": true / observed if observed else None,
        }
    return {
        "total_runs": len(rows),
        "denominator": "observed-records",
        "run_ids": [record["run_id"] for _, record in rows],
        "status_counts": counts,
        "completion_proportion": counts["completed"] / len(rows),
        "native_outcomes": native_outcomes,
        "performance_exclusions": [
            {"run_id": record["run_id"], "reason": primary_performance_exclusion(record)}
            for record in completed
            if not primary_performance_eligible(record)
        ],
        "metrics": metrics,
        "incomplete_runs": [
            {
                "input_index": index,
                "run_id": record["run_id"],
                "status": record["status"],
                "session": record["session"],
            }
            for index, record in rows
            if record["status"] != "completed"
        ],
    }


def summarize(
    records: Sequence[dict[str, Any]], mode: str, *, expected_metrics: Sequence[str] = ()
) -> dict[str, Any]:
    """Keep every run in outcome counts and summarize available completed-run metrics."""
    if mode not in MODES:
        raise ValueError("mode must be synthetic-validation, native-validation, pilot, or formal")
    if not records:
        raise ValueError("at least one measurement record is required")
    if isinstance(expected_metrics, (str, bytes)):
        raise ValueError("expected_metrics must be a sequence of metric names")
    expected_names = set()
    for name in expected_metrics:
        _text(name, "expected metric name")
        expected_names.add(name)
    groups: dict[tuple[Any, ...], list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    seen = set()
    for index, record in enumerate(records):
        _validate(record, mode, index)
        if record["run_id"] in seen:
            raise ValueError(f"duplicate run_id: {record['run_id']}")
        seen.add(record["run_id"])
        condition = tuple(
            record[key].lower() if key == "input_lock_sha256" else record[key] for key in GROUP_KEYS
        )
        groups[condition].append((index, record))
    summaries = []
    for condition, rows in sorted(groups.items(), key=lambda item: json.dumps(item[0])):
        sessions = sorted({record["session"] for _, record in rows})
        names = expected_names | {name for _, record in rows for name in record["metrics"]}
        summaries.append(
            {
                "condition": dict(zip(GROUP_KEYS, condition, strict=True)),
                "replication_unit": "episode" if rows[0][1]["workload"] == "fault" else "run",
                "overall": _summarize_rows(rows, names),
                "sessions": [
                    {
                        "session": session,
                        **_summarize_rows(
                            [row for row in rows if row[1]["session"] == session], names
                        ),
                    }
                    for session in sessions
                ],
            }
        )
    return {
        "schema_version": 1,
        "record_type": "measurement-summary",
        "mode": mode,
        "performance_samples": mode in {"pilot", "formal"},
        "group_keys": list(GROUP_KEYS),
        "quantile_method": "linear interpolation at sorted position (n - 1) * p",
        "metric_population": "completed runs with the named metric; missing values are not zero",
        "status_meaning": (
            "caller-supplied execution outcome; "
            "native recovery and cleanup have separate denominators"
        ),
        "expected_metrics": sorted(expected_names),
        "denominator": "observed-records",
        "inference_pending": [
            "confidence intervals",
            "matched session-aware resampling",
            "planned-case coverage",
        ],
        "total_records": len(records),
        "groups": summaries,
    }


def write_summary(path: Path, summary: dict[str, Any]) -> Path:
    """Write a new summary file while preserving any existing result."""
    serialized = json.dumps(summary, indent=2, allow_nan=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as stream:
        stream.write(serialized)
    return path


def _reject_constant(value: str) -> None:
    raise ValueError(f"JSON contains a nonfinite constant: {value}")


def _load_records(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    content = path.read_bytes()
    data = json.loads(content, parse_constant=_reject_constant)
    if isinstance(data, dict) and data.get("record_type") == "measurement-record":
        records = [data]
    elif isinstance(data, dict) and isinstance(data.get("records"), list):
        records = data["records"]
    elif isinstance(data, list):
        records = data
    else:
        raise ValueError(f"{path} must contain a measurement record or record array")
    return records, {
        "path": str(path.absolute()),
        "records": len(records),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=MODES, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-metric", action="append", default=[])
    parser.add_argument("inputs", type=Path, nargs="+")
    args = parser.parse_args(argv)
    records = []
    inputs = []
    try:
        for path in args.inputs:
            loaded, provenance = _load_records(path)
            records.extend(loaded)
            inputs.append(provenance)
        result = summarize(records, args.mode, expected_metrics=args.expected_metric)
        result["input_files"] = inputs
        write_summary(args.output, result)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
