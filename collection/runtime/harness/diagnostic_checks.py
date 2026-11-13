"""Assess diagnostic completeness separately from the native workflow outcome."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from diagnostic.trace import summarize


def assess_trace(
    path: Path, case: dict[str, Any], tool: dict[str, Any], *, phase: str = "initial"
) -> dict[str, Any]:
    try:
        return _assess_trace(path, case, tool, phase=phase)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return {
            "qualified": False,
            "trace_complete": False,
            "issues": [f"{type(exc).__name__}: {exc}"],
            "native_outcome": None,
        }


def _assess_trace(
    path: Path, case: dict[str, Any], tool: dict[str, Any], *, phase: str
) -> dict[str, Any]:
    summary = summarize(path)
    issues = list(summary["issues"])
    if summary["profile"] != case["profile"]:
        issues.append("trace profile differs from the prepared case")
    selected = {
        row["stage"]
        for row in tool["hooks"]
        if case["profile"] == "detail" or (case["profile"] == "stages" and row["level"] == "stages")
    }
    allowed = {row["stage"] for row in tool["hooks"] if row["kind"] == "span"} & selected
    counts = Counter(row["stage"] for row in summary["spans"])
    if set(counts) - allowed:
        issues.append("trace contains an unknown or unselected stage")
    metadata = summary["metadata"]
    if metadata.get("worker_invoked") is not True:
        issues.append("native worker was not invoked")
    coverage = metadata.get("hook_coverage", [])
    expected = {(row["module"], row["owner"], row["member"], row["stage"]) for row in tool["hooks"]}
    actual = {(r["module"], r["owner"], r["member"], r["stage"]) for r in coverage}
    if actual != expected or len(actual) != len(coverage):
        issues.append("hook coverage identities differ")
    required = set(case["required_stages"])
    if phase == "restart":
        required = allowed
    for row in coverage:
        if row["selected"] != (row["stage"] in selected):
            issues.append("hook selection differs")
        if row["stage"] in required and not row["installed"]:
            issues.append("required hook was not installed: " + row["stage"])
    missing = sorted(required - set(counts))
    if missing:
        issues.append("required stages were not called: " + ", ".join(missing))
    if case["profile"] == "off" and summary["spans"]:
        issues.append("off profile contains stage spans")
    return {
        "qualified": not issues,
        "trace_complete": summary["complete"],
        "issues": issues,
        "phase": phase,
        "stage_calls": dict(sorted(counts.items())),
        "required_stages_missing": missing,
        "selected_stages_without_calls": sorted(allowed - set(counts)),
        "native_outcome": metadata.get("worker_outcome"),
        "performance_samples": False,
    }
