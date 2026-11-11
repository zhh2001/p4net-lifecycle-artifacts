"""Recompute matched effects from the published per-task observations."""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from . import binomial_intervals, median_intervals, resampling

CAMPAIGNS = ("formal", "observer", "diagnostic")
SESSIONS = [1, 2, 3]
FLAGS = (
    "ordinary_stop_timeout",
    "ordinary_cleanup_clean",
    "restart_ordinary_stop_timeout",
    "restart_ordinary_cleanup_clean",
    "recovery_success",
    "framework_complete",
)


def read(path: Path) -> Any:
    return json.loads(path.read_text())


def write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def exclusion(row: dict[str, Any]) -> str | None:
    """Apply both initial and restart cleanup rules before using a metric."""
    if row["state"] != "completed":
        return "not-completed"
    fields = row["eligibility"]
    if any(fields.get(key) is not None and type(fields[key]) is not bool for key in FLAGS):
        return "invalid-native-outcome"
    if not isinstance(fields["measurement_issues"], list):
        return "invalid-measurement-issues"
    if any(
        fields.get(key) is True
        for key in ("ordinary_stop_timeout", "restart_ordinary_stop_timeout")
    ):
        return "ordinary-stop-timeout"
    if any(
        fields.get(key) is False
        for key in ("ordinary_cleanup_clean", "restart_ordinary_cleanup_clean")
    ):
        return "ordinary-cleanup-incomplete"
    return "measurement-issues" if fields["measurement_issues"] else None


def check_integrity(data: Path) -> int:
    root = data.resolve().parent
    manifest = read(data / "manifest.json")
    for relative, expected in manifest["sha256"].items():
        target = (root / relative).resolve()
        if not target.is_relative_to(root):
            raise ValueError("manifest path escapes the artifact root")
        if hashlib.sha256(target.read_bytes()).hexdigest() != expected:
            raise ValueError(f"content hash differs: {relative}")
    return len(manifest["sha256"])


def load_records(data: Path) -> dict[str, list[dict[str, Any]]]:
    datasets = {campaign: read(data / campaign / "records.json") for campaign in CAMPAIGNS}
    for campaign, expected in zip(CAMPAIGNS, (990, 270, 360), strict=True):
        rows = datasets[campaign]
        if len(rows) != expected or len({row["id"] for row in rows}) != expected:
            raise ValueError(f"{campaign} requires {expected} distinct first attempts")
        for row in rows:
            if row["attempt"] != 1 or row["session"] not in SESSIONS:
                raise ValueError("unexpected attempt or session")
            for value in row["metrics"].values():
                if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                    raise ValueError("metrics must be finite, nonnegative numeric observations")
            if campaign == "formal" and exclusion(row) != row["eligibility"]["exclusion"]:
                raise ValueError("stored performance eligibility differs from the phase rules")
    return datasets


def usable(row: dict[str, Any], campaign: str) -> bool:
    if campaign == "formal":
        return exclusion(row) is None
    if campaign == "observer":
        return row["state"] == "completed" and row["qualified"] and row["treatment_valid"]
    return row["primary_performance_eligible"]


def select(rows: list[dict[str, Any]], spec: dict[str, Any]) -> list[dict[str, Any]]:
    if spec["campaign"] == "formal":
        return [
            r for r in rows if r["condition"] == spec["condition"] and r["tool"] in spec["levels"]
        ]
    return [
        r
        for r in rows
        if all(r[key] == value for key, value in spec["condition"].items())
        and r["profile"] in spec["levels"]
    ]


def seed_for(spec: dict[str, Any], scheme: str) -> int:
    if spec["campaign"] == "observer":
        identity = [
            20261029,
            "observer-calibration",
            "-".join(spec["levels"]),
            spec["condition"]["tool"],
            spec["condition"]["switches"],
            spec["metric"],
            scheme,
        ]
    else:
        identity = [20261029, spec["condition"], spec["levels"], spec["metric"], scheme]
    content = json.dumps(identity, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return int.from_bytes(hashlib.sha256(content.encode()).digest()[:8], "big") % 2**63


def comparison(
    rows: list[dict[str, Any]], spec: dict[str, Any], *, bootstrap: bool = False
) -> dict[str, Any]:
    campaign, levels, metric = (spec[key] for key in ("campaign", "levels", "metric"))
    blocks: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    level_key = "tool" if campaign == "formal" else "profile"
    for row in select(rows, spec):
        if row[level_key] in blocks[row["block"]]:
            raise ValueError("duplicate treatment within a matched block")
        blocks[row["block"]][row[level_key]] = row
    if len(blocks) != spec["planned_pairs"]:
        raise ValueError("planned matched-block coverage differs")
    strata: dict[int, list[int | float]] = {s: [] for s in SESSIONS}
    pairs, excluded = [], []
    for block, members in sorted(blocks.items()):
        if set(members) != set(levels):
            raise ValueError("matched block is missing a treatment")
        left, right = (members[level] for level in levels)
        if left["session"] != right["session"]:
            raise ValueError("paired observations must share a session")
        reasons = []
        for row in (left, right):
            if not usable(row, campaign):
                reasons.append(
                    {
                        "id": row["id"],
                        "reason": exclusion(row) if campaign == "formal" else "not-qualified",
                    }
                )
            elif metric not in row["metrics"]:
                reasons.append({"id": row["id"], "reason": "missing-completed-metric"})
        if reasons:
            excluded.append({"block": block, "reasons": reasons})
            continue
        a, b = left["metrics"][metric], right["metrics"][metric]
        difference = a - b
        strata[left["session"]].append(difference)
        pairs.append(
            {
                "block": block,
                "session": left["session"],
                "ids": [left["id"], right["id"]],
                "left_value": a,
                "right_value": b,
                "difference": difference,
            }
        )
    result = {
        **spec,
        "primary": median_intervals.rank_median(strata, expected_sessions=SESSIONS),
        "pairs": pairs,
        "excluded": excluded,
    }
    if bootstrap:
        result["bootstrap"] = {
            scheme: resampling.bootstrap_median(
                strata,
                expected_sessions=SESSIONS,
                scheme=scheme,
                seed=seed_for(spec, scheme),
                resamples=10000,
            )
            for scheme in ("fixed-session", "hierarchical-session")
        }
    return result


def native_outcomes(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        c = row["condition"]
        groups[c["workload"], c["switches"], c["fault"], row["tool"]].append(row)
    output = []
    for (workload, switches, fault, tool), members in sorted(
        groups.items(), key=lambda x: str(x[0])
    ):
        counts: Counter[str] = Counter()
        for row in members:
            counts.update({key: int(value is True) for key, value in row["outcomes"].items()})
            counts["performance_eligible"] += int(usable(row, "formal"))
        output.append(
            {
                "workload": workload,
                "switches": switches,
                "fault": fault,
                "tool": tool,
                "planned_units": len(members),
                "counts": dict(counts),
                "protocol_completion": binomial_intervals.exact_interval(
                    counts["protocol_completed"], len(members)
                ),
            }
        )
    return output


def verify_expected(
    data: Path, results: list[dict[str, Any]], outcomes: list[dict[str, Any]], *, bootstrap: bool
) -> None:
    expected = read(data / "expected-comparisons.json")
    if len(results) != len(expected):
        raise ValueError("comparison coverage differs from the reference results")
    for observed, frozen in zip(results, expected, strict=True):
        if any(
            observed[k] != frozen[k]
            for k in ("campaign", "condition", "levels", "metric", "primary")
        ):
            raise ValueError(
                f"primary comparison differs: {observed['campaign']} {observed['metric']} "
                f"{observed['condition']}"
            )
        if bootstrap and observed["bootstrap"] != frozen["bootstrap"]:
            raise ValueError(
                f"bootstrap comparison differs: {observed['campaign']} {observed['metric']}"
            )
    for observed, frozen in zip(outcomes, read(data / "expected-outcomes.json"), strict=True):
        if any(
            observed[k] != frozen[k]
            for k in ("workload", "switches", "fault", "tool", "planned_units")
        ):
            raise ValueError("outcome group differs")
        if any(observed["counts"].get(k, 0) != v for k, v in frozen["counts"].items()):
            raise ValueError("native outcome counts differ")


def reproduce(data: Path, output: Path, *, bootstrap: bool = False) -> dict[str, Any]:
    checked_files = check_integrity(data)
    datasets = load_records(data)
    specs = read(data.parent / "protocol/comparisons.json")
    results = [comparison(datasets[spec["campaign"]], spec, bootstrap=bootstrap) for spec in specs]
    outcomes = native_outcomes(datasets["formal"])
    verify_expected(data, results, outcomes, bootstrap=bootstrap)
    summary = {
        "tasks": {key: len(rows) for key, rows in datasets.items()},
        "formal_performance_eligible": sum(usable(r, "formal") for r in datasets["formal"]),
        "formal_performance_excluded": sum(not usable(r, "formal") for r in datasets["formal"]),
        "comparisons": len(results),
        "available_intervals": sum(r["primary"]["status"] == "ok" for r in results),
        "verified_input_files": checked_files,
        "all_reference_comparisons_match": True,
        "bootstrap_recomputed": bootstrap,
        "bootstrap_resamples": 10000 if bootstrap else 0,
    }
    write(output / "comparisons.json", results)
    write(output / "outcomes.json", outcomes)
    write(output / "summary.json", summary)
    from .tables import export_tables

    export_tables(data, output, results, outcomes)
    return summary
