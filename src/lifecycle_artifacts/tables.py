"""Export the nine manuscript tables and the complete matched-effect grid."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any


def save(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def interval(row: dict[str, Any], factor: float = 1) -> dict[str, Any]:
    estimate = row["primary"]
    bounds = estimate["interval"]
    return {
        "pairs": estimate["total_n"],
        "median": None
        if estimate["point_estimate"] is None
        else estimate["point_estimate"] * factor,
        "lower": None if bounds is None else bounds["lower"] * factor,
        "upper": None if bounds is None else bounds["upper"] * factor,
    }


def find(
    results: list[dict[str, Any]],
    campaign: str,
    metric: str,
    condition: dict[str, Any],
    levels: list[str],
) -> dict[str, Any]:
    matches = [
        r
        for r in results
        if r["campaign"] == campaign
        and r["metric"] == metric
        and r["levels"] == levels
        and all(r["condition"][k] == v for k, v in condition.items())
    ]
    if len(matches) != 1:
        raise ValueError("the requested table comparison is missing or duplicated")
    return matches[0]


def export_tables(
    data: Path, output: Path, results: list[dict[str, Any]], outcomes: list[dict[str, Any]]
) -> None:
    folder = output / "tables"
    save(
        folder / "table-01-dependencies.csv",
        [
            {"package": "grpcio", "p4net": "1.85.0", "p4utils": "1.44.0", "tutorial": "1.84.1"},
            {"package": "protobuf", "p4net": "7.36.2", "p4utils": "3.20.3", "tutorial": "7.36.2"},
            {"package": "p4runtime", "p4net": "1.6.0", "p4utils": "1.5.0", "tutorial": "1.6.0"},
        ],
    )
    save(
        folder / "table-02-allocation.csv",
        [
            {
                "campaign": "Formal scale",
                "switches": "1,2,4,8,16",
                "conditions": "normal",
                "repetitions_per_session": 10,
                "tasks": 450,
            },
            {
                "campaign": "Formal fault/control",
                "switches": "4",
                "conditions": "6",
                "repetitions_per_session": 10,
                "tasks": 540,
            },
            {
                "campaign": "Observer calibration",
                "switches": "1,16",
                "conditions": "B,T,S",
                "repetitions_per_session": 5,
                "tasks": 270,
            },
            {
                "campaign": "Diagnostic calibration",
                "switches": "1,16",
                "conditions": "native,off,stages,detail",
                "repetitions_per_session": 5,
                "tasks": 360,
            },
        ],
    )
    faults = [
        "normal-control",
        "invalid-p4",
        "occupied-grpc",
        "sigint-startup",
        "kill-bmv2",
        "drop-control",
    ]
    descriptions = [
        "Orderly stop after validated readiness and idle observation",
        "Invalid P4 source before compilation; restore the valid source after initial audit",
        "Occupied first-switch gRPC port before launch; release listener after initial audit",
        "SIGINT after the first owned veth is observed before the ready marker",
        "SIGKILL the verified first BMv2 process after readiness and idle observation",
        "Drop traffic to the first switch control endpoint; remove rule after initial audit",
    ]
    save(
        folder / "table-03-interventions.csv",
        [{"fault": f, "procedure": p} for f, p in zip(faults, descriptions, strict=True)],
    )
    rows = []
    for fault in faults:
        row: dict[str, Any] = {"condition": fault}
        for tool in ("p4net", "p4utils", "tutorial-components"):
            group = next(g for g in outcomes if g["fault"] == fault and g["tool"] == tool)
            row[tool + "_clean"] = group["counts"]["initial_ordinary_cleanup_clean"]
            row[tool + "_planned"] = group["planned_units"]
        rows.append(row)
    save(folder / "table-04-cleanup.csv", rows)
    for number, filename, metric, factor in (
        (5, "startup", "task_to_ready_ns", 1e-9),
        (6, "stop", "stop_to_exit_ns", 1e-9),
        (7, "worker-pss", "idle_worker_pss_bytes", 1 / 2**20),
    ):
        rows = []
        for n in (1, 2, 4, 8, 16):
            for baseline in ("p4utils", "tutorial-components"):
                result = find(
                    results,
                    "formal",
                    metric,
                    {"workload": "scale", "switches": n},
                    ["p4net", baseline],
                )
                rows.append({"switches": n, "baseline": baseline, **interval(result, factor)})
        save(folder / f"table-{number:02}-{filename}.csv", rows)
    rows = []
    for n in (1, 16):
        for tool in ("p4net", "p4utils", "tutorial-components"):
            row = {"tool": tool, "switches": n}
            for metric, label, factor in (
                ("observer_cpu_seconds", "cpu_s", 1),
                ("observer_pss_bytes", "pss_mib", 1 / 2**20),
            ):
                result = find(
                    results, "observer", metric, {"tool": tool, "switches": n}, ["S", "T"]
                )
                row.update(
                    {f"{label}_{key}": value for key, value in interval(result, factor).items()}
                )
            rows.append(row)
    save(folder / "table-08-observer.csv", rows)
    rows = []
    for n in (1, 16):
        for profile in ("stages", "detail"):
            row = {"switches": n, "profile": profile}
            for metric, label, factor in (
                ("reference_body_wall_ns", "wall_ms", 1e-6),
                ("worker_cpu_end_ticks", "cpu_ms", 10),
                ("worker_ready_pss_bytes", "pss_mib", 1 / 2**20),
            ):
                result = find(
                    results,
                    "diagnostic",
                    metric,
                    {"tool": "p4net", "switches": n},
                    [profile, "native"],
                )
                row.update(
                    {f"{label}_{key}": value for key, value in interval(result, factor).items()}
                )
            rows.append(row)
    save(folder / "table-09-diagnostic.csv", rows)
    save(
        output / "all-comparisons.csv",
        [
            {
                "campaign": r["campaign"],
                "tool": r["condition"].get("tool", ""),
                "switches": r["condition"]["switches"],
                "workload": r["condition"].get("workload", "scale"),
                "fault": r["condition"].get("fault"),
                "left": r["levels"][0],
                "right": r["levels"][1],
                "metric": r["metric"],
                **interval(r),
                "status": r["primary"]["status"],
                "reason": r["primary"]["reason"],
            }
            for r in results
        ],
    )
