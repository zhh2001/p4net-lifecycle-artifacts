"""Read observer attempt coverage and matched profile availability without execution."""

from __future__ import annotations

import copy
import fcntl
import hashlib
import json
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from harness.aggregate import quantile
from harness.observer_campaign import SELECTIONS, TERMINAL_STATES, entries_for, read_records

STATES = (*TERMINAL_STATES, "unfinalized", "unattempted")
CONTRASTS = (("S", "B"), ("S", "T"), ("T", "B"))


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def load_snapshot(output: Path, *, base: Path) -> dict[str, Any]:
    """Hold a shared existing lock and read retained files without recovery."""
    output = output.resolve()
    lock = output / ".observer-campaign.lock"
    if lock.is_symlink() or not lock.is_file():
        raise ValueError("observer snapshot requires an existing regular journal lock")
    with lock.open("rb") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("observer journal is currently being changed") from None
        records = read_records(output, base=base)
        for path, expected in records["input_hashes"].items():
            if hashlib.sha256(Path(path).read_bytes()).hexdigest() != expected:
                raise ValueError("observer journal changed during snapshot reading")
        result = {
            "schema_version": 1,
            "record_type": "observer-campaign-snapshot",
            "mode": records["binding"]["mode"],
            "performance_samples": records["binding"]["performance_samples"],
            "read_only": True,
            **records,
        }
        result["snapshot_sha256"] = hashlib.sha256(_canonical(result)).hexdigest()
        return result


def _ratio(count: int, total: int) -> float | None:
    return count / total if total else None


def _available(row: dict[str, Any], name: str) -> bool:
    return (
        row["state"] == "completed"
        and row["measurement"] is not None
        and name in row["measurement"]["metrics"]
    )


def _summary(rows: list[dict[str, Any]], names: set[str]) -> dict[str, Any]:
    counts = {state: sum(row["state"] == state for row in rows) for state in STATES}
    terminal = sum(counts[state] for state in TERMINAL_STATES)
    metrics = {}
    for name in sorted(names):
        available = [row for row in rows if _available(row, name)]
        values = [row["measurement"]["metrics"][name] for row in available]
        metrics[name] = {
            "n": len(values),
            "missing_completed": counts["completed"] - len(values),
            "planned_without_completed_value": len(rows) - len(values),
            "median": quantile(values, 0.5) if values else None,
            "q1": quantile(values, 0.25) if values else None,
            "q3": quantile(values, 0.75) if values else None,
            "planned_ids": [row["planned_id"] for row in available],
        }
    return {
        "planned_units": len(rows),
        "attempted_units": len(rows) - counts["unattempted"],
        "terminal_units": terminal,
        "state_counts": counts,
        "completed_fraction_of_plan": _ratio(counts["completed"], len(rows)),
        "all_planned_terminal": terminal == len(rows) and bool(rows),
        "measurement_qualified_units": sum(
            row["state"] == "completed"
            and row["measurement"] is not None
            and row["measurement"]["qualified"]
            for row in rows
        ),
        "metrics": metrics,
    }


def summarize_snapshot(
    snapshot: dict[str, Any],
    *,
    selection: str,
    phase: str = "calibration",
    sessions: Sequence[int] | None = None,
    expected_metrics: Sequence[str] = (),
) -> dict[str, Any]:
    """Keep first attempts primary and retries in a named supplementary view."""
    if (
        snapshot.get("record_type") != "observer-campaign-snapshot"
        or snapshot.get("read_only") is not True
        or hashlib.sha256(
            _canonical({key: value for key, value in snapshot.items() if key != "snapshot_sha256"})
        ).hexdigest()
        != snapshot.get("snapshot_sha256")
    ):
        raise ValueError("observer snapshot identity or digest differs")
    if selection not in SELECTIONS or phase not in ("qualification", "calibration"):
        raise ValueError("select first/latest attempts and qualification/calibration phase")
    if sessions is not None and (
        phase != "calibration"
        or isinstance(sessions, (str, bytes))
        or not sessions
        or any(type(session) is not int or session not in (1, 2, 3) for session in sessions)
        or len(set(sessions)) != len(sessions)
    ):
        raise ValueError("sessions must contain distinct calibration sessions")
    if isinstance(expected_metrics, (str, bytes)) or any(
        not isinstance(name, str) or not name.strip() for name in expected_metrics
    ):
        raise ValueError("expected metrics must contain nonempty names")
    history: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for attempt in snapshot["attempts"]:
        directory = Path(attempt["directory"])
        history[directory.parent.name].append(attempt)
    rows = []
    names = set(expected_metrics)
    for planned, (entry_phase, entry) in entries_for(snapshot["plan"]).items():
        if entry_phase != phase or (sessions is not None and entry["session"] not in sessions):
            continue
        attempts = sorted(history[planned], key=lambda item: int(Path(item["directory"]).name))
        chosen = attempts[0 if selection == "first-attempt" else -1] if attempts else None
        terminal = chosen["result"] if chosen else None
        measurement = chosen["measurement"] if chosen else None
        if measurement is not None:
            names.update(measurement["metrics"])
        rows.append(
            {
                **copy.deepcopy(entry),
                "planned_id": planned,
                "phase": phase,
                "session": entry.get("session", 0),
                "state": terminal["status"]
                if terminal
                else "unfinalized"
                if chosen
                else "unattempted",
                "attempt_number": int(Path(chosen["directory"]).name) if chosen else None,
                "attempt_id": terminal["attempt_id"]
                if terminal
                else (
                    chosen["started"]["metadata"]["attempt_id"]
                    if chosen and chosen["started"]
                    else None
                ),
                "measurement": measurement,
                "history_attempts": len(attempts),
            }
        )
    conditions = (
        "tool",
        "switches",
        "observer_profile",
        "workload",
        "fault",
        "configuration_profile",
        "build_mode",
    )
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[tuple(row.get(key) for key in conditions)].append(row)
    grouped = []
    for key, members in sorted(groups.items(), key=lambda item: _canonical(item[0])):
        grouped.append(
            {
                "key": dict(zip(conditions, key, strict=True)),
                "overall": _summary(members, names),
                "sessions": {
                    str(session): _summary(
                        [row for row in members if row["session"] == session], names
                    )
                    for session in sorted({row["session"] for row in members})
                },
            }
        )
    blocks: dict[str, list[dict[str, Any]]] = defaultdict(list)
    if phase == "calibration":
        for row in rows:
            blocks[row["matched_block"]].append(row)
    contrasts = []
    for left, right in CONTRASTS:
        by_condition: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
        for label, members in blocks.items():
            profiles = {row["observer_profile"]: row for row in members}
            pair = (profiles[left], profiles[right])
            by_condition[(pair[0]["tool"], pair[0]["switches"])].append(
                {"matched_block": label, "session": pair[0]["session"], "pair": pair}
            )
        for (tool, switches), matched in sorted(by_condition.items()):
            metrics = {}
            for name in sorted(names):
                available = [
                    block
                    for block in matched
                    if all(_available(row, name) for row in block["pair"])
                ]
                metrics[name] = {
                    "eligible_pairs": len(available),
                    "planned_pairs": len(matched),
                    "session_counts": {
                        str(session): sum(block["session"] == session for block in available)
                        for session in sorted({block["session"] for block in matched})
                    },
                    "differences": [
                        {
                            "matched_block": block["matched_block"],
                            "session": block["session"],
                            "difference": block["pair"][0]["measurement"]["metrics"][name]
                            - block["pair"][1]["measurement"]["metrics"][name],
                        }
                        for block in available
                    ],
                    "excluded": [
                        {
                            "matched_block": block["matched_block"],
                            "unavailable": [
                                {
                                    "planned_id": row["planned_id"],
                                    "observer_profile": row["observer_profile"],
                                    "reason": row["state"]
                                    if row["state"] != "completed"
                                    else "missing-completed-metric",
                                }
                                for row in block["pair"]
                                if not _available(row, name)
                            ],
                        }
                        for block in matched
                        if block not in available
                    ],
                }
            contrasts.append(
                {
                    "contrast": f"{left}-{right}",
                    "tool": tool,
                    "switches": switches,
                    "metrics": metrics,
                }
            )
    return {
        "schema_version": 1,
        "record_type": "observer-campaign-coverage",
        "mode": snapshot["mode"],
        "performance_samples": snapshot["performance_samples"],
        "input_lock_sha256": snapshot["binding"]["input_lock_sha256"],
        "snapshot_sha256": snapshot["snapshot_sha256"],
        "selection": selection,
        "analysis_role": "primary" if selection == "first-attempt" else "supplementary",
        "phase": phase,
        "overall": _summary(rows, names),
        "groups": grouped,
        "complete_profile_blocks": sum(
            all(row["state"] == "completed" for row in members) for members in blocks.values()
        ),
        "metric_complete_profile_blocks": {
            name: sum(all(_available(row, name) for row in members) for members in blocks.values())
            for name in sorted(names)
        },
        "contrasts": contrasts,
        "attempt_history": {row["planned_id"]: history[row["planned_id"]] for row in rows},
        "gate_reviews": copy.deepcopy(snapshot["gate_reviews"]),
    }
