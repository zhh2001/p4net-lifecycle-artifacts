"""Prepare an offline observer-calibration allocation without executing workloads."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from collections.abc import Sequence
from itertools import permutations, product
from pathlib import Path
from typing import Any

from harness import campaign

DEFAULT_SEED = 2026103001
SCOPES = ("qualification-only", "qualification-and-calibration")
PROFILES = ("B", "T", "S")
SCALES = (1, 16)
SESSIONS = 3
BLOCKS = 5
HOLD_NS = 10_000_000_000
INTERVAL_NS = 100_000_000
DEFERRED_FEATURES = (
    "three explicit observation profiles",
    "common hold anchor and equal hold implementation",
    "reference-process IPC checkpoints before launch and after final publication",
    "host observer PID and namespace identity mapping",
    "external observer and reference CPU tick endpoints",
    "post-publication endpoint RSS/PSS collection",
    "negative controls and live measurement qualification",
)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _ordered(values: Sequence[Any], seed: int, *identity: Any) -> list[Any]:
    return sorted(
        values,
        key=lambda value: (
            hashlib.sha256(_canonical([seed, *identity, value])).digest(),
            _canonical(value),
        ),
    )


def _profile_orders(seed: int, tool: str, switches: int) -> dict[int, list[tuple[str, ...]]]:
    orders = tuple(permutations(PROFILES))
    first = _ordered(orders, seed, "omitted-cycle", tool, switches)[0]
    cycle = [first[offset:] + first[:offset] for offset in range(3)]
    omitted = _ordered(cycle, seed, "omitted-session", tool, switches)
    return {
        session: _ordered(
            [order for order in orders if order != omitted[session - 1]],
            seed,
            "profile-order",
            tool,
            switches,
            session,
        )
        for session in range(1, SESSIONS + 1)
    }


def _profiles() -> list[dict[str, Any]]:
    return [
        {
            "profile": profile,
            "label": label,
            "boundary_and_target_checks": True,
            "ordinary_audit_and_cleanup": True,
            "internal_recorder": profile != "B",
            "resource_sampler": profile == "S",
            "hold_duration_ns": HOLD_NS,
            "hold_anchor": "after validated readiness and verified target identification",
            "sampling_interval_ns": INTERVAL_NS if profile == "S" else None,
            "expected_resource_endpoints": 101 if profile == "S" else 0,
            "planned_collection_mode": "pilot",
            "external_reference_required": True,
            "runtime_ready": False,
        }
        for profile, label in (
            ("B", "boundary-only"),
            ("T", "timestamps-only"),
            ("S", "sampled"),
        )
    ]


def _qualification(seed: int, tools: tuple[str, ...]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for stage, switches, workload, fault in (
        (1, 1, "scale", None),
        (2, 4, "fault", "normal-control"),
        (3, 16, "scale", None),
    ):
        for tool in _ordered(tools, seed, "qualification", stage):
            rows.append(
                {
                    "planned_parent_id": f"live-qual-stage{stage:02}-n{switches:02}-{tool}",
                    "sequence": len(rows) + 1,
                    "stage": stage,
                    "requires_preceding_stage_qualified": stage > 1,
                    "tool": tool,
                    "switches": switches,
                    "hosts": 2 * switches,
                    "workload": workload,
                    "fault": fault,
                    "observer_profile": "S",
                    "expected_windows": ["initial", "restart"] if fault else ["initial"],
                    "build_mode": campaign.BUILD_MODE,
                    "configuration_profile": "matched-v1",
                    "execution_status": "planned-not-executable",
                }
            )
    return rows


def generate(
    seed: int = DEFAULT_SEED, *, scope: str = "qualification-and-calibration"
) -> dict[str, Any]:
    """Return a deterministic candidate allocation with no runtime authorization."""
    if type(seed) is not int or not 0 <= seed <= 2**63 - 1:
        raise ValueError("seed must be an integer from 0 to 2**63 - 1")
    if not isinstance(scope, str) or scope not in SCOPES:
        raise ValueError("scope must be qualification-only or qualification-and-calibration")
    tools = tuple(item["tool"] for item in campaign.TOOLS)
    qualification = _qualification(seed, tools)
    schedule: list[dict[str, Any]] = []
    if scope == "qualification-and-calibration":
        profile_orders = {
            (tool, switches): _profile_orders(seed, tool, switches)
            for tool, switches in product(tools, SCALES)
        }
        for session in range(1, SESSIONS + 1):
            blocks = _ordered(
                list(product(tools, SCALES, range(1, BLOCKS + 1))),
                seed,
                "calibration-blocks",
                session,
            )
            if session == 1:
                gate_blocks = _ordered(
                    [(tool, 1, 1) for tool in tools], seed, "initial-calibration-wiring-gate"
                )
                blocks = gate_blocks + [
                    block for block in blocks if not (block[1] == 1 and block[2] == 1)
                ]
            for tool, switches, block in blocks:
                label = f"observer-s{session:02}-n{switches:02}-b{block:02}-{tool}"
                order = profile_orders[tool, switches][session][block - 1]
                for position, profile in enumerate(order, start=1):
                    schedule.append(
                        {
                            "planned_task_id": f"{label}-{profile}",
                            "sequence": len(schedule) + 1,
                            "session": session,
                            "tool": tool,
                            "switches": switches,
                            "hosts": 2 * switches,
                            "block": block,
                            "matched_block": label,
                            "observer_profile": profile,
                            "profile_order": list(order),
                            "position_within_block": position,
                            "workload": "scale",
                            "fault": None,
                            "build_mode": campaign.BUILD_MODE,
                            "configuration_profile": "matched-v1",
                            "execution_status": "planned-not-executable",
                        }
                    )
    plan: dict[str, Any] = {
        "schema_version": 1,
        "record_type": "offline-observer-calibration-plan",
        "design_status": "offline-draft",
        "mode": "offline-planning",
        "performance_samples": False,
        "runtime_ready": False,
        "collection_authorized": False,
        "execution_status": "planned-not-executable",
        "scope": scope,
        "seed": seed,
        "seed_scope": "allocation ordering only",
        "ordering": "SHA-256 keyed deterministic ranking; no system clock or entropy source",
        "tools": copy.deepcopy(list(campaign.TOOLS)),
        "python": "3.10.20",
        "profiles": _profiles(),
        "qualification_schedule": qualification,
        "calibration_allocation": (
            {
                "sessions": SESSIONS,
                "blocks_per_session": BLOCKS,
                "switch_counts": list(SCALES),
                "profiles_per_block": list(PROFILES),
                "permutation_balance": "each of six orders appears two or three times",
                "position_balance": "each profile appears five times per position per tool/scale",
            }
            if schedule
            else None
        ),
        "calibration_schedule": schedule,
        "initial_calibration_wiring_gate": (
            {
                "matched_block_ids": [row["matched_block"] for row in schedule[:9:3]],
                "planned_task_ids": [row["planned_task_id"] for row in schedule[:9]],
                "tasks": 9,
                "scope": "session 1; N1 block 1; all tools and profiles",
                "purpose": (
                    "first-live qualification covers S only; this gate qualifies B/T/S "
                    "profile and paired-reference wiring before the remaining allocation"
                ),
                "later_tasks_require_gate_qualified": True,
                "first_attempts_remain_in_calibration_denominator": True,
                "failure_policy": (
                    "retain first outcomes; keep not-yet-started rows unattempted; "
                    "no automatic retry"
                ),
                "execution_status": "planned-not-executable",
            }
            if schedule
            else None
        ),
        "statistics": {
            "pairing_keys": ["session", "tool", "switches", "block"],
            "contrasts": ["S-B", "S-T", "T-B"],
            "effect": "median of within-block profile differences",
            "attempt_selection": "first attempt primary; explicit retries retained separately",
            "pair_eligibility": "per contrast; both selected outcomes and named metrics available",
            "reference_scope": (
                "profile increments relative to shared boundary checks and reference"
            ),
        },
        "deferred_features": list(DEFERRED_FEATURES),
        "formal_allocation": {
            "changed": False,
            "parent_units": 990,
            "scheduled_worker_executions": 1530,
            "relationship": "separate qualification and calibration; no formal rows replaced",
        },
        "summary": {
            "qualification_parent_units": len(qualification),
            "qualification_windows": sum(len(row["expected_windows"]) for row in qualification),
            "calibration_tasks": len(schedule),
            "calibration_matched_blocks": len(schedule) // 3,
        },
        "plan_hash_scope": "allocation identity only; not an execution input binding",
    }
    plan["plan_sha256"] = hashlib.sha256(_canonical(plan)).hexdigest()
    return plan


def validate_plan(value: Any) -> None:
    """Reject changed rows, controls, or authorization flags by canonical regeneration."""
    if not isinstance(value, dict):
        raise ValueError("plan must be a JSON object")
    try:
        expected = generate(value["seed"], scope=value["scope"])
        if _canonical(value) != _canonical(expected):
            raise ValueError("plan differs from its deterministic allocation and draft controls")
    except (KeyError, TypeError, OverflowError) as exc:
        raise ValueError("invalid observer-calibration plan") from exc


def write_plan(path: Path, value: dict[str, Any]) -> None:
    """Publish a validated new draft without replacing an existing file."""
    validate_plan(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--scope", choices=SCOPES, default="qualification-and-calibration")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args(argv)
    try:
        write_plan(args.output, generate(args.seed, scope=args.scope))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
