"""Generate an offline experiment schedule without launching any workload."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

TOOLS = (
    {
        "tool": "p4net",
        "version": "1.8.0",
        "wheel_sha256": "3256de0bf1586bf1baba711eee20c3e514ebaa93d4eb1aa6005e829c75d16544",
    },
    {"tool": "p4utils", "revision": "83b118bbae530b31cc74e7fa32f9174f7c0a1184"},
    {"tool": "tutorial-components", "revision": "15d780e5ac7046aa64d64270ab0ef3852f1103f9"},
)
SCALES = (1, 2, 4, 8, 16)
BUILD_MODE = "native-source-cold"

FAULTS: tuple[dict[str, Any], ...] = (
    {
        "fault": "invalid-p4",
        "trigger": "before-compilation",
        "action": "Supply a shared, deliberately invalid P4 source variant before worker launch.",
        "eligibility": "The invalid source is the only task input change; retain its content hash.",
        "detection": "Record the compiler outcome, reported error, and stage of rejection.",
        "teardown": "Inventory resources after the failed workflow and requested cleanup.",
        "restart": "Restore the correct shared source before the next valid worker launch.",
        "boundary": "Compilation order and prior cleanup are native workflow behavior.",
    },
    {
        "fault": "occupied-grpc",
        "trigger": "listener-confirmed-before-worker-launch",
        "action": "Bind the first switch's gRPC port inside the episode's inner network.",
        "eligibility": "Confirm the supervisor-owned listener and record its identity separately.",
        "detection": "Record startup rejection or timeout and verify listener ownership.",
        "teardown": "Exclude the injected listener from tool residuals and confirm it survives.",
        "restart": "Release the listener after the first residual snapshot, before restart.",
        "boundary": "Listener release is fixture removal, not successful cleanup by the tool.",
    },
    {
        "fault": "sigint-startup",
        "trigger": "first-owned-veth-observed-before-ready",
        "action": "Send SIGINT to the identity-verified worker after an external resource event.",
        "eligibility": "A run-owned veth is observable and the worker's ready marker is absent.",
        "detection": "Record signal delivery, worker response, and interrupted startup stage.",
        "teardown": "Observe ordinary cleanup before any generic rescue.",
        "restart": "Launch the next valid task in the same outer isolation.",
        "boundary": "Use no fixed sleep; retain a missed trigger as its own outcome.",
    },
    {
        "fault": "kill-bmv2",
        "trigger": "ready-and-first-switch-identity-confirmed",
        "action": "Send SIGKILL to the first switch's verified BMv2 PID and kernel start time.",
        "eligibility": "Connectivity is verified, and the BMv2 identity belongs to this episode.",
        "detection": "Issue a common bounded P4Runtime Read probe after confirmed process exit.",
        "teardown": "Request network teardown and preserve the first residual snapshot.",
        "restart": "Run a fresh valid task after the permitted cleanup procedure.",
        "boundary": "Only BMv2 is killed. Detection uses an explicit experiment probe.",
    },
    {
        "fault": "drop-control",
        "trigger": "ready-and-control-endpoint-ownership-confirmed",
        "action": "Block the first switch's recorded P4Runtime endpoint within the inner network.",
        "eligibility": "Verify the owned control connection; preserve BMv2 and data-plane links.",
        "detection": "Issue the same bounded Read probe while reconnection remains blocked.",
        "teardown": "Request network teardown while the endpoint remains blocked, then audit.",
        "restart": "Remove the endpoint rule after the original snapshot and before valid restart.",
        "boundary": (
            "Rule removal is fixture handling; the explicit probe is not automatic monitoring."
        ),
    },
)

CONTROL: dict[str, Any] = {
    "fault": "normal-control",
    "trigger": "normal-ready-followed-by-orderly-stop",
    "action": "Complete the valid task and request ordinary shutdown without fault injection.",
    "eligibility": "The initial task satisfies the same connectivity and ownership checks.",
    "detection": "No fault detection measurement applies to this condition.",
    "teardown": "Audit the ordinary teardown before the next launch.",
    "restart": "Launch a second valid task in the same outer isolation.",
    "boundary": "Stop-to-next-ready is a restart reference, not a paired fault-injection clock.",
}


def _positive_integer(value: int, name: str) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _ordered(labels: tuple[str, ...], seed: int, *block: str | int) -> list[str]:
    """Rank labels by a stable seeded digest independently of interpreter RNG versions."""

    def score(label: str) -> tuple[bytes, str]:
        payload = json.dumps([seed, *block, label], separators=(",", ":")).encode()
        return hashlib.sha256(payload).digest(), label

    return sorted(labels, key=score)


def generate(
    seed: int = 20261027, sessions: int = 3, repetitions_per_session: int = 10
) -> dict[str, Any]:
    """Return planned conditions and schedules; no execution capability is included."""
    if type(seed) is not int or not 0 <= seed <= 2**63 - 1:
        raise ValueError("seed must be an integer from 0 to 2**63 - 1")
    _positive_integer(sessions, "sessions")
    _positive_integer(repetitions_per_session, "repetitions_per_session")
    repetitions = sessions * repetitions_per_session
    tools = tuple(item["tool"] for item in TOOLS)
    scales = tuple(str(n) for n in SCALES)
    fault_names = tuple(item["fault"] for item in (*FAULTS, CONTROL))
    scale_schedule: list[dict[str, Any]] = []
    fault_schedule: list[dict[str, Any]] = []
    for session in range(1, sessions + 1):
        for repetition in range(1, repetitions_per_session + 1):
            for scale in _ordered(scales, seed, "scale", session, repetition):
                n = int(scale)
                for tool in _ordered(tools, seed, "scale", session, repetition, n):
                    case = f"scale-s{session:02}-r{repetition:02}-n{n:02}-{tool}"
                    scale_schedule.append(
                        {
                            "planned_case_id": case,
                            "sequence": len(scale_schedule) + 1,
                            "execution_status": "planned",
                            "session": session,
                            "repetition_within_session": repetition,
                            "matched_block": f"scale-s{session:02}-r{repetition:02}-n{n:02}",
                            "tool": tool,
                            "switches": n,
                            "hosts": 2 * n,
                            "build_mode": BUILD_MODE,
                            "configuration_profile": "matched-v1",
                        }
                    )
            for fault in _ordered(fault_names, seed, "fault", session, repetition):
                for tool in _ordered(tools, seed, "fault", session, repetition, fault):
                    episode = f"fault-s{session:02}-r{repetition:02}-{fault}-{tool}"
                    fault_schedule.append(
                        {
                            "planned_episode_id": episode,
                            "sequence": len(fault_schedule) + 1,
                            "execution_status": "planned",
                            "implementation_status": (
                                "functional-episode-validated-performance-pending"
                            ),
                            "session": session,
                            "repetition_within_session": repetition,
                            "matched_block": f"fault-s{session:02}-r{repetition:02}-{fault}",
                            "tool": tool,
                            "switches": 4,
                            "hosts": 8,
                            "build_mode": BUILD_MODE,
                            "configuration_profile": "matched-v1",
                            "fault": fault,
                            "isolation_scope": "same-outer-isolation-for-entire-episode",
                            "restart_configuration": "same-node-names-addresses-and-service-ports",
                            "executions": [
                                {
                                    "planned_execution_id": episode + "-initial",
                                    "role": "normal" if fault == "normal-control" else "challenged",
                                    "execution_status": "planned",
                                },
                                {
                                    "planned_execution_id": episode + "-restart",
                                    "role": "next-valid-restart",
                                    "execution_status": "planned",
                                },
                            ],
                        }
                    )
    scale_runs = len(SCALES) * len(tools) * repetitions
    injected_episodes = len(FAULTS) * len(tools) * repetitions
    control_episodes = len(tools) * repetitions
    total_episodes = injected_episodes + control_episodes
    return {
        "schema_version": 1,
        "record_type": "offline-experiment-plan",
        "plan_status": "proposed-allocation",
        "execution_status": "planned",
        "campaign_runner_implemented": True,
        "functional_episode_runner_implemented": True,
        "measurement_tools_implemented": True,
        "native_measurement_integration_implemented": True,
        "measurement_defaults": {
            "idle_window_ns": 10_000_000_000,
            "sampling_interval_ns": 100_000_000,
            "status": "user-confirmed-for-implementation-pending-pilot-freeze",
        },
        "functional_qualification": {
            "configuration_profile": "matched-v1",
            "switch_counts": list(SCALES),
            "fault_episode_switches": 4,
            "environment": "WSL2",
            "large_scale_records": "qualification.json",
            "large_scale_mapping_audit": "qualification.json",
            "performance_samples": False,
        },
        "performance_samples": False,
        "python": "3.10.20",
        "topology": "independent-switch-groups-with-two-hosts-each",
        "tools": [dict(item) for item in TOOLS],
        "allocation": {
            "seed": seed,
            "sessions": sessions,
            "repetitions_per_session": repetitions_per_session,
            "repetitions_per_condition": repetitions,
            "session_role": "blocking-factor-not-an-additional-condition",
            "randomization": "sha256-ranked labels within session/repetition/condition blocks",
        },
        "primary_build_mode": BUILD_MODE,
        "primary_configuration_selection": "user-confirmed-matched-v1",
        "available_configuration_profiles": ["native", "matched-v1"],
        "secondary_build_modes": [
            {"mode": "common-precompiled", "status": "pending-adapter-and-control-validation"},
            {"mode": "native-prepared-cache", "status": "pending-reuse-path-validation"},
        ],
        "fault_conditions": [
            dict(item, implementation_status="functional-episode-validated")
            for item in (*FAULTS, CONTROL)
        ],
        "summary": {
            "scale_conditions": len(SCALES) * len(tools),
            "scale_worker_executions": scale_runs,
            "fault_conditions_including_control": len(fault_names) * len(tools),
            "fault_injected_episodes": injected_episodes,
            "fault_control_episodes": control_episodes,
            "fault_episodes": total_episodes,
            "fault_worker_executions": total_episodes * 2,
            "independent_replication_units": scale_runs + total_episodes,
            "scheduled_worker_executions": scale_runs + total_episodes * 2,
            "per_tool": {
                "scale_worker_executions": len(SCALES) * repetitions,
                "fault_episodes": len(fault_names) * repetitions,
                "fault_worker_executions": len(fault_names) * repetitions * 2,
                "scheduled_worker_executions": (len(SCALES) + len(fault_names) * 2) * repetitions,
            },
        },
        "analysis_units": {
            "scale": "one independently restarted worker execution",
            "fault": "one initial execution plus one valid restart in the same isolation",
            "resource_samples": "within-execution observations, not independent repetitions",
            "normal_reference": "one separate control condition per tool in the fault campaign",
        },
        "execution_gates": [
            "Notify the user before any pilot or formal performance collection.",
            "Attach and validate the effective configuration and dependency lock.",
            "Revalidate the frozen inputs against functional qualification at 1/2/4/8/16 switches.",
            "Verify the frozen functional episode and injector identities before timing.",
            "Freeze probe deadlines, watchdogs, stage markers, and analysis rules.",
            "Connect and qualify measurement boundaries in all native worker and episode paths.",
            "Freeze overhead limits, missing-data rules, and matched inference after pilot.",
            "Keep the challenged execution and restart inside the same outer isolation.",
            "Reuse episode node names, addresses, and service ports for the valid restart.",
            "Save original residuals before documented cleanup or generic rescue.",
            "Support episode-owned resource inheritance without accepting unrelated collisions.",
            "Retain missed triggers, failures, timeouts, and blocked restarts as outcomes.",
        ],
        "recovery_order": [
            "Record the injected fixture and trigger, or the normal stop request.",
            "Record the bounded detection probe where applicable.",
            "Request ordinary teardown and preserve the first residual snapshot.",
            "Apply and record the tool's allowed documented cleanup.",
            "Remove injected listener/rule fixtures at the recorded release stage.",
            "Attempt the next valid worker in the same isolation and retain its outcome.",
            "Use generic rescue after recording the primary recovery outcome or safety stop.",
            "Destroy the outer isolation after all episode observations are retained.",
        ],
        "extensions_not_scheduled": [
            "SIGKILL of the entire worker: separate supervisor-rescue study.",
            "p4net asynchronous cancellation: mechanism case, not a synchronous speed baseline.",
            "Common-precompiled and prepared-cache comparisons: pending validated controls.",
        ],
        "scale_schedule": scale_schedule,
        "fault_schedule": fault_schedule,
    }


def write_plan(output: Path, plan: dict[str, Any]) -> Path:
    """Create a new JSON file or a new directory without replacing existing records."""
    payload = json.dumps(plan, indent=2, allow_nan=False) + "\n"
    if output.suffix.lower() == ".json":
        output.parent.mkdir(parents=True, exist_ok=True)
        target = output
    else:
        output.mkdir(parents=True, exist_ok=False)
        target = output / "campaign.json"
    with target.open("x", encoding="utf-8") as stream:
        stream.write(payload)
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20261027)
    parser.add_argument("--sessions", type=int, default=3)
    parser.add_argument("--repetitions-per-session", type=int, default=10)
    args = parser.parse_args()
    try:
        plan = generate(args.seed, args.sessions, args.repetitions_per_session)
        path = write_plan(args.output, plan)
    except (ValueError, OSError) as exc:
        parser.exit(2, f"{type(exc).__name__}: {exc}\n")
    print(
        json.dumps({"plan": str(path), "execution_status": "planned", "summary": plan["summary"]})
    )


if __name__ == "__main__":
    main()
