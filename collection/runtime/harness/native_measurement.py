"""Connect observer boundaries to native workers without changing their outcomes."""

from __future__ import annotations

import copy
import os
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any

from harness import measure
from harness.resources import ProcessTarget


class Observation:
    """Observe boundary order, or use an explicitly supplied measurement recorder."""

    def __init__(
        self,
        *,
        recorder: measure.Recorder | None = None,
        sampler: Callable[[Sequence[ProcessTarget]], dict[str, Any]] | None = None,
        select_targets: Callable[..., Sequence[ProcessTarget]] | None = None,
    ) -> None:
        if sampler is not None and recorder is None:
            raise ValueError("resource sampling requires an explicit measurement recorder")
        self.recorder = recorder
        self.sampler = sampler
        self.select_targets = select_targets
        self.boundaries: list[dict[str, Any]] = []
        self.issues: list[dict[str, str]] = []
        self.targets: dict[str, list[dict[str, Any]]] = {}
        self.seen: set[tuple[str, str]] = set()
        self.validated_phases: set[str] = set()
        self.fault: str | None = None
        self.closed = False
        self.safety_started = False

    @property
    def performance_samples(self) -> bool:
        return self.recorder is not None and self.recorder.mode != "synthetic-validation"

    def issue(self, context: str, exc: Exception) -> None:
        self.issues.append({"context": context, "type": type(exc).__name__, "message": str(exc)})

    def bind(self, manifest: Mapping[str, Any]) -> None:
        """Reject mismatched measurement metadata before starting a native task."""
        self.fault = manifest.get("episode_fault")
        if self.recorder is None:
            return
        if self.performance_samples:
            from harness.faults import require_enclosure

            require_enclosure()
        expected = {
            "run_id": manifest["run_id"],
            "switches": manifest["groups"],
            "configuration_profile": manifest.get("configuration_profile", "native"),
            "fault": manifest.get("episode_fault"),
        }
        if any(self.recorder.metadata.get(key) != value for key, value in expected.items()):
            raise ValueError("measurement metadata differs from the native manifest")

    def clock_ns(self) -> int | None:
        if self.recorder is None:
            return None
        try:
            return self.recorder.clock_ns()
        except Exception as exc:
            self.issue("receive clock", exc)
            return None

    def _validate_boundary(self, name: str, phase: str) -> None:
        if name not in measure.PREREQUISITES:
            raise ValueError("unknown observation boundary")
        prerequisites = [(phase, prior) for prior in measure.PREREQUISITES[name]]
        if phase == "restart" and name == "worker_launch":
            prerequisites = [("initial", "worker_exit"), ("initial", "ordinary_audit_end")]
        if any(prior not in self.seen for prior in prerequisites):
            raise ValueError(f"missing prerequisite for {phase}:{name}")
        if name == "condition_ready" and ("initial", "worker_launch") in self.seen:
            raise ValueError("startup condition follows launch")
        if name == "ready_received" and any(
            (phase, prior) in self.seen
            for prior in ("stop_request", "worker_exit", "ordinary_audit_start")
        ):
            raise ValueError("readiness follows teardown or exit")
        commands = {
            "stop_request",
            "stop_sent",
            "stop_failed",
            "intervention_start",
            "intervention_applied",
            "intervention_failed",
        }
        if name in commands and (phase, "worker_exit") in self.seen:
            raise ValueError("command follows worker exit")
        if name == "intervention_start":
            if (phase, "stop_request") in self.seen:
                raise ValueError("intervention follows teardown")
            if self.fault in {"kill-bmv2", "drop-control"} and phase not in self.validated_phases:
                raise ValueError("running fault requires validated readiness")
        for outcomes in (
            {"stop_sent", "stop_failed"},
            {"intervention_applied", "intervention_failed"},
        ):
            if name in outcomes and any((phase, prior) in self.seen for prior in outcomes):
                raise ValueError("delivery already has an outcome")

    def mark(self, name: str, *, phase: str = "initial", observed_ns: int | None = None) -> None:
        try:
            if self.closed or phase not in {"initial", "restart"}:
                raise ValueError("closed observation or unknown attempt phase")
            if (phase, name) in self.seen:
                # Exit observation can occur in both the event loop and finalization.
                if name == "worker_exit":
                    return
                raise ValueError("duplicate observation boundary")
            if self.safety_started and name != "safety_end":
                raise ValueError("ordinary boundaries cannot follow safety escalation")
            self._validate_boundary(name, phase)
            if name == "safety_start":
                self.safety_started = True
            self.seen.add((phase, name))
            self.boundaries.append({"phase": phase, "boundary": name})
            mapped = name
            if phase == "restart":
                mapped = {
                    "worker_launch": "restart_launch",
                    "ready_received": "restart_ready_received",
                }.get(name, "")
            if self.recorder is not None and mapped:
                self.recorder.mark(mapped, observed_ns=observed_ns)
        except Exception as exc:
            self.issue(f"{phase}:{name}", exc)

    def received(
        self,
        event: Mapping[str, Any],
        *,
        phase: str = "initial",
        observed_ns: int | None = None,
    ) -> None:
        if event.get("event") == "ready":
            if self.recorder is not None and observed_ns is None:
                self.issue(f"{phase}:ready_received", ValueError("receive timestamp is missing"))
                return
            self.mark("ready_received", phase=phase, observed_ns=observed_ns)

    def ready(
        self,
        manifest: Mapping[str, Any],
        worker_identity: Mapping[str, Any],
        event: Mapping[str, Any],
        *,
        phase: str = "initial",
    ) -> None:
        """Accept checked task readiness, then identify and optionally sample targets."""
        try:
            if (
                (phase, "ready_received") not in self.seen
                or self.safety_started
                or phase in self.validated_phases
            ):
                raise ValueError("validated readiness requires an ordinary received boundary")
            if self.recorder is not None:
                self.recorder.accept_ready(restart=phase == "restart")
            self.boundaries.append({"phase": phase, "boundary": "ready_validated"})
            self.validated_phases.add(phase)
        except Exception as exc:
            self.issue(f"{phase}:accept_ready", exc)
            return
        try:
            selector = self.select_targets
            if selector is None:
                from harness.native_resources import select_targets

                selector = select_targets
            targets = tuple(selector(manifest, worker_identity, event))
            if (
                sum(target.role == "worker" for target in targets) != 1
                or sum(target.role == "bmv2" for target in targets) != manifest["groups"]
                or len({target.pid for target in targets}) != len(targets)
            ):
                raise ValueError("targets must cover the worker and every declared switch")
            self.targets[phase] = [asdict(target) for target in targets]
            self.boundaries.append({"phase": phase, "boundary": "targets_verified"})
            if self.sampler is not None:
                assert self.recorder is not None
                window = self.sampler(targets)
                if window.get("targets") != self.targets[phase]:
                    raise ValueError("resource window differs from the verified process targets")
                self.recorder.attach_window(window, restart=phase == "restart")
                self.boundaries.append({"phase": phase, "boundary": "idle_window_attached"})
        except Exception as exc:
            self.issue(f"{phase}:resources", exc)

    def _status(self, result: Mapping[str, Any]) -> str:
        if result.get("ok") is True:
            return "completed"
        error = result.get("framework_error") or result.get("error") or {}
        if "Timeout" in error.get("type", "") or result.get("ordinary_stop_timeout"):
            return "timeout"
        if result.get("cleanup", {}).get("not_started"):
            return "blocked"
        return "failed"

    def _record(self, result: Mapping[str, Any]) -> dict[str, Any]:
        observation = {
            "schema_version": 1,
            "record_type": "native-boundary-validation",
            "performance_samples": False,
            "boundaries": copy.deepcopy(self.boundaries),
            "targets": copy.deepcopy(self.targets),
            "issues": copy.deepcopy(self.issues),
        }
        if self.recorder is None:
            return observation
        recorder = copy.deepcopy(self.recorder)
        cleanup = result.get("cleanup", {})
        initial = result.get("initial") or {}
        restart = result.get("restart") or {}
        outcome = {
            "ordinary_stop_timeout": initial.get(
                "ordinary_stop_timeout", result.get("ordinary_stop_timeout")
            ),
            "ordinary_cleanup_clean": initial.get(
                "ordinary_cleanup_clean", cleanup.get("ordinary_after_clean")
            ),
            "restart_ordinary_stop_timeout": restart.get("ordinary_stop_timeout"),
            "restart_ordinary_cleanup_clean": restart.get("ordinary_cleanup_clean"),
            "recovery_success": result.get("recovery_success"),
            "framework_complete": result.get("framework_complete"),
        }
        record = recorder.finish(self._status(result), **outcome)
        record["native_observation"] = observation
        record["measurement_issues"].extend(copy.deepcopy(self.issues))
        return record

    def checkpoint(self, path: Path, result: Mapping[str, Any]) -> None:
        try:
            measure.write_record(path, self._record(result))
        except Exception as exc:
            self.issue("save primary observation", exc)

    def finish(self, result: Mapping[str, Any]) -> dict[str, Any]:
        try:
            record = self._record(result)
            self.closed = True
            return record
        except Exception as exc:
            self.issue("finish observation", exc)
            self.closed = True
            return {
                "record_type": "measurement-observation-error",
                "performance_samples": self.performance_samples,
                "issues": copy.deepcopy(self.issues),
            }


def measured_observation(
    metadata: Mapping[str, Any],
    *,
    mode: str,
    clock_domain: str,
    duration_ns: int = measure.DEFAULT_WINDOW_NS,
    interval_ns: int = measure.DEFAULT_INTERVAL_NS,
) -> Observation:
    """Configure live sampling for an explicitly initiated pilot or formal run."""
    if mode not in {"pilot", "formal"}:
        raise ValueError("live observations require pilot or formal mode")
    if (
        type(duration_ns) is not int
        or type(interval_ns) is not int
        or not 0 < interval_ns <= duration_ns
    ):
        raise ValueError("invalid live observation schedule")
    recorder = measure.Recorder(metadata, mode=mode, clock_domain=clock_domain)

    def sample(targets: Sequence[ProcessTarget]) -> dict[str, Any]:
        return measure.sample_window(
            targets,
            mode=mode,
            clock_domain=clock_domain,
            clock_ticks=os.sysconf("SC_CLK_TCK"),
            duration_ns=duration_ns,
            interval_ns=interval_ns,
            clock_ns=time.monotonic_ns,
        )

    return Observation(recorder=recorder, sampler=sample)
