"""Keep native boundary validation and attach one common ready hold."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from harness.native_measurement import Observation

from overhead.coordinator import Supervisor
from overhead.proc import ProcReader


class NativeObservation(Observation):  # type: ignore[misc]  # Frozen harness import is skipped.
    def __init__(self, coordinator: Supervisor, *, fixture: bool = False):
        super().__init__()
        self.coordinator, self.fixture = coordinator, fixture

    def mark(self, name: str, *, phase: str = "initial", observed_ns: int | None = None) -> None:
        seen = (phase, name) in self.seen
        super().mark(name, phase=phase, observed_ns=observed_ns)
        if (
            not seen
            and (phase, name) in self.seen
            and phase == "initial"
            and name in {"worker_launch", "stop_request", "worker_exit", "ordinary_audit_end"}
        ):
            self.coordinator.mark(name)

    def ready(
        self,
        manifest: Mapping[str, Any],
        worker_identity: Mapping[str, Any],
        event: Mapping[str, Any],
        *,
        phase: str = "initial",
    ) -> None:
        previous = len(self.issues)
        if self.fixture:
            if (
                phase != "initial"
                or (phase, "ready_received") not in self.seen
                or phase in self.validated_phases
                or event.get("synthetic_checks") is not True
            ):
                raise ValueError("protected fixture readiness differs")
            self.validated_phases.add(phase)
            self.boundaries.append({"phase": phase, "boundary": "fixture_worker_verified"})
        else:
            super().ready(manifest, worker_identity, event, phase=phase)
            if phase not in self.targets or len(self.issues) != previous:
                self.coordinator.issue(
                    "native readiness", ValueError("native targets are unavailable")
                )
                return
        worker = ProcReader().identity(worker_identity["pid"])
        if worker.start_ticks != worker_identity["start_ticks"]:
            raise ProcessLookupError("worker identity changed before common ready hold")
        self.coordinator.ready(worker)

    def finish(self, result: Mapping[str, Any]) -> dict[str, Any]:
        for issue in self.issues:
            self.coordinator.issue("native observation", ValueError(str(issue)))
        return cast(dict[str, Any], super().finish(result))
