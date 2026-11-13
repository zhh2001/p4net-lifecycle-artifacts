"""Apply equal-duration observer profiles with an explicit calibration clock."""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from harness import measure
from harness.aggregate import validate_record
from harness.native_measurement import Observation
from harness.resources import ProcessTarget, read_sample

PROFILES = ("B", "T", "S")


class ProfileObservation(Observation):
    """Keep shared native checks while separating recording and sampling costs."""

    def __init__(
        self,
        profile: str,
        metadata: Mapping[str, Any],
        *,
        mode: str,
        clock_domain: str,
        clock_ns: Callable[[], int],
        sleep: Callable[[float], None],
        duration_ns: int = measure.DEFAULT_WINDOW_NS,
        interval_ns: int = measure.DEFAULT_INTERVAL_NS,
        clock_ticks: int = 100,
        read: Callable[..., dict[str, Any]] | None = None,
        select_targets: Callable[..., Sequence[ProcessTarget]] | None = None,
        on_primary_published: Callable[[Path], None] | None = None,
    ) -> None:
        if not isinstance(profile, str) or profile not in PROFILES:
            raise ValueError("observer profile must be B, T, or S")
        if (
            mode not in measure.MODES
            or not isinstance(clock_domain, str)
            or not clock_domain.strip()
        ):
            raise ValueError("a measurement mode and explicit clock domain are required")
        if not callable(clock_ns) or not callable(sleep):
            raise ValueError("an explicit clock and sleep function are required")
        if on_primary_published is not None and not callable(on_primary_published):
            raise ValueError("primary publication callback must be callable")
        if (
            type(duration_ns) is not int
            or type(interval_ns) is not int
            or not 0 < interval_ns <= duration_ns <= 2**63 - 1
            or type(clock_ticks) is not int
            or clock_ticks <= 0
        ):
            raise ValueError("invalid profile hold or sampling configuration")
        if profile == "S" and mode == "synthetic-validation" and read in (None, read_sample):
            raise ValueError("synthetic sampled profiles require an explicit resource reader")
        self.metadata = copy.deepcopy(dict(metadata))
        reserved = {
            "schema_version",
            "record_type",
            "mode",
            "performance_samples",
            "status",
            "metrics",
            "markers",
            "resource_windows",
            "clock_domain",
        }
        if self.metadata.keys() & reserved:
            raise ValueError("profile metadata cannot override record fields")
        validate_record(
            {
                **self.metadata,
                "schema_version": 1,
                "record_type": "measurement-record",
                "mode": mode,
                "performance_samples": mode != "synthetic-validation",
                "status": "blocked",
                "metrics": {},
            },
            mode,
        )
        self.profile = profile
        self.mode = mode
        self.clock_domain = clock_domain
        self._clock_source = clock_ns
        self._last_clock: int | None = None
        self._sleep = sleep
        self.duration_ns, self.interval_ns = duration_ns, interval_ns
        self.clock_ticks = clock_ticks
        self._read = read_sample if read is None else read
        self.holds: dict[str, dict[str, Any]] = {}
        self._on_primary_published = on_primary_published
        self._primary_notified = False
        recorder = (
            None
            if profile == "B"
            else measure.Recorder(
                self.metadata, mode=mode, clock_domain=clock_domain, clock_ns=self._clock
            )
        )
        super().__init__(recorder=recorder, select_targets=select_targets)

    def _clock(self) -> int:
        current = self._clock_source()
        if type(current) is not int or current < 0:
            raise ValueError("profile clock must return nonnegative integer nanoseconds")
        if self._last_clock is not None and current < self._last_clock:
            raise ValueError("profile clock moved backward")
        self._last_clock = current
        return current

    def bind(self, manifest: Mapping[str, Any]) -> None:
        expected = {
            "run_id": manifest["run_id"],
            "switches": manifest["groups"],
            "configuration_profile": manifest.get("configuration_profile", "native"),
            "fault": manifest.get("episode_fault"),
        }
        if any(self.metadata.get(key) != value for key, value in expected.items()):
            raise ValueError("profile metadata differs from the native manifest")
        if self.profile == "B" and self.mode != "synthetic-validation":
            from harness.faults import require_enclosure

            require_enclosure()
        super().bind(manifest)

    def _wait_until(self, deadline: int) -> int:
        now = self._clock()
        while now < deadline:
            self._sleep((deadline - now) / 1_000_000_000)
            after = self._clock()
            if after <= now:
                raise ValueError("profile wait did not advance its clock")
            now = after
        return now

    def ready(
        self,
        manifest: Mapping[str, Any],
        worker_identity: Mapping[str, Any],
        event: Mapping[str, Any],
        *,
        phase: str = "initial",
    ) -> None:
        already_validated = phase in self.validated_phases
        previous_issues = len(self.issues)
        super().ready(manifest, worker_identity, event, phase=phase)
        if (
            already_validated
            or phase not in self.validated_phases
            or phase not in self.targets
            or len(self.issues) != previous_issues
        ):
            return
        hold: dict[str, Any] = {
            "observer_profile": self.profile,
            "phase": phase,
            "requested_duration_ns": self.duration_ns,
            "complete": False,
        }
        self.holds[phase] = hold
        try:
            anchor = self._clock()
            deadline = anchor + self.duration_ns
            hold.update(anchor_ns=anchor, scheduled_end_ns=deadline)
            if self.profile == "S":
                targets = tuple(ProcessTarget(**target) for target in self.targets[phase])
                window = measure.sample_window(
                    targets,
                    mode=self.mode,
                    clock_domain=self.clock_domain,
                    clock_ticks=self.clock_ticks,
                    duration_ns=self.duration_ns,
                    interval_ns=self.interval_ns,
                    start_ns=anchor,
                    clock_ns=self._clock,
                    sleep=self._sleep,
                    read=self._read,
                )
                assert self.recorder is not None
                self.recorder.attach_window(window, restart=phase == "restart")
                self.boundaries.append({"phase": phase, "boundary": "idle_window_attached"})
                complete = window["complete"]
            else:
                self._wait_until(deadline)
                complete = True
            ended = self._clock()
            if ended < deadline:
                raise ValueError("profile hold ended before its scheduled deadline")
            hold.update(callback_end_ns=ended, extension_ns=ended - deadline, complete=complete)
        except Exception as exc:
            self.issue(f"{phase}:profile_hold", exc)
            hold["error"] = {"type": type(exc).__name__, "message": str(exc)}

    def checkpoint(self, path: Path, result: Mapping[str, Any]) -> None:
        try:
            measure.write_record(path, self._record(result))
        except Exception as exc:
            self.issue("save primary observation", exc)
            return
        if not self._primary_notified and self._on_primary_published is not None:
            self._primary_notified = True
            try:
                self._on_primary_published(path)
            except Exception as exc:
                self.issue("reference primary publication", exc)

    def profile_record(self) -> dict[str, Any]:
        """Expose hold measurements separately from the B boundary observation."""
        return {
            "schema_version": 1,
            "record_type": "observer-profile-record",
            "mode": self.mode,
            "performance_samples": self.mode != "synthetic-validation",
            "run_id": self.metadata["run_id"],
            "observer_profile": self.profile,
            "clock_domain": self.clock_domain,
            "holds": copy.deepcopy(self.holds),
            "issues": copy.deepcopy(self.issues),
        }


def profile_observation(
    profile: str,
    metadata: Mapping[str, Any],
    *,
    mode: str,
    clock_domain: str,
    clock_ns: Callable[[], int],
    sleep: Callable[[float], None],
    duration_ns: int = measure.DEFAULT_WINDOW_NS,
    interval_ns: int = measure.DEFAULT_INTERVAL_NS,
    clock_ticks: int = 100,
    read: Callable[..., dict[str, Any]] | None = None,
    select_targets: Callable[..., Sequence[ProcessTarget]] | None = None,
    on_primary_published: Callable[[Path], None] | None = None,
) -> ProfileObservation:
    """Construct an inert profile; clocks and readers run only at task boundaries."""
    return ProfileObservation(
        profile,
        metadata,
        mode=mode,
        clock_domain=clock_domain,
        clock_ns=clock_ns,
        sleep=sleep,
        duration_ns=duration_ns,
        interval_ns=interval_ns,
        clock_ticks=clock_ticks,
        read=read,
        select_targets=select_targets,
        on_primary_published=on_primary_published,
    )
