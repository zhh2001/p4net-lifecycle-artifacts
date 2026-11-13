"""Retain profile-aware observer attempts without automatic retries."""

from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import math
import os
import re
import uuid
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, TextIO, cast

from harness.campaign_executor import _equal, _json, _sha, _write_new
from harness.observer_campaign_inputs import plan_from_binding, validate_binding, verify_binding

TERMINAL_STATES = ("completed", "failed", "timeout", "blocked")
REFERENCE_METRICS = (
    "observer_body_wall_ns",
    "observer_cpu_seconds",
    "observer_rss_bytes",
    "observer_pss_bytes",
)
PHASES = ("qualification", "calibration")
SELECTIONS = ("first-attempt", "latest-attempt")
GATES = (
    "qualification-stage1",
    "qualification-stage2",
    "qualification-stage3",
    "calibration-wiring",
)


def entries_for(plan: Mapping[str, Any]) -> dict[str, tuple[str, dict[str, Any]]]:
    return {
        str(row["planned_parent_id" if phase == "qualification" else "planned_task_id"]): (
            phase,
            copy.deepcopy(row),
        )
        for phase in PHASES
        for row in plan[phase + "_schedule"]
    }


def gate_requirements(plan: Mapping[str, Any], gate_id: str) -> list[str]:
    if gate_id not in GATES:
        raise ValueError("unknown observer gate")
    if gate_id == "calibration-wiring":
        gate = plan["initial_calibration_wiring_gate"]
        if gate is None:
            raise ValueError("qualification-only plans have no calibration wiring gate")
        return list(gate["planned_task_ids"])
    stage = int(gate_id[-1])
    return [
        row["planned_parent_id"] for row in plan["qualification_schedule"] if row["stage"] == stage
    ]


def required_gates(plan: Mapping[str, Any], phase: str, row: Mapping[str, Any]) -> tuple[str, ...]:
    if phase == "qualification":
        return tuple(f"qualification-stage{stage}" for stage in range(1, row["stage"]))
    gates = tuple(f"qualification-stage{stage}" for stage in (1, 2, 3))
    initial = set(gate_requirements(plan, "calibration-wiring"))
    return gates if row["planned_task_id"] in initial else (*gates, "calibration-wiring")


def metadata_for(
    plan: Mapping[str, Any],
    binding: Mapping[str, Any],
    phase: str,
    row: Mapping[str, Any],
    number: int,
    run_id: str,
) -> dict[str, Any]:
    planned = row["planned_parent_id" if phase == "qualification" else "planned_task_id"]
    return {
        "run_id": run_id,
        "planned_id": planned,
        "phase": phase,
        "attempt_number": number,
        "attempt_id": f"{planned}--a{number:04}",
        "observer_profile": row["observer_profile"],
        "session": 0 if phase == "qualification" else row["session"],
        "tool": row["tool"],
        "python": plan["python"],
        "input_lock_sha256": binding["input_lock_sha256"],
        "workload": row["workload"],
        "switches": row["switches"],
        "configuration_profile": row["configuration_profile"],
        "build_mode": row["build_mode"],
        "fault": row.get("fault"),
        "sequence": row["sequence"],
        "stage": row["stage"] if phase == "qualification" else None,
        "block": row["block"] if phase == "calibration" else None,
        "matched_block": row["matched_block"] if phase == "calibration" else None,
    }


def observation_metadata(metadata: Mapping[str, Any]) -> dict[str, Any]:
    """Keep qualification's campaign index while using a positive recorder index."""
    result = copy.deepcopy(dict(metadata))
    if result.get("phase") == "qualification":
        if type(result.get("session")) is int and result["session"] == 0:
            result.update(session=1, campaign_session=0)
        elif not (
            type(result.get("session")) is int
            and result["session"] == 1
            and type(result.get("campaign_session")) is int
            and result["campaign_session"] == 0
        ):
            raise ValueError("qualification observation requires its campaign session identity")
    return result


def validate_measurement(value: Any, metadata: Mapping[str, Any], mode: str) -> None:
    if (
        not isinstance(value, dict)
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or value.get("record_type") != "observer-calibration-measurement"
        or value.get("mode") != mode
        or value.get("performance_samples") is not (mode == "pilot")
        or value.get("status") not in TERMINAL_STATES
        or value.get("reference_status") not in {"complete", "incomplete"}
        or type(value.get("qualified")) is not bool
        or not isinstance(value.get("measurement_issues"), list)
        or not _equal({key: value.get(key) for key in metadata}, dict(metadata))
    ):
        raise ValueError("observer measurement differs from its claimed attempt")
    metrics = value.get("metrics")
    if not isinstance(metrics, dict) or any(
        not isinstance(name, str)
        or not name.strip()
        or isinstance(number, bool)
        or not isinstance(number, (int, float))
        or not math.isfinite(number)
        for name, number in metrics.items()
    ):
        raise ValueError("observer metrics must contain finite named numeric values")
    if any(metrics[name] < 0 for name in REFERENCE_METRICS if name in metrics):
        raise ValueError("observer reference metrics must be nonnegative")
    if value["reference_status"] == "incomplete" and metrics:
        raise ValueError("incomplete observer references cannot provide metrics")
    if value["qualified"] and (
        value["status"] != "completed"
        or value["reference_status"] != "complete"
        or value["measurement_issues"]
    ):
        raise ValueError("qualified measurements require completed, issue-free reference outcomes")
    json.dumps(value, allow_nan=False)


def _native_status(response: Mapping[str, Any] | None, fallback: str) -> str:
    native = response.get("native_result") if response is not None else None
    if isinstance(native, dict) and type(native.get("ok")) is bool:
        if native["ok"]:
            return "completed"
        status = native.get("status")
        return status if status in {"failed", "timeout", "blocked"} else "failed"
    return fallback


@dataclass(frozen=True)
class Attempt:
    directory: Path
    started: dict[str, Any]

    @property
    def metadata(self) -> dict[str, Any]:
        return copy.deepcopy(self.started["metadata"])

    @property
    def artifacts(self) -> Path:
        return self.directory / "artifacts"


class Backend(Protocol):
    mode: str

    def __call__(self, attempt: Attempt) -> Mapping[str, Any]: ...


class SyntheticBackend:
    """Supply declared fixture values without clocks, procfs, or worker processes."""

    mode = "synthetic-validation"

    def __init__(
        self,
        outcomes: Mapping[str, str] | None = None,
        *,
        unavailable: Sequence[str] = (),
        missing_metrics: Mapping[str, Sequence[str]] | None = None,
    ) -> None:
        self.outcomes = dict(outcomes or {})
        if any(status not in TERMINAL_STATES for status in self.outcomes.values()):
            raise ValueError("unknown synthetic observer outcome")
        self.unavailable = set(unavailable)
        self.missing_metrics = dict(missing_metrics or {})

    def __call__(self, attempt: Attempt) -> Mapping[str, Any]:
        metadata = attempt.metadata
        planned = metadata["planned_id"]
        status = self.outcomes.get(planned, "completed")
        complete = planned not in self.unavailable
        cost = {"B": 10, "T": 12, "S": 20}[metadata["observer_profile"]]
        metrics = (
            {
                "observer_body_wall_ns": cost,
                "observer_cpu_seconds": cost / 100,
                "observer_rss_bytes": cost * 4096,
                "observer_pss_bytes": cost * 2048,
            }
            if status == "completed" and complete
            else {}
        )
        for name in self.missing_metrics.get(planned, ()):
            metrics.pop(name, None)
        issues = [] if complete else ["synthetic reference endpoint unavailable"]
        return {
            "measurement": {
                **metadata,
                "schema_version": 1,
                "record_type": "observer-calibration-measurement",
                "mode": self.mode,
                "performance_samples": False,
                "status": status,
                "reference_status": "complete" if complete else "incomplete",
                "metrics": metrics,
                "measurement_issues": issues,
                "qualified": status == "completed"
                and complete
                and set(REFERENCE_METRICS) <= metrics.keys(),
                "synthetic_fixture": True,
            },
            "native_result": {"ok": status == "completed", "synthetic_fixture": True},
        }


class Campaign:
    _read: Callable[[Path], dict[str, Any]]
    _digest: Callable[[Path], str]

    def __init__(self, output: Path, binding: Mapping[str, Any], *, base: Path) -> None:
        self._read, self._digest = _json, _sha
        self.output, self.base = output.resolve(), base.resolve()
        self.binding = copy.deepcopy(dict(binding))
        verify_binding(self.binding, base=self.base)
        self.plan = plan_from_binding(self.binding)
        self.entries = entries_for(self.plan)
        self._lock: TextIO | None = None

    def __enter__(self) -> Campaign:
        if self._lock is not None:
            raise RuntimeError("observer campaign context is already active")
        self.output.mkdir(parents=True, exist_ok=True)
        lock_path = self.output / ".observer-campaign.lock"
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        self._lock = os.fdopen(descriptor, "a+")
        try:
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            path = self.output / "observer-binding.json"
            if os.path.lexists(path):
                if not _equal(self._read(path), self.binding):
                    raise ValueError("observer binding differs; use a new output directory")
            else:
                if set(self.output.iterdir()) != {lock_path}:
                    raise ValueError("existing observer output has no input binding")
                _write_new(path, self.binding)
            for name in ("attempts", "gates"):
                directory = self.output / name
                if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
                    raise ValueError("observer journal directories must be real directories")
                directory.mkdir(exist_ok=True)
            self._validate_history()
            self._validate_reviews()
        except BaseException:
            self._lock.close()
            self._lock = None
            raise
        return self

    def __exit__(self, *args: Any) -> None:
        if self._lock is not None:
            self._lock.close()
            self._lock = None

    def _active(self) -> None:
        if self._lock is None or self._lock.closed:
            raise RuntimeError("observer campaign operation requires the context lock")

    def _directories(self) -> list[Path]:
        directories = []
        for parent in sorted((self.output / "attempts").iterdir()):
            if parent.is_symlink() or not parent.is_dir() or parent.name not in self.entries:
                raise ValueError("unknown observer attempt directory")
            numbers = []
            for directory in sorted(
                parent.iterdir(), key=lambda path: int(path.name) if path.name.isdecimal() else 0
            ):
                if (
                    directory.is_symlink()
                    or not directory.is_dir()
                    or not re.fullmatch(r"[0-9]{4,}", directory.name)
                    or int(directory.name) < 1
                    or directory.name != f"{int(directory.name):04}"
                ):
                    raise ValueError("invalid observer attempt ordinal")
                numbers.append(int(directory.name))
                directories.append(directory)
            if numbers != list(range(1, len(numbers) + 1)):
                raise ValueError("observer history has missing ordinals")
        return directories

    def _attempt(self, directory: Path) -> Attempt:
        value = self._read(directory / "started.json")
        metadata = value.get("metadata")
        if not isinstance(metadata, dict) or not isinstance(metadata.get("run_id"), str):
            raise ValueError("observer claim requires a run identity")
        run_id = metadata["run_id"]
        if not re.fullmatch(r"[a-f0-9]{32}", run_id):
            raise ValueError("observer run identity must be a UUID hex string")
        phase, entry = self.entries[directory.parent.name]
        number = int(directory.name)
        expected = metadata_for(self.plan, self.binding, phase, entry, number, run_id)
        if (
            type(value.get("schema_version")) is not int
            or value["schema_version"] != 1
            or value.get("record_type") != "observer-attempt-start"
            or not _equal(metadata, expected)
            or not _equal(value.get("entry"), entry)
            or value.get("input_lock_sha256") != self.binding["input_lock_sha256"]
            or value.get("mode") != self.binding["mode"]
            or value.get("performance_samples") is not self.binding["performance_samples"]
            or value.get("previous_attempt_id")
            != (None if number == 1 else f"{directory.parent.name}--a{number - 1:04}")
        ):
            raise ValueError("observer claim differs from its allocation")
        reviews = value.get("gate_reviews")
        required = required_gates(self.plan, phase, entry)
        if not isinstance(reviews, list) or len(reviews) != len(required):
            raise ValueError("observer claim requires its gate-review references")
        for item, gate_id in zip(reviews, required, strict=True):
            if (
                not isinstance(item, dict)
                or set(item) != {"gate_id", "review_number", "sha256"}
                or item.get("gate_id") != gate_id
                or type(item.get("review_number")) is not int
                or item["review_number"] < 1
            ):
                raise ValueError("invalid claimed gate review identity")
            review_path = self.output / "gates" / gate_id / f"{item['review_number']:04}.json"
            review = self._read(review_path)
            if (
                item["sha256"] != self._digest(review_path)
                or review.get("gate_id") != gate_id
                or review.get("review_number") != item["review_number"]
                or review.get("qualified") is not True
                or review.get("input_lock_sha256") != self.binding["input_lock_sha256"]
            ):
                raise ValueError("claimed gate review differs from its pinned positive decision")
        return Attempt(directory, value)

    def _terminal(self, directory: Path) -> dict[str, Any]:
        result = self._read(directory / "result.json")
        number, planned = int(directory.name), directory.parent.name
        if (
            type(result.get("schema_version")) is not int
            or result["schema_version"] != 1
            or result.get("record_type") != "observer-attempt-result"
            or result.get("planned_id") != planned
            or type(result.get("attempt_number")) is not int
            or result["attempt_number"] != number
            or result.get("attempt_id") != f"{planned}--a{number:04}"
            or result.get("status") not in TERMINAL_STATES
            or result.get("mode") != self.binding["mode"]
            or result.get("performance_samples") is not self.binding["performance_samples"]
            or result.get("input_lock_sha256") != self.binding["input_lock_sha256"]
        ):
            raise ValueError("invalid observer terminal identity")
        if (directory / "started.json").exists():
            attempt = self._attempt(directory)
            measurement_path = directory / "measurement.json"
            measurement = self._read(measurement_path)
            validate_measurement(measurement, attempt.metadata, self.binding["mode"])
            if (
                result.get("run_id") != attempt.metadata["run_id"]
                or result["status"] != measurement["status"]
                or result.get("measurement")
                != {"path": "measurement.json", "sha256": self._digest(measurement_path)}
            ):
                raise ValueError("observer terminal differs from its measurement")
            backend = directory / "backend-result.json"
            expected_backend = (
                {"path": "backend-result.json", "sha256": self._digest(backend)}
                if backend.exists()
                else None
            )
            if result.get("backend_result") != expected_backend:
                raise ValueError("observer terminal backend hash differs")
        elif (
            result.get("run_id") is not None
            or result["status"] != "blocked"
            or result.get("reason") != "interrupted-before-start-record"
            or result.get("measurement") is not None
            or result.get("backend_result") is not None
            or any(
                (directory / name).exists() for name in ("measurement.json", "backend-result.json")
            )
        ):
            raise ValueError("invalid unclaimed observer terminal")
        return result

    def _validate_history(self) -> list[Path]:
        directories = self._directories()
        runs = set()
        for directory in directories:
            for name in ("started.json", "measurement.json", "backend-result.json", "result.json"):
                if (directory / name).is_symlink():
                    raise ValueError("observer attempt records must not be symbolic links")
            if (directory / "started.json").exists():
                attempt = self._attempt(directory)
                run_id = attempt.metadata["run_id"]
                if run_id in runs:
                    raise ValueError("observer claims reuse a run identity")
                runs.add(run_id)
                if (directory / "measurement.json").exists():
                    validate_measurement(
                        self._read(directory / "measurement.json"),
                        attempt.metadata,
                        self.binding["mode"],
                    )
                if (directory / "backend-result.json").exists():
                    self._read(directory / "backend-result.json")
            elif any(
                (directory / name).exists() for name in ("measurement.json", "backend-result.json")
            ):
                raise ValueError("observer outcomes have no preceding claim")
            if (directory / "result.json").exists():
                self._terminal(directory)
        return directories

    def _finish(
        self, attempt: Attempt, record: dict[str, Any], *, reason: str | None = None
    ) -> None:
        attempt = self._attempt(attempt.directory)
        validate_measurement(record, attempt.metadata, self.binding["mode"])
        path = attempt.directory / "measurement.json"
        if path.exists():
            if not _equal(self._read(path), record):
                raise ValueError("refusing to replace an observer measurement")
        else:
            _write_new(path, record)
        backend = attempt.directory / "backend-result.json"
        _write_new(
            attempt.directory / "result.json",
            {
                "schema_version": 1,
                "record_type": "observer-attempt-result",
                "planned_id": attempt.metadata["planned_id"],
                "attempt_number": attempt.metadata["attempt_number"],
                "attempt_id": attempt.metadata["attempt_id"],
                "run_id": attempt.metadata["run_id"],
                "status": record["status"],
                "reason": reason,
                "measurement": {"path": "measurement.json", "sha256": self._digest(path)},
                "backend_result": {"path": "backend-result.json", "sha256": self._digest(backend)}
                if backend.exists()
                else None,
                "mode": self.binding["mode"],
                "performance_samples": self.binding["performance_samples"],
                "input_lock_sha256": self.binding["input_lock_sha256"],
            },
        )

    def _missing(self, attempt: Attempt, status: str, reason: str) -> None:
        self._finish(
            attempt,
            {
                **attempt.metadata,
                "schema_version": 1,
                "record_type": "observer-calibration-measurement",
                "mode": self.binding["mode"],
                "performance_samples": self.binding["performance_samples"],
                "status": status,
                "reference_status": "incomplete",
                "metrics": {},
                "measurement_issues": [reason],
                "qualified": False,
            },
            reason=reason,
        )

    def reconcile(self) -> None:
        self._active()
        for directory in self._validate_history():
            if (directory / "result.json").exists():
                continue
            if not (directory / "started.json").exists():
                planned, number = directory.parent.name, int(directory.name)
                _write_new(
                    directory / "result.json",
                    {
                        "schema_version": 1,
                        "record_type": "observer-attempt-result",
                        "planned_id": planned,
                        "attempt_number": number,
                        "attempt_id": f"{planned}--a{number:04}",
                        "run_id": None,
                        "status": "blocked",
                        "reason": "interrupted-before-start-record",
                        "measurement": None,
                        "backend_result": None,
                        "mode": self.binding["mode"],
                        "performance_samples": self.binding["performance_samples"],
                        "input_lock_sha256": self.binding["input_lock_sha256"],
                    },
                )
                continue
            attempt = self._attempt(directory)
            if (directory / "measurement.json").exists():
                self._finish(
                    attempt,
                    self._read(directory / "measurement.json"),
                    reason="recovered-measurement",
                )
            elif (directory / "backend-result.json").exists():
                response = self._read(directory / "backend-result.json")
                record = response.get("measurement")
                try:
                    validate_measurement(record, attempt.metadata, self.binding["mode"])
                except (ValueError, TypeError):
                    self._missing(
                        attempt, _native_status(response, "failed"), "invalid-backend-result"
                    )
                else:
                    self._finish(
                        attempt, cast(dict[str, Any], record), reason="recovered-backend-result"
                    )
            else:
                self._missing(attempt, "blocked", "interrupted-unfinalized-attempt")

    def _gate_ids(self, gate_id: str) -> list[str]:
        return gate_requirements(self.plan, gate_id)

    def _review_paths(self, gate_id: str) -> list[Path]:
        directory = self.output / "gates" / gate_id
        if not directory.exists():
            return []
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError("gate history must be a real directory")
        paths = sorted(
            directory.iterdir(), key=lambda path: int(path.stem) if path.stem.isdecimal() else 0
        )
        if any(path.is_symlink() or not path.is_file() for path in paths) or [
            path.name for path in paths
        ] != [f"{index:04}.json" for index in range(1, len(paths) + 1)]:
            raise ValueError("invalid observer gate review history")
        return paths

    def _validate_reviews(self) -> None:
        for directory in (self.output / "gates").iterdir():
            gate_id = directory.name
            required = self._gate_ids(gate_id)
            for number, path in enumerate(self._review_paths(gate_id), 1):
                review = self._read(path)
                if (
                    type(review.get("schema_version")) is not int
                    or review["schema_version"] != 1
                    or review.get("record_type") != "observer-gate-review"
                    or review.get("gate_id") != gate_id
                    or type(review.get("review_number")) is not int
                    or review["review_number"] != number
                    or review.get("selection") not in SELECTIONS
                    or type(review.get("qualified")) is not bool
                    or not isinstance(review.get("reason"), str)
                    or not review["reason"].strip()
                    or review.get("input_lock_sha256") != self.binding["input_lock_sha256"]
                    or not isinstance(review.get("attempts"), list)
                ):
                    raise ValueError("invalid observer gate review")
                seen = []
                for item in review["attempts"]:
                    if not isinstance(item, dict) or item.get("planned_id") not in required:
                        raise ValueError("gate review refers to an unknown planned task")
                    planned = item["planned_id"]
                    attempt_number = item.get("attempt_number")
                    if type(attempt_number) is not int or attempt_number < 1:
                        raise ValueError("invalid gate attempt ordinal")
                    terminal_path = (
                        self.output / "attempts" / planned / f"{attempt_number:04}" / "result.json"
                    )
                    terminal = self._terminal(terminal_path.parent)
                    if item.get("attempt_id") != terminal["attempt_id"] or item.get(
                        "sha256"
                    ) != self._digest(terminal_path):
                        raise ValueError("gate review refers to a changed terminal")
                    if review["selection"] == "first-attempt" and attempt_number != 1:
                        raise ValueError("first-attempt review selects a retry")
                    if review["qualified"]:
                        measurement = self._read(terminal_path.parent / "measurement.json")
                        if (
                            terminal["status"] != "completed"
                            or not measurement["qualified"]
                            or not set(REFERENCE_METRICS) <= measurement["metrics"].keys()
                        ):
                            raise ValueError("qualified gate contains an ineligible attempt")
                    seen.append(planned)
                if len(seen) != len(set(seen)) or (
                    review["qualified"] and set(seen) != set(required)
                ):
                    raise ValueError("gate review coverage differs from its requirements")

    def _gate_passed(self, gate_id: str) -> bool:
        paths = self._review_paths(gate_id)
        return bool(paths) and self._read(paths[-1])["qualified"] is True

    def review_gate(
        self,
        gate_id: str,
        *,
        qualified: bool,
        reason: str,
        selection: str = "first-attempt",
    ) -> dict[str, Any]:
        self._active()
        if type(qualified) is not bool or not isinstance(reason, str) or not reason.strip():
            raise ValueError("gate review requires an explicit decision and reason")
        if selection not in SELECTIONS:
            raise ValueError("gate review requires first-attempt or latest-attempt selection")
        self._validate_history()
        self._validate_reviews()
        required = self._gate_ids(gate_id)
        selected = []
        for planned in required:
            parent = self.output / "attempts" / planned
            directories = (
                sorted(parent.iterdir(), key=lambda path: int(path.name)) if parent.exists() else []
            )
            directory = (
                directories[0 if selection == "first-attempt" else -1] if directories else None
            )
            if directory is None or not (directory / "result.json").exists():
                if qualified:
                    raise ValueError("gate review has unfinished planned tasks")
                continue
            terminal = self._terminal(directory)
            if qualified:
                if terminal["status"] != "completed" or terminal["measurement"] is None:
                    raise ValueError("gate review requires completed selected attempts")
                measurement = self._read(directory / "measurement.json")
                if (
                    measurement["qualified"] is not True
                    or not set(REFERENCE_METRICS) <= measurement["metrics"].keys()
                ):
                    raise ValueError("gate review requires valid selected measurements")
            selected.append(
                {
                    "planned_id": planned,
                    "attempt_number": int(directory.name),
                    "attempt_id": terminal["attempt_id"],
                    "sha256": self._digest(directory / "result.json"),
                }
            )
        paths = self._review_paths(gate_id)
        directory = self.output / "gates" / gate_id
        directory.mkdir(exist_ok=True)
        value = {
            "schema_version": 1,
            "record_type": "observer-gate-review",
            "gate_id": gate_id,
            "review_number": len(paths) + 1,
            "selection": selection,
            "qualified": qualified,
            "reason": reason,
            "input_lock_sha256": self.binding["input_lock_sha256"],
            "attempts": selected,
        }
        _write_new(directory / f"{len(paths) + 1:04}.json", value)
        return value

    def _eligible(self, phase: str, row: Mapping[str, Any]) -> bool:
        return all(self._gate_passed(gate) for gate in required_gates(self.plan, phase, row))

    def _claim_reviews(self, phase: str, row: Mapping[str, Any]) -> list[dict[str, Any]]:
        result = []
        for gate_id in required_gates(self.plan, phase, row):
            paths = self._review_paths(gate_id)
            if not paths or self._read(paths[-1])["qualified"] is not True:
                raise ValueError("claim requires a positive current gate review")
            review = self._read(paths[-1])
            result.append(
                {
                    "gate_id": gate_id,
                    "review_number": review["review_number"],
                    "sha256": self._digest(paths[-1]),
                }
            )
        return result

    def run(
        self,
        backend: Backend,
        *,
        phase: str,
        session: int | None = None,
        limit: int | None = None,
        retry: Sequence[str] = (),
        collection_authorized: bool = False,
    ) -> dict[str, Any]:
        self._active()
        if (
            phase not in PHASES
            or (phase == "qualification" and session is not None)
            or (phase == "calibration" and (type(session) is not int or not 1 <= session <= 3))
        ):
            raise ValueError("select qualification or one calibration session")
        if backend.mode != self.binding["mode"]:
            raise ValueError("observer backend mode differs from the input binding")
        if backend.mode != "synthetic-validation" and collection_authorized is not True:
            raise PermissionError("observer collection has not been authorized")
        if isinstance(retry, (str, bytes)) or len(set(retry)) != len(retry):
            raise ValueError("retry must contain distinct planned identifiers")
        if limit is not None and (type(limit) is not int or limit < 1):
            raise ValueError("limit must be a positive integer")
        entries = [
            (planned, row)
            for planned, (entry_phase, row) in self.entries.items()
            if entry_phase == phase and (phase == "qualification" or row["session"] == session)
        ]
        if set(retry) - {planned for planned, _ in entries}:
            raise ValueError("retry selection differs from this phase and session")
        verify_binding(self.binding, base=self.base)
        self._validate_history()
        self._validate_reviews()
        for planned in retry:
            parent = self.output / "attempts" / planned
            if not parent.exists() or not any(parent.iterdir()):
                raise ValueError("retry requires a preceding attempt")
        if backend.mode != "synthetic-validation":
            preflight = getattr(backend, "preflight", None)
            if not callable(preflight):
                raise ValueError("native observer backend requires an environment preflight")
            preflight(self.output, self.binding)
        self.reconcile()
        executed: list[str] = []
        blocked_by_gate = None
        pending_error: BaseException | None = None
        try:
            for planned, row in entries:
                parent = self.output / "attempts" / planned
                previous = (
                    sorted(parent.iterdir(), key=lambda path: int(path.name))
                    if parent.exists()
                    else []
                )
                if (previous and planned not in retry) or (retry and planned not in retry):
                    continue
                if limit is not None and len(executed) >= limit:
                    break
                if not self._eligible(phase, row):
                    blocked_by_gate = planned
                    break
                verify_binding(self.binding, base=self.base)
                number = len(previous) + 1
                directory = parent / f"{number:04}"
                directory.mkdir(parents=True, exist_ok=False)
                metadata = metadata_for(
                    self.plan, self.binding, phase, row, number, uuid.uuid4().hex
                )
                started = {
                    "schema_version": 1,
                    "record_type": "observer-attempt-start",
                    "metadata": metadata,
                    "entry": copy.deepcopy(row),
                    "gate_reviews": self._claim_reviews(phase, row),
                    "previous_attempt_id": None if number == 1 else f"{planned}--a{number - 1:04}",
                    "input_lock_sha256": self.binding["input_lock_sha256"],
                    "mode": self.binding["mode"],
                    "performance_samples": self.binding["performance_samples"],
                }
                _write_new(directory / "started.json", started)
                attempt = Attempt(directory, started)
                executed.append(metadata["attempt_id"])
                response = None
                try:
                    response = dict(backend(attempt))
                    record = response.get("measurement")
                    validate_measurement(record, metadata, self.binding["mode"])
                    json.dumps(response, allow_nan=False)
                except Exception as exc:
                    if response is not None:
                        try:
                            json.dumps(response, allow_nan=False)
                        except (ValueError, TypeError):
                            pass
                        else:
                            _write_new(directory / "backend-result.json", response)
                    self._missing(
                        attempt,
                        _native_status(
                            response, "timeout" if isinstance(exc, TimeoutError) else "failed"
                        ),
                        f"{type(exc).__name__}: {exc}",
                    )
                except BaseException as exc:
                    reason = f"interrupted: {type(exc).__name__}"
                    path = directory / "backend-result.json"
                    try:
                        if path.exists():
                            recovered = self._read(path)
                            record = recovered.get("measurement")
                            try:
                                validate_measurement(record, metadata, self.binding["mode"])
                            except (ValueError, TypeError):
                                self._missing(attempt, _native_status(recovered, "blocked"), reason)
                            else:
                                self._finish(attempt, cast(dict[str, Any], record), reason=reason)
                        else:
                            self._missing(attempt, "blocked", reason)
                    except Exception as recovery_error:
                        raise exc from recovery_error
                    raise
                else:
                    _write_new(directory / "backend-result.json", response)
                    self._finish(attempt, cast(dict[str, Any], record))
                terminal = self._terminal(directory)
                measurement = self._read(directory / "measurement.json")
                if (
                    terminal["status"] != "completed"
                    or not measurement["qualified"]
                    or not set(REFERENCE_METRICS) <= measurement["metrics"].keys()
                ):
                    break
        except BaseException as exc:
            pending_error = exc
            raise
        finally:
            try:
                report = self.report()
                report["invocation"] = {
                    "phase": phase,
                    "session": session,
                    "executed_attempt_ids": executed,
                    "explicit_retries": list(retry),
                    "blocked_by_gate": blocked_by_gate,
                }
                _write_new(self.output / f"execution-report-{uuid.uuid4().hex}.json", report)
            except Exception as report_error:
                if pending_error is not None:
                    raise pending_error from report_error
                raise
        return report

    def report(self) -> dict[str, Any]:
        self._active()
        attempts = []
        for directory in self._validate_history():
            if (directory / "result.json").exists():
                result = self._terminal(directory)
            else:
                result = {
                    "planned_id": directory.parent.name,
                    "attempt_number": int(directory.name),
                    "attempt_id": f"{directory.parent.name}--a{int(directory.name):04}",
                    "status": "unfinalized",
                    "measurement": None,
                }
            attempts.append({**result, "directory": str(directory.relative_to(self.output))})
        seen = {row["planned_id"] for row in attempts}
        return {
            "schema_version": 1,
            "record_type": "observer-campaign-attempt-report",
            "mode": self.binding["mode"],
            "performance_samples": self.binding["performance_samples"],
            "input_lock_sha256": self.binding["input_lock_sha256"],
            "planned_units": len(self.entries),
            "planned_units_with_attempts": len(seen),
            "unattempted_planned_ids": sorted(self.entries.keys() - seen),
            "attempt_status_counts": dict(Counter(row["status"] for row in attempts)),
            "attempts": attempts,
            "analysis_selection": "not-selected; retries remain separate history",
        }


class _RetainedReader:
    def __init__(self) -> None:
        self.values: dict[Path, dict[str, Any]] = {}
        self.hashes: dict[str, str] = {}

    def read(self, path: Path) -> dict[str, Any]:
        if path not in self.values:
            if path.is_symlink() or not path.is_file():
                raise ValueError("observer record must be an existing regular file")
            content = path.read_bytes()
            from harness.campaign_inputs import _constant, _pairs

            value = json.loads(content, object_pairs_hook=_pairs, parse_constant=_constant)
            if not isinstance(value, dict):
                raise ValueError("observer record must contain a JSON object")
            json.dumps(value, allow_nan=False)
            self.values[path] = value
            self.hashes[str(path)] = hashlib.sha256(content).hexdigest()
        return copy.deepcopy(self.values[path])

    def digest(self, path: Path) -> str:
        self.read(path)
        return self.hashes[str(path)]


def read_records(output: Path, *, base: Path) -> dict[str, Any]:
    """Read validated journal files without recovery; the caller owns its read lock."""
    reader = _RetainedReader()
    journal = Campaign.__new__(Campaign)
    journal._read, journal._digest = reader.read, reader.digest
    journal.output, journal.base = output.resolve(), base.resolve()
    binding_path = journal.output / "observer-binding.json"
    journal.binding = reader.read(binding_path)
    validate_binding(journal.binding, base=journal.base)
    journal.plan = plan_from_binding(journal.binding)
    journal.entries = entries_for(journal.plan)
    journal._lock = None
    directories = journal._validate_history()
    journal._validate_reviews()
    reader.digest(binding_path)
    attempts = []
    for directory in directories:
        values = {}
        for name in ("started.json", "measurement.json", "backend-result.json", "result.json"):
            path = directory / name
            if path.exists():
                values[name] = reader.read(path)
                reader.digest(path)
        attempts.append(
            {
                "directory": str(directory.relative_to(journal.output)),
                "started": values.get("started.json"),
                "result": values.get("result.json"),
                "measurement": values.get("measurement.json"),
            }
        )
    reviews = []
    for gate in sorted((journal.output / "gates").iterdir()):
        for path in journal._review_paths(gate.name):
            reviews.append(
                {"path": str(path.relative_to(journal.output)), "record": reader.read(path)}
            )
            reader.digest(path)
    return {
        "binding": copy.deepcopy(journal.binding),
        "plan": copy.deepcopy(journal.plan),
        "attempts": attempts,
        "gate_reviews": reviews,
        "input_hashes": dict(reader.hashes),
    }
