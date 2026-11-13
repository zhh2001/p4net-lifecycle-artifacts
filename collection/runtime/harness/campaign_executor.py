"""Execute an immutable study allocation with durable, explicit attempt histories."""

from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
import json
import os
import re
import shutil
import tempfile
import uuid
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, TextIO

from harness import campaign, measure
from harness.aggregate import MODES, STATUSES, validate_record
from harness.campaign_inputs import build_binding, verify_binding

PAPER = Path(__file__).resolve().parents[1]


def _json(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise ValueError(f"record must not be a symbolic link: {path}")

    def distinct(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError(f"duplicate JSON field: {key}")
            result[key] = item
        return result

    value = json.loads(path.read_text(), object_pairs_hook=distinct)
    if not isinstance(value, dict):
        raise ValueError(f"record must be an object: {path}")
    json.dumps(value, allow_nan=False)
    return value


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _equal(left: Any, right: Any) -> bool:
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(
        right, sort_keys=True, allow_nan=False
    )


def _write_new(path: Path, value: Mapping[str, Any]) -> None:
    """Publish a fully flushed record without replacing an earlier record."""
    content = json.dumps(dict(value), indent=2, allow_nan=False) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _resolve(path: str, base: Path) -> Path:
    value = Path(path)
    return value if value.is_absolute() else base / value


def validate_plan(plan: dict[str, Any]) -> None:
    """Check allocation and identity fields against the deterministic schedule."""
    if (
        type(plan.get("schema_version")) is not int
        or plan["schema_version"] != 1
        or plan.get("record_type") != "offline-experiment-plan"
        or plan.get("performance_samples") is not False
        or plan.get("execution_status") != "planned"
    ):
        raise ValueError("a planned offline experiment allocation is required")
    allocation = plan.get("allocation", {})
    if not isinstance(allocation, dict):
        raise ValueError("allocation must be an object")
    if any(
        type(allocation.get(key)) is not int
        for key in ("seed", "sessions", "repetitions_per_session")
    ):
        raise ValueError("allocation requires integer seed, sessions, and repetitions")
    expected = campaign.generate(
        allocation["seed"],
        allocation["sessions"],
        allocation["repetitions_per_session"],
    )
    for key in ("allocation", "tools", "python", "topology", "primary_build_mode", "summary"):
        if not _equal(plan.get(key), expected[key]):
            raise ValueError(f"plan differs from supported allocation: {key}")
    common = (
        "sequence",
        "session",
        "repetition_within_session",
        "matched_block",
        "tool",
        "switches",
        "hosts",
        "build_mode",
        "configuration_profile",
        "execution_status",
    )
    for phase, identity in (("scale", "planned_case_id"), ("fault", "planned_episode_id")):
        rows = plan.get(phase + "_schedule")
        required: tuple[str, ...] = (*common, identity)
        if phase == "fault":
            required += ("fault", "isolation_scope", "restart_configuration", "executions")
        if not isinstance(rows, list) or len(rows) != len(expected[phase + "_schedule"]):
            raise ValueError(f"invalid {phase} schedule length")
        for row, reference in zip(rows, expected[phase + "_schedule"], strict=True):
            if not isinstance(row, dict) or any(
                not _equal(row.get(key), reference[key]) for key in required
            ):
                raise ValueError(f"invalid {phase} schedule identity or condition")
            if {"run_id", "result", "metrics"} & row.keys():
                raise ValueError("planned rows cannot contain observed results")


def _planned_id(entry: Mapping[str, Any], phase: str) -> str:
    return str(entry["planned_case_id" if phase == "scale" else "planned_episode_id"])


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
    """Exercise the execution contract with fixed test timestamps only."""

    mode = "synthetic-validation"

    def __init__(self, outcomes: Mapping[str, str] | None = None) -> None:
        self.outcomes = dict(outcomes or {})
        if any(value not in STATUSES for value in self.outcomes.values()):
            raise ValueError("invalid synthetic outcome")

    def __call__(self, attempt: Attempt) -> Mapping[str, Any]:
        metadata = attempt.metadata
        recorder = measure.Recorder(
            metadata, mode=self.mode, clock_domain="synthetic-fixed-ns", clock_ns=lambda: 0
        )
        status = self.outcomes.get(metadata["planned_id"], "completed")
        recorder.mark("worker_launch", observed_ns=100)
        if status == "completed":
            recorder.mark("ready_received", observed_ns=200)
            recorder.accept_ready()
        record = recorder.finish(status, synthetic_fixture=True)
        return {"measurement": record, "native_result": {"synthetic_fixture": True}}


class Campaign:
    def __init__(self, output: Path, binding: Mapping[str, Any], *, base: Path) -> None:
        self.output = output.resolve()
        self.base = base.resolve()
        self.binding = copy.deepcopy(dict(binding))
        verify_binding(self.binding, base=self.base)
        self.plan = _json(_resolve(self.binding["plan"]["path"], self.base))
        validate_plan(self.plan)
        self.entries = {
            _planned_id(entry, phase): (phase, entry)
            for phase in ("scale", "fault")
            for entry in self.plan[phase + "_schedule"]
        }
        self._lock: TextIO | None = None

    def __enter__(self) -> Campaign:
        if self._lock is not None:
            raise RuntimeError("campaign context is already active")
        self.output.mkdir(parents=True, exist_ok=True)
        if (self.output / ".executor.lock").is_symlink():
            raise ValueError("campaign lock must not be a symbolic link")
        self._lock = (self.output / ".executor.lock").open("a+")
        try:
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            binding_path = self.output / "campaign-binding.json"
            if binding_path.exists():
                if _json(binding_path) != self.binding:
                    raise ValueError("campaign input binding differs; use a new output directory")
            else:
                if set(self.output.iterdir()) != {self.output / ".executor.lock"}:
                    raise ValueError("refusing an existing directory without a campaign binding")
                _write_new(binding_path, self.binding)
            attempts = self.output / "attempts"
            if attempts.is_symlink() or (attempts.exists() and not attempts.is_dir()):
                raise ValueError("attempts must be a real directory")
            attempts.mkdir(exist_ok=True)
        except BaseException:
            self._lock.close()
            self._lock = None
            raise
        return self

    def __exit__(self, *args: Any) -> None:
        if self._lock is not None:
            self._lock.close()
            self._lock = None

    def _directories(self) -> list[Path]:
        result = []
        for planned in sorted((self.output / "attempts").iterdir()):
            if planned.is_symlink() or not planned.is_dir() or planned.name not in self.entries:
                raise ValueError(f"unknown planned attempt directory: {planned}")
            numbers = []
            for directory in sorted(planned.iterdir()):
                if (
                    directory.is_symlink()
                    or not directory.is_dir()
                    or not re.fullmatch(r"[0-9]{4,}", directory.name)
                    or int(directory.name) < 1
                ):
                    raise ValueError(f"invalid attempt directory: {directory}")
                if directory.name != f"{int(directory.name):04}":
                    raise ValueError("attempt ordinal must use its canonical representation")
                numbers.append(int(directory.name))
                result.append(directory)
            if sorted(numbers) != list(range(1, len(numbers) + 1)):
                raise ValueError("attempt history contains missing ordinals")
        return result

    def _attempt(self, directory: Path) -> Attempt:
        started = _json(directory / "started.json")
        phase, entry = self.entries[directory.parent.name]
        number = int(directory.name)
        metadata = started.get("metadata", {})
        run_id = metadata.get("run_id")
        if not isinstance(run_id, str) or not re.fullmatch(r"[a-f0-9]{32}", run_id):
            raise ValueError("invalid recorded native run identity")
        reference = self._metadata(phase, entry, number, run_id)
        if (
            not _equal(metadata, reference)
            or not _equal(started.get("entry"), entry)
            or started.get("input_lock_sha256") != self.binding["input_lock_sha256"]
            or started.get("previous_attempt_id")
            != (None if number == 1 else f"{directory.parent.name}--a{number - 1:04}")
        ):
            raise ValueError("attempt identity differs from the bound allocation")
        return Attempt(directory, started)

    def _metadata(
        self, phase: str, entry: Mapping[str, Any], number: int, run_id: str
    ) -> dict[str, Any]:
        planned = _planned_id(entry, phase)
        return {
            "run_id": run_id,
            "session": entry["session"],
            "tool": entry["tool"],
            "python": self.plan["python"],
            "input_lock_sha256": self.binding["input_lock_sha256"],
            "workload": phase,
            "switches": entry["switches"],
            "configuration_profile": entry["configuration_profile"],
            "build_mode": entry["build_mode"],
            "fault": entry.get("fault") if phase == "fault" else None,
            "planned_id": planned,
            "planned_case_id" if phase == "scale" else "planned_episode_id": planned,
            "planned_execution_ids": [
                item["planned_execution_id"] for item in entry.get("executions", [])
            ],
            "sequence": entry["sequence"],
            "repetition_within_session": entry["repetition_within_session"],
            "matched_block": entry["matched_block"],
            "attempt_number": number,
            "attempt_id": f"{planned}--a{number:04}",
        }

    def _check_measurement(self, attempt: Attempt, value: dict[str, Any]) -> None:
        validate_record(value, self.binding["mode"])
        metadata = self._attempt(attempt.directory).metadata
        if not _equal({key: value.get(key) for key in metadata}, metadata):
            raise ValueError("backend measurement identity differs from its claimed attempt")

    def _terminal(self, directory: Path) -> dict[str, Any]:
        result = _json(directory / "result.json")
        if (
            result.get("status") not in STATUSES
            or result.get("planned_id") != directory.parent.name
            or type(result.get("attempt_number")) is not int
            or result.get("attempt_number") != int(directory.name)
        ):
            raise ValueError("invalid terminal attempt identity")
        if result.get("measurement") is not None:
            attempt = self._attempt(directory)
            reference = result["measurement"]
            if (
                not isinstance(reference, dict)
                or reference.get("path") != "measurement.json"
                or result.get("run_id") != attempt.metadata["run_id"]
            ):
                raise ValueError("terminal measurement reference differs from the claim")
            path = directory / "measurement.json"
            if _sha(path) != result["measurement"]["sha256"]:
                raise ValueError("published measurement changed")
            measurement = _json(path)
            self._check_measurement(attempt, measurement)
            if measurement["status"] != result["status"]:
                raise ValueError("terminal status differs from its measurement")
            backend_path = directory / "backend-result.json"
            if result.get("backend_result") != (
                {"path": "backend-result.json", "sha256": _sha(backend_path)}
                if backend_path.exists()
                else None
            ):
                raise ValueError("published backend outcome changed")
        elif (directory / "started.json").exists():
            raise ValueError("a claimed terminal attempt is missing its measurement")
        elif (
            result.get("status") != "blocked"
            or result.get("run_id") is not None
            or result.get("reason") != "interrupted-before-start-record"
            or result.get("backend_result") is not None
            or any(
                (directory / name).exists() for name in ("measurement.json", "backend-result.json")
            )
        ):
            raise ValueError("invalid unclaimed terminal attempt")
        return result

    def _finish(
        self, attempt: Attempt, record: dict[str, Any], *, reason: str | None = None
    ) -> None:
        attempt = self._attempt(attempt.directory)
        self._check_measurement(attempt, record)
        path = attempt.directory / "measurement.json"
        if path.exists():
            if not _equal(_json(path), record):
                raise ValueError("refusing to replace a measurement")
        else:
            _write_new(path, record)
        _write_new(
            attempt.directory / "result.json",
            {
                "planned_id": attempt.metadata["planned_id"],
                "attempt_number": attempt.metadata["attempt_number"],
                "run_id": attempt.metadata["run_id"],
                "status": record["status"],
                "reason": reason,
                "measurement": {"path": "measurement.json", "sha256": _sha(path)},
                "backend_result": {
                    "path": "backend-result.json",
                    "sha256": _sha(attempt.directory / "backend-result.json"),
                }
                if (attempt.directory / "backend-result.json").exists()
                else None,
            },
        )

    def _missing(self, attempt: Attempt, status: str, reason: str) -> None:
        attempt = self._attempt(attempt.directory)
        if self.binding["mode"] == "native-validation":
            from harness.native_validation import record

            self._finish(attempt, record(attempt.metadata, status, reason=reason), reason=reason)
            return
        recorder = measure.Recorder(
            attempt.metadata,
            mode=self.binding["mode"],
            clock_domain="unobserved",
            clock_ns=lambda: 0,
        )
        self._finish(attempt, recorder.finish(status, reason=reason), reason=reason)

    def _validate_history(self) -> list[Path]:
        directories = self._directories()
        for directory in directories:
            for name in ("started.json", "measurement.json", "result.json", "backend-result.json"):
                if (directory / name).is_symlink():
                    raise ValueError("attempt records must not be symbolic links")
            if (directory / "result.json").exists():
                self._terminal(directory)
            elif (directory / "started.json").exists():
                attempt = self._attempt(directory)
                if (directory / "measurement.json").exists():
                    self._check_measurement(attempt, _json(directory / "measurement.json"))
                if (directory / "backend-result.json").exists():
                    _json(directory / "backend-result.json")
            elif any(
                (directory / name).exists() for name in ("measurement.json", "backend-result.json")
            ):
                raise ValueError("outcomes exist without a preceding start record")
        return directories

    def reconcile(self) -> None:
        """Retain interrupted claims without launching or automatically retrying them."""
        if self._lock is None or self._lock.closed:
            raise RuntimeError("campaign reconciliation requires the context lock")
        for directory in self._validate_history():
            if (directory / "result.json").exists():
                self._terminal(directory)
            elif not (directory / "started.json").exists():
                _write_new(
                    directory / "result.json",
                    {
                        "planned_id": directory.parent.name,
                        "attempt_number": int(directory.name),
                        "run_id": None,
                        "status": "blocked",
                        "reason": "interrupted-before-start-record",
                        "measurement": None,
                    },
                )
            else:
                attempt = self._attempt(directory)
                if (directory / "measurement.json").exists():
                    self._finish(
                        attempt,
                        _json(directory / "measurement.json"),
                        reason="recovered-published-measurement",
                    )
                elif (directory / "backend-result.json").exists():
                    response = _json(directory / "backend-result.json")
                    record = response.get("measurement")
                    if isinstance(record, dict):
                        try:
                            self._check_measurement(attempt, record)
                        except ValueError:
                            self._missing(attempt, "failed", "invalid-backend-result")
                        else:
                            self._finish(attempt, record, reason="recovered-backend-result")
                    else:
                        self._missing(attempt, "failed", "invalid-backend-result")
                else:
                    self._missing(attempt, "blocked", "interrupted-unfinalized-attempt")

    def run(
        self,
        phase: str,
        session: int,
        backend: Backend,
        *,
        retry: Sequence[str] = (),
        limit: int | None = None,
    ) -> dict[str, Any]:
        if self._lock is None or self._lock.closed:
            raise RuntimeError("campaign execution requires the context lock")
        if (
            phase not in {"scale", "fault"}
            or type(session) is not int
            or not 1 <= session <= self.plan["allocation"]["sessions"]
        ):
            raise ValueError("select one valid phase and session")
        if backend.mode != self.binding["mode"]:
            raise ValueError("backend mode differs from the input binding")
        if isinstance(retry, (str, bytes)) or len(set(retry)) != len(retry):
            raise ValueError("retry must contain distinct planned identifiers")
        if limit is not None and (type(limit) is not int or limit < 1):
            raise ValueError("limit must be a positive integer")
        entries = [row for row in self.plan[phase + "_schedule"] if row["session"] == session]
        selected = {_planned_id(row, phase) for row in entries}
        if set(retry) - selected:
            raise ValueError("retry identifiers must belong to this phase and session")
        verify_binding(self.binding, base=self.base)
        history = {directory.parent.name for directory in self._validate_history()}
        for planned in retry:
            if planned not in history:
                raise ValueError("explicit retry requires a preceding attempt")
        self.reconcile()
        if isinstance(backend, NativeBackend):
            backend.preflight(self.output, self.binding)
        executed: list[str] = []
        try:
            for entry in entries:
                planned = _planned_id(entry, phase)
                parent = self.output / "attempts" / planned
                previous = (
                    sorted(parent.glob("[0-9]*"), key=lambda path: int(path.name))
                    if parent.exists()
                    else []
                )
                if previous and planned not in retry:
                    continue
                if retry and planned not in retry:
                    continue
                if limit is not None and len(executed) >= limit:
                    break
                verify_binding(self.binding, base=self.base)
                number = 1 + max((int(path.name) for path in previous), default=0)
                directory = parent / f"{number:04}"
                directory.mkdir(parents=True, exist_ok=False)
                metadata = self._metadata(phase, entry, number, uuid.uuid4().hex)
                started = {
                    "input_lock_sha256": self.binding["input_lock_sha256"],
                    "entry": copy.deepcopy(entry),
                    "metadata": metadata,
                    "previous_attempt_id": None if not previous else f"{planned}--a{number - 1:04}",
                }
                _write_new(directory / "started.json", started)
                attempt = Attempt(directory, copy.deepcopy(started))
                executed.append(metadata["attempt_id"])
                response = None
                try:
                    response = dict(backend(attempt))
                    record = response.get("measurement")
                    if not isinstance(record, dict):
                        raise ValueError("backend did not return a measurement record")
                    self._check_measurement(attempt, record)
                    json.dumps(response, allow_nan=False)
                except Exception as exc:
                    status = "timeout" if isinstance(exc, TimeoutError) else "failed"
                    if response is not None:
                        try:
                            json.dumps(response, allow_nan=False)
                        except (ValueError, TypeError):
                            response = None
                        if response is not None:
                            _write_new(directory / "backend-result.json", response)
                    self._missing(attempt, status, f"{type(exc).__name__}: {exc}")
                except BaseException as exc:
                    self._missing(attempt, "blocked", f"interrupted: {type(exc).__name__}")
                    raise
                else:
                    _write_new(directory / "backend-result.json", response)
                    self._finish(attempt, record)
        finally:
            report = self.report()
            report["invocation"] = {
                "phase": phase,
                "session": session,
                "executed_attempt_ids": executed,
                "explicit_retries": list(retry),
            }
            _write_new(self.output / f"execution-report-{uuid.uuid4().hex}.json", report)
        return report

    def report(self) -> dict[str, Any]:
        attempts = []
        for directory in self._directories():
            result = (
                self._terminal(directory)
                if (directory / "result.json").exists()
                else {
                    "planned_id": directory.parent.name,
                    "attempt_number": int(directory.name),
                    "status": "unfinalized",
                    "measurement": None,
                }
            )
            attempts.append({**result, "directory": str(directory.relative_to(self.output))})
        seen = {row["planned_id"] for row in attempts}
        return {
            "record_type": "campaign-attempt-report",
            "mode": self.binding["mode"],
            "performance_samples": self.binding["performance_samples"],
            "input_lock_sha256": self.binding["input_lock_sha256"],
            "planned_units": len(self.entries),
            "planned_units_with_attempts": len(seen),
            "unattempted_planned_ids": sorted(self.entries.keys() - seen),
            "attempt_status_counts": dict(Counter(row["status"] for row in attempts)),
            "attempts": attempts,
            "analysis_selection": (
                "not-selected; explicit retries are not independent planned repetitions"
            ),
        }


class NativeBackend:
    """Opt-in adapter; a fault episode remains inside one existing enclosure."""

    def __init__(self, mode: str, *, base: Path) -> None:
        if mode not in {"native-validation", "pilot", "formal"}:
            raise ValueError("native execution requires native-validation, pilot, or formal mode")
        self.mode = mode
        self.base = base.resolve()
        self.binding: dict[str, Any] | None = None

    def _tool_lookup(self, binding: Mapping[str, Any]) -> None:
        dependency = _json(_resolve(binding["dependency_manifest"]["path"], self.base))
        root = _resolve(binding["dependency_manifest"]["path"], self.base).parent
        tools = _json(root / dependency["tools_file"])
        for name, identity in tools.items():
            found = shutil.which(name)
            if found is None or Path(found).resolve() != Path(identity["real_path"]).resolve():
                raise ValueError(f"effective tool lookup differs from frozen executable: {name}")

    def preflight(self, output: Path, binding: Mapping[str, Any]) -> None:
        from harness.campaign_inputs import verify_native_environment
        from harness.worker_components import verify_binding_components

        if os.geteuid() != 0:
            raise PermissionError("native campaign execution requires root")
        if binding.get("mode") != self.mode:
            raise ValueError("native backend mode differs from the input binding")
        verify_binding(dict(binding), base=self.base)
        verify_binding_components(binding, base=self.base)
        required = [
            *sorted((self.base / "harness").glob("*.py")),
            self.base / "harness/workloads/l3.p4",
            self.base / "harness/bin/simple_switch_grpc",
        ]
        if any(str(path.relative_to(self.base)) not in binding["sources"] for path in required):
            raise ValueError("native binding does not cover its effective harness and workload")
        verify_native_environment(
            _resolve(binding["dependency_manifest"]["path"], self.base),
            labels=("p4net310", "p4utils310", "tutorial310"),
            file_hashes=binding["locked_inputs"],
            base=self.base,
        )
        self._tool_lookup(binding)
        control = _json(_resolve(binding["frozen_control"]["path"], self.base))
        interpreter = control.get("wrapper_interpreter")
        if (
            not isinstance(interpreter, dict)
            or _sha(Path(interpreter["path"])) != interpreter["sha256"]
        ):
            raise ValueError("matched wrapper interpreter differs from its frozen identity")
        manifests = {
            str(path / "artifacts/manifest.json")
            for path in (output / "attempts").glob("*/*")
            if path.is_dir()
        }
        for process in Path("/proc").iterdir():
            if not process.name.isdecimal():
                continue
            try:
                argv = (process / "cmdline").read_bytes().decode(errors="replace").split("\0")
            except (FileNotFoundError, ProcessLookupError):
                continue
            if manifests.intersection(argv):
                raise RuntimeError("a preceding campaign enclosure is still running")
        self.binding = copy.deepcopy(dict(binding))

    def __call__(self, attempt: Attempt) -> Mapping[str, Any]:
        from harness import isolation, spec
        from harness.worker_components import verify_binding_components

        if self.binding is None:
            raise RuntimeError("native backend requires a successful batch preflight")
        components = verify_binding_components(self.binding, base=self.base)
        self._tool_lookup(self.binding)
        metadata = attempt.metadata
        source = self.base / "harness/workloads/l3.p4"
        path = spec.create(
            attempt.artifacts,
            groups=metadata["switches"],
            source=source,
            configuration_profile="matched-v1",
        )
        manifest = spec.load(path)
        manifest["worker_components"] = components
        manifest["run_id"] = metadata["run_id"]
        if metadata["workload"] == "fault":
            manifest["episode_fault"] = metadata["fault"]
        path.write_text(json.dumps(manifest, indent=2) + "\n")
        treatment = {
            "p4net": "p4net310",
            "p4utils": "p4utils310",
            "tutorial-components": "tutorial310",
        }[metadata["tool"]]
        dependency_path = _resolve(self.binding["dependency_manifest"]["path"], self.base)
        dependency = _json(dependency_path)
        environment_path = _resolve(
            dependency["environment_files"][treatment], dependency_path.parent
        )
        environment = _json(environment_path)
        if environment.get("version_info", [])[:3] != [3, 10, 20]:
            raise ValueError("worker Python version differs from its planned metadata")
        python = _resolve(environment["executable"], environment_path.parent)
        if (
            python.resolve()
            != _resolve(
                environment["interpreter_identity"]["path"], environment_path.parent
            ).resolve()
        ):
            raise ValueError("worker executable differs from its pinned interpreter")
        worker = {
            "p4net": "harness.worker",
            "p4utils": "harness.worker_p4utils",
            "tutorial-components": "harness.worker_tutorial",
        }[metadata["tool"]]
        if self.mode == "native-validation":
            from harness.native_measurement import Observation
            from harness.native_validation import record

            result = isolation.run_isolated(path, python, worker, boundary_validation=True)
            measurement = record(metadata, Observation()._status(result), native_result=result)
            return {"measurement": measurement, "native_result": result}
        configuration = {
            "mode": self.mode,
            "metadata": metadata,
            "clock_domain": "observer-monotonic-ns-v1",
            **self.binding["measurement_defaults"],
        }
        result = isolation.run_isolated(path, python, worker, measurement=configuration)
        return {"measurement": result.get("observation"), "native_result": result}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--control", required=True, type=Path)
    parser.add_argument("--dependencies", required=True, type=Path)
    parser.add_argument("--plan-sha256")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--phase", required=True, choices=("scale", "fault"))
    parser.add_argument("--session", required=True, type=int)
    parser.add_argument("--mode", choices=MODES, default="synthetic-validation")
    parser.add_argument("--native", action="store_true")
    parser.add_argument("--retry", nargs="*", default=[])
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    if args.native != (args.mode != "synthetic-validation"):
        parser.error(
            "native-validation/pilot/formal require --native; "
            "synthetic validation cannot use --native"
        )
    sources = [
        *sorted((PAPER / "harness").glob("*.py")),
        PAPER / "harness/workloads/l3.p4",
        PAPER / "harness/bin/simple_switch_grpc",
    ]
    binding = build_binding(
        args.plan,
        args.control,
        args.dependencies,
        sources,
        mode=args.mode,
        base=PAPER,
        plan_sha256=args.plan_sha256,
    )
    backend: Backend = NativeBackend(args.mode, base=PAPER) if args.native else SyntheticBackend()
    with Campaign(args.output, binding, base=PAPER) as executor:
        report = executor.run(args.phase, args.session, backend, retry=args.retry, limit=args.limit)
    print(
        json.dumps(
            {
                "report_type": report["record_type"],
                "attempt_status_counts": report["attempt_status_counts"],
                "performance_samples": report["performance_samples"],
            }
        )
    )


if __name__ == "__main__":
    main()
