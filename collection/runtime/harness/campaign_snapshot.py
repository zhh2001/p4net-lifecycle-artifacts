"""Read campaign journals consistently without recovering or changing their records."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from harness.aggregate import MODES, STATUSES, validate_record
from harness.campaign_executor import validate_plan


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _same(left: Any, right: Any) -> bool:
    return _canonical(left) == _canonical(right)


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", value):
        raise ValueError(f"{name} must contain 64 hexadecimal digits")
    return value.lower()


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in items:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = item
    return result


def _constant(value: str) -> None:
    raise ValueError(f"nonfinite JSON constant: {value}")


def _reference(value: Any, base: Path, name: str) -> tuple[Path, str]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must contain a path and sha256")
    relative = value.get("path")
    if (
        not isinstance(relative, str)
        or not relative.strip()
        or os.path.normpath(relative) != relative
    ):
        raise ValueError(f"{name} must contain a normalized nonempty path")
    path = Path(relative)
    return (path if path.is_absolute() else base / path), _digest(value.get("sha256"), name)


def _binding(value: dict[str, Any], base: Path) -> None:
    """Validate the retained contract without requiring the old runtime to still exist."""
    if (
        type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or value.get("record_type") != "campaign-input-binding"
        or value.get("mode") not in MODES
        or value.get("performance_samples") is not (value["mode"] in {"pilot", "formal"})
    ):
        raise ValueError("invalid campaign input binding")
    expected = _digest(value.get("input_lock_sha256"), "input_lock_sha256")
    payload = {key: item for key, item in value.items() if key != "input_lock_sha256"}
    if hashlib.sha256(_canonical(payload)).hexdigest() != expected:
        raise ValueError("campaign input binding hash differs")
    defaults = value.get("measurement_defaults")
    if not isinstance(defaults, dict) or any(
        type(defaults.get(key)) is not int for key in ("duration_ns", "interval_ns")
    ):
        raise ValueError("invalid measurement defaults")
    if not 0 < defaults["interval_ns"] <= defaults["duration_ns"]:
        raise ValueError("invalid measurement defaults")
    for name in ("plan", "frozen_control", "dependency_manifest"):
        _reference(value.get(name), base, name)
    for name in ("sources", "locked_inputs"):
        entries = value.get(name)
        if not isinstance(entries, dict) or not entries:
            raise ValueError(f"binding requires nonempty {name}")
        for path, digest in entries.items():
            _reference({"path": path, "sha256": digest}, base, name)
    drift = value.get("historical_source_drift")
    if not isinstance(drift, list):
        raise ValueError("historical_source_drift must be a list")
    for item in drift:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("path"), str)
            or item["path"] not in value["sources"]
        ):
            raise ValueError("historical source drift must refer to a bound source")
        _digest(item.get("expected_sha256"), "historical expected_sha256")
        if item.get("actual_sha256") != value["sources"][item["path"]]:
            raise ValueError("historical source drift differs from its bound source")


class _Reader:
    def __init__(self, output: Path, base: Path) -> None:
        self.output = output
        self.base = base
        self.input_hashes: dict[str, str] = {}
        self.run_ids: set[str] = set()

    def read(self, path: Path) -> dict[str, Any]:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"record must be an existing regular file: {path}")
        content = path.read_bytes()
        value = json.loads(content, object_pairs_hook=_pairs, parse_constant=_constant)
        if not isinstance(value, dict):
            raise ValueError(f"record must contain an object: {path}")
        _canonical(value)
        self.input_hashes[str(path)] = hashlib.sha256(content).hexdigest()
        return value

    def metadata(
        self, phase: str, entry: dict[str, Any], number: int, run_id: str
    ) -> dict[str, Any]:
        identity = "planned_case_id" if phase == "scale" else "planned_episode_id"
        planned = entry[identity]
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
            identity: planned,
            "planned_execution_ids": [
                item["planned_execution_id"] for item in entry.get("executions", [])
            ],
            "sequence": entry["sequence"],
            "repetition_within_session": entry["repetition_within_session"],
            "matched_block": entry["matched_block"],
            "attempt_number": number,
            "attempt_id": f"{planned}--a{number:04}",
        }

    def measurement(self, value: dict[str, Any], metadata: dict[str, Any]) -> None:
        validate_record(value, self.binding["mode"])
        if not _same({key: value.get(key) for key in metadata}, metadata):
            raise ValueError("measurement identity differs from its claimed attempt")

    def attempt(self, directory: Path, phase: str, entry: dict[str, Any]) -> dict[str, Any]:
        planned = directory.parent.name
        number = int(directory.name)
        names = ("started.json", "measurement.json", "backend-result.json", "result.json")
        values = {}
        for name in names:
            path = directory / name
            if path.is_symlink():
                raise ValueError(f"attempt records must not be symbolic links: {path}")
            if path.exists():
                values[name] = self.read(path)
        started = values.get("started.json")
        measurement = values.get("measurement.json")
        result = values.get("result.json")
        run_id = None
        if started is not None:
            metadata = started.get("metadata")
            if not isinstance(metadata, dict):
                raise ValueError("start record requires metadata")
            run_id = metadata.get("run_id")
            if not isinstance(run_id, str) or not re.fullmatch(r"[a-f0-9]{32}", run_id):
                raise ValueError("invalid recorded native run identity")
            if run_id in self.run_ids:
                raise ValueError("duplicate run_id across attempt claims")
            self.run_ids.add(run_id)
            expected = self.metadata(phase, entry, number, run_id)
            if (
                not _same(metadata, expected)
                or not _same(started.get("entry"), entry)
                or started.get("input_lock_sha256") != self.binding["input_lock_sha256"]
                or started.get("previous_attempt_id")
                != (None if number == 1 else f"{planned}--a{number - 1:04}")
            ):
                raise ValueError("attempt identity differs from the bound allocation")
            if measurement is not None:
                self.measurement(measurement, expected)
        elif measurement is not None or "backend-result.json" in values:
            raise ValueError("outcomes exist without a preceding start record")
        state = "unfinalized"
        reason: str | None = "missing-terminal-record"
        if result is not None:
            if (
                result.get("planned_id") != planned
                or type(result.get("attempt_number")) is not int
                or result["attempt_number"] != number
                or result.get("status") not in STATUSES
                or result.get("run_id") != run_id
            ):
                raise ValueError("invalid terminal attempt identity")
            if started is None:
                if (
                    result["status"] != "blocked"
                    or result.get("reason") != "interrupted-before-start-record"
                    or result.get("measurement") is not None
                    or result.get("backend_result") is not None
                ):
                    raise ValueError("invalid unclaimed terminal attempt")
            else:
                if measurement is None:
                    raise ValueError("a claimed terminal attempt is missing its measurement")
                reference = {
                    "path": "measurement.json",
                    "sha256": self.input_hashes[str(directory / "measurement.json")],
                }
                if not _same(result.get("measurement"), reference):
                    raise ValueError("terminal measurement reference or checksum differs")
                if measurement["status"] != result["status"]:
                    raise ValueError("terminal status differs from its measurement")
                backend = (
                    {
                        "path": "backend-result.json",
                        "sha256": self.input_hashes[str(directory / "backend-result.json")],
                    }
                    if "backend-result.json" in values
                    else None
                )
                if not _same(result.get("backend_result"), backend):
                    raise ValueError("terminal backend result reference or checksum differs")
            state = result["status"]
            reason = result.get("reason")
        return {
            "planned_id": planned,
            "attempt_number": number,
            "attempt_id": f"{planned}--a{number:04}",
            "run_id": run_id,
            "state": state,
            "measurement": measurement,
            "directory": directory.relative_to(self.output).as_posix(),
            "reason": reason,
        }

    def load(
        self, expected_plan_sha256: str | None, expected_input_lock_sha256: str | None
    ) -> dict[str, Any]:
        self.binding = self.read(self.output / "campaign-binding.json")
        _binding(self.binding, self.base)
        if (
            expected_input_lock_sha256 is not None
            and _digest(expected_input_lock_sha256, "expected_input_lock_sha256")
            != self.binding["input_lock_sha256"].lower()
        ):
            raise ValueError("campaign input lock differs from the expected pin")
        plan_path, plan_digest = _reference(self.binding["plan"], self.base, "plan")
        if (
            expected_plan_sha256 is not None
            and _digest(expected_plan_sha256, "expected_plan_sha256") != plan_digest
        ):
            raise ValueError("campaign plan differs from the expected pin")
        self.plan = self.read(plan_path)
        if self.input_hashes[str(plan_path)] != plan_digest:
            raise ValueError("campaign plan checksum differs from its binding")
        validate_plan(self.plan)
        entries = {
            entry["planned_case_id" if phase == "scale" else "planned_episode_id"]: (phase, entry)
            for phase in ("scale", "fault")
            for entry in self.plan[phase + "_schedule"]
        }
        attempts_root = self.output / "attempts"
        if attempts_root.is_symlink() or not attempts_root.is_dir():
            raise ValueError("attempts must be an existing real directory")
        attempts: list[dict[str, Any]] = []
        for parent in sorted(attempts_root.iterdir()):
            if parent.is_symlink() or not parent.is_dir() or parent.name not in entries:
                raise ValueError(f"unknown planned attempt directory: {parent}")
            directories = list(parent.iterdir())
            for directory in directories:
                if (
                    directory.is_symlink()
                    or not directory.is_dir()
                    or not re.fullmatch(r"[0-9]{4,}", directory.name)
                    or int(directory.name) < 1
                    or directory.name != f"{int(directory.name):04}"
                ):
                    raise ValueError(f"invalid attempt directory: {directory}")
            directories.sort(key=lambda path: int(path.name))
            if [int(path.name) for path in directories] != list(range(1, len(directories) + 1)):
                raise ValueError("attempt history contains missing ordinals")
            phase, entry = entries[parent.name]
            history = [self.attempt(path, phase, entry) for path in directories]
            if any(row["state"] == "unfinalized" for row in history[:-1]):
                raise ValueError("a retry follows an unfinalized predecessor")
            attempts.extend(history)
        seen = {attempt["planned_id"] for attempt in attempts}
        snapshot = {
            "schema_version": 1,
            "record_type": "campaign-snapshot",
            "binding": self.binding,
            "plan": self.plan,
            "attempts": attempts,
            "unattempted_planned_ids": sorted(entries.keys() - seen),
            "input_hashes": dict(sorted(self.input_hashes.items())),
        }
        snapshot["snapshot_sha256"] = hashlib.sha256(_canonical(snapshot)).hexdigest()
        return snapshot


def validate_snapshot(snapshot: dict[str, Any]) -> None:
    """Check a previously loaded in-memory snapshot without reading retained files."""
    if (
        not isinstance(snapshot, dict)
        or type(snapshot.get("schema_version")) is not int
        or snapshot["schema_version"] != 1
        or snapshot.get("record_type") != "campaign-snapshot"
    ):
        raise ValueError("invalid campaign snapshot schema")
    payload = {key: value for key, value in snapshot.items() if key != "snapshot_sha256"}
    if hashlib.sha256(_canonical(payload)).hexdigest() != _digest(
        snapshot.get("snapshot_sha256"), "snapshot_sha256"
    ):
        raise ValueError("campaign snapshot checksum differs")
    binding, plan = snapshot.get("binding"), snapshot.get("plan")
    if not isinstance(binding, dict) or not isinstance(plan, dict):
        raise ValueError("snapshot requires binding and plan objects")
    _binding(binding, Path("/"))
    validate_plan(plan)
    evidence = snapshot.get("input_hashes")
    if not isinstance(evidence, dict) or not evidence:
        raise ValueError("snapshot requires input hashes")
    for path, digest in evidence.items():
        if (
            not isinstance(path, str)
            or not Path(path).is_absolute()
            or os.path.normpath(path) != path
        ):
            raise ValueError("snapshot input hashes require absolute normalized paths")
        _digest(digest, "snapshot input hash")
    if binding["plan"]["sha256"].lower() not in {value.lower() for value in evidence.values()}:
        raise ValueError("snapshot does not retain its plan input hash")
    entries = {
        entry["planned_case_id" if phase == "scale" else "planned_episode_id"]: (phase, entry)
        for phase in ("scale", "fault")
        for entry in plan[phase + "_schedule"]
    }
    attempts = snapshot.get("attempts")
    if not isinstance(attempts, list):
        raise ValueError("snapshot attempts must be a list")
    reader = _Reader(Path("/"), Path("/"))
    reader.binding, reader.plan = binding, plan
    seen_run_ids: set[str] = set()
    ordinals: dict[str, list[int]] = {}
    for row in attempts:
        if not isinstance(row, dict) or not isinstance(row.get("planned_id"), str):
            raise ValueError("invalid snapshot attempt identity")
        planned = row["planned_id"]
        if planned not in entries:
            raise ValueError("snapshot attempt does not belong to the plan")
        number = row.get("attempt_number")
        if type(number) is not int or number < 1:
            raise ValueError("invalid snapshot attempt ordinal")
        ordinals.setdefault(planned, []).append(number)
        if (
            row.get("attempt_id") != f"{planned}--a{number:04}"
            or row.get("directory") != f"attempts/{planned}/{number:04}"
            or row.get("state") not in (*STATUSES, "unfinalized")
            or (row.get("reason") is not None and not isinstance(row["reason"], str))
        ):
            raise ValueError("snapshot attempt identity or state differs")
        run_id = row.get("run_id")
        measurement = row.get("measurement")
        if run_id is None:
            if measurement is not None or row["state"] not in ("blocked", "unfinalized"):
                raise ValueError("invalid unclaimed snapshot attempt")
            if row["state"] == "blocked" and row.get("reason") != "interrupted-before-start-record":
                raise ValueError("invalid unclaimed blocked snapshot attempt")
        else:
            if not isinstance(run_id, str) or not re.fullmatch(r"[a-f0-9]{32}", run_id):
                raise ValueError("invalid snapshot run identity")
            if run_id in seen_run_ids:
                raise ValueError("duplicate snapshot run_id")
            seen_run_ids.add(run_id)
            if measurement is not None:
                if not isinstance(measurement, dict):
                    raise ValueError("snapshot measurement must be an object")
                phase, entry = entries[planned]
                reader.measurement(measurement, reader.metadata(phase, entry, number, run_id))
                if row["state"] != "unfinalized" and measurement["status"] != row["state"]:
                    raise ValueError("snapshot attempt state differs from its measurement")
            elif row["state"] != "unfinalized":
                raise ValueError("claimed terminal snapshot attempt is missing its measurement")
    for numbers in ordinals.values():
        if sorted(numbers) != list(range(1, len(numbers) + 1)):
            raise ValueError("snapshot history contains missing or duplicate ordinals")
    for row in attempts:
        if row["state"] == "unfinalized" and row["attempt_number"] < max(
            ordinals[row["planned_id"]]
        ):
            raise ValueError("a snapshot retry follows an unfinalized predecessor")
    if snapshot.get("unattempted_planned_ids") != sorted(entries.keys() - ordinals.keys()):
        raise ValueError("snapshot unattempted identities differ from the plan")


def load_snapshot(
    output: Path,
    *,
    base: Path,
    expected_plan_sha256: str | None = None,
    expected_input_lock_sha256: str | None = None,
) -> dict[str, Any]:
    """Hold the existing journal lock while reading a validated, immutable snapshot."""
    output = Path(os.path.abspath(output))
    base = Path(os.path.abspath(base))
    if output.is_symlink() or not output.is_dir():
        raise ValueError("campaign output must be an existing real directory")
    lock_path = output / ".executor.lock"
    if lock_path.is_symlink() or not lock_path.is_file():
        raise ValueError("campaign requires an existing regular executor lock")
    try:
        with lock_path.open("rb") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ValueError(
                    "campaign is being executed; snapshot requires an idle journal"
                ) from exc
            snapshot = _Reader(output, base).load(expected_plan_sha256, expected_input_lock_sha256)
            validate_snapshot(snapshot)
            return snapshot
    except OSError as exc:
        raise ValueError(f"cannot read campaign snapshot: {exc}") from exc
