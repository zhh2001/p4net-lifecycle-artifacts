"""Adapt retained observer artifacts without changing native task outcomes."""

from __future__ import annotations

import copy
import hashlib
import json
import math
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import Any

from harness.campaign_executor import _equal
from harness.campaign_inputs import _constant, _pairs
from harness.observer_campaign import REFERENCE_METRICS, observation_metadata
from harness.observer_reference import BOUNDARIES, ObserverIdentity, _binding
from harness.resources import ProcessTarget, _valid_sample, cpu_interval

DURATION_NS = 10_000_000_000
INTERVAL_NS = 100_000_000
_MISSING = object()


def _integer(value: Any, name: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name} requires an integer of at least {minimum}")
    return value


def _number(value: Any, name: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} requires a finite nonnegative number")
    try:
        finite = math.isfinite(value)
    except OverflowError:
        finite = False
    if not finite or value < 0:
        raise ValueError(f"{name} requires a finite nonnegative number")
    return value


class _Artifacts:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.references: dict[str, dict[str, str]] = {}
        self.values: dict[str, dict[str, Any]] = {}

    def read(self, name: str, reference: Any = _MISSING) -> dict[str, Any]:
        path = self.root / name
        if reference is not _MISSING:
            if not isinstance(reference, Mapping) or not isinstance(reference.get("path"), str):
                raise ValueError(f"{name} requires its published path and SHA-256")
            supplied = Path(reference["path"])
            if not supplied.is_absolute():
                supplied = self.root / supplied
            if supplied != path:
                raise ValueError(f"{name} reference points outside its expected artifact")
        if name not in self.values:
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"{name} must be a regular published file")
            content = path.read_bytes()
            value = json.loads(content, object_pairs_hook=_pairs, parse_constant=_constant)
            if not isinstance(value, dict):
                raise ValueError(f"{name} must contain a JSON object")
            self.values[name] = value
            self.references[name] = {
                "path": str(path),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        value = self.values[name]
        digest = self.references[name]["sha256"]
        if reference is not _MISSING and reference.get("sha256") != digest:
            raise ValueError(f"{name} differs from its published SHA-256")
        self.references[name] = {"path": str(path), "sha256": digest}
        return value


def _record(value: Mapping[str, Any], kind: str, binding: Mapping[str, str]) -> None:
    if (
        type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or value.get("record_type") != kind
        or value.get("mode") != "pilot"
        or value.get("performance_samples") is not True
        or any(value.get(key) != expected for key, expected in binding.items())
    ):
        raise ValueError(f"{kind} schema, mode, or attempt identity differs")


def _native(value: Any, run_id: str) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or value.get("run_id") != run_id
        or type(value.get("ok")) is not bool
    ):
        raise ValueError("native result requires its exact run identity and boolean outcome")
    return value


def _reference_events(reference: Mapping[str, Any]) -> None:
    events = reference.get("reference_events")
    if (
        not isinstance(events, list)
        or any(not isinstance(event, dict) for event in events)
        or [event.get("boundary") for event in events] != list(BOUNDARIES)
    ):
        raise ValueError("reference requires all three ordered publication boundaries")
    previous = 0
    for index, event in enumerate(events):
        received = _integer(event.get("received_ns"), "reference received time")
        acknowledged = _integer(event.get("ack_sent_ns"), "reference acknowledgment time")
        if not previous <= received <= acknowledged:
            raise ValueError("reference checkpoints are not in chronological order")
        if index == 0:
            probe = _integer(event.get("cpu_probe_end_ns"), "initial CPU probe end")
            start = _integer(event.get("start_ack_ns"), "reference start acknowledgment")
            if not received <= probe <= start <= acknowledged:
                raise ValueError("reference start precedes its initial CPU probe")
        elif index == 2:
            cpu = _integer(event.get("cpu_probe_end_ns"), "final CPU probe end")
            memory_start = _integer(event.get("memory_probe_start_ns"), "memory probe start")
            memory_end = _integer(event.get("memory_probe_end_ns"), "memory probe end")
            if not received <= cpu <= memory_start <= memory_end <= acknowledged:
                raise ValueError("endpoint memory probe precedes closure of wall/CPU endpoints")
        previous = acknowledged


def _reference_metrics(reference: Mapping[str, Any], issues: list[str]) -> dict[str, int | float]:
    metrics: dict[str, int | float] = {}
    identity = ObserverIdentity(**reference["observer"]).as_dict()
    try:
        start = _integer(reference.get("wall_start_ns"), "reference wall start")
        end = _integer(reference.get("wall_end_ns"), "reference wall end")
        span = _integer(reference.get("observer_body_wall_ns"), "reference wall duration")
        if (
            end < start
            or span != end - start
            or start != reference["reference_events"][0]["start_ack_ns"]
            or end != reference["reference_events"][2]["received_ns"]
        ):
            raise ValueError("reference wall duration differs from its acknowledged endpoints")
        metrics["observer_body_wall_ns"] = span
    except (KeyError, TypeError, ValueError) as exc:
        issues.append(str(exc))
    try:
        ticks = _integer(reference.get("clock_ticks"), "observer clock ticks", 1)
        endpoints = [reference["observer_cpu_start"], reference["observer_cpu_end"]]
        for endpoint in endpoints:
            if not isinstance(endpoint, dict) or endpoint.get("observer") != identity:
                raise ValueError("observer CPU endpoint identifies another process")
            user = _integer(endpoint.get("user_ticks"), "observer user ticks")
            system = _integer(endpoint.get("system_ticks"), "observer system ticks")
            if _integer(endpoint.get("cpu_ticks"), "observer CPU ticks") != user + system:
                raise ValueError(
                    "observer CPU total includes counters outside its own user/system ticks"
                )
        if any(endpoints[1][key] < endpoints[0][key] for key in ("user_ticks", "system_ticks")):
            raise ValueError("observer CPU counters decreased")
        delta = endpoints[1]["cpu_ticks"] - endpoints[0]["cpu_ticks"]
        seconds = _number(reference.get("observer_cpu_seconds"), "observer CPU seconds")
        resolution = _number(
            reference.get("observer_cpu_resolution_seconds"), "observer CPU resolution"
        )
        if (
            _integer(reference.get("observer_cpu_delta_ticks"), "observer CPU delta") != delta
            or seconds != delta / ticks
            or resolution != 1 / ticks
        ):
            raise ValueError("observer CPU scalar differs from its raw tick endpoints")
        metrics["observer_cpu_seconds"] = seconds
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        issues.append(str(exc))
    endpoint = reference.get("observer_memory_endpoint")
    if not isinstance(endpoint, dict) or endpoint.get("observer") != identity:
        issues.append("observer memory endpoint identifies another process")
    else:
        for source, metric in (
            ("rss_bytes", "observer_rss_bytes"),
            ("pss_bytes", "observer_pss_bytes"),
        ):
            try:
                metrics[metric] = _integer(endpoint.get(source), source)
            except ValueError as exc:
                issues.append(str(exc))
    if reference.get("reference_cost_subtracted") is not False:
        issues.append("reference costs must not be subtracted")
    try:
        _integer(reference.get("reference_process_cpu_ns"), "reference process CPU diagnostics")
    except ValueError as exc:
        issues.append(str(exc))
    return metrics


def _checks(value: Mapping[str, Any]) -> None:
    checks = value.get("checks")
    if value.get("ready") is not True or not isinstance(checks, list) or not checks:
        raise ValueError("native task lacks verified readiness and connectivity checks")
    if any(not isinstance(check, dict) or check.get("ok") is not True for check in checks):
        raise ValueError("native connectivity checks are incomplete")
    if (
        value.get("error") is not None
        or value.get("errors")
        or value.get("ordinary_stop_timeout", False) is not False
    ):
        raise ValueError("native task retained a protocol error or ordinary stop timeout")
    if value.get("worker_returncode") != 0 or type(value.get("worker_returncode")) is not int:
        raise ValueError("native worker did not exit successfully")


def _native_health(native: Mapping[str, Any], phases: tuple[str, ...]) -> None:
    if native.get("framework_error") is not None:
        raise ValueError("native episode retained a framework error")
    if native.get("ok") is not True:
        raise ValueError("native task did not complete")
    if len(phases) == 1:
        _checks(native)
        cleanup = native.get("cleanup")
        if (
            not isinstance(cleanup, dict)
            or cleanup.get("ordinary_after_clean") is not True
            or cleanup.get("after_clean") is not True
            or cleanup.get("rescue_attempted") is not False
            or cleanup.get("not_started", False) is not False
        ):
            raise ValueError("native ordinary cleanup was incomplete or required rescue")
    else:
        if (
            native.get("fault") != "normal-control"
            or native.get("framework_complete") is not True
            or native.get("recovery_success") is not True
            or native.get("primary_outcome_saved_before_safety") is not True
            or native.get("safety_after_clean") is not True
            or native.get("safety_actions") != []
            or native.get("fixture_safety_errors") != []
        ):
            raise ValueError("normal-control recovery or ordinary cleanup was incomplete")
        for phase in phases:
            attempt = native.get(phase)
            if not isinstance(attempt, dict):
                raise ValueError("normal-control episode is missing a task phase")
            _checks(attempt)
            if (
                attempt.get("stopped") is not True
                or attempt.get("ordinary_cleanup_clean") is not True
                or attempt.get("ordinary_stop_timeout") is not False
            ):
                raise ValueError("normal-control task did not stop and clean up ordinarily")


def _window(
    window: Any,
    targets: list[dict[str, Any]],
    hold: Mapping[str, Any],
    domain: str,
    duration: int,
    interval: int,
) -> None:
    if (
        not isinstance(window, dict)
        or window.get("record_type") != "idle-resource-window"
        or window.get("mode") != "pilot"
        or window.get("performance_samples") is not True
        or window.get("clock_domain") != domain
        or window.get("targets") != targets
        or window.get("complete") is not True
        or type(window.get("missed_deadlines")) is not int
        or window["missed_deadlines"] != 0
        or window.get("errors") != []
        or window.get("requested_duration_ns") != duration
        or window.get("requested_interval_ns") != interval
        or window.get("window_start_ns") != hold["anchor_ns"]
        or window.get("scheduled_end_ns") != hold["scheduled_end_ns"]
    ):
        raise ValueError("sampled profile lacks a complete target-bound resource window")
    ended = _integer(window.get("window_end_ns"), "resource window end")
    if not hold["scheduled_end_ns"] <= ended <= hold["callback_end_ns"]:
        raise ValueError("resource window lies outside its scheduled hold and callback")
    if (
        _integer(window.get("overrun_ns"), "resource window overrun")
        != ended - hold["scheduled_end_ns"]
    ):
        raise ValueError("resource window overrun differs from its completed reads")
    frequency = _integer(window.get("clock_ticks"), "resource clock ticks", 1)
    rounds = window.get("rounds")
    if not isinstance(rounds, list) or len(rounds) != (duration + interval - 1) // interval + 1:
        raise ValueError("sampled profile is missing scheduled resource endpoints")
    roles = window.get("role_metrics")
    if not isinstance(roles, dict) or set(roles) != {item["role"] for item in targets}:
        raise ValueError("resource window lacks finite role summaries")
    for role in roles.values():
        if not isinstance(role, dict) or set(role) != {"cpu_percent", "rss_bytes", "pss_bytes"}:
            raise ValueError("resource role summary is incomplete")
        for name, value in role.items():
            _number(value, f"resource role {name}")
    for index, row in enumerate(rounds):
        if not isinstance(row, list) or len(row) != len(targets):
            raise ValueError("resource round does not cover every verified target")
        scheduled = hold["anchor_ns"] + min(index * interval, duration)
        for target, sample in zip(targets, row, strict=True):
            if not isinstance(sample, dict):
                raise ValueError("resource sample must be a record")
            actual, _, _ = _valid_sample(sample)
            if actual != target or sample.get("clock_domain") != domain:
                raise ValueError("resource sample identity or clock domain differs")
            _integer(sample.get("rss_bytes"), "sample RSS")
            _integer(sample.get("pss_bytes"), "sample PSS")
            if sample["sample_start_ns"] < scheduled or sample["sample_end_ns"] > ended:
                raise ValueError("resource sample lies outside its scheduled window endpoint")
            if index + 1 < len(rounds) and sample["sample_end_ns"] > hold["anchor_ns"] + min(
                (index + 1) * interval, duration
            ):
                raise ValueError(
                    "resource reads skipped a scheduled endpoint without a recorded miss"
                )
        if index:
            for previous, current in zip(rounds[index - 1], row, strict=True):
                if cpu_interval(previous, current, clock_ticks=frequency).get("ok") is not True:
                    raise ValueError("resource samples do not have valid paired CPU intervals")


def _profile_health(
    child: Mapping[str, Any],
    native: Mapping[str, Any],
    metadata: Mapping[str, Any],
    phases: tuple[str, ...],
    duration: int,
    interval: int,
) -> None:
    profile = metadata["observer_profile"]
    expected_observation_metadata = observation_metadata(metadata)
    observation = native.get("observation")
    record = child.get("profile_observation")
    if not isinstance(observation, dict) or not isinstance(record, dict):
        raise ValueError("native observation or profile record is missing")
    if (
        type(record.get("schema_version")) is not int
        or record.get("schema_version") != 1
        or record.get("record_type") != "observer-profile-record"
        or record.get("mode") != "pilot"
        or record.get("performance_samples") is not True
        or record.get("run_id") != metadata["run_id"]
        or record.get("observer_profile") != profile
        or record.get("issues") != []
        or not isinstance(record.get("clock_domain"), str)
        or not record["clock_domain"].strip()
    ):
        raise ValueError("profile record schema, identity, or issues differ")
    boundary = observation if profile == "B" else observation.get("native_observation")
    if (
        not isinstance(boundary, dict)
        or type(boundary.get("schema_version")) is not int
        or boundary.get("schema_version") != 1
        or boundary.get("record_type") != "native-boundary-validation"
        or boundary.get("performance_samples") is not False
        or boundary.get("issues") != []
    ):
        raise ValueError("native boundary observation is invalid")
    if profile == "B" and {"markers", "metrics", "resource_windows"} & observation.keys():
        raise ValueError("boundary profile unexpectedly contains timing or resource records")
    if profile != "B" and (
        observation.get("record_type") != "measurement-record"
        or observation.get("mode") != "pilot"
        or observation.get("performance_samples") is not True
        or any(
            observation.get(key) != value for key, value in expected_observation_metadata.items()
        )
        or observation.get("status") != "completed"
        or observation.get("measurement_issues") != []
        or observation.get("clock_domain") != record["clock_domain"]
    ):
        raise ValueError("timestamped native observation has issues or a different identity")
    holds, targets = record.get("holds"), boundary.get("targets")
    if (
        not isinstance(holds, dict)
        or not isinstance(targets, dict)
        or set(holds) != set(phases)
        or set(targets) != set(phases)
    ):
        raise ValueError("profile holds and verified targets do not cover the planned phases")
    boundaries = boundary.get("boundaries")
    if not isinstance(boundaries, list) or any(not isinstance(item, dict) for item in boundaries):
        raise ValueError("native boundaries are missing")
    windows = observation.get("resource_windows", {})
    if not isinstance(windows, dict) or set(windows) != (set(phases) if profile == "S" else set()):
        raise ValueError("resource windows differ from the selected profile")
    groups = _integer(metadata.get("switches"), "switch count", 1)
    for phase in phases:
        selected = targets[phase]
        if not isinstance(selected, list):
            raise ValueError("verified target set is missing")
        for item in selected:
            ProcessTarget(**item)
        if (
            len(selected) != groups + 1
            or len({item["pid"] for item in selected}) != len(selected)
            or sum(item["role"] == "worker" for item in selected) != 1
            or sum(item["role"] == "bmv2" for item in selected) != groups
        ):
            raise ValueError("verified targets do not cover the worker and all switches")
        names = [item.get("boundary") for item in boundaries if item.get("phase") == phase]
        required = (
            "worker_launch",
            "ready_received",
            "ready_validated",
            "targets_verified",
            "worker_exit",
            "ordinary_audit_start",
            "ordinary_audit_end",
        )
        positions = [names.index(name) for name in required]
        if positions != sorted(positions) or any(names.count(name) != 1 for name in required):
            raise ValueError(
                "native readiness, target selection, and audit boundaries are misordered"
            )
        hold = holds[phase]
        if (
            not isinstance(hold, dict)
            or hold.get("phase") != phase
            or hold.get("observer_profile") != profile
            or hold.get("complete") is not True
            or hold.get("requested_duration_ns") != duration
        ):
            raise ValueError("profile hold is incomplete or has a different phase or duration")
        anchor = _integer(hold.get("anchor_ns"), "hold anchor")
        deadline = _integer(hold.get("scheduled_end_ns"), "hold deadline")
        ended = _integer(hold.get("callback_end_ns"), "hold callback end")
        if (
            deadline - anchor != duration
            or ended < deadline
            or hold.get("extension_ns") != ended - deadline
        ):
            raise ValueError("profile hold did not preserve one common scheduled deadline")
        if profile != "B":
            markers = observation.get("markers")
            ready_name = "ready_received" if phase == "initial" else "restart_ready_received"
            if (
                not isinstance(markers, dict)
                or _integer(markers.get(ready_name), "ready marker") > anchor
            ):
                raise ValueError("hold anchor precedes its validated readiness timestamp")
            if (
                phase == "initial"
                and _integer(markers.get("stop_request"), "stop request marker") < ended
            ):
                raise ValueError("hold callback overlaps the initial stop request")
        if profile == "S":
            _window(windows[phase], selected, hold, record["clock_domain"], duration, interval)


def adapt_result(
    dispatch: Mapping[str, Any],
    metadata: Mapping[str, Any],
    *,
    artifacts: Path,
    duration_ns: int = DURATION_NS,
    interval_ns: int = INTERVAL_NS,
) -> dict[str, Any]:
    """Return independently qualified metrics and an unchanged known native outcome."""
    _integer(duration_ns, "hold duration", 1)
    _integer(interval_ns, "sample interval", 1)
    if interval_ns > duration_ns:
        raise ValueError("sample interval exceeds the hold duration")
    binding = _binding(
        metadata.get("run_id"), metadata.get("attempt_id"), metadata.get("observer_profile")
    )
    if metadata.get("workload") not in {"scale", "fault"} or (
        metadata.get("workload") == "fault" and metadata.get("fault") != "normal-control"
    ):
        raise ValueError("observer calibration supports scale and normal-control workloads")
    phases = ("initial", "restart") if metadata["workload"] == "fault" else ("initial",)
    files = _Artifacts(artifacts)
    issues: list[str] = []
    trusted_dispatch = False
    native: dict[str, Any] | None = None
    child: dict[str, Any] | None = None
    metrics: dict[str, int | float] = {}
    reference_status = "incomplete"
    treatment_valid = False
    primary: dict[str, Any] | None = None
    try:
        persisted = files.read("observer-dispatch.json")
        _record(persisted, "observer-calibration-dispatch-record", binding)
        if not _equal(persisted, dict(dispatch)):
            raise ValueError("returned dispatch differs from its published record")
        if persisted.get("dispatch_status") not in {
            "completed",
            "failed",
            "timeout",
            "interrupted",
        }:
            raise ValueError("dispatch has an invalid transport status")
        trusted_dispatch = True
    except (OSError, KeyError, TypeError, ValueError) as exc:
        issues.append(str(exc))
    with suppress(OSError, KeyError, TypeError, ValueError):
        native = _native(files.read("result.json"), binding["run_id"])
    if trusted_dispatch:
        try:
            child = files.read("observer-child-result.json", dispatch.get("child_result"))
            _record(child, "observer-calibration-child-result", binding)
            from_child = _native(child.get("native_result"), binding["run_id"])
            if native is not None and not _equal(native, from_child):
                raise ValueError("ordinary native result differs from the child envelope")
            native = from_child
            source = dispatch.get("native_result_source")
            if not isinstance(source, dict) or source.get("kind") not in {
                "child-envelope",
                "ordinary-result",
            }:
                raise ValueError("dispatch is missing its native result source binding")
            source_name = (
                "observer-child-result.json"
                if source["kind"] == "child-envelope"
                else "result.json"
            )
            source_value = files.read(source_name, source)
            source_native = (
                source_value["native_result"]
                if source_name == "observer-child-result.json"
                else source_value
            )
            if (
                not _equal(source_native, native)
                or dispatch.get("native_outcome_available") is not True
                or dispatch.get("native_ok") is not native["ok"]
            ):
                raise ValueError("dispatch native outcome differs from its published source")
            terminal = files.read(
                "observer-calibration-result.json", dispatch.get("calibration_terminal")
            )
            _record(terminal, "observer-calibration-record", binding)
            if (
                terminal.get("native_ok") is not native["ok"]
                or terminal.get("reference_status") != "complete"
                or terminal.get("reference_failed") is not False
                or type(terminal.get("acknowledged_boundaries")) is not int
                or terminal["acknowledged_boundaries"] != 3
            ):
                raise ValueError(
                    "calibration terminal lacks complete acknowledged reference endpoints"
                )
            files.read("observer-child-result.json", terminal.get("child_result"))
            reference = files.read("observer-reference.json", terminal.get("reference_sidecar"))
            _record(reference, "observer-reference-record", binding)
            files.read("observer-child-result.json", reference.get("child_result"))
            if child.get("reference_primary_acknowledged") is not True:
                raise ValueError("child primary publication was not acknowledged")
            primary = files.read("measurement-primary.json", child.get("primary_publication"))
            identity = ObserverIdentity(**reference["observer"]).as_dict()
            if native.get("pid_namespace") != identity["namespaces"]["pid"]:
                raise ValueError("native task and reference identify different PID namespaces")
            _reference_events(reference)
            reference_status = "complete"
            metrics = _reference_metrics(reference, issues)
        except (OSError, KeyError, TypeError, ValueError) as exc:
            issues.append(str(exc))
        if (
            native is None
            and dispatch.get("native_outcome_available") is True
            and type(dispatch.get("native_ok")) is bool
        ):
            native = {
                "schema_version": 1,
                "run_id": binding["run_id"],
                "ok": dispatch["native_ok"],
                "outcome_source": "published-dispatch",
            }
            issues.append(
                "native outcome retained from dispatch without its original result artifact"
            )
    if native is not None:
        if native["ok"]:
            status = "completed"
        elif (
            native.get("ordinary_stop_timeout") is True
            or any(
                isinstance(native.get(key), dict)
                and isinstance(native[key].get("type"), str)
                and "Timeout" in native[key]["type"]
                for key in ("framework_error", "error")
            )
            or (
                native.get("outcome_source") == "published-dispatch"
                and dispatch.get("dispatch_status") == "timeout"
            )
        ):
            status = "timeout"
        elif (
            isinstance(native.get("cleanup"), dict) and native["cleanup"].get("not_started") is True
        ):
            status = "blocked"
        else:
            status = "failed"
    else:
        status = (
            "timeout"
            if trusted_dispatch and dispatch.get("dispatch_status") == "timeout"
            else ("blocked" if trusted_dispatch and dispatch.get("outer_pid") is None else "failed")
        )
        issues.append("native task outcome is unavailable")
    if not trusted_dispatch or dispatch.get("dispatch_status") != "completed":
        issues.append("observer transport did not complete")
    if dispatch.get("cleanup_issues") or dispatch.get("publication_error") or dispatch.get("error"):
        issues.append("observer dispatch retained cleanup or publication errors")
    if native is not None and child is not None:
        try:
            _native_health(native, phases)
            _profile_health(child, native, metadata, phases, duration_ns, interval_ns)
            if primary is None:
                raise ValueError("original primary observation is unavailable")
            _profile_health(
                child,
                {**native, "observation": primary},
                metadata,
                phases,
                duration_ns,
                interval_ns,
            )
            boundary = (
                primary if metadata["observer_profile"] == "B" else primary["native_observation"]
            )
            if any(
                item["boundary"] in {"safety_start", "safety_end"}
                for item in boundary["boundaries"]
            ):
                raise ValueError("primary observation was saved after safety escalation")
            treatment_valid = True
        except (KeyError, TypeError, ValueError) as exc:
            issues.append(str(exc))
    else:
        issues.append("complete native and profile evidence is unavailable")
    for name, pointer in files.references.items():
        try:
            path = files.root / name
            if (
                path.is_symlink()
                or hashlib.sha256(path.read_bytes()).hexdigest() != pointer["sha256"]
            ):
                raise ValueError("published artifacts changed during result adaptation")
        except (OSError, ValueError) as exc:
            issues.append(str(exc))
            reference_status = "incomplete"
            treatment_valid = False
    if reference_status == "incomplete":
        metrics = {}
    reference_metrics = copy.deepcopy(metrics)
    if not treatment_valid:
        metrics = {}
    measurement = {
        **copy.deepcopy(dict(metadata)),
        "schema_version": 1,
        "record_type": "observer-calibration-measurement",
        "mode": "pilot",
        "performance_samples": True,
        "status": status,
        "reference_status": reference_status,
        "metrics": metrics,
        "reference_metrics": reference_metrics,
        "treatment_valid": treatment_valid,
        "measurement_issues": issues,
        "qualified": status == "completed"
        and not issues
        and set(REFERENCE_METRICS) <= metrics.keys(),
    }
    return {
        "measurement": measurement,
        "native_result": copy.deepcopy(native or {}),
        "dispatch_result": copy.deepcopy(dict(dispatch)),
        "artifact_references": copy.deepcopy(files.references),
    }
