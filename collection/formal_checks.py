"""Inspect formal attempt evidence without launching workers or reading live resources."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping
from itertools import pairwise
from pathlib import Path
from typing import Any

from harness.aggregate import primary_performance_exclusion, validate_record
from harness.audit import is_clean
from harness.campaign_inputs import _constant, _pairs
from harness.episode import allowed_restart, signatures
from harness.measure import PREREQUISITES, Recorder
from harness.resources import _valid_sample, cpu_interval

Record = dict[str, Any]
DURATION_NS = 10_000_000_000
INTERVAL_NS = 100_000_000


def require(value: bool, reason: str) -> None:
    if not value:
        raise ValueError(reason)


class Reader:
    def __init__(self, base: Path, shared_sources: Mapping[Path, str] | None = None) -> None:
        self.base = base.resolve()
        self.files: dict[str, str] = {}
        self.shared_sources = dict(shared_sources or {})

    def content(self, path: Path) -> bytes:
        path = path.absolute()
        require(".." not in path.parts, "evidence path contains parent traversal")
        local = path.is_relative_to(self.base)
        require(local or path in self.shared_sources, "evidence is outside the study")
        for part in (path, *path.parents):
            if part == self.base:
                break
            require(not part.is_symlink(), "evidence uses a symbolic link")
        require(
            path.resolve().is_relative_to(self.base) or path in self.shared_sources,
            "evidence escapes the study",
        )
        require(path.is_file(), f"missing regular evidence file: {path.name}")
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        name = str(path.relative_to(self.base)) if local else str(path)
        if not local:
            require(digest == self.shared_sources[path], "shared workload source changed")
        require(
            name not in self.files or self.files[name] == digest, "evidence changed during read"
        )
        self.files[name] = digest
        return data

    def read(self, path: Path, reference: Any = None) -> Record:
        data = self.content(path)
        digest = hashlib.sha256(data).hexdigest()
        if reference is not None:
            require(isinstance(reference, dict), "published evidence reference is missing")
            require(set(reference) == {"path", "sha256"}, "evidence reference fields differ")
            supplied = Path(reference["path"])
            supplied = supplied if supplied.is_absolute() else path.parent / supplied
            require(supplied == path, "published evidence identifies another file")
            require(reference["sha256"] == digest, "published evidence hash differs")
        value = json.loads(data, object_pairs_hook=_pairs, parse_constant=_constant)
        require(isinstance(value, dict), "evidence must be a JSON object")
        return dict(value)


def window_check(window: Record, targets: list[Record], switches: int, domain: str) -> None:
    require(
        window.get("record_type") == "idle-resource-window"
        and window.get("mode") == "formal"
        and window.get("performance_samples") is True
        and window.get("clock_domain") == domain,
        "resource window measurement identity differs",
    )
    require(window.get("targets") == targets, "resource window target identities differ")
    require(
        window.get("complete") is True
        and window.get("errors") == []
        and type(window.get("missed_deadlines")) is int
        and window["missed_deadlines"] == 0,
        "resource window is incomplete or contains missed or failed reads",
    )
    require(
        window.get("requested_duration_ns") == DURATION_NS
        and window.get("requested_interval_ns") == INTERVAL_NS,
        "resource window schedule differs",
    )
    require(
        Counter(target.get("role") for target in targets) == {"worker": 1, "bmv2": switches}
        and len({target["pid"] for target in targets}) == switches + 1,
        "resource targets do not cover the worker and every switch",
    )
    start, end = window["window_start_ns"], window["window_end_ns"]
    require(type(start) is type(end) is int and start >= 0, "invalid resource window endpoints")
    require(
        window.get("scheduled_end_ns") == start + DURATION_NS
        and end >= start + DURATION_NS
        and window.get("overrun_ns") == end - start - DURATION_NS,
        "resource window endpoints differ",
    )
    ticks = window["clock_ticks"]
    require(type(ticks) is int and ticks > 0, "invalid resource clock ticks")
    rounds = window["rounds"]
    require(isinstance(rounds, list) and len(rounds) == 101, "resource window needs 101 rounds")
    for index, row in enumerate(rounds):
        require(isinstance(row, list) and len(row) == switches + 1, "resource round lacks targets")
        for target, sample in zip(targets, row, strict=True):
            actual, _, _ = _valid_sample(sample)
            require(
                actual == target and sample.get("clock_domain") == domain, "sample identity differs"
            )
            begin, finish = sample["sample_start_ns"], sample["sample_end_ns"]
            read_end = sample["cpu_read_end_ns"]
            require(
                begin <= read_end <= finish
                and sample["cpu_midpoint_ns"] == (begin + read_end) // 2,
                "sample CPU midpoint differs",
            )
            require(begin >= start + index * INTERVAL_NS and finish <= end, "sample timing differs")
            if index < 100:
                require(finish <= start + (index + 1) * INTERVAL_NS, "sample skipped an endpoint")
            require(
                all(
                    type(sample[key]) is int and sample[key] >= 0
                    for key in ("rss_bytes", "pss_bytes")
                ),
                "sample memory value differs",
            )
    roles: Record = {}
    for index, target in enumerate(targets):
        samples = [row[index] for row in rounds]
        intervals = [cpu_interval(a, b, clock_ticks=ticks) for a, b in pairwise(samples)]
        require(all(item.get("ok") is True for item in intervals), "CPU sample intervals differ")
        wall = sum(item["wall_ns"] for item in intervals)
        values = {
            "cpu_percent": sum(item["cpu_ticks"] for item in intervals)
            * 100_000_000_000
            / (ticks * wall)
        }
        for key in ("rss_bytes", "pss_bytes"):
            values[key] = (
                sum(
                    (a[key] + b[key]) / 2 * interval["wall_ns"]
                    for (a, b), interval in zip(pairwise(samples), intervals, strict=True)
                )
                / wall
            )
        totals = roles.setdefault(target["role"], dict.fromkeys(values, 0.0))
        for key, value in values.items():
            totals[key] += value
    require(window.get("role_metrics") == roles, "resource metrics differ from raw observations")


def inspect_attempt(
    journal: Path, row: Record, *, base: Path, shared_sources: Mapping[Path, str] | None = None
) -> Record:
    report: Record = {
        "record_type": "formal-measurement-inspection",
        "inspection_read_only": True,
        "new_worker_launches": 0,
        "new_resource_samples": 0,
        "planned_id": row.get("planned_id"),
        "attempt_number": row.get("attempt_number"),
        "status": row.get("status"),
        "measurement_intact": False,
        "safe_to_continue": False,
        "can_continue": False,
        "primary_performance_eligible": False,
        "primary_performance_exclusion": None,
        "issues": [],
    }
    reader = Reader(base, shared_sources)
    try:
        directory = journal / row["directory"]
        require(
            ".." not in Path(row["directory"]).parts
            and directory.resolve().is_relative_to(journal.resolve()),
            "attempt directory is outside its journal",
        )
        terminal = reader.read(directory / "result.json")
        if not (directory / "started.json").exists():
            require(
                terminal.get("status") == "blocked"
                and terminal.get("run_id") is None
                and terminal.get("reason") == "interrupted-before-start-record",
                "terminal claim lacks its start record",
            )
            raise ValueError("interrupted claim has no inspectable native measurement")
        started = reader.read(directory / "started.json")
        metadata, entry = started["metadata"], started["entry"]
        measurement = reader.read(directory / "measurement.json", terminal["measurement"])
        backend = reader.read(directory / "backend-result.json", terminal["backend_result"])
        native = backend["native_result"]
        binding = reader.read(journal / "campaign-binding.json")
        require(binding.get("mode") == "formal", "formal inspection requires a formal binding")
        require(
            metadata["input_lock_sha256"]
            == binding["input_lock_sha256"]
            == started["input_lock_sha256"],
            "input lock differs",
        )
        require(
            row["status"] == terminal["status"] == measurement["status"], "terminal status differs"
        )
        for key in ("planned_id", "attempt_number", "run_id", "measurement", "backend_result"):
            require(row.get(key) == terminal.get(key), f"attempt row differs: {key}")
        require(metadata["planned_id"] == directory.parent.name, "planned directory differs")
        require(directory.name == f"{metadata['attempt_number']:04}", "attempt ordinal differs")
        require(
            metadata["attempt_id"] == f"{metadata['planned_id']}--a{metadata['attempt_number']:04}",
            "attempt identity differs",
        )
        require(metadata["workload"] in ("scale", "fault"), "unsupported workload")
        identity_key = (
            "planned_case_id" if metadata["workload"] == "scale" else "planned_episode_id"
        )
        require(
            metadata.get(identity_key) == entry.get(identity_key) == metadata["planned_id"],
            "planned case or episode identity differs",
        )
        require(metadata.get("fault") == entry.get("fault"), "planned fault identity differs")
        require(
            metadata.get("planned_execution_ids")
            == [item["planned_execution_id"] for item in entry.get("executions", [])],
            "planned execution identities differ",
        )
        require(metadata["configuration_profile"] == "matched-v1", "configuration differs")
        require(metadata["build_mode"] == "native-source-cold", "build workflow differs")
        require(metadata["python"] == "3.10.20", "worker Python differs")
        for key in (
            "session",
            "tool",
            "switches",
            "configuration_profile",
            "build_mode",
            "sequence",
            "repetition_within_session",
            "matched_block",
        ):
            require(metadata[key] == entry[key], f"planned metadata differs: {key}")
        for key, value in metadata.items():
            require(measurement.get(key) == value, f"measurement metadata differs: {key}")
        require(backend["measurement"] == measurement, "backend measurement differs")
        require(native.get("observation") == measurement, "native observation differs")
        validate_record(measurement, "formal")
        require(
            measurement.get("measurement_issues") == [],
            "retained measurement issues prevent advancement",
        )
        observed = measurement["native_observation"]
        require(
            observed.get("record_type") == "native-boundary-validation"
            and observed.get("performance_samples") is False
            and observed.get("issues") == [],
            "native boundary evidence is damaged",
        )
        boundaries = observed.get("boundaries")
        require(isinstance(boundaries, list), "native boundary list is missing")
        identities = [(value.get("phase"), value.get("boundary")) for value in boundaries]
        require(len(set(identities)) == len(identities), "native boundary is duplicated")
        require(
            all(
                phase in ("initial", "restart")
                and isinstance(name, str)
                and name
                in {*PREREQUISITES, "ready_validated", "targets_verified", "idle_window_attached"}
                for phase, name in identities
            ),
            "native boundary identity differs",
        )
        mapped = []
        for phase, name in identities:
            if phase == "initial" and name in PREREQUISITES:
                mapped.append(name)
            elif phase == "restart" and name in ("worker_launch", "ready_received"):
                mapped.append(
                    "restart_launch" if name == "worker_launch" else "restart_ready_received"
                )
        require(mapped == list(measurement["markers"]), "native and numeric boundary order differ")
        require(native.get("run_id") == metadata["run_id"], "native run identity differs")
        require(
            native.get("mode") == "formal" and native.get("performance_samples") is True,
            "native measurement mode differs",
        )
        manifest = reader.read(directory / "artifacts/manifest.json")
        require(manifest.get("run_id") == metadata["run_id"], "manifest run identity differs")
        require(manifest.get("groups") == metadata["switches"], "manifest topology differs")
        require(
            manifest.get("configuration_profile") == "matched-v1", "manifest configuration differs"
        )
        require(
            reader.read(directory / "artifacts/result.json") == native,
            "published native result differs",
        )
        isolation_path = directory / "artifacts-isolation.json"
        require(
            native.get("isolation_record") == str(isolation_path),
            "native isolation reference differs",
        )
        isolation = reader.read(isolation_path)
        require(
            isolation.get("mode") == "formal" and isolation.get("performance_samples") is True,
            "isolation measurement mode differs",
        )
        inner, outer = isolation["inner_namespaces"], isolation["outer_namespaces"]
        for key in ("pid", "net", "mnt", "ipc", "uts"):
            require(
                isinstance(inner.get(key), str) and inner[key] != outer.get(key),
                f"private {key} enclosure differs",
            )
        require(native.get("pid_namespace") == inner["pid"], "native PID enclosure differs")
        phases = (
            {"initial": native}
            if metadata["workload"] == "scale"
            else {
                key: value
                for key in ("initial", "restart")
                if isinstance(value := native.get(key), dict)
            }
        )
        if metadata["workload"] == "fault":
            require(
                native.get("fault") == metadata["fault"] == manifest.get("episode_fault"),
                "native fault identity differs",
            )
            for phase, value in phases.items():
                if "blocked" in value:
                    require(
                        phase == "restart" and value.get("ready") is not True,
                        "blocked phase contradicts readiness",
                    )
                    continue
                child = reader.read(directory / "artifacts" / phase / "manifest.json")
                for key in (
                    "groups",
                    "configuration_profile",
                    "service_ports",
                    "host_names",
                    "switch_names",
                    "addresses",
                    "interfaces",
                ):
                    if key in manifest:
                        require(child.get(key) == manifest[key], f"child manifest differs: {key}")
                require(
                    isinstance(child.get("run_id"), str) and child["run_id"] != metadata["run_id"],
                    "child manifest run identity differs",
                )
                require(
                    value.get("pid_namespace") == inner["pid"]
                    and value.get("outer_network_namespace") == inner["net"],
                    "native phases do not share their original enclosure",
                )
                source = Path(child["p4_source"])
                require(
                    hashlib.sha256(reader.content(source)).hexdigest() == child["source_sha256"],
                    "phase P4 source differs",
                )
                if phase == "restart" or metadata["fault"] != "invalid-p4":
                    require(
                        child["p4_source"] == manifest["p4_source"]
                        and child["source_sha256"] == manifest["source_sha256"],
                        "valid phase P4 source differs",
                    )
                inventory = reader.read(
                    directory / "artifacts" / phase / "inventory-ordinary-after.json"
                )
                require(
                    inventory.get("run_id") == metadata["run_id"]
                    and inventory.get("snapshot_errors") == [],
                    "ordinary inventory differs",
                )
                require(
                    value.get("ordinary_cleanup_clean") is is_clean(inventory),
                    "ordinary-cleanup outcome contradicts its inventory",
                )
            primary = reader.read(directory / "artifacts/primary-outcome.json")
            require(
                native.get("primary_outcome_saved_before_safety") is True,
                "original native outcome was not saved before safety cleanup",
            )
            require(
                "safety_actions" not in primary and "observation" not in primary,
                "primary native outcome contains later safety results",
            )
            require(
                all(native.get(key) == value for key, value in primary.items()),
                "native outcome changed after original publication",
            )
            if "restart" in phases and "blocked" not in phases["restart"]:
                initial_child = reader.read(directory / "artifacts/initial/manifest.json")
                restart_child = reader.read(directory / "artifacts/restart/manifest.json")
                require(
                    initial_child["run_id"] != restart_child["run_id"],
                    "initial and restart worker identities are not distinct",
                )
                original = reader.read(
                    directory / "artifacts/initial/inventory-ordinary-after.json"
                )
                before_restart = reader.read(directory / "artifacts/inventory-before-restart.json")
                require(
                    allowed_restart(before_restart, signatures(original)),
                    "restart inherited uncertain or unregistered residual identities",
                )
        initial = phases.get("initial", {})
        restart = phases.get("restart", {})
        cleanup = native.get("cleanup", {})
        for key, expected in {
            "ordinary_stop_timeout": initial.get(
                "ordinary_stop_timeout", native.get("ordinary_stop_timeout")
            ),
            "ordinary_cleanup_clean": initial.get(
                "ordinary_cleanup_clean", cleanup.get("ordinary_after_clean")
            ),
            "restart_ordinary_stop_timeout": restart.get("ordinary_stop_timeout"),
            "restart_ordinary_cleanup_clean": restart.get("ordinary_cleanup_clean"),
            "recovery_success": native.get("recovery_success"),
            "framework_complete": native.get("framework_complete"),
        }.items():
            if key.startswith("restart_ordinary_"):
                require(key in measurement, f"restart outcome field is missing: {key}")
            require(
                measurement.get(key) is expected, f"native outcome differs from measurement: {key}"
            )
        ready = sorted(
            "ready_received" if phase == "initial" else "restart_ready_received"
            for phase, value in phases.items()
            if value.get("ready") is True
        )
        require(measurement.get("validated_ready") == ready, "accepted readiness phases differ")
        windows, targets = measurement.get("resource_windows", {}), observed.get("targets", {})
        ready_phases = {"initial" if name == "ready_received" else "restart" for name in ready}
        require(
            set(windows) == set(targets) == ready_phases, "ready phases and resource windows differ"
        )
        for phase in ready_phases:
            expected_boundaries = [
                (phase, name)
                for name in (
                    "ready_received",
                    "ready_validated",
                    "targets_verified",
                    "idle_window_attached",
                )
            ]
            require(
                all(value in identities for value in expected_boundaries)
                and [identities.index(value) for value in expected_boundaries]
                == sorted(identities.index(value) for value in expected_boundaries),
                "ready resource boundary order differs",
            )
            window_check(
                windows[phase], targets[phase], metadata["switches"], measurement["clock_domain"]
            )
            worker = next(target for target in targets[phase] if target["role"] == "worker")
            identity = phases[phase].get("worker_identity")
            if identity is not None:
                require(
                    all(worker.get(key) == identity.get(key) for key in ("pid", "start_ticks")),
                    "resource worker differs from its native phase identity",
                )
            elif metadata["workload"] == "fault":
                raise ValueError("ready fault phase lacks its worker identity")
        recorder = Recorder(
            metadata, mode="formal", clock_domain=measurement["clock_domain"], clock_ns=lambda: 0
        )
        for name, value in measurement["markers"].items():
            recorder.mark(name, observed_ns=value)
            if name in ready:
                recorder.accept_ready(restart=name == "restart_ready_received")
                phase = "initial" if name == "ready_received" else "restart"
                recorder.attach_window(windows[phase], restart=phase == "restart")
        recomputed = recorder.finish(
            measurement["status"],
            **{
                key: measurement.get(key)
                for key in (
                    "ordinary_stop_timeout",
                    "ordinary_cleanup_clean",
                    "restart_ordinary_stop_timeout",
                    "restart_ordinary_cleanup_clean",
                    "recovery_success",
                    "framework_complete",
                )
            },
        )
        require(
            recomputed["metrics"] == measurement["metrics"],
            "published metrics differ from retained boundaries",
        )
        require(recomputed["measurement_issues"] == [], "retained boundary order is damaged")
        primary_path = directory / "artifacts/measurement-primary.json"
        primary_measurement = reader.read(primary_path)
        require(primary_measurement.get("mode") == "formal", "primary measurement mode differs")
        for key in (
            "ordinary_stop_timeout",
            "ordinary_cleanup_clean",
            "restart_ordinary_stop_timeout",
            "restart_ordinary_cleanup_clean",
            "recovery_success",
            "framework_complete",
        ):
            require(
                primary_measurement.get(key) is measurement.get(key),
                f"native outcome changed after primary publication: {key}",
            )
        if metadata["workload"] == "fault":
            require(
                primary_measurement.get("status") == measurement["status"],
                "primary fault measurement outcome differs",
            )
        require(
            primary_measurement.get("measurement_issues") == [], "primary measurement is damaged"
        )
        require(
            primary_measurement.get("metrics") == measurement["metrics"],
            "primary metrics changed during safety cleanup",
        )
        require(
            not {"safety_start", "safety_end"} & primary_measurement["markers"].keys(),
            "primary measurement includes safety cleanup timing",
        )
        require(
            all(
                measurement["markers"].get(key) == value
                for key, value in primary_measurement["markers"].items()
            ),
            "primary measurement boundaries changed after publication",
        )
        report.update(
            measurement_intact=True,
            attempt_id=metadata["attempt_id"],
            run_id=metadata["run_id"],
            native_ok=native.get("ok"),
            recovery_success=native.get("recovery_success"),
            ordinary_stop_timeout=measurement.get("ordinary_stop_timeout"),
            ordinary_cleanup_clean=measurement.get("ordinary_cleanup_clean"),
            restart_ordinary_stop_timeout=measurement.get("restart_ordinary_stop_timeout"),
            restart_ordinary_cleanup_clean=measurement.get("restart_ordinary_cleanup_clean"),
            resource_windows=len(windows),
            sample_rounds=sum(len(value["rounds"]) for value in windows.values()),
            primary_performance_exclusion=primary_performance_exclusion(measurement),
        )
        report["primary_performance_eligible"] = report["primary_performance_exclusion"] is None
        if metadata["workload"] == "fault":
            safety = reader.read(directory / "artifacts/inventory-after-safety.json")
            require(safety.get("run_id") == metadata["run_id"], "safety inventory identity differs")
            require(
                native.get("safety_after_clean") is is_clean(safety),
                "safety outcome contradicts inventory",
            )
            require(native.get("safety_after_clean") is True, "final safety cleanup is incomplete")
        else:
            cleanup = native.get("cleanup", {})
            ordinary = reader.read(directory / "artifacts/inventory-ordinary-after.json")
            require(
                ordinary.get("run_id") == metadata["run_id"]
                and ordinary.get("snapshot_errors") == [],
                "ordinary scale inventory differs",
            )
            require(
                cleanup.get("ordinary_after_clean") is is_clean(ordinary),
                "ordinary scale cleanup contradicts its inventory",
            )
            rescued = cleanup.get("rescue_attempted") is True
            key = "after_rescue_clean" if rescued else "after_clean"
            require(cleanup.get(key) is True, "final scale cleanup is incomplete")
            filename = "inventory-after-rescue.json" if rescued else "inventory-after.json"
            inventory = reader.read(directory / "artifacts" / filename)
            require(
                inventory.get("run_id") == metadata["run_id"] and is_clean(inventory),
                "final scale inventory is not clean",
            )
        report["safe_to_continue"] = True
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        IndexError,
        OverflowError,
        AttributeError,
    ) as exc:
        report["issues"].append(f"{type(exc).__name__}: {exc}")
    report["can_continue"] = (
        report["measurement_intact"] and report["safe_to_continue"] and not report["issues"]
    )
    report["files"] = [
        {"path": name, "sha256": digest} for name, digest in sorted(reader.files.items())
    ]
    return report
