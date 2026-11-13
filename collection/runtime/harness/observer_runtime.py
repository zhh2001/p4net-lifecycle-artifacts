"""Publish calibration child and parent records at acknowledged boundaries."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from harness.campaign_executor import _write_new
from harness.observer_profiles import ProfileObservation
from harness.observer_reference import ChildReference, ParentReference


def _publish(path: Path, value: Mapping[str, Any]) -> None:
    _write_new(path, value)


def _file(path: Path) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("a published regular result file is required")
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def run_synthetic_child(
    path: Path,
    reference: ChildReference,
    *,
    build_observation: Callable[[Callable[[Path], None]], ProfileObservation],
    run_task: Callable[[ProfileObservation], Mapping[str, Any]],
) -> dict[str, Any]:
    """Exercise the child coordinator using a synthetic observation only."""
    return run_child(
        path,
        reference,
        mode="synthetic-validation",
        build_observation=build_observation,
        run_task=run_task,
    )


def run_child(
    path: Path,
    reference: ChildReference,
    *,
    mode: str,
    build_observation: Callable[[Callable[[Path], None]], ProfileObservation],
    run_task: Callable[[ProfileObservation], Mapping[str, Any]],
) -> dict[str, Any]:
    """Publish the final child before closing independent reference endpoints.

    The native dispatcher checks collection authorization before launch.
    The coordinator neither starts a worker nor chooses its clock or reader.
    """
    if mode not in ("synthetic-validation", "pilot"):
        raise ValueError("observer child mode must be synthetic-validation or pilot")
    if os.path.lexists(path):
        raise FileExistsError(path)
    if reference.index != 0 or reference.failed:
        raise ValueError("a fresh child reference is required")
    primary: dict[str, str] | None = None

    def published(primary_path: Path) -> None:
        nonlocal primary
        if primary is not None:
            raise ValueError("the primary result has already been published")
        primary = _file(primary_path)
        reference.checkpoint("ref_primary_published")

    reference.checkpoint("ref_begin")
    observation = build_observation(published)
    if (
        not isinstance(observation, ProfileObservation)
        or observation.mode != mode
        or observation.profile != reference.binding["observer_profile"]
        or observation.metadata["run_id"] != reference.binding["run_id"]
    ):
        raise ValueError("observation mode and reference identity must match")
    result = copy.deepcopy(dict(run_task(observation)))
    if type(result.get("ok")) is not bool:
        raise ValueError("native task requires an explicit boolean outcome")
    if result.get("run_id", reference.binding["run_id"]) != reference.binding["run_id"]:
        raise ValueError("native task identifies another run")
    if not observation.closed:
        result["observation"] = observation.finish(result)
    child = {
        "schema_version": 1,
        "record_type": "observer-calibration-child-result",
        **reference.binding,
        "mode": mode,
        "performance_samples": mode == "pilot",
        "native_result": result,
        "profile_observation": observation.profile_record(),
        "primary_publication": primary,
        "reference_primary_acknowledged": reference.index == 2 and not reference.failed,
    }
    _publish(path, child)
    if reference.index == 2 and not reference.failed:
        reference.checkpoint("ref_complete")
    return child


def publish_terminal(
    path: Path,
    child_result: Path,
    sidecar: Path,
    reference: ParentReference,
) -> dict[str, Any]:
    """Keep reference availability independent of the native task outcome."""
    if os.path.lexists(path) or os.path.lexists(sidecar):
        raise FileExistsError("calibration output already exists")
    child_file = _file(child_result)
    child = json.loads(child_result.read_bytes())
    if (
        not isinstance(child, dict)
        or type(child.get("schema_version")) is not int
        or child.get("schema_version") != 1
        or child.get("record_type") != "observer-calibration-child-result"
        or child.get("mode") != reference.mode
        or child.get("performance_samples") is not (reference.mode == "pilot")
        or any(child.get(key) != value for key, value in reference.binding.items())
    ):
        raise ValueError("child envelope and reference identity must match")
    result = child.get("native_result")
    if not isinstance(result, dict) or type(result.get("ok")) is not bool:
        raise ValueError("child envelope requires an explicit native outcome")
    complete = reference.index == 3 and not reference.failed
    if complete:
        if child.get("reference_primary_acknowledged") is not True:
            raise ValueError("completed reference lacks an acknowledged primary publication")
        reference.publish_sidecar(sidecar, child_result)
    if _file(child_result) != child_file:
        raise ValueError("child result changed during terminal publication")
    terminal = {
        "schema_version": 1,
        "record_type": "observer-calibration-record",
        **reference.binding,
        "mode": reference.mode,
        "performance_samples": reference.mode == "pilot",
        "native_ok": result["ok"],
        "reference_status": "complete" if complete else "incomplete",
        "reference_failed": reference.failed,
        "acknowledged_boundaries": reference.index,
        "child_result": child_file,
        "reference_sidecar": _file(sidecar) if complete else None,
    }
    _publish(path, terminal)
    return terminal
