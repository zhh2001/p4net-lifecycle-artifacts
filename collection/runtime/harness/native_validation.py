"""Represent native functional outcomes without recording performance values."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import Any

from harness.aggregate import validate_record


def record(
    metadata: Mapping[str, Any],
    status: str,
    *,
    native_result: Mapping[str, Any] | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    """Build a journal record from outcome counts and optional boundary evidence."""
    value = {
        **copy.deepcopy(dict(metadata)),
        "schema_version": 1,
        "record_type": "measurement-record",
        "mode": "native-validation",
        "performance_samples": False,
        "status": status,
        "metrics": {},
        "measurement_issues": [],
    }
    if reason is not None:
        value["reason"] = reason
    if native_result is None and status == "completed":
        raise ValueError("completed native validation requires boundary evidence")
    if native_result is not None:
        if native_result.get("performance_samples") is not False:
            raise ValueError(
                "native functional results must explicitly disable performance samples"
            )
        observation = native_result.get("observation")
        if observation is not None:
            if (
                not isinstance(observation, Mapping)
                or observation.get("record_type") != "native-boundary-validation"
                or observation.get("performance_samples") is not False
            ):
                raise ValueError("a native boundary observation is required")
            value["native_observation"] = copy.deepcopy(dict(observation))
            value["measurement_issues"] = copy.deepcopy(observation.get("issues", []))
        elif status == "completed":
            raise ValueError("completed native validation requires boundary evidence")
        else:
            value["measurement_issues"] = ["native boundary evidence unavailable"]
        cleanup = native_result.get("cleanup", {})
        initial = native_result.get("initial") or {}
        restart = native_result.get("restart") or {}
        value.update(
            ordinary_stop_timeout=initial.get(
                "ordinary_stop_timeout", native_result.get("ordinary_stop_timeout")
            ),
            ordinary_cleanup_clean=initial.get(
                "ordinary_cleanup_clean", cleanup.get("ordinary_after_clean")
            ),
            restart_ordinary_stop_timeout=restart.get("ordinary_stop_timeout"),
            restart_ordinary_cleanup_clean=restart.get("ordinary_cleanup_clean"),
            recovery_success=native_result.get("recovery_success"),
            framework_complete=native_result.get("framework_complete"),
        )
    validate_record(value, "native-validation")
    return value
