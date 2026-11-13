"""Validate native observer calibration inputs without launching or sampling."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from harness.campaign_bridge import MEASUREMENT_KEYS, validate_measurement
from harness.observer_reference import _binding

CALIBRATION_KEYS = MEASUREMENT_KEYS | {"observer_profile", "attempt_id"}


def validate_calibration(
    value: Mapping[str, Any], manifest: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Return a detached pilot configuration with explicit attempt identity."""
    if not isinstance(value, Mapping) or set(value) != CALIBRATION_KEYS:
        raise ValueError(
            "calibration requires measurement fields, observer_profile, and attempt_id"
        )
    measurement = validate_measurement({key: value[key] for key in MEASUREMENT_KEYS}, manifest)
    if measurement["mode"] != "pilot":
        raise ValueError("observer calibration requires pilot mode")
    binding = _binding(
        measurement["metadata"]["run_id"], value["attempt_id"], value["observer_profile"]
    )
    return {
        **measurement,
        "observer_profile": binding["observer_profile"],
        "attempt_id": binding["attempt_id"],
    }
