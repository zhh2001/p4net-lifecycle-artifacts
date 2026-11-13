"""Validate explicit campaign measurements before entering their native enclosure."""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from typing import Any

from harness.measure import Recorder

MEASUREMENT_KEYS = {"mode", "clock_domain", "duration_ns", "interval_ns", "metadata"}
MAX_SCHEDULE_NS = 2**63 - 1


def validate_measurement(
    value: Mapping[str, Any], manifest: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Return an independent JSON configuration without reading clocks or resources."""
    if not isinstance(value, Mapping) or set(value) != MEASUREMENT_KEYS:
        raise ValueError(
            "measurement requires mode, clock_domain, duration_ns, interval_ns, metadata"
        )
    configuration = copy.deepcopy(dict(value))
    mode = configuration["mode"]
    if not isinstance(mode, str) or mode not in {"pilot", "formal"}:
        raise ValueError("measurement mode must be pilot or formal")
    clock_domain = configuration["clock_domain"]
    if not isinstance(clock_domain, str) or not clock_domain.strip():
        raise ValueError("measurement clock_domain must be a nonempty string")
    duration = configuration["duration_ns"]
    interval = configuration["interval_ns"]
    if (
        type(duration) is not int
        or type(interval) is not int
        or not 0 < interval <= duration <= MAX_SCHEDULE_NS
    ):
        raise ValueError(
            "measurement schedule requires 0 < interval_ns <= duration_ns <= 2**63 - 1"
        )
    metadata = configuration["metadata"]
    if not isinstance(metadata, Mapping):
        raise ValueError("measurement metadata must be an object")
    configuration["metadata"] = dict(metadata)
    try:
        json.dumps(configuration, allow_nan=False)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("measurement configuration must contain finite JSON values") from exc
    # Recorder validates metadata and reserved fields without invoking its clock.
    Recorder(configuration["metadata"], mode=mode, clock_domain=clock_domain, clock_ns=lambda: 0)
    if manifest is not None:
        expected = {
            "run_id": manifest["run_id"],
            "switches": manifest["groups"],
            "configuration_profile": manifest.get("configuration_profile", "native"),
            "fault": manifest.get("episode_fault"),
            "workload": "fault" if "episode_fault" in manifest else "scale",
        }
        if any(metadata.get(key) != expected_value for key, expected_value in expected.items()):
            raise ValueError("measurement metadata differs from the native manifest")
    return configuration
