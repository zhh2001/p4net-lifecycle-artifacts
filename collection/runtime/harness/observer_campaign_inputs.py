"""Bind observer campaigns to one retained allocation and complete runtime inventory."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from harness import campaign_inputs, campaign_snapshot, observer_calibration_plan

MODES = {"synthetic-validation", "pilot"}
KEYS = {
    "schema_version",
    "record_type",
    "mode",
    "performance_samples",
    "plan",
    "plan_content",
    "base_binding",
    "profiles",
    "measurement_defaults",
    "runtime_sources",
    "collection_authorized",
    "input_lock_sha256",
}
DEFAULTS = {
    "duration_ns": observer_calibration_plan.HOLD_NS,
    "interval_ns": observer_calibration_plan.INTERVAL_NS,
}


def _canonical(value: Any) -> bytes:
    try:
        return campaign_inputs._canonical(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("observer binding must contain finite JSON values") from exc


def _plan(content: Any) -> dict[str, Any]:
    if not isinstance(content, str):
        raise ValueError("retained plan_content must be UTF-8 text")
    try:
        content.encode("utf-8")
        plan = json.loads(
            content,
            object_pairs_hook=campaign_inputs._pairs,
            parse_constant=campaign_inputs._constant,
        )
    except (UnicodeError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("retained observer plan is not valid UTF-8 JSON") from exc
    if not isinstance(plan, dict):
        raise ValueError("retained observer plan must be a JSON object")
    observer_calibration_plan.validate_plan(plan)
    return plan


def runtime_sources() -> list[Path]:
    """Return every Python runtime module in the current harness directory."""
    return sorted(Path(__file__).resolve().parent.glob("*.py"))


def plan_from_binding(binding: dict[str, Any]) -> dict[str, Any]:
    """Read the retained allocation without consulting its original file."""
    if not isinstance(binding, dict):
        raise ValueError("observer binding must be an object")
    content = binding.get("plan_content")
    plan = _plan(content)
    reference = binding.get("plan")
    if not isinstance(reference, dict) or not isinstance(content, str):
        raise ValueError("observer binding requires a retained plan reference")
    expected = campaign_inputs._digest(reference.get("sha256"), "observer plan sha256")
    if hashlib.sha256(content.encode("utf-8")).hexdigest() != expected:
        raise ValueError("retained observer plan bytes differ from their pin")
    return plan


def validate_binding(binding: dict[str, Any], *, base: Path) -> None:
    """Validate retained identities without reading current files or packages."""
    if not isinstance(binding, dict) or set(binding) != KEYS:
        raise ValueError("observer binding requires its exact contract fields")
    if (
        type(binding.get("schema_version")) is not int
        or binding["schema_version"] != 1
        or binding.get("record_type") != "observer-campaign-input-binding"
        or not isinstance(binding.get("mode"), str)
        or binding["mode"] not in MODES
        or binding.get("performance_samples") is not (binding["mode"] == "pilot")
        or binding.get("collection_authorized") is not False
    ):
        raise ValueError("invalid observer binding schema, mode, or authorization")
    expected = campaign_inputs._digest(binding.get("input_lock_sha256"), "input_lock_sha256")
    payload = {key: value for key, value in binding.items() if key != "input_lock_sha256"}
    if hashlib.sha256(_canonical(payload)).hexdigest() != expected:
        raise ValueError("observer input binding hash differs")
    inner = binding.get("base_binding")
    if not isinstance(inner, dict):
        raise ValueError("observer binding requires its base input binding")
    campaign_snapshot._binding(inner, campaign_inputs._absolute(base))
    if (
        binding["mode"] != inner["mode"]
        or _canonical(binding["plan"]) != _canonical(inner["plan"])
        or _canonical(binding["measurement_defaults"]) != _canonical(DEFAULTS)
        or _canonical(inner["measurement_defaults"]) != _canonical(DEFAULTS)
    ):
        raise ValueError(
            "observer mode, plan, or equal-hold schedule differs from its base binding"
        )
    plan = plan_from_binding(binding)
    if _canonical(binding["profiles"]) != _canonical(plan["profiles"]):
        raise ValueError("observer profiles differ from the retained allocation")
    inventory = binding.get("runtime_sources")
    if (
        not isinstance(inventory, list)
        or not inventory
        or any(not isinstance(name, str) for name in inventory)
        or inventory != sorted(set(inventory))
        or any(name not in inner["sources"] or Path(name).suffix != ".py" for name in inventory)
    ):
        raise ValueError("runtime_sources must identify distinct bound Python modules")


def build_binding(
    plan_path: Path,
    control_path: Path,
    dependency_path: Path,
    sources: Sequence[Path] = (),
    *,
    mode: str,
    base: Path,
    plan_sha256: str | None = None,
) -> dict[str, Any]:
    """Bind all profiles to the same runtime, dependencies, and exact plan bytes."""
    if not isinstance(mode, str) or mode not in MODES:
        raise ValueError("observer mode must be synthetic-validation or pilot")
    if isinstance(sources, (str, bytes, Path)) or not isinstance(sources, Sequence):
        raise ValueError("additional sources must be a sequence of paths")
    try:
        content = plan_path.read_bytes().decode("utf-8")
    except UnicodeError as exc:
        raise ValueError("observer plan must contain UTF-8 JSON") from exc
    plan = _plan(content)
    automatic = runtime_sources()
    if not automatic:
        raise ValueError("the observer runtime inventory is empty")
    effective = sorted({campaign_inputs._absolute(path) for path in (*automatic, *sources)})
    inner = campaign_inputs.build_binding(
        plan_path,
        control_path,
        dependency_path,
        effective,
        mode=mode,
        base=base,
        plan_sha256=plan_sha256,
        **DEFAULTS,
    )
    binding = {
        "schema_version": 1,
        "record_type": "observer-campaign-input-binding",
        "mode": mode,
        "performance_samples": mode == "pilot",
        "plan": copy.deepcopy(inner["plan"]),
        "plan_content": content,
        "base_binding": inner,
        "profiles": copy.deepcopy(plan["profiles"]),
        "measurement_defaults": dict(DEFAULTS),
        "runtime_sources": sorted(
            campaign_inputs._name(path, campaign_inputs._absolute(base)) for path in automatic
        ),
        "collection_authorized": False,
    }
    binding["input_lock_sha256"] = hashlib.sha256(_canonical(binding)).hexdigest()
    validate_binding(binding, base=base)
    return binding


def verify_binding(binding: dict[str, Any], *, base: Path) -> None:
    """Require unchanged current runtime and dependency files before execution."""
    validate_binding(binding, base=base)
    current = sorted(
        campaign_inputs._name(path, campaign_inputs._absolute(base)) for path in runtime_sources()
    )
    if current != binding["runtime_sources"]:
        raise ValueError("current observer runtime inventory differs from the binding")
    campaign_inputs.verify_binding(binding["base_binding"], base=base)
