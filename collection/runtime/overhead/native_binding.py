"""Bind prepared native controls to the copied capsule and frozen allocation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from harness.diagnostic_binding import ROOT, digest, read_pin, verify
from harness.spec import load

from overhead.model import Context
from overhead.native_context import PreparedContext
from overhead.publication import pointer


def context_for(value: dict[str, Any]) -> Context:
    return (
        PreparedContext.from_dict(value)
        if value.get("mode") == "pilot"
        else Context.from_dict(value)
    )


def read_control(
    pin: dict[str, Any], *, full: bool = False
) -> tuple[dict[str, Any], dict[str, Any], Context]:
    control = read_pin(pin)
    if (
        set(control)
        != {"schema_version", "record_type", "binding", "manifest", "context", "planned_task_id"}
        or type(control["schema_version"]) is not int
        or control["schema_version"] != 1
        or control["record_type"] != "diagnostic-overhead-native-control"
    ):
        raise ValueError("native control contract differs")
    binding = read_pin(control["binding"])
    if (
        binding.get("schema_version") != 1
        or binding.get("record_type") != "diagnostic-overhead-native-binding"
        or binding.get("runtime_root") != str(ROOT)
        or binding.get("collection_authorized") is not False
        or binding.get("execution_kind") not in {"protected-synthetic", "prepared-native"}
    ):
        raise ValueError("native binding contract differs")
    context = context_for(control["context"])
    fixture = binding["execution_kind"] == "protected-synthetic"
    if fixture != (context.mode == "synthetic-validation"):
        raise ValueError("native context and execution kind differ")
    if binding["hold_ns"] != (10_000_000 if fixture else 10_000_000_000):
        raise ValueError("native hold differs from its bound schedule")
    manifest = read_pin(control["manifest"])
    load(Path(control["manifest"]["path"]))
    if (
        context.run_id != manifest["run_id"]
        or manifest.get("configuration_profile") != "matched-v1"
        or manifest.get("p4_source") != str(ROOT / "harness/workloads/l3.p4")
        or "episode_fault" in manifest
        or manifest.get("source_sha256") != digest(Path(manifest["p4_source"]))
        or Path(control["manifest"]["path"]).parent.name != "native"
    ):
        raise ValueError("native control and manifest differ")
    if fixture:
        if manifest.get("fixture_profile") != context.diagnostic_profile or manifest.get(
            "fixture_sha256"
        ) != digest(ROOT / "overhead/protected_fixture.py"):
            raise ValueError("protected fixture source differs")
        if control["planned_task_id"] is not None:
            raise ValueError("synthetic controls cannot claim planned tasks")
    else:
        allocation = read_pin(binding["allocation"])
        rows = [
            row
            for row in allocation["tasks"]
            if row["planned_task_id"] == control["planned_task_id"]
        ]
        if len(rows) != 1:
            raise ValueError("control has no unique frozen allocation row")
        row = rows[0]
        if (row["tool"], row["diagnostic_profile"], row["switches"]) != (
            context.tool,
            context.diagnostic_profile,
            manifest["groups"],
        ):
            raise ValueError("native treatment differs from frozen allocation")
        if manifest.get("worker_components") != binding["worker_components"]:
            raise ValueError("native worker components differ")
        if context.diagnostic_profile == "native":
            if "diagnostic" in manifest:
                raise ValueError("native treatment cannot select diagnostic entry")
        else:
            expected_case = (
                f"{context.tool}-n{manifest['groups']:02d}-{context.diagnostic_profile}-normal"
            )
            if manifest.get("diagnostic") != {
                "binding": binding["diagnostic_binding"],
                "case_id": expected_case,
            }:
                raise ValueError("diagnostic treatment differs from the prepared case")
    if full:
        actual = {
            str(path.relative_to(ROOT)): digest(path)
            for path in ROOT.rglob("*")
            if path.is_file() and "__pycache__" not in path.parts
        }
        if actual != binding["runtime_files"]:
            raise ValueError("calibration runtime source changed")
        for name, sha in binding["external_files"].items():
            if not Path(name).is_absolute() or digest(Path(name)) != sha:
                raise ValueError("calibration external source changed")
        if not fixture:
            verify(binding["diagnostic_binding"])
            for reference in binding["references"].values():
                read_pin(reference)
    return control, binding, context


def selected_entry(binding: dict[str, Any], context: Context) -> dict[str, Any]:
    if binding["execution_kind"] == "protected-synthetic":
        module = (
            "overhead.protected_fixture"
            if context.diagnostic_profile == "native"
            else "overhead.protected_instrumented"
        )
    else:
        module = (
            binding["tools"][context.tool]["worker"]
            if context.diagnostic_profile == "native"
            else "harness.diagnostic_worker"
        )
    relative = module.replace(".", "/") + ".py"
    return {
        "module": module,
        "source": str(ROOT / relative),
        "sha256": binding["runtime_files"][relative],
    }


def control_pin(path: Path) -> str:
    return json.dumps(pointer(path), separators=(",", ":"))
