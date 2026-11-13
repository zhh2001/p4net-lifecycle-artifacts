"""Verify a diagnostic capsule and prepare its isolated native worker launch."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_pin(pin: dict[str, Any]) -> dict[str, Any]:
    path = Path(pin["path"])
    if not path.is_absolute() or digest(path) != pin["sha256"]:
        raise ValueError("diagnostic input differs from its binding")
    value: dict[str, Any] = json.loads(path.read_text())
    return value


def verify(pin: dict[str, Any]) -> dict[str, Any]:
    binding = read_pin(pin)
    if (
        binding.get("record_type") != "native-diagnostic-input-binding"
        or binding.get("schema_version") != 1
        or binding.get("performance_samples") is not False
        or Path(binding["runtime_root"]) != ROOT
    ):
        raise ValueError("diagnostic binding contract differs")
    actual = {
        str(path.relative_to(ROOT))
        for path in ROOT.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }
    if actual != set(binding["runtime_files"]):
        raise ValueError("diagnostic runtime file set changed")
    for name, expected in binding["runtime_files"].items():
        path = Path(name)
        if path.is_absolute() or ".." in path.parts or digest(ROOT / path) != expected:
            raise ValueError(f"diagnostic runtime changed: {name}")
    for name, expected in binding["external_files"].items():
        if not Path(name).is_absolute() or digest(Path(name)) != expected:
            raise ValueError(f"diagnostic external input changed: {name}")
    for reference in binding["references"].values():
        read_pin(reference)
    return binding


def case_for(manifest: dict[str, Any], binding: dict[str, Any]) -> dict[str, Any]:
    case: dict[str, Any] | None = next(
        (row for row in binding["cases"] if row["id"] == manifest["diagnostic"]["case_id"]), None
    )
    if case is None or manifest["groups"] != case["groups"]:
        raise ValueError("manifest has no matching diagnostic case")
    if manifest.get("source_sha256") != digest(Path(manifest["p4_source"])):
        raise ValueError("diagnostic workload bytes differ from the manifest")
    if manifest.get("worker_components") != binding["worker_components"]:
        raise ValueError("diagnostic worker components differ")
    if manifest.get("configuration_profile") != "matched-v1":
        raise ValueError("diagnostic task requires the matched native configuration")
    if (
        Path(manifest["output_dir"]).resolve()
        != Path(manifest["diagnostic_manifest_dir"]).resolve()
    ):
        # Episode child manifests deliberately use their own phase directories.
        parent = Path(manifest["diagnostic_manifest_dir"]).resolve()
        output = Path(manifest["output_dir"]).resolve()
        if output.parent != parent or output.name not in {"initial", "restart"}:
            raise ValueError("diagnostic phase directory differs")
    else:
        if manifest["p4_source"] != binding["workload"]["path"]:
            raise ValueError("diagnostic parent workload differs")
        expected = None if case["fault"] == "normal" else case["fault"]
        if manifest.get("episode_fault") != expected:
            raise ValueError("diagnostic fault differs from its prepared case")
    return case


def launch_spec(path: Path) -> dict[str, Any]:
    """Return argv and environment without launching a process or allocating resources."""
    from harness import isolation
    from harness.spec import load

    manifest = load(path)
    binding = verify(manifest["diagnostic"]["binding"])
    case = case_for(manifest, binding)
    python = Path(binding["tools"][case["tool"]]["interpreter"])
    command = isolation.isolated_command(
        path.resolve(), python, "harness.diagnostic_worker", True, True
    )
    command[command.index("harness.isolation")] = "harness.diagnostic_isolation"
    command[command.index("-m") - 1] = binding["wrapper_interpreter"]
    environment = isolation.environment_for(manifest)
    environment["PATH"] = str(ROOT / "harness/bin") + os.pathsep + binding["execution_path"]
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return {
        "argv": command,
        "env": environment,
        "cwd": str(ROOT),
        "outer_timeout": 210 if case["fault"] == "normal" else 360,
        "performance_samples": False,
        "resource_sampling_enabled": False,
    }


def require_worker_enclosure() -> None:
    """Require a supervised child in the protected enclosure established by its init."""
    try:
        expected = json.loads(os.environ.get("P4NET_STUDY_INNER_NS", "{}"))
    except (TypeError, ValueError) as exc:
        raise RuntimeError("worker enclosure metadata is invalid") from exc
    names = {"net", "mnt", "pid", "ipc", "uts"}
    if (
        not isinstance(expected, dict)
        or set(expected) != names
        or any(not isinstance(value, str) or not value for value in expected.values())
    ):
        raise RuntimeError("worker enclosure metadata is incomplete")
    if os.getpid() <= 1 or os.getppid() != 1:
        raise RuntimeError("diagnostic worker requires a direct child of the enclosure init")
    for name, identity in expected.items():
        if (
            os.readlink(f"/proc/self/ns/{name}") != identity
            or os.readlink(f"/proc/1/ns/{name}") != identity
        ):
            raise RuntimeError("worker or init namespace identity differs from the enclosure")
    if not os.statvfs("/proc/sys/vm").f_flag & os.ST_RDONLY:
        raise RuntimeError("worker enclosure lacks global sysctl protection")


def execute(path: Path) -> int:
    from diagnostic.hooks import Hook
    from diagnostic.runner import run_worker

    from harness.spec import load

    require_worker_enclosure()
    manifest = load(path)
    binding = verify(manifest["diagnostic"]["binding"])
    case = case_for(manifest, binding)
    tool = binding["tools"][case["tool"]]
    # Keep the virtual-environment executable path; resolving it loses environment identity.
    if os.path.abspath(sys.executable) != tool["interpreter"]:
        raise ValueError("diagnostic worker interpreter differs")
    result, _receipt = run_worker(
        tool["worker"],
        path,
        path.parent / "diagnostic-trace.jsonl",
        [Hook(**row) for row in tool["hooks"]],
        case["profile"],
        stacks=case["stacks"],
    )
    return result
