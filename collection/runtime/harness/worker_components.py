"""Resolve and verify extracted worker components from explicit frozen inputs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

TUTORIAL_REVISION = "15d780e5ac7046aa64d64270ab0ef3852f1103f9"
ENV_FILE = "P4NET_STUDY_COMPONENTS_FILE"
ENV_SHA256 = "P4NET_STUDY_COMPONENTS_SHA256"
REQUIRED = {"p4_mininet.py", "p4runtime_switch.py", "netstat.py", "p4runtime_lib/__init__.py"}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _digest(value: Any) -> str:
    if not isinstance(value, str) or re.fullmatch("[a-f0-9]{64}", value) is None:
        raise ValueError("worker component SHA-256 must contain 64 lowercase hexadecimal digits")
    return value


def _absolute(value: Any) -> Path:
    if not isinstance(value, str) or not value or os.path.normpath(value) != value:
        raise ValueError("worker component location must be a normalized absolute path")
    path = Path(value)
    if not path.is_absolute() or path.resolve() != path or path.is_symlink():
        raise ValueError(
            "worker component location must be an absolute path without symbolic links"
        )
    return path


def _inventory(root: Path) -> dict[str, str]:
    if not root.is_dir():
        raise FileNotFoundError(f"worker component directory is missing: {root}")
    result = {}
    for path in sorted(root.rglob("*")):
        if "__pycache__" in path.relative_to(root).parts or path.suffix in {".pyc", ".pyo"}:
            continue
        if path.is_symlink():
            raise ValueError(f"worker component contains a symbolic link: {path}")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = _sha(path)
    if not result.keys() >= REQUIRED:
        raise ValueError("worker component directory lacks required tutorial sources")
    return result


def build_manifest(utils_root: Path) -> dict[str, Any]:
    """Inventory the actual extracted tutorial utils directory without importing it."""
    root = _absolute(str(utils_root.absolute()))
    return {
        "schema_version": 1,
        "record_type": "frozen-worker-components",
        "tutorial_utils": {
            "path": str(root),
            "revision": TUTORIAL_REVISION,
            "files": _inventory(root),
        },
    }


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError(f"duplicate worker component field: {key}")
        result[key] = value
    return result


def read_manifest(pin: Mapping[str, Any], *, verify_files: bool = True) -> dict[str, Any]:
    """Read a byte-pinned manifest and optionally verify its complete component tree."""
    if not isinstance(pin, Mapping):
        raise ValueError("worker component manifest requires a path and SHA-256")
    path = _absolute(pin.get("path"))
    if not path.is_file() or _sha(path) != _digest(pin.get("sha256")):
        raise ValueError("worker component manifest differs from its frozen identity")
    value = json.loads(path.read_bytes(), object_pairs_hook=_pairs)
    if (
        not isinstance(value, dict)
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or value.get("record_type") != "frozen-worker-components"
    ):
        raise ValueError("invalid worker component manifest")
    tutorial = value.get("tutorial_utils")
    if not isinstance(tutorial, dict) or tutorial.get("revision") != TUTORIAL_REVISION:
        raise ValueError("tutorial component revision differs from its frozen baseline")
    root = _absolute(tutorial.get("path"))
    if not root.is_dir():
        raise FileNotFoundError(f"worker component directory is missing: {root}")
    files = tutorial.get("files")
    if not isinstance(files, dict) or not files.keys() >= REQUIRED:
        raise ValueError("worker component inventory lacks required tutorial sources")
    for name, digest in files.items():
        if (
            not isinstance(name, str)
            or not name
            or Path(name).is_absolute()
            or Path(name).as_posix() != name
            or ".." in Path(name).parts
            or "." in Path(name).parts
            or "__pycache__" in Path(name).parts
            or Path(name).suffix in {".pyc", ".pyo"}
        ):
            raise ValueError("worker component inventory contains an invalid relative filename")
        _digest(digest)
    if verify_files and _inventory(root) != files:
        raise ValueError(
            "worker component file set or source hash differs from its frozen inventory"
        )
    return value


def locked_files(pin: Mapping[str, Any]) -> dict[Path, str]:
    """Return every file that the component contract adds to the input binding."""
    manifest = read_manifest(pin)
    tutorial = manifest["tutorial_utils"]
    root = Path(tutorial["path"])
    return {
        _absolute(pin.get("path")): _digest(pin.get("sha256")),
        **{root / name: digest for name, digest in tutorial["files"].items()},
    }


def verify_binding_components(binding: Mapping[str, Any], *, base: Path) -> dict[str, str]:
    """Require component inputs to match the byte-bound native execution contract."""
    pin = binding.get("worker_components")
    if not isinstance(pin, dict):
        raise ValueError("native binding requires explicit frozen worker components")
    path = Path(pin.get("path", ""))
    if not path.is_absolute():
        path = base / path
    absolute_pin = {"path": str(path.absolute()), "sha256": pin.get("sha256")}
    locked = binding.get("locked_inputs")
    if not isinstance(locked, dict):
        raise ValueError("worker component binding requires locked inputs")
    for component, digest in locked_files(absolute_pin).items():
        name = (
            str(component.relative_to(base)) if component.is_relative_to(base) else str(component)
        )
        if locked.get(name) != digest:
            raise ValueError(f"worker component is outside the frozen input binding: {component}")
    return {"path": str(path.absolute()), "sha256": _digest(pin.get("sha256"))}


def from_environment() -> dict[str, Any] | None:
    """Read only the component pin propagated by the scoped worker environment."""
    path, digest = os.environ.get(ENV_FILE), os.environ.get(ENV_SHA256)
    if path is None and digest is None:
        return None
    return read_manifest({"path": path, "sha256": digest}, verify_files=False)


def verify_loaded_modules(manifest: Mapping[str, Any]) -> None:
    """Reject previously imported or newly loaded tutorial modules from other paths."""
    tutorial = manifest["tutorial_utils"]
    root = Path(tutorial["path"])
    files = tutorial["files"]
    families = {
        Path(name).stem if "/" not in name else Path(name).parts[0]
        for name in files
        if name.endswith(".py") and ("/" not in name or Path(name).name == "__init__.py")
    }
    for name, module in list(sys.modules.items()):
        if name.split(".", 1)[0] not in families:
            continue
        supplied = getattr(module, "__file__", None)
        if supplied is None:
            raise ValueError(f"tutorial module has no source identity: {name}")
        path = Path(supplied).resolve()
        if not path.is_relative_to(root):
            raise ValueError(f"tutorial module resolves outside frozen components: {name}")
        expected = files.get(path.relative_to(root).as_posix())
        if expected is None or _sha(path) != expected:
            raise ValueError(f"tutorial module source differs from frozen components: {name}")
