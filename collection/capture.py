"""Record installed study dependencies and tool identities without changing them."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

BASE = Path(__file__).resolve().parent

PROBE = r"""
import hashlib, importlib.metadata, json, os, platform, sys, sysconfig

def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest() if text is not None else None

records = []
for dist in importlib.metadata.distributions():
    direct = dist.read_text("direct_url.json")
    records.append({
        "name": dist.metadata["Name"], "version": dist.version,
        "direct_url": json.loads(direct) if direct else None,
        "installer": (dist.read_text("INSTALLER") or "").strip() or None,
        "requires_python": dist.metadata.get("Requires-Python"),
        "requires_dist": dist.metadata.get_all("Requires-Dist") or [],
        "metadata_sha256": digest(dist.read_text("METADATA")),
        "record_sha256": digest(dist.read_text("RECORD")),
        "recorded_files": len(dist.files or []),
        "installation_root": str(dist.locate_file("")),
    })
records.sort(key=lambda item: (item["name"].lower(), item["version"]))
print(json.dumps({
    "version": sys.version, "version_info": list(sys.version_info),
    "implementation": platform.python_implementation(),
    "compiler": platform.python_compiler(), "build": list(platform.python_build()),
    "executable": sys.executable, "base_executable": sys._base_executable,
    "prefix": sys.prefix, "base_prefix": sys.base_prefix,
    "sysconfig_paths": sysconfig.get_paths(),
    "libdir": sysconfig.get_config_var("LIBDIR"),
    "ldlibrary": sysconfig.get_config_var("LDLIBRARY"),
    "observed_protobuf_backend_env": os.environ.get("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"),
    "distributions": records,
}, sort_keys=True))
"""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def file_identity(path: Path) -> dict[str, Any]:
    real = path.resolve(strict=True)
    return {
        "path": str(path.absolute()),
        "real_path": str(real),
        "sha256": sha256(real),
        "size_bytes": real.stat().st_size,
    }


def normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, timeout=30, check=False)


def capture_environment(label: str, python: Path, special: dict[str, str]) -> dict[str, Any]:
    directory = BASE / label
    directory.mkdir(exist_ok=False)
    probe = run([str(python), "-I", "-c", PROBE])
    if probe.returncode:
        raise RuntimeError(f"metadata probe failed for {label}: {probe.stderr}")
    data: dict[str, Any] = json.loads(probe.stdout)
    data["interpreter_identity"] = file_identity(python)
    base_interpreter = Path(data["base_executable"])
    data["base_interpreter_identity"] = file_identity(base_interpreter)
    if data["libdir"] and data["ldlibrary"]:
        library = Path(data["libdir"]) / data["ldlibrary"]
        data["python_library_identity"] = file_identity(library) if library.exists() else None
    freeze = run([str(python), "-m", "pip", "freeze", "--all"])
    if freeze.returncode:
        raise RuntimeError(f"pip inventory failed for {label}: {freeze.stderr}")
    (directory / "pip-freeze-all.txt").write_text(freeze.stdout)
    lock = [
        "# Exact installed distribution versions for this study environment.",
        "# Local artifact URLs identify the retained source or wheel.",
        "# Transitive package archives are not vendored in a complete wheelhouse.",
    ]
    seen = set()
    for dist in data["distributions"]:
        name = normalized(dist["name"])
        if name in seen:
            raise RuntimeError(f"duplicate installed distribution: {label} {name}")
        seen.add(name)
        lock.append(special.get(name, f"{dist['name']}=={dist['version']}"))
    (directory / "requirements.lock").write_text("\n".join(lock) + "\n")
    data["requirement_lock_sha256"] = sha256(directory / "requirements.lock")
    data["pip_freeze_sha256"] = sha256(directory / "pip-freeze-all.txt")
    data["required_execution_environment"] = {"PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION": "python"}
    if label != "p4net310":
        source = Path("/usr/lib/python3/dist-packages/mininet")
        package_link = Path(data["sysconfig_paths"]["purelib"]) / "mininet"
        data["mininet_package_link"] = {
            "path": str(package_link),
            "resolved_source": str(package_link.resolve()),
            "is_symlink": package_link.is_symlink(),
            "matches_frozen_system_source": package_link.resolve() == source,
        }
        if package_link.resolve() != source:
            raise RuntimeError(f"unexpected Mininet source for {label}")
    write_json(directory / "environment.json", data)
    return data


def capture_tools() -> dict[str, Any]:
    arguments = {
        "p4c": ["--version"],
        "p4c-bm2-ss": ["--version"],
        "simple_switch_grpc": ["--version"],
        "mnexec": ["-v"],
        "ethtool": ["--version"],
        "ip": ["-Version"],
        "sysctl": ["--version"],
        "mount": ["--version"],
        "unshare": ["--version"],
        "cpp": ["--version"],
    }
    tools = {}
    for name, args in arguments.items():
        found = shutil.which(name)
        if found is None:
            raise FileNotFoundError(f"required installed tool missing: {name}")
        result = run([found, *args])
        tools[name] = {
            **file_identity(Path(found)),
            "version_command": [found, *args],
            "version_exit_code": result.returncode,
            "version_stdout": result.stdout,
            "version_stderr": result.stderr,
        }
    write_json(BASE / "tools.json", tools)
    return tools


def capture_mininet() -> dict[str, Any]:
    root = Path("/usr/lib/python3/dist-packages/mininet")
    files = {str(path.relative_to(root)): sha256(path) for path in sorted(root.rglob("*.py"))}
    package = run(["dpkg-query", "-W", "-f=${Package} ${Version}\n", "mininet"])
    result = {
        "source_root": str(root),
        "python_source_files": files,
        "file_count": len(files),
        "dpkg_exit_code": package.returncode,
        "dpkg_record": package.stdout.strip(),
        "dpkg_error": package.stderr,
    }
    write_json(BASE / "mininet-source.json", result)
    return result
