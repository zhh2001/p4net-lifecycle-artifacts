"""Bind an experiment plan to retained input files without executing workloads."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
from base64 import urlsafe_b64encode
from collections.abc import Mapping, Sequence
from importlib import invalidate_caches
from importlib import metadata as package_metadata
from pathlib import Path
from typing import Any

MODES = {"synthetic-validation", "native-validation", "pilot", "formal"}


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", value):
        raise ValueError(f"{name} must contain 64 hexadecimal digits")
    return value.lower()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _constant(value: str) -> None:
    raise ValueError(f"JSON contains a nonfinite constant: {value}")


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError(f"JSON contains duplicate key: {key}")
        result[key] = value
    return result


def _object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes(), parse_constant=_constant, object_pairs_hook=_pairs)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _reference(directory: Path, value: Any) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("an input reference must be a nonempty path")
    path = Path(value)
    return _absolute(path if path.is_absolute() else directory / path)


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(path))


def _name(path: Path, base: Path) -> str:
    path = _absolute(path)
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return str(path)


def _entry(path: Path, base: Path) -> dict[str, str]:
    return {"path": _name(path, base), "sha256": _hash(path)}


def _schedule(mode: Any, duration_ns: Any, interval_ns: Any) -> None:
    if not isinstance(mode, str) or mode not in MODES:
        raise ValueError("mode must be synthetic-validation, native-validation, pilot, or formal")
    if (
        type(duration_ns) is not int
        or type(interval_ns) is not int
        or not 0 < interval_ns <= duration_ns
    ):
        raise ValueError("measurement duration and interval must be positive integer nanoseconds")


def _pinned_entry(value: Any, name: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object with path and sha256")
    path = value.get("path")
    if not isinstance(path, str) or not path.strip():
        raise ValueError(f"{name} must contain a nonempty path")
    return {"path": path, "sha256": _digest(value.get("sha256"), f"{name}.sha256")}


def _linked_inputs(dependency: dict[str, Any], directory: Path, base: Path) -> dict[str, str]:
    locked: dict[str, str] = {}

    def add(value: Any, expected: str | None = None) -> None:
        path = _reference(directory, value)
        actual = _hash(path)
        if expected is not None and actual != expected:
            raise ValueError(f"dependency artifact hash differs: {path}")
        locked[_name(path, base)] = actual

    environments = dependency.get("environment_files")
    if not isinstance(environments, dict) or not environments:
        raise ValueError("dependency manifest requires environment_files")
    for label, value in environments.items():
        if not isinstance(label, str) or not label.strip():
            raise ValueError("environment labels must be nonempty strings")
        add(value)
        environment_path = _reference(directory, value)
        environment = _object(environment_path)
        if "distributions" in environment:
            _verify_distributions(
                environment, environment_path.parent, snapshot_unhashed=locked, base=base
            )
    for key in ("tools_file", "mininet_source_file"):
        add(dependency.get(key))
    artifacts = dependency.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        raise ValueError("dependency manifest requires artifacts")
    for label, value in artifacts.items():
        if not isinstance(label, str) or not label.strip():
            raise ValueError("artifact labels must be nonempty strings")
        artifact = _pinned_entry(value, f"artifact {label}")
        add(artifact["path"], artifact["sha256"])
    return dict(sorted(locked.items()))


def build_binding(
    plan_path: Path,
    control_path: Path,
    dependency_path: Path,
    sources: Sequence[Path],
    *,
    mode: str,
    duration_ns: int = 10_000_000_000,
    interval_ns: int = 100_000_000,
    base: Path,
    plan_sha256: str | None = None,
) -> dict[str, Any]:
    """Hash effective inputs and validate retained plan and dependency pointers."""
    _schedule(mode, duration_ns, interval_ns)
    base = _absolute(base)
    plan_path, control_path, dependency_path = (
        _absolute(path) for path in (plan_path, control_path, dependency_path)
    )
    control = _object(control_path)
    plan = _entry(plan_path, base)
    if plan_sha256 is None:
        expected_plan = _pinned_entry(control.get("campaign"), "frozen campaign")
        if _reference(control_path.parent, expected_plan["path"]) != plan_path:
            raise ValueError("plan path differs from the frozen campaign pointer")
        expected_plan_sha256 = expected_plan["sha256"]
    else:
        expected_plan_sha256 = _digest(plan_sha256, "plan_sha256")
    if plan["sha256"] != expected_plan_sha256:
        raise ValueError("plan hash differs from its explicit or frozen pin")
    dependency_pointer = _pinned_entry(control.get("dependency_freeze"), "dependency freeze")
    if _reference(control_path.parent, dependency_pointer["path"]) != dependency_path:
        raise ValueError("dependency manifest path differs from the frozen pointer")
    dependency_entry = _entry(dependency_path, base)
    if dependency_entry["sha256"] != dependency_pointer["sha256"]:
        raise ValueError("dependency manifest hash differs from the frozen pointer")
    historical = control.get("sources", {})
    if not isinstance(historical, dict):
        raise ValueError("frozen sources must be a path-to-digest object")
    pins = {
        _reference(control_path.parent, path): _digest(value, f"frozen source {path}")
        for path, value in historical.items()
    }
    if isinstance(sources, (str, bytes, Path)) or not sources:
        raise ValueError("sources must be a nonempty sequence of paths")
    effective: dict[str, str] = {}
    drift: list[dict[str, str]] = []
    for source in sources:
        path = _absolute(source)
        name, actual = _name(path, base), _hash(path)
        effective[name] = actual
        if path in pins and actual != pins[path]:
            if path.suffix.lower() == ".p4":
                raise ValueError(f"P4 source hash differs from its frozen pin: {name}")
            drift.append({"path": name, "expected_sha256": pins[path], "actual_sha256": actual})
    binding: dict[str, Any] = {
        "schema_version": 1,
        "record_type": "campaign-input-binding",
        "mode": mode,
        "performance_samples": mode in {"pilot", "formal"},
        "plan": plan,
        "frozen_control": _entry(control_path, base),
        "dependency_manifest": dependency_entry,
        "sources": dict(sorted(effective.items())),
        "locked_inputs": _linked_inputs(_object(dependency_path), dependency_path.parent, base),
        "historical_source_drift": sorted(drift, key=lambda item: item["path"]),
        "measurement_defaults": {"duration_ns": duration_ns, "interval_ns": interval_ns},
    }
    if "worker_components" in control:
        from harness.worker_components import locked_files

        component = _pinned_entry(control["worker_components"], "worker components")
        component_path = _reference(control_path.parent, component["path"])
        absolute_pin = {"path": str(component_path), "sha256": component["sha256"]}
        binding["worker_components"] = _entry(component_path, base)
        binding["locked_inputs"].update(
            {_name(path, base): digest for path, digest in locked_files(absolute_pin).items()}
        )
        binding["locked_inputs"] = dict(sorted(binding["locked_inputs"].items()))
    binding["input_lock_sha256"] = hashlib.sha256(_canonical(binding)).hexdigest()
    return binding


def verify_binding(binding: dict[str, Any], *, base: Path) -> None:
    """Reject malformed bindings or changed files before resume or backend execution."""
    if not isinstance(binding, dict):
        raise ValueError("binding must be an object")
    if type(binding.get("schema_version")) is not int or binding["schema_version"] != 1:
        raise ValueError("unsupported binding schema")
    if binding.get("record_type") != "campaign-input-binding":
        raise ValueError("not a campaign input binding")
    schedule = binding.get("measurement_defaults")
    if not isinstance(schedule, dict):
        raise ValueError("binding requires measurement_defaults")
    _schedule(binding.get("mode"), schedule.get("duration_ns"), schedule.get("interval_ns"))
    if binding.get("performance_samples") is not (binding["mode"] in {"pilot", "formal"}):
        raise ValueError("performance_samples differs from the binding mode")
    expected = _digest(binding.get("input_lock_sha256"), "input_lock_sha256")
    payload = {key: value for key, value in binding.items() if key != "input_lock_sha256"}
    if hashlib.sha256(_canonical(payload)).hexdigest() != expected:
        raise ValueError("input binding hash differs")
    base = _absolute(base)

    def check(name: Any, value: Any) -> None:
        path = _reference(base, name)
        if _name(path, base) != name:
            raise ValueError(f"input path is not normalized: {name}")
        if _hash(path) != _digest(value, f"input {name}"):
            raise ValueError(f"input file hash differs: {name}")

    for key in ("plan", "frozen_control", "dependency_manifest"):
        entry = _pinned_entry(binding.get(key), key)
        check(entry["path"], entry["sha256"])
    for key in ("sources", "locked_inputs"):
        entries = binding.get(key)
        if not isinstance(entries, dict) or not entries:
            raise ValueError(f"binding requires nonempty {key}")
        for name, value in entries.items():
            check(name, value)
    drift = binding.get("historical_source_drift")
    if not isinstance(drift, list):
        raise ValueError("historical_source_drift must be a list")
    for item in drift:
        if not isinstance(item, dict) or item.get("path") not in binding["sources"]:
            raise ValueError("historical drift must refer to an effective source")
        _digest(item.get("expected_sha256"), "historical expected_sha256")
        if (
            _digest(item.get("actual_sha256"), "historical actual_sha256")
            != binding["sources"][item["path"]]
        ):
            raise ValueError("historical drift differs from its effective source")
    rebuilt = build_binding(
        _reference(base, binding["plan"]["path"]),
        _reference(base, binding["frozen_control"]["path"]),
        _reference(base, binding["dependency_manifest"]["path"]),
        [_reference(base, name) for name in binding["sources"]],
        mode=binding["mode"],
        duration_ns=schedule["duration_ns"],
        interval_ns=schedule["interval_ns"],
        base=base,
        plan_sha256=binding["plan"]["sha256"],
    )
    if rebuilt != binding:
        raise ValueError("input binding differs from its linked input contract")


def _identity(value: Any, directory: Path, name: str) -> Path:
    entry = _pinned_entry(value, name)
    path = _reference(directory, entry["path"])
    real_path = _reference(directory, value.get("real_path"))
    if path.resolve(strict=True) != real_path:
        raise ValueError(f"{name} resolved path differs from its frozen identity")
    if _hash(path) != entry["sha256"]:
        raise ValueError(f"{name} file hash differs from its frozen identity")
    if "size_bytes" in value and (
        type(value["size_bytes"]) is not int or path.stat().st_size != value["size_bytes"]
    ):
        raise ValueError(f"{name} file size differs from its frozen identity")
    return path


def _distribution_name(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("distribution name must be a nonempty string")
    return re.sub(r"[-_.]+", "-", value).lower()


def _generated_cache(path: Path) -> bool:
    return path.suffix.lower() in {".pyc", ".pyo"} or "__pycache__" in path.parts


def _distribution_records(
    distribution: package_metadata.Distribution,
) -> tuple[list[tuple[Path, str | None]], tuple[int, int], int | None]:
    root = _absolute(Path(str(distribution.locate_file(""))))
    record = distribution.read_text("RECORD")
    legacy_count = None
    metadata_files: list[Path] = []
    if record is not None:
        files = []
        for row in csv.reader(record.splitlines()):
            if not row or not row[0] or len(row) > 3:
                raise ValueError("invalid installed distribution RECORD row")
            files.append((_reference(root, row[0]), row[1] if len(row) > 1 and row[1] else None))
    else:
        installed = distribution.read_text("installed-files.txt")
        sources = distribution.read_text("SOURCES.txt")
        metadata_path = getattr(distribution, "_path", None)
        if metadata_path is None:
            raise ValueError("legacy distribution metadata directory is unavailable")
        metadata_root = _absolute(Path(str(metadata_path)))
        if installed is not None:
            files = [(_reference(metadata_root, name), None) for name in installed.splitlines()]
            metadata_files.append(metadata_root / "installed-files.txt")
            # Older metadata readers counted source-archive entries instead of installed files.
            legacy_count = len(sources.splitlines()) if sources is not None else None
        elif sources is not None:
            files = [(_reference(root, name), None) for name in sources.splitlines()]
        else:
            raise ValueError("installed distribution file inventory is missing")
        if sources is not None:
            metadata_files.append(metadata_root / "SOURCES.txt")
    minimum = sum(not _generated_cache(path) for path, _ in files)
    bounds = minimum, len(files)
    unique = dict(files)
    for path in metadata_files:
        unique.setdefault(path, None)
    return list(unique.items()), bounds, legacy_count


def _verify_distributions(
    environment: dict[str, Any],
    directory: Path,
    *,
    file_hashes: Mapping[str, str] | None = None,
    base: Path | None = None,
    snapshot_unhashed: dict[str, str] | None = None,
) -> Path:
    paths = environment.get("sysconfig_paths")
    if not isinstance(paths, dict):
        raise ValueError("environment requires sysconfig_paths")
    purelib = _reference(directory, paths.get("purelib"))
    if not purelib.is_dir():
        raise ValueError(f"installed package directory is missing: {purelib}")
    frozen = environment.get("distributions")
    if not isinstance(frozen, list):
        raise ValueError("environment distributions must be a list")
    expected: dict[str, dict[str, Any]] = {}
    for item in frozen:
        if not isinstance(item, dict):
            raise ValueError("a frozen distribution must be an object")
        name = _distribution_name(item.get("name"))
        if name in expected:
            raise ValueError(f"duplicate frozen distribution: {name}")
        expected[name] = item
    installed: dict[str, package_metadata.Distribution] = {}
    invalidate_caches()
    # Python 3.10's general import-cache invalidation does not refresh this finder.
    package_metadata.MetadataPathFinder().invalidate_caches()
    for distribution in package_metadata.distributions(path=[str(purelib)]):
        name = _distribution_name(distribution.metadata["Name"])
        if name in installed:
            raise ValueError(f"duplicate installed distribution: {name}")
        installed[name] = distribution
    if expected.keys() != installed.keys():
        missing = sorted(expected.keys() - installed.keys())
        extra = sorted(installed.keys() - expected.keys())
        raise ValueError(f"installed distributions differ: missing={missing}, extra={extra}")
    for name, item in expected.items():
        distribution = installed[name]
        if not isinstance(item.get("version"), str) or distribution.version != item["version"]:
            raise ValueError(f"distribution version differs: {name}")
        root = _absolute(Path(str(distribution.locate_file(""))))
        if root != purelib or root != _reference(directory, item.get("installation_root")):
            raise ValueError(f"distribution installation root differs: {name}")
        for filename, key in (("METADATA", "metadata_sha256"), ("RECORD", "record_sha256")):
            text = distribution.read_text(filename)
            actual = hashlib.sha256(text.encode("utf-8")).hexdigest() if text is not None else None
            if key not in item:
                raise ValueError(f"frozen distribution requires {key}: {name}")
            pin = item[key]
            if pin is not None:
                pin = _digest(pin, f"{name} {key}")
            if actual != pin:
                raise ValueError(f"distribution {filename} hash differs: {name}")
        files, (required_count, total_count), legacy_count = _distribution_records(distribution)
        if type(item.get("recorded_files")) is not int or not (
            required_count <= item["recorded_files"] <= total_count
            or item["recorded_files"] == legacy_count
        ):
            raise ValueError(f"distribution recorded file count differs: {name}")
        for path, recorded_hash in files:
            # Generated bytecode can be recreated between attempts; source files stay bound.
            if _generated_cache(path):
                continue
            if not path.is_file():
                raise FileNotFoundError(f"declared distribution file is missing: {name}/{path}")
            if recorded_hash is None:
                actual_sha256 = _hash(path)
                path_key = _name(path, base) if base is not None else str(path)
                if snapshot_unhashed is not None:
                    snapshot_unhashed[path_key] = actual_sha256
                    continue
                pin = file_hashes.get(path_key) if file_hashes is not None else None
                if pin is None:
                    metadata_key = {"METADATA": "metadata_sha256", "RECORD": "record_sha256"}.get(
                        path.name
                    )
                    if metadata_key is not None and item.get(metadata_key) == actual_sha256:
                        continue
                    raise ValueError(f"insufficient file coverage for unhashed file: {name}/{path}")
                if actual_sha256 != _digest(pin, f"unhashed file {path_key}"):
                    raise ValueError(f"unhashed distribution file differs: {name}/{path}")
                continue
            try:
                algorithm, expected_digest = recorded_hash.split("=", 1)
                content = path.read_bytes()
                digest = hashlib.new(algorithm, content).digest()
            except (ValueError, TypeError) as exc:
                raise ValueError(f"unsupported distribution file hash: {name}/{path}") from exc
            actual_digest = urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
            if actual_digest != expected_digest:
                raise ValueError(f"distribution file hash differs: {name}/{path}")
    return purelib


def verify_native_environment(
    dependency_path: Path,
    *,
    labels: Sequence[str],
    file_hashes: Mapping[str, str] | None = None,
    base: Path | None = None,
) -> None:
    """Check retained files, excluding generated .pyc/.pyo and __pycache__ entries."""
    dependency_path = _absolute(dependency_path)
    directory = dependency_path.parent
    if base is not None:
        base = _absolute(base)
    if file_hashes is not None and not isinstance(file_hashes, Mapping):
        raise ValueError("file_hashes must be a path-to-digest mapping")
    dependency = _object(dependency_path)
    environments = dependency.get("environment_files")
    if not isinstance(environments, dict):
        raise ValueError("dependency manifest requires environment_files")
    if isinstance(labels, (str, bytes)) or not labels:
        raise ValueError("at least one environment label is required")
    if any(not isinstance(label, str) or label not in environments for label in labels):
        raise ValueError("an environment label is not present in the dependency manifest")
    if len(set(labels)) != len(labels):
        raise ValueError("environment labels must be distinct")
    tools = _object(_reference(directory, dependency.get("tools_file")))
    if not tools:
        raise ValueError("frozen tools must be nonempty")
    if "tools" in dependency and set(dependency["tools"]) != tools.keys():
        raise ValueError("tool names differ from the dependency manifest")
    for name, identity in tools.items():
        _identity(identity, directory, f"tool {name}")
    mininet = _object(_reference(directory, dependency.get("mininet_source_file")))
    source_root = _reference(directory, mininet.get("source_root"))
    sources = mininet.get("python_source_files")
    if not isinstance(sources, dict) or not sources:
        raise ValueError("Mininet requires declared Python source files")
    actual_sources = {
        path.relative_to(source_root).as_posix() for path in source_root.rglob("*.py")
    }
    if actual_sources != sources.keys():
        raise ValueError("Mininet Python source file set differs")
    for name, pin in sources.items():
        if _hash(source_root / name) != _digest(pin, f"Mininet source {name}"):
            raise ValueError(f"Mininet source hash differs: {name}")
    for label in labels:
        environment_path = _reference(directory, environments[label])
        environment = _object(environment_path)
        identities = {}
        for key in ("interpreter_identity", "base_interpreter_identity", "python_library_identity"):
            identities[key] = _identity(
                environment.get(key), environment_path.parent, f"{label} {key}"
            )
        for key, identity in (
            ("executable", "interpreter_identity"),
            ("base_executable", "base_interpreter_identity"),
        ):
            if _reference(environment_path.parent, environment.get(key)) != identities[identity]:
                raise ValueError(f"{label} {key} differs from its frozen identity")
        purelib = _verify_distributions(
            environment, environment_path.parent, file_hashes=file_hashes, base=base
        )
        if "mininet_package_link" in environment:
            link = environment["mininet_package_link"]
            if not isinstance(link, dict):
                raise ValueError(f"{label} Mininet link must be an object")
            path = _reference(environment_path.parent, link.get("path"))
            target = _reference(environment_path.parent, link.get("resolved_source"))
            if (
                path != purelib / "mininet"
                or path.is_symlink() is not link.get("is_symlink")
                or path.resolve(strict=True) != target
                or target != source_root.resolve(strict=True)
                or link.get("matches_frozen_system_source") is not True
            ):
                raise ValueError(f"{label} Mininet package link differs")
