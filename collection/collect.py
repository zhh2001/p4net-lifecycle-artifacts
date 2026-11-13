"""Prepare and execute fresh lifecycle experiments from local pinned inputs."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import subprocess
import sys
import tarfile
import uuid
import zipfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
RUNTIME = HERE / "runtime"
REPOSITORY = HERE.parent
sys.path.insert(0, str(RUNTIME))

# Runtime modules are also imported by workers in separate environments.
import capture  # noqa: E402
from formal_checks import inspect_attempt  # noqa: E402
from harness import (  # noqa: E402
    campaign,
    campaign_executor,
    campaign_inputs,
    configuration_checks,
    isolation,
    observer_calibration_plan,
    observer_campaign,
    observer_campaign_inputs,
    observer_campaign_native,
    spec,
    worker_components,
)

TOOLS = {
    "p4net": ("p4net310", "harness.worker"),
    "p4utils": ("p4utils310", "harness.worker_p4utils"),
    "tutorial-components": ("tutorial310", "harness.worker_tutorial"),
}


def read(path: Path) -> dict[str, Any]:
    return campaign_inputs._object(path)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pin(path: Path) -> dict[str, str]:
    return {"path": str(path.absolute()), "sha256": digest(path)}


def write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def inventory() -> dict[str, str]:
    return {
        str(p.relative_to(RUNTIME)): digest(p)
        for p in sorted(RUNTIME.rglob("*"))
        if p.is_file() and "__pycache__" not in p.parts
    }


def sources() -> list[Path]:
    return [
        *(RUNTIME / name for name in inventory()),
        HERE / "collect.py",
        HERE / "capture.py",
        HERE / "hooks.json",
        HERE / "cases.json",
        HERE / "formal_checks.py",
        *sorted((HERE / "requirements").glob("*.txt")),
        REPOSITORY / "protocol/diagnostic-allocation.json",
    ]


def plans(output: Path) -> dict[str, Any]:
    """Write the original schedules without importing a tool or reading procfs."""
    output.mkdir(parents=True, exist_ok=False)
    formal = campaign.generate()
    observer = observer_calibration_plan.generate()
    diagnostic = read(REPOSITORY / "protocol/diagnostic-allocation.json")
    write(output / "formal.json", formal)
    write(output / "observer.json", observer)
    write(output / "diagnostic.json", diagnostic)
    return {
        "formal_tasks": len(formal["scale_schedule"]) + len(formal["fault_schedule"]),
        "observer_tasks": len(observer["calibration_schedule"]),
        "observer_qualification_tasks": len(observer["qualification_schedule"]),
        "diagnostic_tasks": len(diagnostic["tasks"]),
        "workloads_started": 0,
    }


def locations(config: Path) -> dict[str, Any]:
    value = read(config)
    if set(value) != {"interpreters", "artifacts", "tutorial_utils", "wrapper_interpreter"}:
        raise ValueError(
            "configuration requires interpreters, artifacts, tutorial_utils, "
            "and wrapper_interpreter"
        )
    if set(value["interpreters"]) != {label for label, _ in TOOLS.values()}:
        raise ValueError("configuration must select all three Python environments")
    if set(value["artifacts"]) != {"p4net_wheel", "p4utils_source", "tutorial_source"}:
        raise ValueError("configuration must select the three retained distribution archives")

    def absolute(name: str) -> str:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("configuration paths must be nonempty strings")
        path = Path(name)
        # Preserve virtual-environment executable paths instead of resolving their symlinks.
        return os.path.abspath(path if path.is_absolute() else config.absolute().parent / path)

    return {
        "interpreters": {label: absolute(path) for label, path in value["interpreters"].items()},
        "artifacts": {label: absolute(path) for label, path in value["artifacts"].items()},
        "tutorial_utils": absolute(value["tutorial_utils"]),
        "wrapper_interpreter": absolute(value["wrapper_interpreter"]),
    }


def capture_dependencies(output: Path, config: dict[str, Any]) -> Path:
    output.mkdir()
    capture.BASE = output
    environments = {
        label: capture.capture_environment(label, Path(python), {})
        for label, python in config["interpreters"].items()
    }
    for label, environment in environments.items():
        if environment["version_info"][:3] != [3, 10, 20]:
            raise ValueError(f"{label} requires Python 3.10.20")
        expected = {}
        for line in (HERE / "requirements" / f"{label}.txt").read_text().splitlines():
            if "==" in line:
                name, version = line.split("==", 1)
                expected[capture.normalized(name)] = version
        installed = {
            capture.normalized(d["name"]): d["version"] for d in environment["distributions"]
        }
        if any(installed.get(name) != version for name, version in expected.items()):
            raise ValueError(f"{label} package versions differ from the distributed lock")
        if label == "p4utils310" and installed.get("p4utils") != "0.2":
            raise ValueError("P4-Utils distribution version differs")
    tools = capture.capture_tools()
    capture.capture_mininet()
    artifacts = {
        name: capture.file_identity(Path(path)) for name, path in config["artifacts"].items()
    }
    verify_archives(config, environments)
    for name, expected_hash in {
        "p4utils_source": "6d5e7e7e9160d0d47d49e149ed66923e8357c5a4e8a5ac5080906898adcdbeb2",
        "tutorial_source": "3df99eedfe95d191852bc14a579028bec6e50b8c198176f140ec97fc73f32e7b",
    }.items():
        if artifacts[name]["sha256"] != expected_hash:
            raise ValueError(f"{name} archive differs from the pinned revision")
    path = output / "manifest.json"
    write(
        path,
        {
            "environment_files": {label: f"{label}/environment.json" for label in environments},
            "tools_file": "tools.json",
            "tools": sorted(tools),
            "mininet_source_file": "mininet-source.json",
            "artifacts": artifacts,
        },
    )
    locked = campaign_inputs._linked_inputs(read(path), path.parent, RUNTIME)
    campaign_inputs.verify_native_environment(
        path, labels=list(environments), file_hashes=locked, base=RUNTIME
    )
    return path


def verify_archives(config: dict[str, Any], environments: dict[str, Any]) -> None:
    """Match installed and extracted study sources to the supplied archives."""
    wheel = Path(config["artifacts"]["p4net_wheel"])
    with zipfile.ZipFile(wheel) as archive:
        root = Path(environments["p4net310"]["sysconfig_paths"]["purelib"])
        members = [
            name
            for name in archive.namelist()
            if name.startswith("p4net/") and not name.endswith("/")
        ]
        if not members:
            raise ValueError("the p4net wheel contains no package files")
        for name in members:
            if (root / name).read_bytes() != archive.read(name):
                raise ValueError(f"installed p4net source differs from its wheel: {name}")
    for label, archive_name, package in (
        ("p4utils310", "p4utils_source", "p4utils"),
        ("tutorial310", "tutorial_source", "utils"),
    ):
        with tarfile.open(config["artifacts"][archive_name]) as archive:
            seen = 0
            for member in archive.getmembers():
                parts = Path(member.name).parts
                if len(parts) < 3 or parts[1] != package or not member.isfile():
                    continue
                if package == "p4utils" and not member.name.endswith(".py"):
                    continue
                relative = Path(*parts[2:])
                if ".." in relative.parts or relative.is_absolute():
                    raise ValueError("archive member path is not relative")
                root = (
                    Path(config["tutorial_utils"])
                    if package == "utils"
                    else Path(environments[label]["sysconfig_paths"]["purelib"]) / package
                )
                content = archive.extractfile(member)
                if content is None or (root / relative).read_bytes() != content.read():
                    raise ValueError(f"extracted source differs from its archive: {relative}")
                seen += 1
            if not seen:
                raise ValueError(f"archive contains no {package} sources")


def _module_source(
    module: str, tool: str, config: dict[str, Any], environments: dict[str, Any]
) -> Path:
    relative = Path(module.replace(".", "/") + ".py")
    if module.startswith("harness."):
        return RUNTIME / relative
    if module.startswith("mininet."):
        return Path("/usr/lib/python3/dist-packages") / relative
    if module.startswith(("p4runtime_lib.", "p4_mininet", "p4runtime_switch", "netstat")):
        return Path(config["tutorial_utils"]) / relative
    label = TOOLS[tool][0]
    root = Path(environments[label]["sysconfig_paths"]["purelib"])
    path = root / relative
    return path if path.is_file() else root / module.replace(".", "/") / "__init__.py"


def prepare_diagnostic(
    output: Path, config: dict[str, Any], components: dict[str, str], dependency: Path
) -> None:
    """Bind the diagnostic profiles to installed modules without importing them."""
    from overhead.native_context import PreparedContext
    from overhead.readiness import boot_id

    directory = output / "diagnostic"
    directory.mkdir()
    dependency_value = read(dependency)
    environments = {
        label: read(dependency.parent / name)
        for label, name in dependency_value["environment_files"].items()
    }
    hooks = read(HERE / "hooks.json")
    tools = {}
    external = {str(p): digest(p) for p in sources() if not p.is_relative_to(RUNTIME)}
    for tool, rows in hooks.items():
        actual = []
        for row in rows:
            path = _module_source(row["module"], tool, config, environments)
            actual.append({**row, "source": str(path), "sha256": digest(path)})
            external[str(path)] = digest(path)
        tools[tool] = {
            "interpreter": config["interpreters"][TOOLS[tool][0]],
            "worker": TOOLS[tool][1],
            "hooks": actual,
            "environment": pin(
                dependency.parent / dependency_value["environment_files"][TOOLS[tool][0]]
            ),
        }
    cases = read(HERE / "cases.json")["cases"]
    common = {
        "schema_version": 1,
        "runtime_root": str(RUNTIME),
        "runtime_files": inventory(),
        "external_files": external,
        "collection_authorized": False,
        "execution_path": os.environ["PATH"],
        "wrapper_interpreter": config["wrapper_interpreter"],
        "tools": tools,
        "worker_components": components,
        "references": {"dependencies": pin(dependency)},
    }
    diagnostic = {
        **common,
        "record_type": "native-diagnostic-input-binding",
        "performance_samples": False,
        "cases": cases,
        "workload": pin(RUNTIME / "harness/workloads/l3.p4"),
    }
    write(directory / "diagnostic-binding.json", diagnostic)
    native = {
        **common,
        "record_type": "diagnostic-overhead-native-binding",
        "execution_kind": "prepared-native",
        "hold_ns": 10_000_000_000,
        "diagnostic_binding": pin(directory / "diagnostic-binding.json"),
        "allocation": pin(output / "plans/diagnostic.json"),
        "resource_sampling_enabled": False,
        "stack_capture_enabled": False,
        "limits_seconds": {"readiness": 120, "ordinary_stop": 30, "outer_watchdog": 210},
    }
    write(directory / "native-binding.json", native)
    fixture = {
        **copy.deepcopy(native),
        "execution_kind": "protected-synthetic",
        "hold_ns": 10_000_000,
    }
    for tool in fixture["tools"].values():
        tool["interpreter"] = sys.executable
    write(directory / "fixture-binding.json", fixture)
    prepared = []
    for row in read(output / "plans/diagnostic.json")["tasks"]:
        run_id = uuid.uuid4().hex
        prefix = "r" + run_id[:6]
        hosts, switches = spec.names(prefix, row["switches"])
        task = directory / "prepared" / row["planned_task_id"]
        path = task / "native/manifest.json"
        manifest = {
            "schema_version": 1,
            "purpose": "functional-check",
            "configuration_profile": "matched-v1",
            "run_id": run_id,
            "prefix": prefix,
            "groups": row["switches"],
            "host_names": hosts,
            "switch_names": switches,
            "service_ports": list(range(50051, 50051 + 2 * row["switches"])),
            "p4_source": str(RUNTIME / "harness/workloads/l3.p4"),
            "source_sha256": digest(RUNTIME / "harness/workloads/l3.p4"),
            "output_dir": str(path.parent),
            "worker_components": components,
        }
        if row["diagnostic_profile"] != "native":
            manifest.update(
                diagnostic={
                    "binding": pin(directory / "diagnostic-binding.json"),
                    "case_id": (
                        f"{row['tool']}-n{row['switches']:02}-{row['diagnostic_profile']}-normal"
                    ),
                },
                diagnostic_manifest_dir=str(path.parent),
            )
        spec.validate(manifest)
        write(path, manifest)
        control = task / "control/task.json"
        context = PreparedContext(
            run_id, "a1", row["tool"], row["diagnostic_profile"], mode="pilot"
        )
        write(
            control,
            {
                "schema_version": 1,
                "record_type": "diagnostic-overhead-native-control",
                "binding": pin(directory / "native-binding.json"),
                "manifest": pin(path),
                "context": context.as_dict(),
                "planned_task_id": row["planned_task_id"],
            },
        )
        prepared.append({"allocation_row": row, "control": pin(control)})
    write(
        directory / "prepared-inputs.json",
        {"native_binding": pin(directory / "native-binding.json"), "tasks": prepared},
    )
    write(
        directory / "controller-binding.json",
        {
            "schema_version": 1,
            "record_type": "diagnostic-overhead-controller-binding",
            "mode": "pilot",
            "allocation": pin(output / "plans/diagnostic.json"),
            "prepared_inputs": pin(directory / "prepared-inputs.json"),
            "native_binding": pin(directory / "native-binding.json"),
            "fixture_binding": pin(directory / "fixture-binding.json"),
            "preparation_boot_id": boot_id(),
            "previous_freeze": pin(output / "preparation.json"),
            "collection_authorized": False,
            "native_backend_qualified": False,
        },
    )


def prepare(config_path: Path, output: Path) -> dict[str, Any]:
    from overhead.readiness import boot_id

    config, output = locations(config_path), output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    counts = plans(output / "plans")
    dependency = capture_dependencies(output / "dependencies", config)
    components_path = output / "worker-components.json"
    write(components_path, worker_components.build_manifest(Path(config["tutorial_utils"])))
    components = pin(components_path)
    control = {
        "profile": "matched-v1",
        "dependency_freeze": pin(dependency),
        "wrapper_interpreter": {**capture.file_identity(Path(config["wrapper_interpreter"]))},
        "worker_components": components,
    }
    for name, mode in (("formal", "formal"), ("observer", "pilot")):
        target = output / name
        target.mkdir()
        plan_path = output / "plans" / f"{name}.json"
        write(target / "control.json", {**control, "campaign": pin(plan_path)})
        builder = (
            campaign_inputs.build_binding
            if name == "formal"
            else observer_campaign_inputs.build_binding
        )
        binding = builder(
            plan_path, target / "control.json", dependency, sources(), mode=mode, base=RUNTIME
        )
        write(target / "binding.json", binding)
    write(
        output / "preparation.json",
        {
            "record_type": "fresh-collection-preparation",
            "counts": counts,
            "locations": config,
            "runtime_files": inventory(),
            "dependencies": pin(dependency),
            "preparation_boot_id": boot_id(),
            "formal_binding": pin(output / "formal/binding.json"),
            "observer_binding": pin(output / "observer/binding.json"),
            "workloads_started": 0,
        },
    )
    prepare_diagnostic(output, config, components, dependency)
    write(
        output / "input-seal.json",
        {
            str(path.relative_to(output)): digest(path)
            for path in sorted(output.rglob("*"))
            if path.is_file()
        },
    )
    return counts


def verify_preparation(output: Path) -> dict[str, Any]:
    for name, expected in read(output / "input-seal.json").items():
        if digest(output / name) != expected:
            raise ValueError(f"prepared input changed: {name}")
    value = read(output / "preparation.json")
    if value["runtime_files"] != inventory():
        raise ValueError("collection runtime changed; create a fresh preparation")
    for name in ("formal", "observer"):
        reference = value[name + "_binding"]
        if pin(Path(reference["path"])) != reference:
            raise ValueError(f"{name} binding changed")
        binding = read(Path(reference["path"]))
        verifier = (
            campaign_inputs.verify_binding
            if name == "formal"
            else observer_campaign_inputs.verify_binding
        )
        verifier(binding, base=RUNTIME)
    campaign_inputs.verify_native_environment(
        Path(value["dependencies"]["path"]),
        labels=[label for label, _ in TOOLS.values()],
        file_hashes=read(output / "formal/binding.json")["locked_inputs"],
        base=RUNTIME,
    )
    return value


def qualify(output: Path) -> dict[str, Any]:
    """Check installed workloads and diagnostic profiles without performance samples."""
    from harness.diagnostic_binding import launch_spec
    from harness.diagnostic_checks import assess_trace

    if os.geteuid() != 0:
        raise PermissionError("native qualification requires root")
    prepared = verify_preparation(output)
    directory = output / "qualification"
    directory.mkdir()
    checks = []
    for tool, (label, worker) in TOOLS.items():
        for groups in (1, 16):
            path = spec.create(
                directory / f"{tool}-n{groups:02}",
                groups=groups,
                configuration_profile="matched-v1",
            )
            manifest = read(path)
            manifest["worker_components"] = pin(output / "worker-components.json")
            path.write_text(json.dumps(manifest, indent=2) + "\n")
            result = isolation.run_isolated(
                path,
                Path(prepared["locations"]["interpreters"][label]),
                worker,
                boundary_validation=True,
                guards=True,
            )
            if (
                result.get("ok") is not True
                or result.get("cleanup", {}).get("ordinary_after_clean") is not True
            ):
                raise RuntimeError(f"native qualification failed: {tool}, {groups} switches")
            check = configuration_checks.inspect_trial(path)
            checks.append(
                {
                    "tool": tool,
                    "switches": groups,
                    "profile": "native",
                    "result": pin(path.parent / "result.json"),
                    "configuration": check,
                }
            )
    diagnostic_path = output / "diagnostic/diagnostic-binding.json"
    diagnostic = read(diagnostic_path)
    for case in diagnostic["cases"]:
        if case["fault"] != "normal":
            continue
        path = spec.create(
            directory / case["id"], groups=case["groups"], configuration_profile="matched-v1"
        )
        manifest = read(path)
        manifest.update(
            worker_components=pin(output / "worker-components.json"),
            diagnostic={"binding": pin(diagnostic_path), "case_id": case["id"]},
            diagnostic_manifest_dir=str(path.parent),
        )
        path.write_text(json.dumps(manifest, indent=2) + "\n")
        command = launch_spec(path)
        with (directory / f"{case['id']}-enclosure.log").open("x") as log:
            subprocess.run(
                command["argv"],
                cwd=command["cwd"],
                env=command["env"],
                timeout=command["outer_timeout"],
                check=True,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        result = read(path.parent / "result.json")
        trace = path.parent / "diagnostic-trace.jsonl"
        assessment = assess_trace(trace, case, diagnostic["tools"][case["tool"]])
        if (
            result.get("ok") is not True
            or result.get("cleanup", {}).get("ordinary_after_clean") is not True
            or assessment["qualified"] is not True
        ):
            raise RuntimeError(f"diagnostic qualification failed: {case['id']}")
        checks.append(
            {
                "tool": case["tool"],
                "switches": case["groups"],
                "profile": case["profile"],
                "result": pin(path.parent / "result.json"),
                "trace": pin(trace),
                "assessment": assessment,
            }
        )
    certificate = {
        "passed": True,
        "preparation": pin(output / "preparation.json"),
        "checks": checks,
        "performance_samples": False,
    }
    write(output / "qualification.json", certificate)
    controller_path = output / "diagnostic/controller-binding.json"
    controller = read(controller_path)
    controller["native_backend_qualified"] = True
    controller["previous_freeze"] = pin(output / "qualification.json")
    write(output / "diagnostic/qualified-controller-binding.json", controller)
    return certificate


def require_qualification(output: Path) -> None:
    verify_preparation(output)
    certificate = read(output / "qualification.json")
    if certificate.get("passed") is not True or certificate.get("preparation") != pin(
        output / "preparation.json"
    ):
        raise PermissionError("native qualification must pass for these prepared inputs")
    for row in certificate["checks"]:
        if pin(Path(row["result"]["path"])) != row["result"]:
            raise ValueError("native qualification evidence changed")
        if "trace" in row and pin(Path(row["trace"]["path"])) != row["trace"]:
            raise ValueError("diagnostic qualification trace changed")


def readiness(output: Path, name: str, session: int, confirmed: bool) -> dict[str, Any]:
    from overhead.readiness import boot_id

    require_qualification(output)
    directory = output / name / "sessions"
    current = boot_id()
    if read(output / "preparation.json").get("preparation_boot_id") == current:
        raise PermissionError("reboot the experiment host after preparation and qualification")
    path = directory / f"{session:02}.json"
    if path.exists():
        value = read(path)
        if value["boot_id"] != current:
            raise PermissionError("this session belongs to a different boot")
        return value
    if not confirmed:
        raise PermissionError("confirm the rebooted, idle host with --confirm-ready")
    previous = [read(p) for p in directory.glob("*.json")]
    if session != len(previous) + 1 or any(row["boot_id"] == current for row in previous):
        raise PermissionError("sessions require sequential confirmation and distinct boots")
    value = {
        "session": session,
        "boot_id": current,
        "preparation": pin(output / "preparation.json"),
    }
    write(path, value)
    return value


def formal_inspections(executor: campaign_executor.Campaign, output: Path) -> list[dict[str, Any]]:
    inspected = []
    for row in executor.report()["attempts"]:
        phase, entry = executor.entries[row["planned_id"]]
        described = {
            **row,
            "session": entry["session"],
            "workload": phase,
            "attempt_id": f"{row['planned_id']}--a{row['attempt_number']:04}",
        }
        source = RUNTIME / "harness/workloads/l3.p4"
        inspected.append(
            {
                "row": described,
                "inspection": inspect_attempt(
                    output / "formal/journal",
                    row,
                    base=output,
                    shared_sources={source: digest(source)},
                ),
            }
        )
    return inspected


def formal_run(args: argparse.Namespace, executor: campaign_executor.Campaign) -> dict[str, Any]:
    """Check every terminal task before advancing to the next scheduled task."""
    output = args.output.absolute()
    inspections = formal_inspections(executor, output)
    latest = {item["row"]["planned_id"]: item for item in inspections}
    unsafe = {planned for planned, item in latest.items() if not item["inspection"]["can_continue"]}
    if unsafe - set(args.retry):
        raise PermissionError(
            "inspect the failed task and create an explicit retry before continuing"
        )
    retried = {
        item["row"]["planned_id"]
        for item in inspections
        if item["row"].get("attempt_number", 1) > 1 and item["row"]["session"] == args.session
    }
    if retried and not args.retry:
        reviews = sorted(
            (output / "formal/reviews" / f"s{args.session:02}-continuation").glob("*.json")
        )
        approved = read(reviews[-1]) if reviews else {}
        selected = [
            pin(output / "formal/journal" / latest[planned]["row"]["directory"] / "result.json")
            for planned in sorted(retried)
        ]
        if approved.get("passed") is not True or approved.get("selected_results") != selected:
            raise PermissionError("review the successful explicit retries before continuing")
    if args.session > 1:
        for phase in ("scale", "fault"):
            formal_review_valid(output, args.session - 1, phase, inspections)
    if args.phase == "fault":
        formal_review_valid(output, args.session, "scale", inspections)
    backend = campaign_executor.NativeBackend("formal", base=RUNTIME)
    executed = []
    report: dict[str, Any] = {}
    for _ in range(args.limit):
        report = executor.run(args.phase, args.session, backend, retry=args.retry, limit=1)
        new = report["invocation"]["executed_attempt_ids"]
        if not new:
            break
        executed.extend(new)
        current = formal_inspections(executor, output)
        last = next(item for item in current if item["row"]["attempt_id"] == new[-1])
        if not last["inspection"]["can_continue"] or args.retry:
            break
    return {"executed_attempt_ids": executed, "report": report}


def formal_review_valid(
    output: Path, session: int, phase: str, inspections: list[dict[str, Any]]
) -> None:
    reviews = sorted((output / "formal/reviews" / f"s{session:02}-{phase}").glob("*.json"))
    if not reviews:
        raise PermissionError("the preceding phase requires an explicit review")
    value = read(reviews[-1])
    selected = [
        item
        for item in inspections
        if item["row"]["session"] == session and item["row"]["workload"] == phase
    ]
    latest = dict(sorted({item["row"]["planned_id"]: item for item in selected}.items()))
    expected = 150 if phase == "scale" else 180
    if len(latest) != expected or any(
        not item["inspection"]["can_continue"] for item in latest.values()
    ):
        raise PermissionError("the preceding phase requires complete, intact terminal evidence")
    pins = [
        pin(output / "formal/journal" / item["row"]["directory"] / "result.json")
        for item in latest.values()
    ]
    if value.get("passed") is not True or value.get("selected_results") != pins:
        raise PermissionError("the preceding phase requires a current positive review")


def run(args: argparse.Namespace) -> dict[str, Any]:
    if not args.execute:
        raise PermissionError("fresh collection requires --execute")
    if os.geteuid() != 0:
        raise PermissionError("fresh collection requires root")
    if args.limit < 1:
        raise ValueError("limit must be positive")
    output = args.output.absolute()
    readiness(output, args.campaign, args.session, args.confirm_ready)
    if args.campaign == "diagnostic":
        from overhead.campaign import Campaign
        from overhead.native_backend import NativeBackend

        with Campaign(
            output / "diagnostic/journal",
            pin(output / "diagnostic/qualified-controller-binding.json"),
        ) as executor:
            if args.confirm_ready:
                executor.confirm_session(args.session, confirmed=True)
            return executor.run(
                NativeBackend(), session=args.session, limit=args.limit, retry=args.retry
            )
    binding = read(output / args.campaign / "binding.json")
    if args.campaign == "formal":
        if args.phase not in {"scale", "fault"}:
            raise ValueError("formal collection requires --phase scale or fault")
        with campaign_executor.Campaign(
            output / "formal/journal", binding, base=RUNTIME
        ) as executor:
            return formal_run(args, executor)
    if args.phase not in {"qualification", "calibration"}:
        raise ValueError("observer collection requires --phase qualification or calibration")
    with observer_campaign.Campaign(output / "observer/journal", binding, base=RUNTIME) as executor:
        return executor.run(
            observer_campaign_native.NativeObserverBackend(base=RUNTIME),
            phase=args.phase,
            session=0 if args.phase == "qualification" else args.session,
            collection_authorized=True,
            retry=args.retry,
            limit=args.limit,
        )


def review(args: argparse.Namespace) -> dict[str, Any]:
    output = args.output.absolute()
    require_qualification(output)
    if args.campaign == "formal":
        if args.gate not in {"scale", "fault", "continuation"} or args.session is None:
            raise ValueError("formal review requires a phase or continuation gate and --session")
        binding = read(output / "formal/binding.json")
        with campaign_executor.Campaign(
            output / "formal/journal", binding, base=RUNTIME
        ) as executor:
            inspected = formal_inspections(executor, output)
        selected = {
            item["row"]["planned_id"]: item
            for item in inspected
            if item["row"]["session"] == args.session
            and (args.gate == "continuation" or item["row"]["workload"] == args.gate)
        }
        if args.gate == "continuation":
            selected = {
                planned: item
                for planned, item in selected.items()
                if item["row"].get("attempt_number", 1) > 1
            }
        selected = dict(sorted(selected.items()))
        expected = (
            len(selected) if args.gate == "continuation" else (150 if args.gate == "scale" else 180)
        )
        if args.decision == "passed" and (
            not selected
            or len(selected) != expected
            or any(not item["inspection"]["can_continue"] for item in selected.values())
        ):
            raise ValueError("a positive review requires complete, intact terminal evidence")
        value = {
            "session": args.session,
            "phase": args.gate,
            "passed": args.decision == "passed",
            "reason": args.reason,
            "selected_results": [
                pin(output / "formal/journal" / item["row"]["directory"] / "result.json")
                for item in selected.values()
            ],
        }
        directory = output / "formal/reviews" / f"s{args.session:02}-{args.gate}"
        number = 1 + len(list(directory.glob("*.json")))
        write(directory / f"{number:04}.json", value)
        return value
    if args.campaign == "observer":
        binding = read(output / "observer/binding.json")
        with observer_campaign.Campaign(
            output / "observer/journal", binding, base=RUNTIME
        ) as executor:
            return executor.review_gate(
                args.gate,
                qualified=args.decision == "passed",
                reason=args.reason,
                selection="latest-attempt",
            )
    if args.campaign == "diagnostic":
        from overhead.campaign import Campaign

        with Campaign(
            output / "diagnostic/journal",
            pin(output / "diagnostic/qualified-controller-binding.json"),
        ) as executor:
            from overhead.campaign import qualified

            results = [
                executor.attempts.get(planned, []) for planned in executor.gate_tasks(args.gate)
            ]
            actual = bool(results) and all(
                items and items[-1]["result"] is not None and qualified(items[-1]["result"])
                for items in results
            )
            if actual is not (args.decision == "passed"):
                raise ValueError("the requested review decision differs from the retained outcomes")
            return executor.review(args.gate, reason=args.reason)
    raise ValueError("unknown campaign")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan", help="write schedules without native tools")
    plan.add_argument("--output", type=Path, required=True)
    prep = commands.add_parser(
        "prepare", help="bind installed environments without starting workloads"
    )
    prep.add_argument("--config", type=Path, required=True)
    prep.add_argument("--output", type=Path, required=True)
    qualification = commands.add_parser("qualify", help="run boundary-only native checks")
    qualification.add_argument("--output", type=Path, required=True)
    collect = commands.add_parser(
        "run", help="execute or resume explicitly authorized fresh collection"
    )
    collect.add_argument("--output", type=Path, required=True)
    collect.add_argument("--campaign", choices=("formal", "observer", "diagnostic"), required=True)
    collect.add_argument("--session", type=int, choices=(1, 2, 3), required=True)
    collect.add_argument("--phase", choices=("scale", "fault", "qualification", "calibration"))
    collect.add_argument("--confirm-ready", action="store_true")
    collect.add_argument("--execute", action="store_true")
    collect.add_argument("--limit", type=int, default=1)
    collect.add_argument("--retry", nargs="*", default=[])
    gate = commands.add_parser("review", help="record a wiring-gate assessment")
    gate.add_argument("--output", type=Path, required=True)
    gate.add_argument("--campaign", choices=("formal", "observer", "diagnostic"), required=True)
    gate.add_argument("--session", type=int, choices=(1, 2, 3))
    gate.add_argument("--gate", required=True)
    gate.add_argument("--decision", choices=("passed", "failed"), required=True)
    gate.add_argument("--reason", required=True)
    args = parser.parse_args()
    try:
        if args.command == "plan":
            value = plans(args.output)
        elif args.command == "prepare":
            value = prepare(args.config, args.output)
        elif args.command == "qualify":
            value = qualify(args.output.absolute())
        elif args.command == "review":
            value = review(args)
        else:
            value = run(args)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        parser.exit(2, f"{type(exc).__name__}: {exc}\n")
    print(json.dumps(value, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
