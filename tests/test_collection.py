"""Check portable preparation, immutable bindings, and collection controls."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import collect
import pytest
from harness import campaign_executor, campaign_inputs, observer_campaign_inputs
from overhead.native_binding import read_control


@pytest.fixture
def prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    config = tmp_path / "config.json"
    values = {
        "interpreters": {label: f"env/{label}/bin/python" for label, _ in collect.TOOLS.values()},
        "artifacts": {name: name for name in ("p4net_wheel", "p4utils_source", "tutorial_source")},
        "tutorial_utils": "utils",
        "wrapper_interpreter": "/usr/bin/python3",
    }
    config.write_text(json.dumps(values))
    utils = tmp_path / "utils"
    for name in collect.worker_components.REQUIRED:
        path = utils / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# temporary component fixture\n")

    def capture(output: Path, locations: dict) -> Path:
        output.mkdir()
        for label in locations["interpreters"]:
            collect.write(
                output / label / "environment.json", {"sysconfig_paths": {"purelib": str(tmp_path)}}
            )
        collect.write(output / "tools.json", {})
        collect.write(output / "mininet.json", {})
        artifact = output / "fixture.whl"
        artifact.write_bytes(b"fixture")
        path = output / "manifest.json"
        collect.write(
            path,
            {
                "environment_files": {
                    label: f"{label}/environment.json" for label in locations["interpreters"]
                },
                "tools_file": "tools.json",
                "mininet_source_file": "mininet.json",
                "artifacts": {"fixture": collect.pin(artifact)},
            },
        )
        return path

    monkeypatch.setattr(collect, "capture_dependencies", capture)
    monkeypatch.setattr(collect, "_module_source", lambda *a: collect.HERE / "hooks.json")
    output = tmp_path / "fresh"
    collect.prepare(config, output)
    return output


def test_offline_schedules_do_not_launch_or_read_resources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    forbidden = Mock(side_effect=AssertionError("unexpected live operation"))
    monkeypatch.setattr(collect.subprocess, "Popen", forbidden)
    monkeypatch.setattr(collect.os, "readlink", forbidden)
    monkeypatch.setattr(collect.capture, "capture_tools", forbidden)
    assert collect.plans(tmp_path / "plans") == {
        "formal_tasks": 990,
        "observer_tasks": 270,
        "observer_qualification_tasks": 9,
        "diagnostic_tasks": 360,
        "workloads_started": 0,
    }
    forbidden.assert_not_called()


def test_plan_cli_works_outside_checkout(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(collect.HERE / "collect.py"),
            "plan",
            "--output",
            str(tmp_path / "plans"),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(result.stdout)["formal_tasks"] == 990


def test_existing_output_is_preserved(tmp_path: Path) -> None:
    tmp_path.joinpath("keep.txt").write_text("existing\n")
    with pytest.raises(FileExistsError):
        collect.plans(tmp_path)
    assert tmp_path.joinpath("keep.txt").read_text() == "existing\n"


def test_configuration_keeps_virtual_environment_symlink(tmp_path: Path) -> None:
    interpreter = tmp_path / "env/bin/python"
    interpreter.parent.mkdir(parents=True)
    interpreter.symlink_to(sys.executable)
    value = json.loads((collect.HERE / "config.example.json").read_text())
    value["interpreters"]["p4net310"] = "env/bin/python"
    config = tmp_path / "config.json"
    config.write_text(json.dumps(value))
    assert collect.locations(config)["interpreters"]["p4net310"] == str(interpreter)


def test_preparation_binds_all_three_experiments(prepared: Path) -> None:
    formal = collect.read(prepared / "formal/binding.json")
    campaign_inputs.verify_binding(formal, base=collect.RUNTIME)
    observer_campaign_inputs.verify_binding(
        collect.read(prepared / "observer/binding.json"), base=collect.RUNTIME
    )
    inputs = collect.read(prepared / "diagnostic/prepared-inputs.json")
    assert len(inputs["tasks"]) == 360
    for task in inputs["tasks"]:
        _, binding, context = read_control(task["control"], full=True)
        assert context.diagnostic_profile == task["allocation_row"]["diagnostic_profile"]
        assert binding["hold_ns"] == 10_000_000_000
    assert formal["measurement_defaults"] == {
        "duration_ns": 10_000_000_000,
        "interval_ns": 100_000_000,
    }


def test_changed_workload_plan_is_rejected(prepared: Path) -> None:
    path = prepared / "plans/formal.json"
    path.write_text(path.read_text() + "\n")
    with pytest.raises(ValueError, match="hash differs"):
        campaign_inputs.verify_binding(
            collect.read(prepared / "formal/binding.json"), base=collect.RUNTIME
        )


def test_diagnostic_trace_requirements_are_retained() -> None:
    cases = collect.read(collect.HERE / "cases.json")["cases"]
    assert len([case for case in cases if case["fault"] == "normal"]) == 18
    assert all(case["required_stages"] for case in cases if case["profile"] != "off")


def test_run_requires_explicit_execution() -> None:
    with pytest.raises(PermissionError, match="--execute"):
        collect.run(argparse.Namespace(execute=False))


def test_native_qualification_requires_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(collect.os, "geteuid", lambda: 1000)
    with pytest.raises(PermissionError, match="requires root"):
        collect.qualify(tmp_path)


@pytest.mark.parametrize("clean", [True, False])
def test_qualification_logs_leave_trial_directory_new(
    prepared: Path, monkeypatch: pytest.MonkeyPatch, clean: bool
) -> None:
    from harness import diagnostic_binding, diagnostic_checks

    monkeypatch.setattr(collect.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        collect, "verify_preparation", lambda p: collect.read(p / "preparation.json")
    )
    monkeypatch.setattr(collect.configuration_checks, "inspect_trial", lambda _: {})

    def native(path: Path, *args, **kwargs) -> dict:
        result = {"ok": True, "cleanup": {"ordinary_after_clean": True}}
        collect.write(path.parent / "result.json", result)
        return result

    def launch(path: Path) -> dict:
        return {
            "argv": ["fixture", str(path)],
            "cwd": str(path.parent),
            "env": {},
            "outer_timeout": 1,
        }

    def diagnostic(argv: list[str], **kwargs) -> None:
        path = Path(argv[1])
        assert sorted(p.name for p in path.parent.iterdir()) == ["manifest.json"]
        assert Path(kwargs["stdout"].name).parent != path.parent
        collect.write(
            path.parent / "result.json", {"ok": True, "cleanup": {"ordinary_after_clean": clean}}
        )
        path.with_name("diagnostic-trace.jsonl").write_text("fixture\n")

    monkeypatch.setattr(collect.isolation, "run_isolated", native)
    monkeypatch.setattr(diagnostic_binding, "launch_spec", launch)
    monkeypatch.setattr(diagnostic_checks, "assess_trace", lambda *a: {"qualified": True})
    monkeypatch.setattr(collect.subprocess, "run", diagnostic)
    if clean:
        assert len(collect.qualify(prepared)["checks"]) == 24
    else:
        with pytest.raises(RuntimeError, match="diagnostic qualification failed"):
            collect.qualify(prepared)


def test_session_confirmation_is_reused_only_within_same_boot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from overhead import readiness

    monkeypatch.setattr(collect, "require_qualification", lambda _: None)
    monkeypatch.setattr(readiness, "boot_id", lambda: "boot-a")
    collect.write(tmp_path / "preparation.json", {})
    with pytest.raises(PermissionError, match="--confirm-ready"):
        collect.readiness(tmp_path, "formal", 1, False)
    first = collect.readiness(tmp_path, "formal", 1, True)
    assert collect.readiness(tmp_path, "formal", 1, False) == first
    with pytest.raises(PermissionError, match="distinct boots"):
        collect.readiness(tmp_path, "formal", 2, True)
    monkeypatch.setattr(readiness, "boot_id", lambda: "boot-b")
    with pytest.raises(PermissionError, match="different boot"):
        collect.readiness(tmp_path, "formal", 1, False)
    assert collect.readiness(tmp_path, "formal", 2, True)["boot_id"] == "boot-b"


def test_formal_inspector_includes_planned_session_and_phase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executor = Mock(spec=campaign_executor.Campaign)
    executor.entries = {"task": ("fault", {"session": 2})}
    executor.report.return_value = {
        "attempts": [{"planned_id": "task", "directory": "task/0001", "attempt_number": 1}]
    }
    monkeypatch.setattr(collect, "inspect_attempt", lambda *a, **k: {"can_continue": False})
    assert collect.formal_inspections(executor, tmp_path)[0]["row"]["workload"] == "fault"
    assert collect.formal_inspections(executor, tmp_path)[0]["row"]["session"] == 2


def test_formal_failure_blocks_automatic_continuation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        collect,
        "formal_inspections",
        lambda *a: [{"row": {"planned_id": "failed"}, "inspection": {"can_continue": False}}],
    )
    with pytest.raises(PermissionError, match="explicit retry"):
        collect.formal_run(argparse.Namespace(output=tmp_path, retry=[]), Mock())


def test_formal_advance_matches_attempt_identity_not_process_run_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inspected = {"row": {"attempt_id": "task--a0001"}, "inspection": {"can_continue": True}}
    monkeypatch.setattr(collect, "formal_inspections", Mock(side_effect=[[], [inspected]]))
    executor = Mock()
    executor.run.return_value = {"invocation": {"executed_attempt_ids": ["task--a0001"]}}
    args = argparse.Namespace(output=tmp_path, retry=[], session=1, phase="scale", limit=1)
    assert collect.formal_run(args, executor)["executed_attempt_ids"] == ["task--a0001"]


def test_external_workload_requires_its_bound_hash(tmp_path: Path) -> None:
    from formal_checks import Reader

    source = tmp_path / "shared/l3.p4"
    source.parent.mkdir()
    source.write_text("original workload\n")
    root = tmp_path / "results"
    root.mkdir()
    expected = collect.digest(source)
    with pytest.raises(ValueError, match="outside the study"):
        Reader(root).content(source)
    reader = Reader(root, {source: expected})
    assert reader.content(source) == b"original workload\n"
    source.write_text("changed workload\n")
    with pytest.raises(ValueError, match="source changed"):
        reader.content(source)
