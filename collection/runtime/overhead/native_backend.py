"""Dispatch source-bound native work with durable ownership and bounded recovery."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from harness.baseline_checks import host_links
from harness.isolation import namespace_ids
from harness.observer_reference import discover_observer

from overhead.authority import check, create
from overhead.campaign import Attempt, result_for
from overhead.host_guards import assess_guards
from overhead.kernel_handles import probe
from overhead.ledger import read
from overhead.model import Identity
from overhead.native_binding import read_control
from overhead.native_dispatch import launch_spec
from overhead.ownership import Ownership, live
from overhead.proc import ProcReader
from overhead.publication import pointer, publish
from overhead.reference import ParentReference
from overhead.results import finalize
from overhead.wire import Channel


def snapshot(ownership: Ownership) -> dict[str, Any]:
    result: dict[str, Any] = {"errors": []}
    for key, callback in (
        ("links", host_links),
        ("hugepages", lambda: Path("/proc/sys/vm/nr_hugepages").read_text()),
        ("namespaces", namespace_ids),
    ):
        try:
            result[key] = callback()
        except Exception as exc:
            result["errors"].append(f"{key}: {type(exc).__name__}: {exc}")
    file_record = read(ownership.root / "host-file.json")
    try:
        target = Path(file_record["target"])
        result["file_survived"] = pointer(target)["sha256"] == file_record["backing"][
            "sha256"
        ] and (target.stat().st_dev, target.stat().st_ino) == (
            file_record["device"],
            file_record["inode"],
        )
    except (OSError, ValueError):
        result["file_survived"] = False
    result["process_survived"] = live(Identity.from_dict(ownership.process("guard")["identity"]))
    return result


class NativeBackend:
    def __init__(self, *, fixture: bool = False, checkpoint: Callable[[str], None] | None = None):
        if checkpoint is not None and not fixture:
            raise PermissionError("fault injection is restricted to protected fixtures")
        self.mode = "synthetic-validation" if fixture else "pilot"
        self.fixture = fixture
        self.checkpoint = (lambda _: None) if checkpoint is None else checkpoint

    def preflight(self) -> None:
        if os.geteuid() != 0:
            raise PermissionError("native dispatch requires root and pidfd support")
        probe()
        if Path(__file__).stat().st_dev != Path("/tmp").stat().st_dev:
            raise RuntimeError("host fixture backing and /tmp require the same filesystem")

    def __call__(self, attempt: Attempt) -> dict[str, Any]:
        self.preflight()
        _control, binding, context = read_control(attempt.control, full=True)
        if context.mode != self.mode or self.fixture != (
            binding["execution_kind"] == "protected-synthetic"
        ):
            raise ValueError("native backend treatment differs from the attempt")
        if ProcReader().identity(os.getpid()).as_dict() != attempt.payload["owner"]:
            raise PermissionError("backend caller differs from the attempt owner")
        permit = create(attempt)
        check(permit, attempt.control)
        ownership = Ownership(attempt.directory, attempt.control)
        ownership.initialize()
        ownership.file(Path("/tmp") / f"research-{context.run_id}.log")
        parent, child = socket.socketpair()
        processes: list[subprocess.Popen[bytes]] = []
        reference = None
        errors: list[dict[str, str]] = []
        before: dict[str, Any] = {}
        after: dict[str, Any] = {}
        assessment: dict[str, Any] = {"qualified": False}
        native_result = None
        cleanup = None
        output = attempt.directory
        try:
            with parent, child, (output / "enclosure.log").open("x") as log:
                deadline = time.monotonic() + (60 if self.fixture else 210)
                spec = launch_spec(Path(attempt.control["path"]), child.fileno(), deadline)
                spec["env"]["P4NET_OVERHEAD_PERMIT"] = json.dumps(permit)
                processes.append(
                    ownership.launch(
                        "guard",
                        ["mininet:outside-guard", "infinity"],
                        env=spec["env"],
                        cwd=spec["cwd"],
                        log=log,
                        checkpoint=self.checkpoint,
                    )
                )
                before = snapshot(ownership)
                self.checkpoint("guard_ready")
                start = time.monotonic_ns()
                outer = ownership.launch(
                    "outer",
                    spec["argv"],
                    env=spec["env"],
                    cwd=spec["cwd"],
                    log=log,
                    pass_fds=(child.fileno(),),
                    checkpoint=self.checkpoint,
                )
                processes.append(outer)
                child.close()
                reader = ProcReader()
                initial = Identity.from_dict(ownership.process("outer")["identity"])
                channel = Channel(parent, deadline)
                try:
                    first = channel.receive()
                    inside = Identity.from_dict(first["supervisor"])
                    discovered = discover_observer(
                        outer.pid,
                        {name: inside.namespaces[name] for name in ("pid", "net", "mnt")},
                        outer_start_ticks=initial.start_ticks,
                    )
                    supervisor = reader.identity(discovered.host_pid)
                    if not supervisor.same_process(inside) or inside.pid != 1:
                        raise ProcessLookupError("native init differs from the owned process tree")
                    ownership.register_init(supervisor)
                    self.checkpoint("init_registered")
                    reference = ParentReference(context, supervisor, channel.send, reader=reader)
                    reference.handle(first)
                    while reference.history[-1] != "ref_complete":
                        frame = channel.receive()
                        self.checkpoint(frame["boundary"] + "_received")
                        reference.handle(frame)
                except (OSError, ValueError, KeyError, EOFError) as exc:
                    if reference is None:
                        raise
                    reference.failed = True
                    errors.append(
                        {
                            "metric": "reference_transport",
                            "type": type(exc).__name__,
                            "message": str(exc),
                        }
                    )
                    parent.close()
                outer.wait(timeout=max(0.1, deadline - time.monotonic()))
                end = time.monotonic_ns()
                if outer.returncode not in (0, 1):
                    errors.append(
                        {
                            "metric": "enclosure_exit",
                            "type": "RuntimeError",
                            "message": str(outer.returncode),
                        }
                    )
                assert reference is not None
                native_result = finalize(
                    reference,
                    output / "measurement",
                    outer_span={"start_ns": start, "end_ns": end},
                    external_issues=errors,
                )
                after = snapshot(ownership)
                enclosure = read(output / "native-isolation.json")
                assessment = assess_guards(
                    before, after, enclosure, "p4net" if self.fixture else context.tool
                )
                self.checkpoint("reference_published")
        finally:
            parent.close()
            child.close()
            cleanup = ownership.cleanup()
            for process in processes:
                process.wait(timeout=5)
            publish(output / "owned-cleanup.json", cleanup)
        assert native_result is not None and cleanup is not None
        receipt = {
            "performance_samples": context.mode == "pilot",
            "context": context.as_dict(),
            "reference_result": pointer(output / "measurement/reference-result.json"),
            "host_before": before,
            "host_after": after,
            "guard_assessment": assessment,
            "owned_cleanup": pointer(output / "owned-cleanup.json"),
            "owned_processes": [record["identity"] for record in cleanup["processes"]],
            "owned_processes_gone": [record["gone"] for record in cleanup["processes"]],
        }
        publish(output / "dispatch-receipt.json", receipt)
        native = native_result["native_result"]
        native_ok = None if native is None else native["ok"]
        status = (
            "blocked"
            if native is None
            else "completed"
            if native_ok
            else "timeout"
            if native.get("ordinary_stop_timeout")
            else "failed"
        )
        diagnostic = context.diagnostic_profile == "native"
        trace = output / "native/diagnostic-trace.jsonl"
        if trace.exists():
            from diagnostic.trace import summarize

            summary = summarize(trace)
            diagnostic = summary["complete"] and not summary["issues"]
        result = result_for(
            attempt,
            status=status,
            native_ok=native_ok,
            complete=native_result["measurement_complete"],
            diagnostic=bool(diagnostic),
            guards=assessment["qualified"] and cleanup["clean"],
            reason="protected protocol fixture"
            if self.fixture
            else "source-bound native calibration task",
        )
        result["artifacts"] = {
            "reference_result": pointer(output / "measurement/reference-result.json"),
            "dispatch_receipt": pointer(output / "dispatch-receipt.json"),
            "owned_cleanup": pointer(output / "owned-cleanup.json"),
        }
        self.checkpoint("backend_complete")
        return result


def recover(attempt_directory: Path, control: dict[str, str]) -> dict[str, Any] | None:
    ownership = Ownership(attempt_directory, control)
    if not ownership.root.exists():
        return None
    result = ownership.cleanup(recovery=True)
    result["native_ok"] = None
    result["artifacts"] = {}
    _control, _binding, context = read_control(control)
    primary_path = attempt_directory / "measurement/primary.json"
    if primary_path.exists():
        from overhead.results import read_bound

        primary = read_bound(
            primary_path, pointer(primary_path), context, "diagnostic-calibration-primary"
        )
        native = primary["native_result"]
        if isinstance(native, dict):
            if native.get("run_id") != context.run_id or type(native.get("ok")) is not bool:
                raise ValueError("recovered native outcome identifies another run")
            result["native_ok"] = native["ok"]
            result["artifacts"]["native_primary"] = pointer(primary_path)
        reference_path = attempt_directory / "measurement/reference-result.json"
        if reference_path.exists():
            read_bound(
                reference_path,
                pointer(reference_path),
                context,
                "diagnostic-calibration-reference-result",
            )
            result["artifacts"]["reference_result"] = pointer(reference_path)
    path = attempt_directory / "ownership-recovery.json"
    if path.exists():
        retained = read(path)
        if not retained["clean"] or retained["control"] != control:
            raise ValueError("preceding resource recovery was incomplete")
        return retained
    else:
        publish(path, result)
    return result
