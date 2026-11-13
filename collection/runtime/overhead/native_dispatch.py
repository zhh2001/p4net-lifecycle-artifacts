"""Run protected synthetic wiring checks through an owned namespace init."""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

from harness.isolation import environment_for, namespace_ids
from harness.observer_reference import discover_observer

from overhead.host_guards import HostGuards, assess_guards
from overhead.model import Identity
from overhead.native_binding import read_control
from overhead.proc import ProcReader
from overhead.publication import pointer, publish
from overhead.reference import ParentReference
from overhead.results import finalize
from overhead.wire import Channel


def launch_spec(path: Path, descriptor: int, deadline: float) -> dict[str, Any]:
    control, binding, context = read_control(pointer(path), full=True)
    manifest = json.loads(Path(control["manifest"]["path"]).read_text())
    env = environment_for(manifest)
    env.update(PYTHONDONTWRITEBYTECODE="1")
    env["PATH"] = (
        str(Path(binding["runtime_root"]) / "harness/bin") + os.pathsep + binding["execution_path"]
    )
    command = [
        "unshare",
        "--net",
        "--pid",
        "--mount",
        "--ipc",
        "--uts",
        "--fork",
        "--mount-proc",
        "--kill-child=KILL",
        binding["wrapper_interpreter"],
        "-m",
        "overhead.native",
        "--inside-control",
        json.dumps(pointer(path)),
        "--descriptor",
        str(descriptor),
        "--outer",
        json.dumps(namespace_ids()),
        "--deadline",
        str(deadline),
    ]
    return {
        "argv": command,
        "env": env,
        "cwd": binding["runtime_root"],
        "context": context.as_dict(),
        "execution_kind": binding["execution_kind"],
    }


def run_fixture(path: Path, *, drop_checkpoint: str | None = None) -> dict[str, Any]:
    control, binding, context = read_control(pointer(path), full=True)
    if binding["execution_kind"] != "protected-synthetic":
        raise PermissionError(
            "planned pilot tasks require the session controller and readiness record"
        )
    output = Path(control["manifest"]["path"]).parent.parent
    measurement = output / "measurement"
    if any(measurement.iterdir()):
        raise FileExistsError("an existing attempt cannot be rerun")
    if os.geteuid() != 0:
        raise PermissionError("protected namespace validation requires root")
    reader = ProcReader()
    parent, child = socket.socketpair()
    with (
        parent,
        child,
        HostGuards(context.run_id) as guards,
        (output / "enclosure.log").open("x") as log,
    ):
        deadline = time.monotonic() + 60
        spec = launch_spec(path, child.fileno(), deadline)
        start = time.monotonic_ns()
        with subprocess.Popen(
            spec["argv"],
            env=spec["env"],
            cwd=spec["cwd"],
            pass_fds=(child.fileno(),),
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        ) as process:
            child.close()
            outer_identity = reader.identity(process.pid)
            channel = Channel(parent, deadline)
            reference = None
            errors = []
            try:
                first = channel.receive()
                inner = Identity.from_dict(first["supervisor"])
                discovered = discover_observer(
                    process.pid,
                    {name: inner.namespaces[name] for name in ("pid", "net", "mnt")},
                    outer_start_ticks=outer_identity.start_ticks,
                )
                supervisor = reader.identity(discovered.host_pid)
                if not supervisor.same_process(inner) or inner.pid != 1:
                    raise ProcessLookupError("namespace init differs from the owned enclosure")

                def acknowledge(value: dict[str, Any]) -> None:
                    if value["boundary"] == drop_checkpoint:
                        raise EOFError("injected protected reference acknowledgment loss")
                    channel.send(value)

                reference = ParentReference(context, supervisor, acknowledge, reader=reader)
                reference.handle(first)
                while reference.history[-1] != "ref_complete":
                    reference.handle(channel.receive())
            except (OSError, ValueError, KeyError, EOFError) as exc:
                if reference is None:
                    raise RuntimeError("protected init did not establish its reference") from exc
                reference.failed = True
                errors.append(
                    {
                        "metric": "reference_transport",
                        "type": type(exc).__name__,
                        "message": str(exc),
                    }
                )
                parent.close()
            finally:
                try:
                    process.wait(timeout=max(0.1, deadline - time.monotonic()))
                except BaseException:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGTERM)
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.wait(timeout=5)
                    raise
            end = time.monotonic_ns()
            assert reference is not None
            if process.returncode not in (0, 1):
                errors.append(
                    {
                        "metric": "enclosure_exit",
                        "type": "RuntimeError",
                        "message": str(process.returncode),
                    }
                )
            result = finalize(
                reference,
                measurement,
                outer_span={"start_ns": start, "end_ns": end},
                external_issues=errors,
            )
            enclosure_path = output / "native-isolation.json"
            enclosure = json.loads(enclosure_path.read_text()) if enclosure_path.exists() else {}
            after = guards.snapshot()
            # Fixtures have no P4-Utils cleanup body; retain the common host policy explicitly.
            assessment = (
                assess_guards(guards.before, after, enclosure, "p4net")
                if enclosure
                else {
                    "qualified": False,
                    "dispatch_blocked_before_mounts": drop_checkpoint == "ref_begin",
                }
            )
            if drop_checkpoint == "ref_begin" and not enclosure:
                assessment["qualified"] = all(
                    (
                        after["errors"] == [],
                        after["links"] == guards.before["links"],
                        after["hugepages"] == guards.before["hugepages"],
                        after["namespaces"] == guards.before["namespaces"],
                        after["file_survived"],
                        after["process_survived"],
                    )
                )
            owned = [outer_identity, supervisor]
            if "worker_identity" in result["reference"]["endpoints"]:
                owned.append(
                    Identity.from_dict(result["reference"]["endpoints"]["worker_identity"])
                )
    gone = []
    for identity in owned:
        try:
            reader.verify(identity)
            gone.append(False)
        except (OSError, ProcessLookupError):
            gone.append(True)
    receipt = {
        "performance_samples": False,
        "scope": "protected protocol fixtures; no native tool workload",
        "context": context.as_dict(),
        "reference_result": pointer(measurement / "reference-result.json"),
        "host_before": guards.before,
        "host_after": after,
        "host_cleanup": guards.cleanup,
        "guard_assessment": assessment,
        "owned_processes": [identity.as_dict() for identity in owned],
        "owned_processes_gone": gone,
        "enclosure_returncode": process.returncode,
    }
    publish(output / "dispatch-receipt.json", receipt)
    return {"result": result, "receipt": receipt}
