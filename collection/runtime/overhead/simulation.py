"""Exercise the measurement interfaces using toy workers and a local socket pair."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from overhead.coordinator import Supervisor
from overhead.model import Context, Identity
from overhead.proc import ProcReader
from overhead.publication import publish
from overhead.reference import ParentReference
from overhead.results import finalize
from overhead.wire import Channel, ChildReference


def inside(config_path: Path, descriptor: int) -> None:
    config = json.loads(config_path.read_text())
    context = Context.from_dict(config["context"])
    output = config_path.parent
    reader = ProcReader()
    identity = reader.identity(os.getpid())
    with socket.socket(fileno=descriptor) as sock:
        sock.set_inheritable(False)
        channel = Channel(sock, time.monotonic() + 20)
        child = ChildReference(context, identity, channel.send, channel.receive)
        supervisor = Supervisor(context, child, output, hold_ns=config["hold_ns"])

        def execute(observation: Supervisor) -> dict[str, Any]:
            profile = context.diagnostic_profile
            target = "native" if profile == "native" else "instrumented"
            source = Path(__file__).resolve().parents[1] / "overhead_fixtures" / (target + ".py")
            manifest = output / "manifest.json"
            publish(
                manifest,
                {
                    "run_id": context.run_id,
                    "diagnostic_profile": profile,
                    "behavior": config["behavior"],
                    "native_source_sha256": hashlib.sha256(
                        source.with_name("native.py").read_bytes()
                    ).hexdigest(),
                },
            )
            entry_config = output / "worker-entry.json"
            publish(
                entry_config,
                {
                    "schema_version": 1,
                    "record_type": "synthetic-diagnostic-entry",
                    "context": context.as_dict(),
                    "entry": {
                        "module": "overhead_fixtures." + target,
                        "source": str(source),
                        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                    },
                    "arguments": ["--manifest", str(manifest)],
                    "output": str(output / "worker-cpu-end.json"),
                },
            )
            observation.mark("worker_launch")
            protocol = []
            stopped = False
            ready = False
            with (
                (output / "worker.log").open("w") as log,
                subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "overhead.entry",
                        "--synthetic-config",
                        str(entry_config),
                    ],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=log,
                    text=True,
                ) as worker,
            ):
                assert worker.stdout is not None and worker.stdin is not None
                try:
                    line = worker.stdout.readline()
                    if line:
                        event = json.loads(line)
                        protocol.append(event)
                        if event["event"] != "ready":
                            raise ValueError("synthetic worker did not report ready")
                        ready = True
                        observation.ready(Identity.from_dict(event["worker"]))
                        observation.mark("stop_request")
                        worker.stdin.write("stop\n")
                        worker.stdin.flush()
                        line = worker.stdout.readline()
                        if line:
                            event = json.loads(line)
                            protocol.append(event)
                            stopped = event["event"] == "stopped"
                    returncode = worker.wait(timeout=5)
                finally:
                    if worker.poll() is None:
                        worker.kill()
                        worker.wait(timeout=5)
                observation.mark("worker_exit")
            observation.mark("ordinary_audit_end")
            publish(output / "protocol.json", {"events": protocol, "performance_samples": False})
            return {
                "ok": ready and stopped and returncode == 0,
                "ready": ready,
                "worker_returncode": returncode,
                "mode": "synthetic-validation",
                "performance_samples": False,
                "cleanup": {"ordinary_after_clean": True, "rescue_attempted": False},
            }

        supervisor.run(execute)


def run(
    output: Path,
    context: Context,
    *,
    behavior: str = "return",
    hold_ns: int = 10_000_000,
    drop_checkpoint: str | None = None,
) -> dict[str, Any]:
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    config = output / "simulation.json"
    publish(config, {"context": context.as_dict(), "behavior": behavior, "hold_ns": hold_ns})
    reader = ProcReader()
    parent, child = socket.socketpair()
    with parent, child, (output / "supervisor.log").open("w") as log:
        command = [
            sys.executable,
            "-m",
            "overhead.simulation",
            "--inside",
            str(config),
            "--descriptor",
            str(child.fileno()),
        ]
        outer_start = time.monotonic_ns()
        with subprocess.Popen(
            command,
            pass_fds=(child.fileno(),),
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        ) as process:
            child.close()
            try:
                identity = reader.identity(process.pid)
                channel = Channel(parent, time.monotonic() + 25)

                def acknowledge(value: dict[str, Any]) -> None:
                    if value["boundary"] == drop_checkpoint:
                        raise EOFError("injected reference acknowledgment loss")
                    channel.send(value)

                reference = ParentReference(context, identity, acknowledge, reader=reader)
                errors = []
                try:
                    while not reference.history or reference.history[-1] != "ref_complete":
                        reference.handle(channel.receive())
                except (OSError, ValueError, KeyError, EOFError) as exc:
                    reference.failed = True
                    errors.append(
                        {
                            "metric": "reference_transport",
                            "type": type(exc).__name__,
                            "message": str(exc),
                        }
                    )
                    parent.close()
                returncode = process.wait(timeout=5)
                if returncode != 0:
                    errors.append(
                        {
                            "metric": "supervisor_exit",
                            "type": "RuntimeError",
                            "message": str(returncode),
                        }
                    )
                outer_end = time.monotonic_ns()
                return finalize(
                    reference,
                    output,
                    outer_span={"start_ns": outer_start, "end_ns": outer_end},
                    external_issues=errors,
                )
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inside", type=Path, required=True)
    parser.add_argument("--descriptor", type=int, required=True)
    args = parser.parse_args()
    inside(args.inside, args.descriptor)


if __name__ == "__main__":
    main()
