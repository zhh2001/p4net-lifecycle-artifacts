"""Connect the common entry to the unchanged protected native supervisor."""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from pathlib import Path
from typing import Any

from overhead.native_binding import read_control, selected_entry

ENV = "P4NET_OVERHEAD_CONTROL"


def worker(manifest_path: Path) -> None:
    from harness.diagnostic_binding import require_worker_enclosure

    from overhead.entry import Entry, run_module

    require_worker_enclosure()
    control, binding, context = read_control(json.loads(os.environ[ENV]))
    if str(manifest_path) != control["manifest"]["path"]:
        raise ValueError("worker manifest differs from the bound control")
    if os.path.abspath(sys.executable) != binding["tools"][context.tool]["interpreter"]:
        raise ValueError("worker interpreter differs from the bound tool")
    target = selected_entry(binding, context)
    run_module(
        context,
        Entry(target["module"], Path(target["source"]), target["sha256"]),
        ["--manifest", str(manifest_path)],
        manifest_path.parent.parent / "measurement/worker-cpu-end.json",
    )


def inside(pin: dict[str, Any], descriptor: int, outer: dict[str, str], deadline: float) -> int:
    from harness import isolation, native_measurement

    from overhead.coordinator import Supervisor
    from overhead.native_observation import NativeObservation
    from overhead.proc import ProcReader
    from overhead.wire import Channel, ChildReference

    isolation.require_private(outer)
    control, binding, context = read_control(pin)
    fixture = binding["execution_kind"] == "protected-synthetic"
    permit = os.environ.get("P4NET_OVERHEAD_PERMIT")
    if permit is not None:
        from overhead.authority import check

        check(json.loads(permit), pin)
    elif not fixture:
        raise PermissionError("native pilot requires the session controller and readiness record")
    manifest_path = Path(control["manifest"]["path"])
    os.environ[ENV] = json.dumps(pin)
    with socket.socket(fileno=descriptor) as sock:
        sock.set_inheritable(False)
        channel = Channel(sock, deadline)
        reference = ChildReference(
            context, ProcReader().identity(os.getpid()), channel.send, channel.receive
        )
        coordinator = Supervisor(
            context,
            reference,
            manifest_path.parent.parent / "measurement",
            hold_ns=binding["hold_ns"],
        )

        def prepare() -> None:
            if context.diagnostic_profile != "native":
                read_control(pin, full=True)

        def execute(observation: Supervisor) -> dict[str, Any]:
            module: Any = native_measurement
            original = module.Observation
            try:
                module.Observation = lambda: NativeObservation(observation, fixture=fixture)
                isolation.inside(
                    manifest_path,
                    Path(binding["tools"][context.tool]["interpreter"]),
                    "overhead.native",
                    outer,
                    guards=True,
                    boundary_validation=True,
                )
            finally:
                module.Observation = original
            result: dict[str, Any] = json.loads((manifest_path.parent / "result.json").read_text())
            return result

        result = coordinator.run(execute, prepare=prepare)
        return 0 if result["ok"] else 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--inside-control", type=json.loads)
    parser.add_argument("--descriptor", type=int)
    parser.add_argument("--outer", type=json.loads)
    parser.add_argument("--deadline", type=float)
    args = parser.parse_args()
    if args.manifest is not None:
        if any(
            value is not None
            for value in (args.inside_control, args.descriptor, args.outer, args.deadline)
        ):
            parser.error("worker and enclosure arguments cannot be combined")
        worker(args.manifest)
    elif all(
        value is not None
        for value in (args.inside_control, args.descriptor, args.outer, args.deadline)
    ):
        raise SystemExit(inside(args.inside_control, args.descriptor, args.outer, args.deadline))
    else:
        parser.error("a bound worker or enclosure invocation is required")


if __name__ == "__main__":
    main()
