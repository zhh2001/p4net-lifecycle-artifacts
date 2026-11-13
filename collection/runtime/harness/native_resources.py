"""Identify native worker and BMv2 targets without collecting resource metrics."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from harness.bmv2_launcher import _option, _value
from harness.resources import ProcessTarget


def _identity(text: str) -> dict[str, Any]:
    head, tail = text.rsplit(")", 1)
    fields = tail.split()
    pid = int(head.split("(", 1)[0])
    if len(fields) < 20 or pid <= 0 or int(fields[19]) < 0 or len(fields[0]) != 1:
        raise ValueError("invalid process identity fields")
    if fields[0] in {"Z", "X", "x"}:
        raise ProcessLookupError("target has exited")
    return {
        "pid": pid,
        "start_ticks": int(fields[19]),
        "ppid": int(fields[1]),
        "pgrp": int(fields[2]),
    }


def _view(pid: int, proc_root: Path) -> dict[str, Any]:
    directory = proc_root / str(pid)
    before_text = (directory / "stat").read_text()
    before = _identity(before_text)
    args = (directory / "cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
    after = _identity((directory / "stat").read_text())
    if before["pid"] != pid or before != after:
        raise ProcessLookupError("target PID identity changed during identification")
    return {
        **before,
        "cmdline": args,
    }


def _descendant(view: Mapping[str, Any], worker: Mapping[str, Any], proc_root: Path) -> bool:
    if view["pgrp"] == worker["pid"]:
        return True
    parent = view["ppid"]
    seen = {view["pid"]}
    while parent > 1 and parent not in seen:
        if parent == worker["pid"]:
            return True
        seen.add(parent)
        parent = _view(parent, proc_root)["ppid"]
    return False


def select_targets(
    manifest: Mapping[str, Any],
    worker_identity: Mapping[str, Any],
    event: Mapping[str, Any],
    *,
    proc_root: Path = Path("/proc"),
) -> tuple[ProcessTarget, ...]:
    """Match live identities to the recorded command for every declared switch."""
    groups = manifest["groups"]
    if type(groups) is not int or groups <= 0:
        raise ValueError("groups must be a positive integer")
    worker = ProcessTarget(worker_identity["pid"], worker_identity["start_ticks"], "worker")
    current = _view(worker.pid, proc_root)
    if current["start_ticks"] != worker.start_ticks or current["pgrp"] != worker.pid:
        raise ProcessLookupError("worker identity or process group differs")
    launches = Path(manifest["output_dir"]) / "bmv2-launches"
    selected: dict[int, ProcessTarget] = {}
    for path in sorted(launches.glob("launch-*.json")):
        launch = json.loads(path.read_text())
        if launch.get("query") is True:
            continue
        if launch.get("status") != "prepared" or launch.get("query") is not False:
            raise ValueError("BMv2 launch did not reach the prepared state")
        pid = launch["pid"]
        if type(pid) is not int or pid <= 1 or path.name != f"launch-{pid}.json":
            raise ValueError("invalid BMv2 launch identity")
        args = launch["effective_argv"]
        if (
            not isinstance(args, list)
            or not args
            or any(not isinstance(arg, str) for arg in args)
            or Path(args[0]).name != "simple_switch_grpc"
        ):
            raise ValueError("launch is not a BMv2 command")
        view = _view(pid, proc_root)
        if view["cmdline"] != args or not _descendant(view, current, proc_root):
            raise ValueError("BMv2 command or worker ownership differs")
        values = {}
        for flag in ("--device-id", "--grpc-server-addr", "--thrift-port"):
            if args.count(flag) != 1:
                raise ValueError(f"BMv2 command must contain one {flag}")
            values[flag] = args[args.index(flag) + 1]
        device = int(values["--device-id"])
        if not 0 <= device < groups or device in selected:
            raise ValueError("duplicate or unexpected BMv2 device ID")
        ports = manifest["service_ports"]
        if (
            values["--grpc-server-addr"] != f"127.0.0.1:{ports[2 * device]}"
            or int(values["--thrift-port"]) != ports[2 * device + 1]
        ):
            raise ValueError("BMv2 service ports differ from the task")
        core = args[1 : args.index("--")] if "--" in args else args[1:]
        interfaces = [
            _value(core, index, option, attached)[0]
            for index, arg in enumerate(core)
            for option, attached in (_option(arg),)
            if option == "--interface"
        ]
        switch = manifest["switch_names"][device]
        if sorted(interfaces) != [f"1@{switch}-eth1", f"2@{switch}-eth2"]:
            raise ValueError("BMv2 switch interface mapping differs")
        selected[device] = ProcessTarget(pid, view["start_ticks"], "bmv2")
    if set(selected) != set(range(groups)):
        raise ValueError("BMv2 targets do not cover every declared switch")
    if len({worker.pid, *(target.pid for target in selected.values())}) != groups + 1:
        raise ValueError("target PID is duplicated")
    if _view(worker.pid, proc_root)["start_ticks"] != worker.start_ticks:
        raise ProcessLookupError("worker identity changed during target identification")
    return (worker, *(selected[index] for index in range(groups)))
