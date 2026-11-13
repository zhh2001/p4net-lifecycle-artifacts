"""Protocol helpers shared by workers without importing a network library."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, TextIO

PROTOCOL_OUT: TextIO = sys.stdout


def identity(pid: int) -> dict[str, int]:
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    if fields[0] in {"Z", "X", "x"}:
        raise ProcessLookupError(f"process {pid} has exited")
    return {"pid": pid, "start_ticks": int(fields[19])}


def emit(manifest: dict[str, Any], event: str, **fields: Any) -> None:
    print(
        json.dumps(
            {"schema_version": 1, "run_id": manifest["run_id"], "event": event, **fields},
            allow_nan=False,
        ),
        file=PROTOCOL_OUT,
        flush=True,
    )


def read_stop() -> None:
    line = sys.stdin.readline()
    if line and json.loads(line) != {"command": "stop"}:
        raise ValueError("unsupported supervisor command")


def bounded_read(stub: Any) -> dict[str, int]:
    """Probe the existing connection with one common wildcard table Read."""
    if stub is None:
        raise RuntimeError("the existing control connection is unavailable")
    os.environ.setdefault("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", "python")
    from p4.v1 import p4runtime_pb2

    request = p4runtime_pb2.ReadRequest(device_id=0)
    request.entities.add().table_entry.SetInParent()
    count = sum(len(response.entities) for response in stub.Read(request, timeout=2.0))
    return {"entries": count}


def serve_commands(manifest: dict[str, Any], probe: Callable[[], dict[str, int]]) -> None:
    for line in sys.stdin:
        command = json.loads(line)
        if command == {"command": "stop"}:
            return
        if (
            not isinstance(command, dict)
            or command.get("command") != "probe"
            or set(command) != {"command", "request_id"}
            or not isinstance(command["request_id"], str)
            or not 1 <= len(command["request_id"]) <= 128
        ):
            raise ValueError("unsupported supervisor command")
        try:
            result = probe()
            emit(manifest, "probe", request_id=command["request_id"], ok=True, **result)
        except Exception as exc:
            fields: dict[str, Any] = {"error_type": type(exc).__name__, "message": str(exc)}
            status_code = getattr(exc, "code", None)
            if callable(status_code):
                fields["grpc_status"] = str(status_code())
            emit(manifest, "probe", request_id=command["request_id"], ok=False, **fields)


def grouped_identities(pids: list[int]) -> list[dict[str, int]]:
    """Register only live processes belonging to the worker's process group."""
    records = []
    for pid in pids:
        try:
            if os.getpgid(pid) == os.getpgrp():
                records.append(identity(pid))
        except ProcessLookupError:
            continue
    return records
