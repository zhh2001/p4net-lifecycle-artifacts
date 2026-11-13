"""Bound reference frames and bind each acknowledgment to its exact request."""

from __future__ import annotations

import copy
import json
import math
import socket
import time
from collections.abc import Callable
from typing import Any

from overhead.model import Context, Identity, integer

LIMIT = 4096
TRANSITIONS = {
    None: {"ref_begin"},
    "ref_begin": {"ref_ready", "ref_primary_published"},
    "ref_ready": {"ref_primary_published"},
    "ref_primary_published": {"ref_complete"},
    "ref_complete": set(),
}


def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate reference key")
        result[key] = value
    return result


def invalid_number(value: str) -> Any:
    raise ValueError(f"reference frame requires integer numeric values: {value}")


def encode(value: dict[str, Any]) -> bytes:
    data = (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    )
    if len(data) > LIMIT:
        raise ValueError("reference frame exceeds limit")
    return data


def decode(data: bytes) -> dict[str, Any]:
    if not data.endswith(b"\n") or data.count(b"\n") != 1 or len(data) > LIMIT:
        raise ValueError("invalid reference frame boundary")
    value = json.loads(
        data.decode("utf-8"),
        object_pairs_hook=pairs,
        parse_constant=invalid_number,
        parse_float=invalid_number,
    )
    if not isinstance(value, dict):
        raise ValueError("reference frame must be an object")
    return value


class Channel:
    def __init__(
        self, sock: socket.socket, deadline: float, *, clock: Callable[[], float] = time.monotonic
    ):
        if (
            isinstance(deadline, bool)
            or not isinstance(deadline, (int, float))
            or not math.isfinite(deadline)
        ):
            raise ValueError("finite absolute reference deadline required")
        self.sock, self.deadline, self.clock = sock, float(deadline), clock
        self.buffer = bytearray()

    def remaining(self) -> float:
        now = self.clock()
        if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now):
            raise ValueError("invalid reference clock")
        left = self.deadline - now
        if not math.isfinite(left) or left <= 0:
            raise TimeoutError("reference deadline expired")
        return left

    def send(self, value: dict[str, Any]) -> None:
        frame = encode(value)
        self.sock.settimeout(self.remaining())
        self.sock.sendall(frame)

    def receive(self) -> dict[str, Any]:
        while True:
            self.remaining()
            position = self.buffer.find(b"\n")
            if position >= 0:
                data = bytes(self.buffer[: position + 1])
                del self.buffer[: position + 1]
                return decode(data)
            if len(self.buffer) >= LIMIT:
                raise ValueError("reference frame exceeds limit")
            self.sock.settimeout(self.remaining())
            chunk = self.sock.recv(LIMIT + 1 - len(self.buffer))
            if not chunk:
                raise EOFError("reference closed before acknowledgment")
            self.buffer.extend(chunk)


def message(
    context: Context,
    supervisor: Identity,
    boundary: str,
    sequence: int,
    payload: dict[str, Any] | None = None,
    *,
    ack: bool = False,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "record_type": "diagnostic-reference-ack" if ack else "diagnostic-reference-checkpoint",
        "context": context.as_dict(),
        "supervisor": supervisor.as_dict(),
        "boundary": boundary,
        "sequence": integer(sequence, "sequence", 1),
        "payload": {} if payload is None else payload,
    }


def check(value: dict[str, Any], context: Context, supervisor: Identity) -> None:
    if set(value) != {
        "schema_version",
        "record_type",
        "context",
        "supervisor",
        "boundary",
        "sequence",
        "payload",
    }:
        raise ValueError("reference fields differ")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError("reference version differs")
    if (
        value["record_type"] != "diagnostic-reference-checkpoint"
        or value["context"] != context.as_dict()
    ):
        raise ValueError("reference identity differs")
    type(context).from_dict(value["context"])
    supplied = Identity.from_dict(value["supervisor"])
    if not supplied.same_process(supervisor) or supplied.pid != supplied.namespace_pid:
        raise ValueError("reference supervisor process differs")
    integer(value["sequence"], "sequence", 1)
    if not isinstance(value["payload"], dict) or value["boundary"] not in {
        "ref_begin",
        "ref_ready",
        "ref_primary_published",
        "ref_complete",
    }:
        raise ValueError("reference boundary or payload differs")
    if value["boundary"] in {"ref_primary_published", "ref_complete"}:
        name = "primary" if value["boundary"] == "ref_primary_published" else "child"
        payload = value["payload"]
        if (
            set(payload) != {name}
            or not isinstance(payload[name], dict)
            or set(payload[name]) != {"path", "sha256"}
        ):
            raise ValueError("publication pointer fields differ")
        path, sha = payload[name]["path"], payload[name]["sha256"]
        if (
            not isinstance(path, str)
            or not path
            or len(path) > 2048
            or any(ord(c) < 32 for c in path)
        ):
            raise ValueError("invalid publication path")
        if (
            not isinstance(sha, str)
            or len(sha) != 64
            or any(c not in "0123456789abcdef" for c in sha)
        ):
            raise ValueError("invalid publication digest")


class ChildReference:
    def __init__(
        self,
        context: Context,
        supervisor: Identity,
        send: Callable[[dict[str, Any]], None],
        receive: Callable[[], dict[str, Any]],
    ):
        self.context, self.supervisor, self.send, self.receive = context, supervisor, send, receive
        self.history: list[str] = []
        self.failed = False

    def checkpoint(self, boundary: str, payload: dict[str, Any] | None = None) -> None:
        if self.failed:
            raise RuntimeError("reference already failed")
        try:
            previous = self.history[-1] if self.history else None
            if boundary not in TRANSITIONS[previous]:
                raise ValueError("reference checkpoint order differs")
            request = message(
                self.context, self.supervisor, boundary, len(self.history) + 1, payload
            )
            expected = copy.deepcopy({**request, "record_type": "diagnostic-reference-ack"})
            self.send(copy.deepcopy(request))
            ack = self.receive()
            if encode(ack) != encode(expected):
                raise ValueError("reference acknowledgment differs")
            self.history.append(boundary)
        except BaseException:
            self.failed = True
            raise
