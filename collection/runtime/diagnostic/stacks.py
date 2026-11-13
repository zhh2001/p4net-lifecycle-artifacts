"""Capture Python join/RPC waits through a process-verified local control endpoint."""

from __future__ import annotations

import contextlib
import faulthandler
import hashlib
import json
import os
import socket
import struct
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, BinaryIO


def start_ticks(pid: int) -> int:
    return int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19])


def receive(stream: socket.socket) -> dict[str, Any]:
    data = bytearray()
    while not data.endswith(b"\n"):
        chunk = stream.recv(4096)
        if not chunk or len(data) + len(chunk) > 65536:
            raise ValueError("incomplete or oversized stack response")
        data.extend(chunk)
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("stack response must be an object")
    return value


class StackEndpoint:
    def __init__(self, path: Path, ready: Path, run_id: str) -> None:
        self.path, self.ready, self.run_id = path, ready, run_id
        self.file: BinaryIO | None = None
        self.listener: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.errors: list[str] = []
        self.address = "\0p4diag-" + uuid.uuid4().hex
        self._requests: set[str] = set()

    def __enter__(self) -> StackEndpoint:
        if self.ready.exists():
            raise FileExistsError(self.ready)
        self.file = self.path.open("x+b")
        try:
            self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.listener.bind(self.address)
            self.listener.listen(4)
            value = {
                "run_id": self.run_id,
                "pid": os.getpid(),
                "start_ticks": start_ticks(os.getpid()),
                "address": self.address,
                "stack_file": str(self.path.resolve()),
                "pid_namespace": os.readlink("/proc/self/ns/pid"),
                "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            }
            self.thread = threading.Thread(target=self._serve, daemon=True, name="diagnostic-stack")
            self.thread.start()
            with tempfile.NamedTemporaryFile(
                mode="w", dir=self.ready.parent, delete=False
            ) as stream:
                temporary = Path(stream.name)
                json.dump(value, stream)
                stream.write("\n")
                stream.flush()
                try:
                    os.link(temporary, self.ready)
                finally:
                    temporary.unlink()
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def _capture(self, request_id: str) -> dict[str, Any]:
        assert self.file is not None
        if request_id in self._requests:
            raise ValueError("duplicate stack request")
        self._requests.add(request_id)
        begin = self.file.tell()
        self.file.write(f"BEGIN {self.run_id} {request_id}\n".encode())
        self.file.flush()
        faulthandler.dump_traceback(file=self.file, all_threads=True)
        self.file.write(f"END {self.run_id} {request_id}\n".encode())
        self.file.flush()
        os.fsync(self.file.fileno())
        end = self.file.tell()
        digest = hashlib.sha256(os.pread(self.file.fileno(), end - begin, begin)).hexdigest()
        return {
            "ok": True,
            "capture_complete": True,
            "run_id": self.run_id,
            "request_id": request_id,
            "begin_offset": begin,
            "end_offset": end,
            "sha256": digest,
            "captured_at_ns": time.monotonic_ns(),
        }

    def _serve(self) -> None:
        assert self.listener is not None
        while True:
            try:
                connection, _ = self.listener.accept()
            except OSError:
                return
            with connection:
                connection.settimeout(2)
                stop = False
                response: dict[str, Any]
                try:
                    _pid, uid, _gid = struct.unpack(
                        "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                    )
                    if uid != os.geteuid():
                        raise PermissionError("stack requester has a different effective user")
                    request = receive(connection)
                    if request.get("run_id") != self.run_id:
                        raise ValueError("stack request run identity differs")
                    if request.get("command") == "close":
                        response = {"ok": True, "closed": True}
                        stop = True
                    elif request.get("command") == "capture":
                        request_id = request.get("request_id")
                        if (
                            not isinstance(request_id, str)
                            or not request_id.isalnum()
                            or len(request_id) > 128
                        ):
                            raise ValueError("invalid stack request identity")
                        response = self._capture(request_id)
                    else:
                        raise ValueError("unknown stack command")
                except Exception as exc:
                    response = {
                        "ok": False,
                        "capture_complete": False,
                        "error_type": type(exc).__name__,
                        "message": str(exc),
                    }
                with contextlib.suppress(OSError):
                    connection.sendall((json.dumps(response) + "\n").encode())
                if stop:
                    return

    def __exit__(self, *args: Any) -> None:
        if self.thread is not None and self.thread.is_alive():
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                    connection.settimeout(2)
                    connection.connect(self.address)
                    connection.sendall(
                        (json.dumps({"command": "close", "run_id": self.run_id}) + "\n").encode()
                    )
                    receive(connection)
            except Exception as exc:
                self.errors.append(f"{type(exc).__name__}: {exc}")
            self.thread.join(timeout=2)
            if self.thread.is_alive():
                self.errors.append("stack service did not stop")
        if self.listener is not None:
            try:
                self.listener.close()
            except OSError as exc:
                self.errors.append(f"{type(exc).__name__}: {exc}")
            self.listener = None
        if self.file is not None and (self.thread is None or not self.thread.is_alive()):
            try:
                self.file.close()
            except OSError as exc:
                self.errors.append(f"{type(exc).__name__}: {exc}")
            self.file = None


def request_stack(
    ready: Path,
    run_id: str,
    pid: int,
    expected_start_ticks: int,
    request_id: str,
    timeout: float = 3,
) -> dict[str, Any]:
    value = json.loads(ready.read_text())
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    namespace = os.readlink("/proc/self/ns/pid")
    if (
        value.get("run_id"),
        value.get("pid"),
        value.get("start_ticks"),
        value.get("boot_id"),
        value.get("pid_namespace"),
    ) != (run_id, pid, expected_start_ticks, boot, namespace):
        raise ValueError("stack endpoint identity differs")
    if start_ticks(pid) != expected_start_ticks:
        raise ProcessLookupError("stack target process identity changed")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect(value["address"])
        peer, uid, _gid = struct.unpack(
            "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        if peer != pid or uid != os.geteuid() or start_ticks(pid) != expected_start_ticks:
            raise ProcessLookupError("stack peer identity differs")
        connection.sendall(
            (
                json.dumps({"command": "capture", "run_id": run_id, "request_id": request_id})
                + "\n"
            ).encode()
        )
        response = receive(connection)
    if response.get("ok") is True and (response.get("run_id"), response.get("request_id")) != (
        run_id,
        request_id,
    ):
        raise ValueError("stack capture response identity differs")
    return response
