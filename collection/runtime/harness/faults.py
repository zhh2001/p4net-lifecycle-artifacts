"""Identity-checked fault fixtures confined to an existing episode enclosure."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

from harness.supervisor import process_identity


def require_enclosure() -> None:
    expected = json.loads(os.environ.get("P4NET_STUDY_INNER_NS", "{}"))
    if os.getpid() != 1 or not expected:
        raise RuntimeError("fault fixtures require the verified inner enclosure init")
    if any(os.readlink(f"/proc/self/ns/{name}") != value for name, value in expected.items()):
        raise RuntimeError("fault fixture namespace identity does not match the enclosure")
    if not os.statvfs("/proc/sys/vm").f_flag & os.ST_RDONLY:
        raise RuntimeError("global sysctl protection is missing")


def invalid_source(path: Path) -> Path:
    with path.open("x") as stream:
        stream.write("deliberately invalid shared P4 source\n")
    return path


def signal_verified(identity: dict[str, int], sig: signal.Signals) -> dict[str, Any]:
    require_enclosure()
    if identity.get("pid", 0) <= 1 or process_identity(identity["pid"]) != identity:
        raise ProcessLookupError("fault target exited or its PID was reused")
    os.kill(identity["pid"], sig)
    return {"action": "signal", "signal": sig.name, **identity}


def confirm_exit(identity: dict[str, int], timeout: float = 3) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while process_identity(identity["pid"]) == identity:
        if time.monotonic() >= deadline:
            raise TimeoutError("terminated BMv2 identity is still live")
        time.sleep(0.005)
    return {"exit_confirmed": True, **identity}


def owned_veth_present(snapshot: dict[str, Any], manifest: dict[str, Any]) -> bool:
    return any(
        link.get("link_type") == "ether"
        and str(link.get("ifname", "")).startswith(manifest["prefix"])
        for link in snapshot.get("interfaces", [])
    )


def identify_first_switch(snapshot: dict[str, Any], manifest: dict[str, Any]) -> dict[str, int]:
    port = manifest["service_ports"][0]
    first = manifest["switch_names"][0]
    for proc in snapshot.get("processes", []):
        args = proc.get("cmdline", [])
        if (
            not args
            or Path(args[0]).name != "simple_switch_grpc"
            or not any(first + "-eth" in arg for arg in args)
        ):
            continue
        identity = {"pid": proc["pid"], "start_ticks": proc["start_ticks"]}
        if any(
            listener.get("local_port") == port and identity in listener.get("owners", [])
            for listener in snapshot.get("listeners", [])
        ):
            if process_identity(identity["pid"]) != identity:
                raise ProcessLookupError("BMv2 identity changed during verification")
            return identity
    raise RuntimeError("first-switch process and listener ownership are not established")


class OwnedListener:
    def __init__(self, port: int) -> None:
        self.port = port
        self.socket: socket.socket | None = None

    def start(self) -> None:
        require_enclosure()
        if self.socket is not None:
            raise RuntimeError("listener already started")
        listener = socket.socket()
        try:
            listener.bind(("127.0.0.1", self.port))
            listener.listen()
        except BaseException:
            listener.close()
            raise
        self.socket = listener

    def verify(self) -> dict[str, Any]:
        if self.socket is None or self.socket.getsockname() != ("127.0.0.1", self.port):
            raise RuntimeError("injected listener is no longer owned")
        return {
            "pid": os.getpid(),
            "fd": self.socket.fileno(),
            "port": self.port,
            "socket_inode": os.fstat(self.socket.fileno()).st_ino,
            "alive": True,
        }

    def release(self) -> None:
        if self.socket is not None:
            self.socket.close()
            self.socket = None


class EndpointBlocker:
    def __init__(self, manifest: dict[str, Any], snapshot: dict[str, Any]) -> None:
        self.identity = identify_first_switch(snapshot, manifest)
        self.port = manifest["service_ports"][0]
        self.tag = "p4study-" + hashlib.sha256(manifest["run_id"].encode()).hexdigest()[:16]
        self.rule = [
            "OUTPUT",
            "-o",
            "lo",
            "-p",
            "tcp",
            "-d",
            "127.0.0.1",
            "--dport",
            str(self.port),
            "-m",
            "comment",
            "--comment",
            self.tag,
            "-j",
            "DROP",
        ]
        self.installed = False

    def _command(self, operation: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["iptables", "-w", "3", operation, *self.rule],
            capture_output=True,
            text=True,
            timeout=6,
        )

    def install(self) -> dict[str, Any]:
        require_enclosure()
        if self.installed or self._command("-C").returncode == 0:
            raise RuntimeError("endpoint rule already exists")
        self._command("-A").check_returncode()
        self.installed = True
        self._command("-C").check_returncode()
        return {"action": "endpoint-block", "rule": self.rule, "identity": self.identity}

    def release(self) -> None:
        if self.installed:
            require_enclosure()
            self._command("-D").check_returncode()
            self.installed = False
