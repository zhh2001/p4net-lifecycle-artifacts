"""Register external resources before execution and signal verified kernel process handles."""

from __future__ import annotations

import os
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from overhead.kernel_handles import open_handle, send_handle
from overhead.ledger import pinned, read
from overhead.model import Identity
from overhead.proc import ProcReader
from overhead.publication import pointer, publish


def stable(left: Identity, right: Identity, *, transition: bool) -> bool:
    return (left.pid, left.namespace_pid, left.start_ticks, left.boot_id) == (
        right.pid,
        right.namespace_pid,
        right.start_ticks,
        right.boot_id,
    ) and (transition or dict(left.namespaces) == dict(right.namespaces))


def live(identity: Identity, *, transition: bool = False) -> bool:
    try:
        return stable(identity, ProcReader().identity(identity.pid), transition=transition)
    except (FileNotFoundError, ProcessLookupError):
        return False


def terminate(identity: Identity, *, transition: bool = False, grace: float = 2.0) -> bool:
    if not live(identity, transition=transition):
        return False
    try:
        descriptor = open_handle(identity.pid)
    except ProcessLookupError:
        return False
    try:
        if not live(identity, transition=transition):
            return False
        try:
            send_handle(descriptor, signal.SIGTERM)
            deadline = time.monotonic() + grace
            while live(identity, transition=transition) and time.monotonic() < deadline:
                time.sleep(0.01)
            if live(identity, transition=transition):
                send_handle(descriptor, signal.SIGKILL)
                deadline = time.monotonic() + 2
                while live(identity, transition=transition) and time.monotonic() < deadline:
                    time.sleep(0.01)
        except ProcessLookupError:
            pass
        if live(identity, transition=transition):
            raise TimeoutError("registered process survived bounded termination")
        return True
    finally:
        os.close(descriptor)


class Ownership:
    def __init__(self, output: Path, control: dict[str, str]):
        self.output, self.control = output, dict(control)
        self.root = output / "ownership"

    def initialize(self) -> None:
        self.root.mkdir(exist_ok=False)
        publish(
            self.root / "scope.json",
            {
                "schema_version": 1,
                "record_type": "diagnostic-resource-scope",
                "control": self.control,
                "owner": ProcReader().identity(os.getpid()).as_dict(),
            },
        )

    def scope(self) -> dict[str, Any]:
        if self.root.is_symlink() or not self.root.is_dir():
            raise ValueError("ownership directory must be real")
        value = read(self.root / "scope.json")
        if (
            set(value) != {"schema_version", "record_type", "control", "owner"}
            or value["schema_version"] != 1
            or value["record_type"] != "diagnostic-resource-scope"
            or value["control"] != self.control
        ):
            raise ValueError("resource ownership scope differs")
        pinned(self.control)
        Identity.from_dict(value["owner"])
        return value

    def file(self, target: Path) -> None:
        scope = self.scope()
        data = self.root / "host-guard-data.json"
        publish(data, {"payload": "outer host fixture", "control": self.control})
        inode = data.stat()
        record = {
            "scope": pointer(self.root / "scope.json"),
            "target": str(target),
            "backing": pointer(data),
            "device": inode.st_dev,
            "inode": inode.st_ino,
            "owner": scope["owner"],
        }
        publish(self.root / "host-file.json", record)
        # Registration precedes the atomic host link, so an interrupted link remains attributable.
        os.link(data, target)

    def unlink_file(self) -> bool:
        path = self.root / "host-file.json"
        if not path.exists():
            return True
        record = read(path)
        if record["scope"] != pointer(self.root / "scope.json"):
            raise ValueError("host file scope differs")
        backing = Path(record["backing"]["path"])
        pinned(record["backing"])
        control = pinned(self.control)
        expected = Path("/tmp") / f"research-{control['context']['run_id']}.log"
        if record["target"] != str(expected):
            raise ValueError("host file target differs from the run identity")
        inode = backing.stat()
        if (inode.st_dev, inode.st_ino) != (record["device"], record["inode"]):
            raise ValueError("host file backing identity differs")
        try:
            current = expected.lstat()
        except FileNotFoundError:
            return True
        if not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != (
            inode.st_dev,
            inode.st_ino,
        ):
            raise ValueError("host file was replaced; retaining the replacement")
        expected.unlink()
        return True

    def register_init(self, identity: Identity) -> None:
        publish(
            self.root / "init.json",
            {
                "scope": pointer(self.root / "scope.json"),
                "role": "init",
                "identity": identity.as_dict(),
            },
        )

    def launch(
        self,
        role: str,
        argv: list[str],
        *,
        env: dict[str, str],
        cwd: str,
        log: Any,
        pass_fds: tuple[int, ...] = (),
        checkpoint: Callable[[str], None] = lambda _: None,
    ) -> subprocess.Popen[bytes]:
        if role not in {"guard", "outer"}:
            raise ValueError("unknown owned launch role")
        intent = self.root / (role + "-intent.json")
        publish(
            intent,
            {
                "scope": pointer(self.root / "scope.json"),
                "role": role,
                "argv": argv,
                "executable": "/bin/sleep" if role == "guard" else argv[0],
                "inherited_fds": list(pass_fds),
            },
        )
        receive, send = os.pipe2(os.O_CLOEXEC)
        process = None
        try:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "overhead.owned_child",
                    "--intent",
                    str(intent),
                    "--barrier",
                    str(receive),
                ],
                env=env,
                cwd=cwd,
                pass_fds=(receive, *pass_fds),
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            os.close(receive)
            receive = -1
            deadline = time.monotonic() + 10
            path = self.root / (role + ".json")
            while not path.exists():
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("owned child did not publish its registration")
                time.sleep(0.005)
            record = self.process(role)
            if record["identity"]["pid"] != process.pid:
                raise ProcessLookupError("owned child registration identifies another PID")
            checkpoint(role + "_registered")
            os.write(send, b"G")
            checkpoint(role + "_released")
            return process
        except BaseException:
            if process is not None:
                process.kill()
                process.wait(timeout=5)
            raise
        finally:
            if receive >= 0:
                os.close(receive)
            os.close(send)

    def process(self, role: str) -> dict[str, Any]:
        record = read(self.root / (role + ".json"))
        if record["scope"] != pointer(self.root / "scope.json") or record["role"] != role:
            raise ValueError("registered process scope differs")
        Identity.from_dict(record["identity"])
        if role != "init":
            intent = pinned(record["intent"])
            if (
                intent["scope"] != record["scope"]
                or intent["role"] != role
                or record["parent"] != self.scope()["owner"]
            ):
                raise ValueError("registered process parent or intent differs")
        return record

    def cleanup(self, *, recovery: bool = False) -> dict[str, Any]:
        scope = self.scope()
        owner = Identity.from_dict(scope["owner"])
        if recovery and live(owner):
            raise RuntimeError("resource owner is still live")
        records = []
        for role in ("init", "outer", "guard"):
            path = self.root / (role + ".json")
            if path.exists() or path.is_symlink():
                record = self.process(role)
                identity = Identity.from_dict(record["identity"])
                signaled = terminate(identity, transition=role == "outer")
                records.append(
                    {
                        "role": role,
                        "identity": identity.as_dict(),
                        "signaled": signaled,
                        "gone": not live(identity, transition=role == "outer"),
                    }
                )
        removed = self.unlink_file()
        return {
            "control": self.control,
            "recovery": recovery,
            "processes": records,
            "owned_file_removed": removed,
            "clean": removed and all(record["gone"] for record in records),
        }
