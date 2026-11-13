"""Apply the established host-isolation checks to a diagnostic dispatch."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from harness.baseline_checks import host_links
from harness.isolation import NAMESPACES, namespace_ids


def assess_guards(
    before: dict[str, Any], after: dict[str, Any], enclosure: dict[str, Any], tool: str
) -> dict[str, Any]:
    if tool not in {"p4net", "p4utils", "tutorial-components"}:
        raise ValueError("unknown diagnostic tool")
    before_ns = before.get("namespaces")
    inner_ns = enclosure.get("inner_namespaces")
    before_ns = before_ns if isinstance(before_ns, dict) else {}
    inner_ns = inner_ns if isinstance(inner_ns, dict) else {}
    namespace_values_present = all(
        isinstance(before_ns.get(key), str)
        and before_ns[key]
        and isinstance(inner_ns.get(key), str)
        and inner_ns[key]
        for key in NAMESPACES
    )
    checks = {
        "host_reads_complete": after.get("errors") == [],
        "host_network_links_unchanged": before.get("links") is not None
        and after.get("links") == before["links"],
        "host_hugepages_unchanged": before.get("hugepages") is not None
        and after.get("hugepages") == before["hugepages"],
        "host_namespaces_unchanged": set(before_ns) == set(NAMESPACES)
        and after.get("namespaces") == before["namespaces"],
        "outer_log_survived": after.get("file_survived") is True,
        "outer_process_survived": after.get("process_survived") is True,
        "private_namespaces_verified": set(before_ns) == set(NAMESPACES)
        and set(inner_ns) == set(NAMESPACES)
        and enclosure.get("outer_namespaces") == before.get("namespaces")
        and namespace_values_present
        and all(inner_ns[key] != before_ns[key] for key in NAMESPACES),
        "global_sysctls_read_only": enclosure.get("global_sysctls_read_only") is True,
        "inner_observations_present": all(
            type(enclosure.get(key)) is bool
            for key in ("inner_log_sentinel_remaining", "inner_process_sentinel_running")
        ),
    }
    if tool == "p4utils":
        checks["native_inner_cleanup_observed"] = all(
            enclosure.get(key) is False
            for key in ("inner_log_sentinel_remaining", "inner_process_sentinel_running")
        )
    return {
        "qualified": all(checks.values()),
        "checks": checks,
        "inner_cleanup_observations": {
            "log_remaining": enclosure.get("inner_log_sentinel_remaining"),
            "process_running": enclosure.get("inner_process_sentinel_running"),
        },
        "inner_policy": "removed by native cleanup"
        if tool == "p4utils"
        else "record without a preservation requirement",
        "policy_source": "harness.baseline_checks.check_one",
    }


class HostGuards:
    """Keep host fixtures outside the child enclosure and retain their actual state."""

    payload = b"outer host fixture\n"

    def __init__(self, run_id: str) -> None:
        self.path = Path("/tmp") / f"research-{run_id}.log"
        self.fd: int | None = None
        self.process: subprocess.Popen[bytes] | None = None
        self.before: dict[str, Any] = {}
        self.after: dict[str, Any] = {}
        self.cleanup: dict[str, Any] = {}

    def __enter__(self) -> HostGuards:
        self.before = {
            "links": host_links(),
            "hugepages": Path("/proc/sys/vm/nr_hugepages").read_text(),
            "namespaces": namespace_ids(),
        }
        try:
            self.fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o600)
            with os.fdopen(os.dup(self.fd), "wb") as stream:
                stream.write(self.payload)
                stream.flush()
                os.fsync(stream.fileno())
            self.process = subprocess.Popen(
                ["mininet:outside-guard", "infinity"], executable="/bin/sleep"
            )
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def snapshot(self) -> dict[str, Any]:
        state: dict[str, Any] = {"errors": []}
        for key, callback in (
            ("links", host_links),
            ("hugepages", lambda: Path("/proc/sys/vm/nr_hugepages").read_text()),
            ("namespaces", namespace_ids),
        ):
            try:
                state[key] = callback()
            except Exception as exc:
                state["errors"].append(f"{key}: {type(exc).__name__}: {exc}")
        try:
            original = os.fstat(self.fd) if self.fd is not None else None
            current = self.path.lstat()
            state["file_survived"] = (
                original is not None
                and not self.path.is_symlink()
                and (original.st_dev, original.st_ino) == (current.st_dev, current.st_ino)
                and self.path.read_bytes() == self.payload
            )
        except OSError as exc:
            state["file_survived"] = False
            state["errors"].append(f"host file: {type(exc).__name__}: {exc}")
        state["process_survived"] = self.process is not None and self.process.poll() is None
        self.after = state
        return state

    def __exit__(self, *args: Any) -> None:
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
            self.cleanup["process_reaped"] = self.process.poll() is not None
        if self.fd is not None:
            original = os.fstat(self.fd)
            try:
                current = self.path.lstat()
                if (current.st_dev, current.st_ino) == (original.st_dev, original.st_ino):
                    self.path.unlink()
                    self.cleanup["owned_file_removed"] = True
                else:
                    self.cleanup["owned_file_removed"] = False
            except FileNotFoundError:
                self.cleanup["owned_file_removed"] = True
            finally:
                os.close(self.fd)
                self.fd = None
