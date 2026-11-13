"""Read-only, externally observable resource inventory for one research run."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

PROC = Path("/proc")
NETNS = Path("/var/run/netns")
COMMAND_TIMEOUT = 10.0
RESOURCE_KEYS = ("processes", "namespaces", "interfaces", "listeners")


def parse_process_stat(text: str) -> dict[str, Any]:
    """Parse identity fields without splitting a parenthesized process name."""
    head, tail = text.rsplit(")", 1)
    pid_text, name = head.split("(", 1)
    fields = tail.split()
    if len(fields) < 20:
        raise ValueError("incomplete process stat")
    return {
        "pid": int(pid_text.strip()),
        "name": name,
        "state": fields[0],
        "ppid": int(fields[1]),
        "start_ticks": int(fields[19]),
    }


def parse_tcp_listeners(text: str, family: str) -> list[dict[str, Any]]:
    """Read TCP listen entries and their socket inodes from procfs."""
    result = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if not fields:
            continue
        if len(fields) < 10:
            raise ValueError("incomplete procfs TCP entry")
        if fields[3] != "0A":
            continue
        address, port = fields[1].rsplit(":", 1)
        result.append(
            {
                "family": family,
                "local_address_hex": address,
                "local_port": int(port, 16),
                "socket_inode": int(fields[9]),
            }
        )
    return result


def same_process(record: dict[str, Any], identity: dict[str, Any]) -> bool:
    """Match both PID and kernel start time before accepting an identity."""
    return record.get("pid") == identity.get("pid") and record.get("start_ticks") == identity.get(
        "start_ticks"
    )


def _error(errors: list[dict[str, str]], operation: str, exc: Exception) -> None:
    errors.append({"operation": operation, "error": f"{type(exc).__name__}: {exc}"})


def _command(argv: list[str], errors: list[dict[str, str]]) -> str | None:
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, check=True, timeout=COMMAND_TIMEOUT
        )
    except (OSError, subprocess.SubprocessError) as exc:
        _error(errors, " ".join(argv), exc)
        return None
    return result.stdout


def _read_processes(errors: list[dict[str, str]]) -> dict[int, dict[str, Any]]:
    processes: dict[int, dict[str, Any]] = {}
    try:
        directories = list(PROC.iterdir())
    except OSError as exc:
        _error(errors, f"list {PROC}", exc)
        return processes
    for directory in directories:
        if not directory.name.isdecimal():
            continue
        try:
            record = parse_process_stat((directory / "stat").read_text())
            record["cmdline"] = [
                arg.decode("utf-8", errors="replace")
                for arg in (directory / "cmdline").read_bytes().split(b"\0")
                if arg
            ]
            try:
                record["netns"] = os.readlink(directory / "ns/net")
            except FileNotFoundError:
                if record["state"] not in {"Z", "X", "x"}:
                    raise
                record["netns"] = None
            current = parse_process_stat((directory / "stat").read_text())
            if not same_process(current, record):
                continue
            processes[record["pid"]] = record
        except (FileNotFoundError, ProcessLookupError):
            continue
        except (OSError, ValueError) as exc:
            _error(errors, f"read process {directory.name}", exc)
    return processes


def _ancestors(processes: dict[int, dict[str, Any]], pid: int) -> set[int]:
    result: set[int] = set()
    while pid and pid not in result:
        result.add(pid)
        pid = int(processes.get(pid, {}).get("ppid", 0))
    return result


def _namespace_id(value: Any) -> str:
    text = str(value)
    return text if text.startswith("net:[") else f"net:[{text}]"


def select_owned_processes(
    processes: dict[int, dict[str, Any]],
    manifest: dict[str, Any],
    namespace_ids: set[str],
    auditor_pid: int,
) -> list[dict[str, Any]]:
    """Resolve resource ownership from identities, ancestry, and unique markers."""
    excluded = _ancestors(processes, auditor_pid)
    for identity in manifest.get("excluded_processes", []):
        record = processes.get(identity.get("pid"))
        if record is not None and same_process(record, identity):
            excluded.add(record["pid"])
    identities = list(manifest.get("owned_processes", []))
    worker = manifest.get("worker_identity")
    if worker:
        identities.append(worker)
    owned: dict[int, dict[str, Any]] = {}
    trusted: set[int] = set()
    worker_tree: set[int] = set()
    prefix = manifest.get("prefix", "")
    output = manifest.get("output_dir", "")
    marker = re.compile(rf"(?<![A-Za-z0-9]){re.escape(prefix)}") if prefix else None
    for pid, record in processes.items():
        if pid in excluded:
            continue
        reasons = []
        if any(same_process(record, identity) for identity in identities):
            reasons.append("registered_identity")
            trusted.add(pid)
            if worker and same_process(record, worker):
                worker_tree.add(pid)
        if record.get("netns") in namespace_ids:
            reasons.append("owned_network_namespace")
        args = record.get("cmdline", [])
        if any(
            (marker is not None and marker.search(arg) is not None)
            or (
                output
                and (
                    arg.split("=", 1)[-1] == output
                    or arg.split("=", 1)[-1].startswith(output.rstrip("/") + "/")
                )
            )
            for arg in args
        ):
            reasons.append("run_marker")
        if reasons:
            owned[pid] = {**record, "ownership": reasons}
    changed = True
    while changed:
        changed = False
        for pid, record in processes.items():
            parent = record["ppid"]
            if (
                pid in excluded
                or parent not in owned
                or record["start_ticks"] < owned[parent]["start_ticks"]
            ):
                continue
            if parent in trusted and pid not in trusted:
                reason = "worker_descendant" if parent in worker_tree else "trusted_descendant"
                if pid not in owned:
                    owned[pid] = {**record, "ownership": []}
                owned[pid]["ownership"].append(reason)
                trusted.add(pid)
                if parent in worker_tree:
                    worker_tree.add(pid)
                changed = True
            elif pid not in owned:
                owned[pid] = {**record, "ownership": ["candidate_descendant"]}
                changed = True
    return sorted(owned.values(), key=lambda item: item["pid"])


def _link_inventory(namespace: str | None, errors: list[dict[str, str]]) -> list[dict[str, Any]]:
    argv = ["ip", "-j"]
    if namespace is not None:
        argv.extend(["-n", namespace])
    argv.extend(["link", "show"])
    text = _command(argv, errors)
    if text is None:
        return []
    try:
        links = json.loads(text)
        if not isinstance(links, list) or any(not isinstance(link, dict) for link in links):
            raise ValueError("link inventory must be a list of objects")
        return [{**link, "namespace": namespace or "root"} for link in links]
    except (ValueError, TypeError) as exc:
        _error(errors, "decode " + " ".join(argv), exc)
        return []


def _named_namespaces(
    manifest: dict[str, Any], errors: list[dict[str, str]]
) -> list[dict[str, Any]]:
    text = _command(["ip", "netns", "list"], errors)
    if text is None:
        return []
    expected = set(manifest.get("host_names", []))
    prefix = manifest["prefix"]
    result = []
    for line in text.splitlines():
        if not line.strip():
            continue
        name = line.split()[0]
        if name not in expected and not name.startswith(prefix):
            continue
        try:
            inode = (NETNS / name).stat().st_ino
        except FileNotFoundError:
            continue
        except OSError as exc:
            _error(errors, f"stat namespace {name}", exc)
            continue
        result.append({"name": name, "netns": _namespace_id(inode)})
    return result


def _owned_listeners(
    processes: list[dict[str, Any]], errors: list[dict[str, str]]
) -> list[dict[str, Any]]:
    socket_owners: dict[int, list[dict[str, int]]] = {}
    tables: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for record in processes:
        directory = PROC / str(record["pid"])
        try:
            current = parse_process_stat((directory / "stat").read_text())
            if not same_process(current, record):
                continue
            for descriptor in (directory / "fd").iterdir():
                try:
                    target = os.readlink(descriptor)
                except FileNotFoundError:
                    continue
                match = re.fullmatch(r"socket:\[(\d+)\]", target)
                if match:
                    socket_owners.setdefault(int(match[1]), []).append(
                        {"pid": record["pid"], "start_ticks": record["start_ticks"]}
                    )
            for family, filename in (("ipv4", "tcp"), ("ipv6", "tcp6")):
                key = (str(record.get("netns")), family)
                if key not in tables:
                    tables[key] = parse_tcp_listeners(
                        (directory / "net" / filename).read_text(), family
                    )
        except (FileNotFoundError, ProcessLookupError):
            continue
        except (OSError, ValueError) as exc:
            _error(errors, f"inspect sockets for process {record['pid']}", exc)
    result = []
    for (namespace, _family), entries in tables.items():
        for entry in entries:
            owners = socket_owners.get(entry["socket_inode"])
            if owners:
                result.append({**entry, "netns": namespace, "owners": owners})
    return result


def _namespace_fd_holders(
    processes: dict[int, dict[str, Any]],
    namespace_ids: set[str],
    errors: list[dict[str, str]],
) -> dict[str, list[dict[str, int]]]:
    """Find known namespace objects held through descriptors after unmounting."""
    holders: dict[str, list[dict[str, int]]] = {}
    if not namespace_ids:
        return holders
    try:
        namespace_device = (PROC / "self/ns/net").stat().st_dev
        namespace_inodes = {}
        for namespace_id in namespace_ids:
            match = re.fullmatch(r"net:\[(\d+)\]", namespace_id)
            if match is None:
                raise ValueError(f"invalid network namespace identity: {namespace_id}")
            namespace_inodes[int(match[1])] = namespace_id
    except (OSError, ValueError) as exc:
        _error(errors, "identify namespace filesystem", exc)
        return holders
    for record in processes.values():
        directory = PROC / str(record["pid"])
        try:
            if not same_process(parse_process_stat((directory / "stat").read_text()), record):
                continue
            held = set()
            for descriptor in (directory / "fd").iterdir():
                try:
                    identity = descriptor.stat()
                except FileNotFoundError:
                    continue
                # A bind-mounted namespace descriptor can display a deleted
                # mount path instead of net:[inode]. Procfs stat follows the
                # held object without reopening the descriptor's target.
                if identity.st_dev == namespace_device:
                    held_namespace = namespace_inodes.get(identity.st_ino)
                    if held_namespace is not None:
                        held.add(held_namespace)
            if not same_process(parse_process_stat((directory / "stat").read_text()), record):
                continue
            for namespace_id in held:
                holders.setdefault(namespace_id, []).append(
                    {"pid": record["pid"], "start_ticks": record["start_ticks"]}
                )
        except (FileNotFoundError, ProcessLookupError):
            continue
        except (OSError, ValueError) as exc:
            _error(errors, f"inspect namespace descriptors for process {record['pid']}", exc)
    return holders


def capture(manifest: dict[str, Any]) -> dict[str, Any]:
    """Capture owned resources without creating, signaling, or deleting them.

    ``namespace_ids`` preserves previously observed namespace identities after
    named mounts disappear. ``owned_processes`` and ``excluded_processes`` use
    dictionaries containing both ``pid`` and ``start_ticks``. Listeners require
    an owned process's socket descriptor; a matching port alone is insufficient.
    """
    prefix = manifest.get("prefix")
    if not isinstance(prefix, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{3,11}", prefix):
        raise ValueError("a unique ASCII run prefix of 4 to 12 characters is required")
    errors: list[dict[str, str]] = []
    named = _named_namespaces(manifest, errors)
    namespace_ids = {_namespace_id(value) for value in manifest.get("namespace_ids", [])}
    namespace_ids.update(namespace["netns"] for namespace in named)
    all_processes = _read_processes(errors)
    owned = select_owned_processes(all_processes, manifest, namespace_ids, os.getpid())
    # A process can reveal an unnamed namespace that other surviving processes hold.
    root_namespace = all_processes.get(os.getpid(), {}).get("netns")
    observed = {
        record["netns"]
        for record in owned
        if root_namespace is not None
        and record.get("netns") is not None
        and record["netns"] != root_namespace
    }
    if root_namespace is None:
        _error(errors, "identify auditor network namespace", RuntimeError("identity unavailable"))
    namespace_ids.update(observed)
    owned = select_owned_processes(all_processes, manifest, namespace_ids, os.getpid())
    namespaces = list(named)
    mounted_ids = {namespace["netns"] for namespace in named}
    fd_holders = _namespace_fd_holders(all_processes, namespace_ids, errors)
    for namespace_id in sorted(namespace_ids - mounted_ids):
        holders = [record["pid"] for record in owned if record.get("netns") == namespace_id]
        if holders or fd_holders.get(namespace_id):
            entry: dict[str, Any] = {
                "name": None,
                "netns": namespace_id,
                "holder_pids": holders,
            }
            if fd_holders.get(namespace_id):
                entry["descriptor_holders"] = fd_holders[namespace_id]
            namespaces.append(entry)
    root_links = _link_inventory(None, errors)
    interfaces = [link for link in root_links if str(link.get("ifname", "")).startswith(prefix)]
    for namespace in named:
        interfaces.extend(
            link
            for link in _link_inventory(namespace["name"], errors)
            if link.get("ifname") != "lo"
        )
    listeners = _owned_listeners(owned, errors)
    return {
        "run_id": manifest.get("run_id"),
        "prefix": prefix,
        "processes": owned,
        "namespaces": namespaces,
        "interfaces": interfaces,
        "listeners": listeners,
        "snapshot_errors": errors,
        "observed_namespace_ids": sorted(namespace_ids),
        "root_interface_inventory": root_links,
    }


def compare_root_interfaces(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Mark unattributed root-link changes as uncertainty without deleting them.

    An interface's index and name identify the observed object. Changes outside
    the run prefix can reflect temporary leaked links or unrelated host activity;
    either prevents an unqualified clean result. Lightweight injected audit
    snapshots without full root inventories remain supported.
    """
    if "root_interface_inventory" not in before or "root_interface_inventory" not in after:
        return after
    result = {**after, "snapshot_errors": list(after.get("snapshot_errors", []))}
    prefix = after.get("prefix", before.get("prefix"))
    inventory: list[dict[int, str]] = []
    for label, snapshot in (("before", before), ("after", after)):
        value = snapshot["root_interface_inventory"]
        links: dict[int, str] = {}
        if not isinstance(value, list):
            _error(
                result["snapshot_errors"],
                f"compare root interfaces {label}",
                ValueError("inventory must be a list"),
            )
            return result
        for link in value:
            if (
                not isinstance(link, dict)
                or not isinstance(link.get("ifindex"), int)
                or isinstance(link["ifindex"], bool)
                or link["ifindex"] <= 0
                or not isinstance(link.get("ifname"), str)
                or not link["ifname"]
                or link["ifindex"] in links
            ):
                _error(
                    result["snapshot_errors"],
                    f"compare root interfaces {label}",
                    ValueError("invalid or duplicate interface identity"),
                )
                return result
            links[link["ifindex"]] = link["ifname"]
        inventory.append(links)
    previous, current = inventory
    changed = []
    for ifindex in sorted(previous.keys() | current.keys()):
        old_name, new_name = previous.get(ifindex), current.get(ifindex)
        if old_name == new_name:
            continue
        names = [name for name in (old_name, new_name) if name is not None]
        if isinstance(prefix, str) and prefix and all(name.startswith(prefix) for name in names):
            continue
        changed.append({"ifindex": ifindex, "before": old_name, "after": new_name})
    if changed:
        result["snapshot_errors"].append(
            {
                "operation": "compare root interface inventory",
                "error": "unattributed interface changes require inspection",
                "changes": changed,
            }
        )
    return result


def is_clean(snapshot: dict[str, Any]) -> bool:
    """Require explicit empty resource and error lists, rejecting partial audits."""
    return all(snapshot.get(key) == [] for key in (*RESOURCE_KEYS, "snapshot_errors"))
