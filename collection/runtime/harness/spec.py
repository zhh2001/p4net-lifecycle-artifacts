"""Create and validate a trial's resource names and forwarding task."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import re
import socket
import uuid
from pathlib import Path
from typing import Any

DEFAULT_SOURCE = Path(__file__).resolve().parent / "workloads" / "l3.p4"


def names(prefix: str, groups: int) -> tuple[list[str], list[str]]:
    return (
        [f"{prefix}{letter}{i:x}" for i in range(groups) for letter in ("a", "b")],
        [f"{prefix}s{i:x}" for i in range(groups)],
    )


def validate(manifest: dict[str, Any]) -> None:
    if type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 1:
        raise ValueError("unsupported manifest schema")
    if not isinstance(manifest.get("run_id"), str) or not re.fullmatch(
        r"[a-f0-9]{32}", manifest["run_id"]
    ):
        raise ValueError("run_id must be a UUID hex string")
    prefix = manifest.get("prefix")
    if not isinstance(prefix, str) or not re.fullmatch(r"r[a-f0-9]{6}", prefix):
        raise ValueError("prefix must contain r followed by six hex digits")
    groups = manifest.get("groups")
    if type(groups) is not int or not 1 <= groups <= 16:
        raise ValueError("groups must be an integer from 1 to 16")
    hosts, switches = names(prefix, groups)
    if manifest.get("host_names") != hosts or manifest.get("switch_names") != switches:
        raise ValueError("resource names do not match prefix and scale")
    ports = manifest.get("service_ports")
    if not isinstance(ports, list) or len(ports) != 2 * groups:
        raise ValueError("two service ports are required per switch")
    if any(type(p) is not int or not 1024 <= p <= 65535 for p in ports):
        raise ValueError("invalid service port")
    if len(set(ports)) != len(ports):
        raise ValueError("service ports must be distinct")
    for key in ("output_dir", "p4_source"):
        if not isinstance(manifest.get(key), str) or not Path(manifest[key]).is_absolute():
            raise ValueError(f"{key} must be an absolute path")
    if not Path(manifest["p4_source"]).is_file():
        raise ValueError("P4 source does not exist")
    if manifest.get("purpose") != "functional-check":
        raise ValueError("this framework currently supports functional checks only")
    profile = manifest.get("configuration_profile", "native")
    if not isinstance(profile, str) or profile not in {"native", "matched-v1"}:
        raise ValueError("unknown configuration profile")


def load(path: Path) -> dict[str, Any]:
    manifest: dict[str, Any] = json.loads(path.read_text())
    validate(manifest)
    if Path(manifest["output_dir"]) != path.resolve().parent:
        raise ValueError("manifest must be inside its own output directory")
    return manifest


def create(
    output: Path,
    groups: int = 1,
    source: Path = DEFAULT_SOURCE,
    *,
    configuration_profile: str = "native",
) -> Path:
    run_id = uuid.uuid4().hex
    prefix = "r" + run_id[:6]
    hosts, switches = names(prefix, groups)
    with contextlib.ExitStack() as stack:
        sockets = [stack.enter_context(socket.socket()) for _ in range(2 * groups)]
        for sock in sockets:
            sock.bind(("127.0.0.1", 0))
        ports = [int(sock.getsockname()[1]) for sock in sockets]
        manifest = {
            "schema_version": 1,
            "purpose": "functional-check",
            "configuration_profile": configuration_profile,
            "run_id": run_id,
            "prefix": prefix,
            "groups": groups,
            "host_names": hosts,
            "switch_names": switches,
            "service_ports": ports,
            "p4_source": str(source.resolve()),
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "output_dir": str(output.resolve()),
        }
        validate(manifest)
        output.mkdir(parents=True, exist_ok=False)
        path = output / "manifest.json"
        path.write_text(json.dumps(manifest, indent=2) + "\n")
    return path


def task_rows(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for i, switch in enumerate(manifest["switch_names"]):
        pair = manifest["host_names"][2 * i : 2 * i + 2]
        for port, name in enumerate(pair, 1):
            rows.append(
                {
                    "switch": switch,
                    "host": name,
                    "peer": pair[2 - port],
                    "port": port,
                    "ip": f"10.231.{i}.{port}",
                    "peer_ip": f"10.231.{i}.{3 - port}",
                    "mac": f"02:77:00:{i:02x}:00:{port:02x}",
                    "switch_mac": f"02:77:01:{i:02x}:00:{port:02x}",
                }
            )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--groups", type=int, default=1)
    args = parser.parse_args()
    print(create(args.output, args.groups))


if __name__ == "__main__":
    main()
