"""Run a table-programmed L3 connectivity check in a fresh process."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import sys
import traceback
from functools import partial
from pathlib import Path
from typing import Any

from harness import settings
from harness.events import bounded_read, serve_commands
from harness.spec import load, task_rows


def identity(pid: int) -> dict[str, int]:
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return {"pid": pid, "start_ticks": int(fields[19])}


def emit(manifest: dict[str, Any], event: str, **fields: Any) -> None:
    print(
        json.dumps(
            {
                "schema_version": 1,
                "run_id": manifest["run_id"],
                "event": event,
                **fields,
            },
            allow_nan=False,
        ),
        flush=True,
    )


def build(manifest: dict[str, Any]) -> Any:
    from p4net.topo import Topology

    topo = Topology()
    rows = task_rows(manifest)
    for i, switch in enumerate(manifest["switch_names"]):
        topo.add_switch(
            switch,
            p4_src=Path(manifest["p4_source"]),
            device_id=i,
            grpc_port=manifest["service_ports"][2 * i],
            thrift_port=manifest["service_ports"][2 * i + 1],
            pcap_enabled=False,
        )
        for row in rows[2 * i : 2 * i + 2]:
            topo.add_host(row["host"], ip=row["ip"] + "/24", mac=row["mac"])
            topo.add_link(row["host"], switch, port_b=row["port"])
    topo.validate()
    return topo


def execute(path: Path) -> int:
    manifest = load(path)
    emit(manifest, "starting", purpose="functional-check")
    net = None
    failed = False
    try:
        from p4net import Network
        from p4net.compiler import P4Compiler

        topo = build(manifest)
        output = Path(manifest["output_dir"])
        net = Network(
            topo, compiler=P4Compiler(cache_dir=output / "compiler"), log_dir=output / "bmv2"
        )
        emit(manifest, "inventory", owned_processes=[identity(os.getpid())])
        net.start()
        processes = [identity(os.getpid())]
        for switch in net.switches.values():
            pid = switch.bmv2.pid
            if pid is None:
                raise RuntimeError("BMv2 is missing its process identity")
            processes.append(identity(pid))
        namespace_ids = [
            f"net:[{os.stat('/var/run/netns/' + name).st_ino}]" for name in manifest["host_names"]
        ]
        emit(manifest, "inventory", owned_processes=processes, observed_namespace_ids=namespace_ids)
        host_settings = []
        for row in task_rows(manifest):
            net.switch(row["switch"]).client.insert_table_entry(
                "L3Ingress.ipv4_lpm",
                {"hdr.ipv4.dstAddr": row["ip"] + "/32"},
                "L3Ingress.forward",
                {"dst_mac": row["mac"], "src_mac": row["switch_mac"], "port": row["port"]},
            )
            host = net.host(row["host"])
            iface = next(iter(host.interfaces))
            command = [
                "ip",
                "neigh",
                "replace",
                row["peer_ip"],
                "lladdr",
                row["switch_mac"],
                "dev",
                iface,
                "nud",
                "permanent",
            ]
            completed = host.exec(command)
            if completed.returncode:
                raise RuntimeError(f"neighbor configuration failed for {row['host']}")
            if settings.matched(manifest):
                host_settings.append(
                    settings.configure_host(
                        row,
                        iface,
                        partial(host.exec, capture_output=True, check=False, timeout=6),
                    )
                )
        if settings.matched(manifest):
            settings.write_hosts(manifest, host_settings)
            checks = [
                {
                    "src": row["host"],
                    "dst": row["peer"],
                    "ok": net.host(row["host"])
                    .exec(
                        settings.ping_command(row["peer_ip"]),
                        capture_output=True,
                        check=False,
                        timeout=6,
                    )
                    .returncode
                    == 0,
                }
                for row in task_rows(manifest)
            ]
        else:
            checks = [
                {
                    "src": row["host"],
                    "dst": row["peer"],
                    "ok": net.ping(row["host"], row["peer"], count=1, timeout=2),
                }
                for row in task_rows(manifest)
            ]
        if not all(check["ok"] for check in checks):
            raise RuntimeError(f"connectivity checks failed: {checks}")
        emit(
            manifest,
            "ready",
            checks=checks,
            owned_processes=processes,
            observed_namespace_ids=namespace_ids,
            distribution=importlib.metadata.version("p4net"),
        )
        serve_commands(
            manifest, lambda: bounded_read(net.switch(manifest["switch_names"][0]).client._stub)
        )
    except BaseException as exc:
        failed = True
        emit(manifest, "error", error_type=type(exc).__name__, message=str(exc))
        traceback.print_exc(file=sys.stderr)
    finally:
        if net is not None:
            try:
                net.stop()
            except BaseException as exc:
                failed = True
                emit(manifest, "error", error_type=type(exc).__name__, message=str(exc))
                traceback.print_exc(file=sys.stderr)
        emit(manifest, "stopped", worker_ok=not failed)
    return int(failed)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(execute(args.manifest))


if __name__ == "__main__":
    main()
