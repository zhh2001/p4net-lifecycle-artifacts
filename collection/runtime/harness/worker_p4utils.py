"""Run the matched L3 task through the pinned P4-Utils public APIs."""

from __future__ import annotations

import argparse
import contextlib
import importlib.metadata
import os
import subprocess
import sys
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any

from harness import settings
from harness.events import bounded_read, emit, identity, serve_commands
from harness.spec import load, task_rows

UPSTREAM_COMMIT = "83b118bbae530b31cc74e7fa32f9174f7c0a1184"


def configure(manifest: dict[str, Any], factory: Callable[[], Any] | None = None) -> Any:
    """Configure upstream objects without replacing their startup behavior."""
    if factory is None:
        factory = importlib.import_module("p4utils.mininetlib.network_API").NetworkAPI
    network = factory()
    output = Path(manifest["output_dir"])
    (output / "compiler").mkdir()
    (output / "bmv2").mkdir()
    network.disableCli()
    network.disableArpTables()
    network.disableGwArp()
    network.setLogLevel("info")
    network.setCompiler(p4rt=True, outdir=str(output / "compiler"), p4c_bin="p4c")
    network.setTopologyFile(str(output / "topology.json"))
    rows = task_rows(manifest)
    for index, switch in enumerate(manifest["switch_names"]):
        network.addP4RuntimeSwitch(
            switch,
            device_id=index,
            grpc_port=manifest["service_ports"][2 * index],
            thrift_port=manifest["service_ports"][2 * index + 1],
            p4_src=manifest["p4_source"],
            pcap_dump=False,
            log_enabled=True,
            log_dir=str(output / "bmv2"),
        )
        for row in rows[2 * index : 2 * index + 2]:
            network.addHost(row["host"], ip=row["ip"] + "/24", mac=row["mac"])
            network.addLink(
                row["host"],
                switch,
                port1=0,
                port2=row["port"],
                intfName1=row["host"] + "-eth0",
                intfName2=switch + "-eth" + str(row["port"]),
                addr1=row["mac"],
                addr2=row["switch_mac"],
                params1={"ip": row["ip"] + "/24"},
            )
    network.disableSchedulerAll()
    network.disableDhcpAll()
    return network


def register_inventory(network: Any, manifest: dict[str, Any]) -> None:
    """Record host namespaces and only process identities in the worker group."""
    worker_pid = os.getpid()
    processes = [identity(worker_pid)]
    namespace_ids = []
    for host in network.net.hosts:
        namespace_ids.append(os.readlink(f"/proc/{host.pid}/ns/net"))
        if os.getpgid(host.pid) == worker_pid:
            processes.append(identity(host.pid))
    for switch in network.net.switches:
        pid = switch.switch_pid
        if pid is not None and os.getpgid(pid) == worker_pid:
            processes.append(identity(pid))
    emit(
        manifest,
        "inventory",
        owned_processes=processes,
        observed_namespace_ids=sorted(set(namespace_ids)),
    )


def program(
    network: Any,
    manifest: dict[str, Any],
    controllers: list[Any],
    factory: Callable[..., Any] | None = None,
) -> None:
    """Use upstream table_add and retain every controller for teardown."""
    if factory is None:
        factory = importlib.import_module(
            "p4utils.utils.sswitch_p4runtime_API"
        ).SimpleSwitchP4RuntimeAPI
    rows = task_rows(manifest)
    for index, switch in enumerate(manifest["switch_names"]):
        info = network.getNode(switch)
        controller = factory(
            device_id=index,
            grpc_port=manifest["service_ports"][2 * index],
            grpc_ip="127.0.0.1",
            p4rt_path=info["p4rt_path"],
            json_path=info["json_path"],
        )
        controllers.append(controller)
        for row in rows[2 * index : 2 * index + 2]:
            accepted = controller.table_add(
                "L3Ingress.ipv4_lpm",
                "L3Ingress.forward",
                [row["ip"] + "/32"],
                [row["mac"], row["switch_mac"], str(row["port"])],
            )
            if accepted is not True:
                raise RuntimeError(f"P4-Utils rejected the forwarding entry for {row['host']}")


def host_command(host: Any, argv: list[str], timeout: float = 6) -> int:
    process = host.popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        _stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise
    if process.returncode and argv[0] != "ping":
        raise RuntimeError(f"host command failed: {argv!r}: {stderr.decode(errors='replace')}")
    return int(process.returncode)


def check_connectivity(network: Any, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    rows = task_rows(manifest)
    host_settings = []
    for row in rows:
        host_command(
            network.net.get(row["host"]),
            [
                "ip",
                "neigh",
                "replace",
                row["peer_ip"],
                "lladdr",
                row["switch_mac"],
                "dev",
                row["host"] + "-eth0",
                "nud",
                "permanent",
            ],
        )
        if settings.matched(manifest):
            host_settings.append(
                settings.configure_host(
                    row,
                    row["host"] + "-eth0",
                    settings.mininet_runner(network.net.get(row["host"])),
                )
            )
    if settings.matched(manifest):
        settings.write_hosts(manifest, host_settings)
    checks = [
        {
            "src": row["host"],
            "dst": row["peer"],
            "ok": host_command(
                network.net.get(row["host"]),
                settings.ping_command(row["peer_ip"]),
            )
            == 0,
        }
        for row in rows
    ]
    if not all(check["ok"] for check in checks):
        raise RuntimeError(f"connectivity checks failed: {checks}")
    return checks


def execute(path: Path) -> int:
    manifest = load(path)
    emit(manifest, "starting", purpose="functional-check", tool="p4utils")
    network = None
    controllers: list[Any] = []
    failed = False
    with contextlib.redirect_stdout(sys.stderr):
        try:
            network = configure(manifest)
            emit(manifest, "inventory", owned_processes=[identity(os.getpid())])
            network.startNetwork()
            register_inventory(network, manifest)
            program(network, manifest, controllers)
            checks = check_connectivity(network, manifest)
            emit(
                manifest,
                "ready",
                checks=checks,
                tool="p4utils",
                distribution=importlib.metadata.version("p4utils"),
                upstream_commit=UPSTREAM_COMMIT,
            )
            serve_commands(manifest, lambda: bounded_read(controllers[0].client.stub))
        except BaseException as exc:
            failed = True
            emit(manifest, "error", error_type=type(exc).__name__, message=str(exc))
            traceback.print_exc(file=sys.stderr)
        finally:
            for controller in reversed(controllers):
                try:
                    controller.teardown()
                except BaseException as exc:
                    failed = True
                    emit(manifest, "error", error_type=type(exc).__name__, message=str(exc))
                    traceback.print_exc(file=sys.stderr)
            if network is not None:
                try:
                    network.stopNetwork()
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
