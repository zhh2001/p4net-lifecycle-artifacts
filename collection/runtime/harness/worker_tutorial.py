"""Run the shared L3 task with official tutorial components and Mininet."""

from __future__ import annotations

import argparse
import contextlib
import importlib
import json
import os
import shutil
import subprocess
import sys
import traceback
from pathlib import Path
from typing import Any

from harness import settings, worker_components
from harness.events import bounded_read, emit, identity, serve_commands
from harness.spec import load, task_rows

REVISION = "15d780e5ac7046aa64d64270ab0ef3852f1103f9"
BASE = Path(__file__).resolve().parents[1] / "baselines" / "tutorial"


def load_components() -> dict[str, Any]:
    os.environ.setdefault("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", "python")
    frozen = worker_components.from_environment()
    utils = (
        Path(frozen["tutorial_utils"]["path"])
        if frozen is not None
        else BASE / "source" / f"tutorials-{REVISION}" / "utils"
    )
    if not (utils / "p4runtime_switch.py").is_file():
        raise FileNotFoundError(f"official tutorial snapshot is missing: {utils}")
    if frozen is not None:
        worker_components.verify_loaded_modules(frozen)
    sys.path.insert(0, str(utils))
    components = {
        "Mininet": importlib.import_module("mininet.net").Mininet,
        "TCLink": importlib.import_module("mininet.link").TCLink,
        "P4Host": importlib.import_module("p4_mininet").P4Host,
        "P4RuntimeSwitch": importlib.import_module("p4runtime_switch").P4RuntimeSwitch,
        "P4InfoHelper": importlib.import_module("p4runtime_lib.helper").P4InfoHelper,
        "Bmv2SwitchConnection": importlib.import_module("p4runtime_lib.bmv2").Bmv2SwitchConnection,
    }
    if frozen is not None:
        worker_components.verify_loaded_modules(frozen)
    return components


def compile_task(manifest: dict[str, Any]) -> tuple[Path, Path]:
    output = Path(manifest["output_dir"]) / "compiler"
    output.mkdir()
    info = output / "program.p4info.txtpb"
    command = [
        "p4c",
        "--target",
        "bmv2",
        "--arch",
        "v1model",
        "--std",
        "p4-16",
        "-o",
        str(output),
        "--p4runtime-files",
        str(info),
        manifest["p4_source"],
    ]
    (output / "command.json").write_text(json.dumps(command, indent=2) + "\n")
    result = subprocess.run(command, capture_output=True, timeout=90)
    (output / "stdout.log").write_bytes(result.stdout)
    (output / "stderr.log").write_bytes(result.stderr)
    result.check_returncode()
    program = output / (Path(manifest["p4_source"]).stem + ".json")
    if any(not path.is_file() or not path.stat().st_size for path in (program, info)):
        raise RuntimeError("compiler did not produce nonempty BMv2 and P4Info artifacts")
    return program, info


def populate_network(
    net: Any, components: dict[str, Any], manifest: dict[str, Any], program: Path
) -> None:
    log_dir = Path(manifest["output_dir"]) / "bmv2"
    log_dir.mkdir()
    binary = shutil.which("simple_switch_grpc")
    if binary is None:
        raise FileNotFoundError("simple_switch_grpc is not available")
    rows = task_rows(manifest)
    for i, name in enumerate(manifest["switch_names"]):
        switch = net.addSwitch(
            name,
            cls=components["P4RuntimeSwitch"],
            sw_path=binary,
            json_path=str(program),
            grpc_port=manifest["service_ports"][2 * i],
            thrift_port=manifest["service_ports"][2 * i + 1],
            device_id=i,
            dpid=f"{i + 1:016x}",
            pcap_dump=False,
            log_console=True,
            log_file=str(log_dir / f"{name}.log"),
        )
        # This public attribute supplies BMv2's nanolog endpoint.
        switch.nanomsg = f"ipc:///tmp/{name}-nanolog.ipc"
        for row in rows[2 * i : 2 * i + 2]:
            host = net.addHost(
                row["host"], cls=components["P4Host"], ip=row["ip"] + "/24", mac=row["mac"]
            )
            net.addLink(host, switch, port1=0, port2=row["port"])


def configure_task(net: Any, helper: Any, connections: list[Any], manifest: dict[str, Any]) -> None:
    for row in task_rows(manifest):
        i = manifest["switch_names"].index(row["switch"])
        entry = helper.buildTableEntry(
            table_name="L3Ingress.ipv4_lpm",
            match_fields={"hdr.ipv4.dstAddr": (row["ip"], 32)},
            action_name="L3Ingress.forward",
            action_params={
                "dst_mac": row["mac"],
                "src_mac": row["switch_mac"],
                "port": row["port"],
            },
        )
        connections[i].WriteTableEntry(entry)
        host = net.get(row["host"])
        args = [
            "ip",
            "neigh",
            "replace",
            row["peer_ip"],
            "lladdr",
            row["switch_mac"],
            "dev",
            str(host.defaultIntf()),
            "nud",
            "permanent",
        ]
        _stdout, stderr, returncode = host.pexec(args)
        if returncode:
            raise RuntimeError(f"neighbor configuration failed for {row['host']}: {stderr}")


def inventory(net: Any) -> tuple[list[dict[str, int]], list[str]]:
    processes = [identity(os.getpid())]
    namespaces = []
    group = os.getpgrp()
    for node in [*net.hosts, *net.switches]:
        if os.getpgid(node.pid) == group:
            processes.append(identity(node.pid))
    for host in net.hosts:
        namespaces.append(os.readlink(f"/proc/{host.pid}/ns/net"))
    return processes, sorted(set(namespaces))


def _execute_task(path: Path) -> int:
    manifest = load(path)
    emit(manifest, "starting", purpose="functional-check", baseline="tutorial-components")
    net = None
    connections: list[Any] = []
    failed = False
    try:
        with contextlib.redirect_stdout(sys.stderr):
            components = load_components()
            program, info = compile_task(manifest)
            net = components["Mininet"](
                topo=None,
                host=components["P4Host"],
                switch=components["P4RuntimeSwitch"],
                link=components["TCLink"],
                controller=None,
                build=False,
                cleanup=False,
                autoStaticArp=False,
            )
            populate_network(net, components, manifest, program)
            net.build()
            processes, namespaces = inventory(net)
            emit(
                manifest, "inventory", owned_processes=processes, observed_namespace_ids=namespaces
            )
            net.start()
            helper = components["P4InfoHelper"](str(info))
            for i, name in enumerate(manifest["switch_names"]):
                connection = components["Bmv2SwitchConnection"](
                    name=name,
                    address=f"127.0.0.1:{manifest['service_ports'][2 * i]}",
                    device_id=i,
                )
                connections.append(connection)
                connection.MasterArbitrationUpdate()
                connection.SetForwardingPipelineConfig(
                    p4info=helper.p4info, bmv2_json_file_path=str(program)
                )
            configure_task(net, helper, connections, manifest)
            if settings.matched(manifest):
                host_settings = []
                for row in task_rows(manifest):
                    host = net.get(row["host"])
                    host_settings.append(
                        settings.configure_host(
                            row, str(host.defaultIntf()), settings.mininet_runner(host)
                        )
                    )
                settings.write_hosts(manifest, host_settings)
            checks = []
            for row in task_rows(manifest):
                _stdout, _stderr, returncode = net.get(row["host"]).pexec(
                    settings.ping_command(row["peer_ip"])
                    if settings.matched(manifest)
                    else ["ping", "-c", "1", "-W", "2", row["peer_ip"]]
                )
                checks.append({"src": row["host"], "dst": row["peer"], "ok": returncode == 0})
            if not all(check["ok"] for check in checks):
                raise RuntimeError(f"connectivity checks failed: {checks}")
            processes, namespaces = inventory(net)
        emit(
            manifest,
            "ready",
            checks=checks,
            owned_processes=processes,
            observed_namespace_ids=namespaces,
            baseline={
                "tool": "official-tutorial-components",
                "revision": REVISION,
                "protobuf_backend": os.environ.get("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"),
            },
        )
        serve_commands(manifest, lambda: bounded_read(connections[0].client_stub))
    except BaseException as exc:
        failed = True
        emit(manifest, "error", error_type=type(exc).__name__, message=str(exc))
        traceback.print_exc(file=sys.stderr)
    finally:
        with contextlib.redirect_stdout(sys.stderr):
            for connection in reversed(connections):
                try:
                    connection.shutdown()
                    connection.channel.close()
                except BaseException as exc:
                    failed = True
                    emit(manifest, "error", error_type=type(exc).__name__, message=str(exc))
                    traceback.print_exc(file=sys.stderr)
            if net is not None:
                try:
                    net.stop()
                except BaseException as exc:
                    failed = True
                    emit(manifest, "error", error_type=type(exc).__name__, message=str(exc))
                    traceback.print_exc(file=sys.stderr)
                for switch in net.switches:
                    try:
                        switch.output.close()
                    except BaseException as exc:
                        failed = True
                        emit(manifest, "error", error_type=type(exc).__name__, message=str(exc))
                        traceback.print_exc(file=sys.stderr)
        emit(manifest, "stopped", worker_ok=not failed)
    return int(failed)


def execute(path: Path) -> int:
    # Keep asynchronous upstream prints away from the protocol stream as well.
    with contextlib.redirect_stdout(sys.stderr):
        return _execute_task(path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(execute(args.manifest))


if __name__ == "__main__":
    main()
