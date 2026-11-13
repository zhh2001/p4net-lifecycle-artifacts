"""Define source-specific diagnostic boundaries for the three pinned native workers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from diagnostic.hooks import Hook


def build(tool: str, inventory: list[dict[str, Any]]) -> list[Hook]:
    sources = {entry["label"]: entry for entry in inventory}
    result: list[Hook] = []

    def add(
        label: str,
        module: str,
        owner: str,
        member: str,
        stage: str,
        level: str = "stages",
        kind: str = "span",
    ) -> None:
        entry = sources[label]
        result.append(
            Hook(module, owner, member, stage, entry["path"], entry["sha256"], level, kind)
        )

    worker = {
        "p4net": "harness.worker",
        "p4utils": "harness.worker_p4utils",
        "tutorial-components": "harness.worker_tutorial",
    }.get(tool)
    if worker is None:
        raise ValueError("unknown diagnostic tool")
    label = {
        "p4net": "worker-p4net",
        "p4utils": "worker-p4utils",
        "tutorial-components": "worker-tutorial",
    }[tool]
    add(label, worker, "", "emit", "worker.protocol", kind="event")
    add(label, worker, "", "execute", "worker.workflow")
    add("worker-settings", "harness.settings", "", "configure_host", "task.host_settings")
    if tool == "p4net":
        add(label, worker, "", "build", "topology.specification")
        for member, stage in (
            ("_do_start", "network.start"),
            ("_do_stop", "network.stop"),
            ("_wire_link", "link.wire"),
        ):
            add("p4net-network", "p4net.network.orchestrator", "Network", member, stage)
        for member, stage, level in (
            ("compile", "compiler.request", "stages"),
            ("_preprocess", "compiler.preprocess", "detail"),
            ("_real_compile", "compiler.build", "detail"),
            ("_publish_cache", "compiler.publish", "detail"),
        ):
            add("p4net-compiler", "p4net.compiler.p4c", "P4Compiler", member, stage, level)
        for member in ("create", "destroy", "exec"):
            add(
                "p4net-namespace",
                "p4net.runtime.netns",
                "NetworkNamespace",
                member,
                "namespace." + member,
                "detail",
            )
        for member in ("create", "destroy"):
            add("p4net-link", "p4net.runtime.link", "VethPair", member, "veth." + member, "detail")
        for member, stage in (
            ("start", "bmv2.launch"),
            ("wait_until_ready", "bmv2.readiness"),
            ("stop", "bmv2.stop"),
        ):
            add("p4net-bmv2", "p4net.runtime.bmv2", "BMv2Switch", member, stage)
        for member, stage in (
            ("connect", "control.connect"),
            ("_teardown", "control.disconnect"),
            ("set_pipeline_config", "control.pipeline"),
        ):
            add("p4net-client", "p4net.control.client", "P4RuntimeClient", member, stage)
    elif tool == "p4utils":
        add(label, worker, "", "configure", "topology.specification")
        add(label, worker, "", "program", "task.program")
        add(label, worker, "", "check_connectivity", "task.host_configuration_and_checks")
        add(label, worker, "", "host_command", "host.command", "detail")
        for member, stage in (
            ("startNetwork", "network.start"),
            ("stopNetwork", "network.stop"),
            ("cleanup", "network.prestart_cleanup"),
            ("compile", "compiler.sources"),
        ):
            add("p4utils-network", "p4utils.mininetlib.network_API", "NetworkAPI", member, stage)
        add(
            "p4utils-mininet", "p4utils.mininetlib.net", "P4Mininet", "stop", "network.mininet_stop"
        )
        for member, stage in (("start", "bmv2.launch_and_readiness"), ("stop", "bmv2.stop")):
            add("p4utils-node", "p4utils.mininetlib.node", "P4Switch", member, stage)
        for member, stage in (
            ("__init__", "control.connect"),
            ("set_fwd_pipe_config", "control.pipeline"),
            ("tear_down", "control.disconnect"),
        ):
            add(
                "p4utils-client",
                "p4utils.utils.p4runtime_API.p4runtime",
                "P4RuntimeClient",
                member,
                stage,
            )
    else:
        for member, stage in (
            ("compile_task", "compiler.build"),
            ("populate_network", "network.population"),
            ("configure_task", "task.table_and_neighbor_configuration"),
        ):
            add(label, worker, "", member, stage)
        for member, stage in (
            ("start", "bmv2.launch_and_readiness"),
            ("check_switch_started", "bmv2.readiness"),
        ):
            add("tutorial-node", "p4runtime_switch", "P4RuntimeSwitch", member, stage)
        add("tutorial-stop", "p4_mininet", "P4Switch", "stop", "bmv2.stop")
        for member, stage in (
            ("MasterArbitrationUpdate", "control.arbitration"),
            ("SetForwardingPipelineConfig", "control.pipeline"),
            ("shutdown", "control.stream_shutdown"),
        ):
            add("tutorial-client", "p4runtime_lib.switch", "SwitchConnection", member, stage)
    if tool != "p4net":
        for member, stage in (
            ("build", "network.mininet_build"),
            ("start", "network.mininet_start"),
            ("addLink", "link.wire"),
        ):
            add("mininet-network", "mininet.net", "Mininet", member, stage)
        if tool == "tutorial-components":
            add("mininet-network", "mininet.net", "Mininet", "stop", "network.stop")
        add("mininet-node", "mininet.node", "Node", "pexec", "host.command", "detail")
    return result


def from_mapping(rows: list[Mapping[str, Any]]) -> list[Hook]:
    return [Hook(**dict(row)) for row in rows]
