"""Verify normalized launch arguments and matched host state without timing."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from harness import settings, spec
from harness.bmv2_launcher import POLICY, _option, _value


def inspect_trial(
    path: Path, *, verified_targets: Sequence[Mapping[str, Any]] | None = None
) -> dict[str, Any]:
    manifest = spec.load(path)
    directory = path.parent
    hosts = json.loads((directory / "host-settings.json").read_text())
    assert hosts["configuration_profile"] == settings.MATCHED
    assert hosts["performance_samples"] is False
    assert len(hosts["hosts"]) == 2 * manifest["groups"]
    for row, actual in zip(spec.task_rows(manifest), hosts["hosts"], strict=True):
        assert actual["host"] == row["host"]
        assert actual["ipv4"] == [row["ip"] + "/24"] and actual["mac"] == row["mac"]
        assert actual["mtu"] == 1500
        assert actual["offloads"] == {"rx": False, "tx": False, "sg": False}
        assert actual["ipv6_disabled"] == {
            "all": True,
            "default": True,
            "lo": True,
            "interface": True,
        }
    if verified_targets is None:
        ready = json.loads((directory / "inventory-ready.json").read_text())
        processes = {process["pid"]: process for process in ready["processes"]}
        target_pids = None
    else:
        # Observation records these identities only after the native selector
        # verifies each live command line against its prepared launch record.
        assert len(verified_targets) == manifest["groups"] + 1
        assert sum(target["role"] == "worker" for target in verified_targets) == 1
        assert len({target["pid"] for target in verified_targets}) == len(verified_targets)
        target_pids = {target["pid"] for target in verified_targets if target["role"] == "bmv2"}
        assert len(target_pids) == manifest["groups"]
        processes = None
    launches = [
        json.loads(p.read_text()) for p in sorted((directory / "bmv2-launches").glob("*.json"))
    ]
    switches = [launch for launch in launches if not launch["query"]]
    assert len(switches) == manifest["groups"]
    device_ids = set()
    for launch in switches:
        assert launch["policy"] == POLICY and launch["status"] == "prepared"
        effective = launch["effective_argv"]
        assert "--log-console" in effective and effective[effective.index("-L") + 1] == "info"
        assert not {"--log-flush", "--log-file", "--nanolog", "--pcap"}.intersection(effective)
        endpoint = effective[effective.index("--grpc-server-addr") + 1]
        for flag in ("--device-id", "--thrift-port", "--grpc-server-addr"):
            assert effective.count(flag) == 1
        device_id = int(effective[effective.index("--device-id") + 1])
        assert 0 <= device_id < manifest["groups"] and device_id not in device_ids
        device_ids.add(device_id)
        switch = manifest["switch_names"][device_id]
        assert endpoint == f"127.0.0.1:{manifest['service_ports'][2 * device_id]}"
        assert (
            int(effective[effective.index("--thrift-port") + 1])
            == manifest["service_ports"][2 * device_id + 1]
        )
        separator = effective.index("--") if "--" in effective else len(effective)
        core = effective[1:separator]
        interfaces = [
            _value(core, i, option, attached)[0]
            for i, arg in enumerate(core)
            for option, attached in (_option(arg),)
            if option == "--interface"
        ]
        assert interfaces == [
            f"1@{switch}-eth1",
            f"2@{switch}-eth2",
        ]
        if processes is not None:
            assert processes[launch["pid"]]["cmdline"] == effective
        else:
            assert target_pids is not None
            assert launch["pid"] in target_pids
    return {
        "configuration_profile": settings.MATCHED,
        "verified_hosts": len(hosts["hosts"]),
        "verified_bmv2_processes": len(switches),
        "effective_argv_matches_procfs": True,
        "procfs_evidence": (
            "saved-ready-inventory"
            if processes is not None
            else "validated-native-boundary-targets"
        ),
        "device_port_interface_mapping_verified": True,
        "performance_samples": False,
    }
