"""Apply and verify the matched host configuration through public host APIs."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

MATCHED = "matched-v1"
FEATURE_KEYS = {"rx": "rx-checksumming", "tx": "tx-checksumming", "sg": "scatter-gather"}
Runner = Callable[[list[str]], subprocess.CompletedProcess[bytes]]


def matched(manifest: dict[str, Any]) -> bool:
    profile = manifest.get("configuration_profile", "native")
    if profile not in {"native", MATCHED}:
        raise ValueError(f"unknown configuration profile: {profile}")
    return bool(profile == MATCHED)


def ping_command(destination: str) -> list[str]:
    return ["ping", "-n", "-c", "1", "-W", "2", "-w", "4", destination]


def run_command(run: Runner, argv: list[str]) -> str:
    result = run(argv)
    if result.returncode:
        stderr = result.stderr.decode(errors="replace") if result.stderr else ""
        raise RuntimeError(f"host command failed: {argv!r}: {stderr}")
    return result.stdout.decode() if result.stdout else ""


def parse_features(text: str) -> dict[str, bool]:
    values: dict[str, bool] = {}
    for line in text.splitlines():
        if line.startswith((" ", "\t")) or ":" not in line:
            continue
        name, value = line.split(":", 1)
        for short, full in FEATURE_KEYS.items():
            if name == full:
                token = value.strip().split()[0]
                if token not in {"on", "off"} or short in values:
                    raise ValueError(f"invalid or duplicate offload state: {name}")
                values[short] = token == "on"
    if set(values) != set(FEATURE_KEYS):
        raise ValueError("offload report does not contain all required features")
    return values


def configure_host(row: dict[str, Any], iface: str, run: Runner) -> dict[str, Any]:
    commands = [
        ["ip", "link", "set", "dev", iface, "mtu", "1500"],
        ["ethtool", "-K", iface, "rx", "off", "tx", "off", "sg", "off"],
    ]
    scopes = ("all", "default", "lo", iface)
    keys = [f"net.ipv6.conf.{scope}.disable_ipv6" for scope in scopes]
    commands.append(["sysctl", "-w", *[key + "=1" for key in keys]])
    for argv in commands:
        run_command(run, argv)
    link_text = run_command(run, ["ip", "-j", "addr", "show", "dev", iface])
    links = json.loads(link_text)
    if not isinstance(links, list) or len(links) != 1:
        raise RuntimeError("host interface snapshot is incomplete")
    link = links[0]
    features_text = run_command(run, ["ethtool", "-k", iface])
    features = parse_features(features_text)
    ipv6_values = run_command(run, ["sysctl", "-n", *keys]).splitlines()
    ipv4 = [
        f"{a['local']}/{a['prefixlen']}"
        for a in link.get("addr_info", [])
        if a.get("family") == "inet"
    ]
    ipv6 = [a for a in link.get("addr_info", []) if a.get("family") == "inet6"]
    if (
        link.get("ifname") != iface
        or link.get("mtu") != 1500
        or str(link.get("address")).lower() != row["mac"].lower()
        or ipv4 != [row["ip"] + "/24"]
        or ipv6
        or features != {"rx": False, "tx": False, "sg": False}
        or ipv6_values != ["1"] * len(keys)
    ):
        raise RuntimeError(f"matched host postconditions failed for {row['host']}")
    return {
        "host": row["host"],
        "interface": iface,
        "mtu": link["mtu"],
        "mac": link["address"].lower(),
        "ipv4": ipv4,
        "ipv6_disabled": {"all": True, "default": True, "lo": True, "interface": True},
        "offloads": features,
        "commands": commands,
        "raw_link": link,
        "raw_features": features_text,
    }


def mininet_runner(host: Any) -> Runner:
    def run(argv: list[str]) -> subprocess.CompletedProcess[bytes]:
        process = host.popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = process.communicate(timeout=6)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise
        return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)

    return run


def write_hosts(manifest: dict[str, Any], hosts: list[dict[str, Any]]) -> None:
    if len(hosts) != len(manifest["host_names"]):
        raise ValueError("host configuration inventory is incomplete")
    value = {
        "configuration_profile": MATCHED,
        "performance_samples": False,
        "hosts": hosts,
        "ping_argv_template": ping_command("DESTINATION"),
    }
    (Path(manifest["output_dir"]) / "host-settings.json").write_text(
        json.dumps(value, indent=2) + "\n"
    )
