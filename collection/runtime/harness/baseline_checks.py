"""Run equivalent baseline tasks serially and verify host isolation guards."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from harness import isolation, spec

PAPER = Path(__file__).resolve().parents[1]


def host_links() -> list[dict[str, Any]]:
    raw = json.loads(subprocess.check_output(["ip", "-j", "link", "show"], text=True))
    return [
        {key: link.get(key) for key in ("ifindex", "ifname", "address", "mtu", "operstate")}
        for link in raw
    ]


def check_one(
    manifest_path: Path, python: Path, worker: str, *, boundary_validation: bool = False
) -> dict[str, Any]:
    manifest = spec.load(manifest_path)
    before = host_links()
    hugepages = Path("/proc/sys/vm/nr_hugepages").read_text()
    host_file = Path("/tmp") / f"research-{manifest['run_id']}.log"
    if host_file.exists():
        raise FileExistsError(host_file)
    host_file.write_text("outer host fixture\n")
    guard = subprocess.Popen(["mininet:outside-guard", "240"], executable="/bin/sleep")
    try:
        result = isolation.run_isolated(
            manifest_path, python, worker, guards=True, boundary_validation=boundary_validation
        )
        assert host_links() == before, "host network links changed"
        assert Path("/proc/sys/vm/nr_hugepages").read_text() == hugepages
        assert host_file.read_text() == "outer host fixture\n"
        assert guard.poll() is None, "outer process sentinel was terminated"
        record = json.loads(Path(result["isolation_record"]).read_text())
        assert all(
            record["inner_namespaces"][key] != record["outer_namespaces"][key]
            for key in isolation.NAMESPACES
        )
        if worker == "harness.worker_p4utils":
            assert record["inner_log_sentinel_remaining"] is False, record
            assert record["inner_process_sentinel_running"] is False, record
        result["host_guards"] = {
            "network_links_unchanged": True,
            "hugepages_unchanged": True,
            "outer_log_survived": True,
            "outer_process_survived": True,
            "inner_cleanup_observations": {
                "log_remaining": record["inner_log_sentinel_remaining"],
                "process_running": record["inner_process_sentinel_running"],
            },
        }
        return result
    finally:
        if guard.poll() is None:
            guard.terminate()
        guard.wait(timeout=5)
        host_file.unlink(missing_ok=True)


def check_watchdog(output: Path) -> dict[str, Any]:
    path = spec.create(output)
    try:
        isolation.run_isolated(
            path, Path(sys.executable), "harness_tests.fixtures.hang_worker", timeout=5
        )
    except TimeoutError:
        pass
    else:
        raise AssertionError("the deliberately unready worker escaped the watchdog")
    record_path = output.parent / f"{output.name}-isolation.json"
    record = json.loads(record_path.read_text())
    expected = record["inner_namespaces"]["pid"]

    def holders() -> list[int]:
        found = []
        for item in Path("/proc").iterdir():
            if not item.name.isdecimal():
                continue
            try:
                if os.readlink(item / "ns/pid") == expected:
                    found.append(int(item.name))
            except (FileNotFoundError, ProcessLookupError):
                continue
        return found

    remaining = holders()
    for _ in range(50):
        if not remaining:
            break
        time.sleep(0.02)
        remaining = holders()
    assert not remaining, remaining
    result = {
        "expected_timeout": True,
        "namespace_processes_remaining": remaining,
        "performance_samples": False,
    }
    (output / "watchdog-check.json").write_text(json.dumps(result, indent=2) + "\n")
    return result
