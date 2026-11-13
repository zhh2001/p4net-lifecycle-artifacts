"""Exercise the native line protocol without creating hosts or switches."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from harness.events import emit, serve_commands


def detail() -> int:
    return sum(range(10))


def execute(path: Path) -> int:
    data = json.loads(path.read_text())
    emit(data, "starting")
    emit(data, "inventory", processes=[])
    behavior = data.get("fixture_behavior", "return")
    if behavior == "raise":
        raise RuntimeError("protected fixture failure")
    if behavior == "exit7":
        return 7
    if behavior == "interrupt":
        raise KeyboardInterrupt("protected fixture interruption")
    detail()
    hosts = data["host_names"]
    checks = [
        {"src": hosts[i + direction], "dst": hosts[i + 1 - direction], "ok": True}
        for i in range(0, len(hosts), 2)
        for direction in (0, 1)
    ]
    emit(data, "ready", checks=checks, worker_pid=os.getpid(), synthetic_checks=True)
    serve_commands(data, lambda: {"entries": 0})
    emit(data, "stopped")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    return execute(parser.parse_args().manifest)


if __name__ == "__main__":
    raise SystemExit(main())
