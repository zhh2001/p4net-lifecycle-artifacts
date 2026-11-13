"""Exercise the ordinary worker protocol without constructing network resources."""

import argparse
import json
import os
import sys
from pathlib import Path

from overhead.proc import ProcReader


def prepare() -> int:
    return sum(range(40))


def detail() -> int:
    return sum(range(60))


def execute(path: Path) -> int:
    data = json.loads(path.read_text())
    prepare()
    detail()
    if data.get("behavior") == "raise":
        raise RuntimeError("synthetic native failure")
    if data.get("behavior") == "exit":
        raise SystemExit(7)
    if data.get("behavior") == "interrupt":
        raise KeyboardInterrupt("synthetic native interruption")
    print(
        json.dumps(
            {
                "event": "ready",
                "worker": ProcReader().identity(os.getpid()).as_dict(),
                "diagnostic_loaded": any(
                    name == "diagnostic" or name.startswith("diagnostic.") for name in sys.modules
                ),
            }
        ),
        flush=True,
    )
    if sys.stdin.readline() != "stop\n":
        raise ValueError("synthetic stop command was not received")
    detail()
    print(json.dumps({"event": "stopped"}), flush=True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    return execute(parser.parse_args().manifest)


if __name__ == "__main__":
    raise SystemExit(main())
