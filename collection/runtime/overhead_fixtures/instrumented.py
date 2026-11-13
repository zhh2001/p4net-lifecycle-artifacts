"""Apply the qualified diagnostic package to the same synthetic worker body."""

import argparse
import json
from pathlib import Path

from diagnostic.hooks import Hook
from diagnostic.runner import run_worker


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    path = parser.parse_args().manifest
    data = json.loads(path.read_text())
    source = Path(__file__).with_name("native.py")
    hooks = [
        Hook(
            "overhead_fixtures.native",
            "",
            member,
            stage,
            str(source),
            data["native_source_sha256"],
            level,
        )
        for member, stage, level in (
            ("execute", "worker.workflow", "stages"),
            ("prepare", "task.prepare", "stages"),
            ("detail", "task.detail", "detail"),
        )
    ]
    result, _receipt = run_worker(
        "overhead_fixtures.native",
        path,
        path.parent / "diagnostic-trace.jsonl",
        hooks,
        data["diagnostic_profile"],
    )
    return result


if __name__ == "__main__":
    raise SystemExit(main())
