"""Close fixture diagnostics before the common worker CPU endpoint."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from diagnostic.hooks import Hook
from diagnostic.runner import run_worker


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    path = parser.parse_args().manifest
    data = json.loads(path.read_text())
    source = Path(__file__).with_name("protected_fixture.py")
    hooks = [
        Hook(
            "overhead.protected_fixture",
            "",
            member,
            stage,
            str(source),
            data["fixture_sha256"],
            level,
        )
        for member, stage, level in (
            ("execute", "worker.workflow", "stages"),
            ("detail", "task.detail", "detail"),
        )
    ]
    result, _ = run_worker(
        "overhead.protected_fixture",
        path,
        path.parent / "diagnostic-trace.jsonl",
        hooks,
        data["fixture_profile"],
    )
    if type(result) is not int:
        raise TypeError("fixture entry returned a noninteger code")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
