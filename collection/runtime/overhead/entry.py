"""Run each treatment in its existing process and retain an independent CPU end record."""

from __future__ import annotations

import hashlib
import importlib.machinery
import os
import runpy
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

from overhead.model import Context, Identity
from overhead.proc import ProcReader
from overhead.publication import publish
from overhead.reference import cpu_endpoint

T = TypeVar("T")


@dataclass(frozen=True)
class Entry:
    module: str
    source: Path
    sha256: str

    def verify(self) -> None:
        path = None
        fullname = ""
        spec = None
        for part in self.module.split("."):
            fullname = part if not fullname else fullname + "." + part
            spec = importlib.machinery.PathFinder.find_spec(fullname, path)
            if spec is None:
                raise ImportError(fullname)
            path = spec.submodule_search_locations
        if (
            not self.source.is_absolute()
            or spec is None
            or spec.origin is None
            or Path(spec.origin).resolve() != self.source.resolve()
        ):
            raise ImportError("worker entry resolved outside its pinned source")
        if hashlib.sha256(self.source.read_bytes()).hexdigest() != self.sha256:
            raise ValueError("worker entry source changed")

    def invoke(self, arguments: list[str]) -> None:
        self.verify()
        original = sys.argv
        try:
            sys.argv = [self.module, *arguments]
            runpy.run_module(self.module, run_name="__main__", alter_sys=True)
        finally:
            sys.argv = original


def run_entry(
    context: Context,
    invoke: Callable[[], T],
    output: Path,
    *,
    identity: Identity,
    read_cpu: Callable[[], dict[str, Any]],
    publisher: Callable[[Path, dict[str, Any]], None] = publish,
    clock: Callable[[], int] = time.monotonic_ns,
    report_issue: Callable[[str], None] | None = None,
) -> T:
    """Measurement failures do not replace the selected entry's return or exception."""
    outcome: dict[str, Any] = {"status": "not-invoked"}
    try:
        result = invoke()
        outcome = {"status": "returned"}
        return result
    except BaseException as exc:
        outcome = {"status": "raised", "exception_type": type(exc).__name__}
        if isinstance(exc, SystemExit):
            outcome["exit_code"] = (
                exc.code if isinstance(exc.code, (int, str)) or exc.code is None else str(exc.code)
            )
        raise
    finally:
        try:
            cpu = cpu_endpoint(read_cpu(), identity)
            if not Identity.from_dict(cpu["identity"]).same_process(identity):
                raise ProcessLookupError("worker end CPU identity differs")
            value = {
                "schema_version": 1,
                "record_type": "diagnostic-worker-cpu-end",
                "context": context.as_dict(),
                "worker_identity": identity.as_dict(),
                "native_outcome": outcome,
                "cpu": cpu,
                "scope": "process-start-through-selected-entry-completion",
                "before_own_publication_ns": clock(),
                "interpreter_finalization_included": False,
            }
            publisher(output, value)
        except BaseException as exc:
            message = f"worker CPU end record unavailable: {type(exc).__name__}: {exc}"
            try:
                if report_issue is None:
                    print(message, file=sys.stderr)
                else:
                    report_issue(message)
            except BaseException:
                pass


def run_module(context: Context, entry: Entry, arguments: list[str], output: Path) -> None:
    reader = ProcReader()
    identity = reader.identity(os.getpid())
    run_entry(
        context,
        lambda: entry.invoke(arguments),
        output,
        identity=identity,
        read_cpu=lambda: reader.cpu(identity, self_read=True),
    )


def main() -> None:
    """The current CLI accepts only the two source-pinned synthetic fixture entries."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--synthetic-config", type=Path, required=True)
    config = json.loads(parser.parse_args().synthetic_config.read_text())
    if (
        set(config) != {"schema_version", "record_type", "context", "entry", "arguments", "output"}
        or type(config["schema_version"]) is not int
        or config["schema_version"] != 1
        or config["record_type"] != "synthetic-diagnostic-entry"
    ):
        raise ValueError("synthetic entry configuration differs")
    context = Context.from_dict(config["context"])
    expected = "native" if context.diagnostic_profile == "native" else "instrumented"
    source = Path(__file__).resolve().parents[1] / "overhead_fixtures" / (expected + ".py")
    target = config["entry"]
    if (
        set(target) != {"module", "source", "sha256"}
        or target["module"] != "overhead_fixtures." + expected
        or Path(target["source"]) != source
    ):
        raise ValueError("synthetic entry target differs from its treatment")
    if not isinstance(config["arguments"], list) or not all(
        isinstance(arg, str) for arg in config["arguments"]
    ):
        raise ValueError("worker arguments must be strings")
    run_module(
        context,
        Entry(target["module"], source, target["sha256"]),
        config["arguments"],
        Path(config["output"]),
    )


if __name__ == "__main__":
    main()
