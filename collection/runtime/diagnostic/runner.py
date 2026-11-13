"""Run an explicitly selected worker through optional diagnostic hooks."""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any

from diagnostic.hooks import Hook, Session
from diagnostic.stacks import StackEndpoint
from diagnostic.trace import Trace


def run_worker(
    module_name: str,
    manifest: Path,
    trace_path: Path,
    hooks: list[Hook],
    profile: str,
    *,
    stacks: bool = False,
) -> tuple[int, dict[str, Any]]:
    """Caller owns dispatch authorization and isolation; this function launches no child worker."""
    data = json.loads(manifest.read_text())
    run_id = data["run_id"]
    trace = Trace(trace_path, run_id, profile)
    session = None
    endpoint = None
    invoked = False
    outcome: dict[str, Any] = {"status": "not-invoked"}
    try:
        session = Session(trace, hooks)
        endpoint = (
            StackEndpoint(
                trace_path.with_name("threads.txt"),
                trace_path.with_name("stack-ready.json"),
                run_id,
            )
            if stacks
            else None
        )
        with session:
            if endpoint is not None:
                endpoint.__enter__()
            try:
                worker = importlib.import_module(module_name)
                invoked = True
                result = worker.execute(manifest)
                outcome = {"status": "returned", "returncode": result}
            finally:
                if endpoint is not None:
                    endpoint.__exit__(None, None, None)
                    trace.errors.extend(endpoint.errors)
    except BaseException as exc:
        outcome = {"status": "raised", "exception_type": type(exc).__name__}
        raise
    finally:
        receipt = trace.close(
            hook_coverage=session.coverage() if session is not None else [],
            stack_endpoint_enabled=stacks,
            worker_invoked=invoked,
            worker_outcome=outcome,
        )
    return result, receipt
