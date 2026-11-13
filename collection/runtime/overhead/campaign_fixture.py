"""Connect journal checks to protected fixtures without running native tool workloads."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from diagnostic.trace import summarize

from overhead.campaign import Attempt, result_for
from overhead.native_dispatch import run_fixture
from overhead.publication import pointer


class ProtectedFixtureBackend:
    mode = "synthetic-validation"

    def __call__(self, attempt: Attempt) -> dict[str, Any]:
        outcome = run_fixture(Path(attempt.control["path"]))
        reference, receipt = outcome["result"], outcome["receipt"]
        native = reference["native_result"]
        native_ok = None if native is None else native["ok"]
        trace = attempt.directory / "native/diagnostic-trace.jsonl"
        diagnostic = attempt.payload["context"]["diagnostic_profile"] == "native"
        if trace.exists():
            summary = summarize(trace)
            diagnostic = summary["complete"] and not summary["issues"]
        status = "blocked" if native is None else "completed" if native_ok else "failed"
        result = result_for(
            attempt,
            status=status,
            native_ok=native_ok,
            complete=reference["measurement_complete"],
            diagnostic=bool(diagnostic),
            guards=receipt["guard_assessment"]["qualified"]
            and all(receipt["owned_processes_gone"])
            and all(receipt["host_cleanup"].values()),
            reason="protected protocol fixture; no native network tool workflow",
        )
        result["artifacts"] = {
            "reference_result": pointer(attempt.directory / "measurement/reference-result.json"),
            "dispatch_receipt": pointer(attempt.directory / "dispatch-receipt.json"),
        }
        return result
