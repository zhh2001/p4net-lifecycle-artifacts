"""Attach diagnostic capture after ordinary audit while preserving native supervision."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from diagnostic.stacks import request_stack

from harness import isolation, native_measurement
from harness.diagnostic_binding import case_for, verify
from harness.spec import load

OriginalObservation = native_measurement.Observation


class DiagnosticObservation(OriginalObservation):
    def __init__(self, manifest: dict[str, Any], case: dict[str, Any]) -> None:
        super().__init__()
        self.manifest = manifest
        self.case = case
        self.capture_attempts: set[str] = set()

    def mark(self, name: str, *, phase: str = "initial", observed_ns: int | None = None) -> None:
        super().mark(name, phase=phase, observed_ns=observed_ns)
        if name != "ordinary_audit_end" or phase != "initial" or not self.case["stacks"]:
            return
        if phase in self.capture_attempts:
            return
        self.capture_attempts.add(phase)
        directory = Path(self.manifest["output_dir"]) / phase
        result: dict[str, Any] = {"phase": phase, "after_ordinary_audit": True}
        try:
            ready_path = directory / "stack-ready.json"
            ready = json.loads(ready_path.read_text())
            from harness.supervisor import process_identity

            identity = process_identity(ready["pid"])
            if identity is None:
                result.update(status="worker-exited", capture_complete=False)
            elif identity["start_ticks"] != ready["start_ticks"]:
                raise ProcessLookupError("diagnostic worker identity changed")
            else:
                capture = request_stack(
                    ready_path, ready["run_id"], ready["pid"], ready["start_ticks"], "afteraudit"
                )
                result.update(
                    status="captured" if capture.get("capture_complete") else "capture-failed",
                    capture=capture,
                )
        except Exception as exc:
            result.update(status="capture-failed", error_type=type(exc).__name__, message=str(exc))
        try:
            with (directory / "diagnostic-capture.json").open("x") as stream:
                json.dump(result, stream, indent=2)
                stream.write("\n")
        except Exception as exc:
            self.issue("diagnostic capture receipt", exc)


def inside(path: Path, python: Path, worker: str, outer: dict[str, str]) -> int:
    manifest = load(path)
    binding = verify(manifest["diagnostic"]["binding"])
    case = case_for(manifest, binding)
    if python != Path(binding["tools"][case["tool"]]["interpreter"]):
        raise ValueError("diagnostic enclosure interpreter differs")
    if worker != "harness.diagnostic_worker":
        raise ValueError("diagnostic enclosure worker differs")

    # The existing enclosure constructs its boundary observer after namespace setup.
    # Replacing only that constructor leaves worker and cleanup control in the native supervisor.
    class BoundObservation(DiagnosticObservation):
        def __init__(self) -> None:
            super().__init__(manifest, case)

    module: Any = native_measurement
    original = module.Observation
    try:
        module.Observation = BoundObservation
        return isolation.inside(path, python, worker, outer, guards=True, boundary_validation=True)
    finally:
        module.Observation = original


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--worker", required=True)
    parser.add_argument("--outer-namespaces", type=json.loads, required=True)
    parser.add_argument("--inside", action="store_true", required=True)
    parser.add_argument("--verify-guards", action="store_true", required=True)
    parser.add_argument("--validate-boundaries", action="store_true", required=True)
    args = parser.parse_args()
    return inside(args.manifest, args.python, args.worker, args.outer_namespaces)


if __name__ == "__main__":
    raise SystemExit(main())
