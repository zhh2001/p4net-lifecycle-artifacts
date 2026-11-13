"""Coordinate common timing, a single ready hold, and independently published records."""

from __future__ import annotations

import copy
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from overhead.model import Context, Identity, integer
from overhead.publication import pointer, publish
from overhead.wire import ChildReference


class Supervisor:
    def __init__(
        self,
        context: Context,
        reference: ChildReference,
        output: Path,
        *,
        hold_ns: int = 10_000_000_000,
        clock: Callable[[], int] = time.monotonic_ns,
        sleep: Callable[[float], None] = time.sleep,
        publisher: Callable[[Path, dict[str, Any]], None] = publish,
    ):
        if reference.context != context:
            raise ValueError("supervisor and reference identify different tasks")
        self.context, self.reference, self.output = context, reference, output
        self.hold_ns = integer(hold_ns, "hold duration", 1)
        self.clock, self.sleep, self.publisher = clock, sleep, publisher
        self.markers: dict[str, int] = {}
        self.hold: dict[str, Any] | None = None
        self.issues: list[dict[str, str]] = []
        self.previous_clock = -1

    def now(self) -> int:
        value = integer(self.clock(), "supervisor clock")
        if value < self.previous_clock:
            raise ValueError("supervisor clock moved backward")
        self.previous_clock = value
        return value

    def issue(self, context: str, exc: BaseException) -> None:
        self.issues.append({"context": context, "type": type(exc).__name__, "message": str(exc)})

    def notify(self, boundary: str, payload: dict[str, Any]) -> None:
        if self.reference.failed:
            return
        try:
            self.reference.checkpoint(boundary, payload)
        except Exception as exc:
            self.issue(boundary, exc)

    def mark(self, name: str) -> None:
        try:
            if (
                name
                not in {
                    "worker_launch",
                    "validated_ready",
                    "stop_request",
                    "worker_exit",
                    "ordinary_audit_end",
                }
                or name in self.markers
            ):
                raise ValueError("invalid or duplicate lifecycle marker")
            if name != "worker_launch" and "worker_launch" not in self.markers:
                raise ValueError("lifecycle marker precedes worker launch")
            if name in {"validated_ready", "stop_request"} and "worker_exit" in self.markers:
                raise ValueError("live-worker marker follows exit")
            if name == "validated_ready" and "stop_request" in self.markers:
                raise ValueError("readiness follows stop")
            self.markers[name] = self.now()
        except Exception as exc:
            self.issue("lifecycle:" + name, exc)

    def ready(self, worker: Identity) -> None:
        if self.hold is not None:
            self.issue("ready", ValueError("ready hold was already requested"))
            return
        self.mark("validated_ready")
        self.hold = {"requested_duration_ns": self.hold_ns, "complete": False}
        try:
            anchor = self.now()
            deadline = anchor + self.hold_ns
            self.hold.update(anchor_ns=anchor, scheduled_end_ns=deadline)
            self.notify(
                "ref_ready",
                {
                    "worker": worker.as_dict(),
                    "hold_anchor_ns": anchor,
                    "hold_deadline_ns": deadline,
                },
            )
            current = self.now()
            while current < deadline:
                self.sleep((deadline - current) / 1_000_000_000)
                after = self.now()
                if after <= current:
                    raise ValueError("ready hold clock did not advance")
                current = after
            self.hold.update(
                complete=True, callback_end_ns=current, extension_ns=current - deadline
            )
        except Exception as exc:
            self.issue("ready hold", exc)

    def run(
        self,
        execute: Callable[[Supervisor], dict[str, Any]],
        *,
        prepare: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        # Failed entry acknowledgment blocks dispatch; later transport faults allow native cleanup.
        self.reference.checkpoint("ref_begin")
        result = None
        outcome: dict[str, Any] = {"status": "not-invoked"}
        try:
            if prepare is not None:
                prepare()
            outcome = {"status": "invoked"}
            result = execute(self)
            outcome = {"status": "returned"}
            return result
        except BaseException as exc:
            outcome = {"status": "raised", "exception_type": type(exc).__name__}
            raise
        finally:
            try:
                primary = {
                    "schema_version": 1,
                    "record_type": "diagnostic-calibration-primary",
                    "context": self.context.as_dict(),
                    "native_result": copy.deepcopy(result),
                    "native_outcome": outcome,
                    "markers": dict(self.markers),
                    "hold": copy.deepcopy(self.hold),
                    "issues": copy.deepcopy(self.issues),
                }
                path = self.output / "primary.json"
                self.publisher(path, primary)
                self.notify("ref_primary_published", {"primary": pointer(path)})
                child = {
                    "schema_version": 1,
                    "record_type": "diagnostic-calibration-child",
                    "context": self.context.as_dict(),
                    "primary": pointer(path),
                    "native_result": copy.deepcopy(result),
                    "native_outcome": outcome,
                    "markers": dict(self.markers),
                    "hold": copy.deepcopy(self.hold),
                    "issues": copy.deepcopy(self.issues),
                }
                path = self.output / "child.json"
                self.publisher(path, child)
                self.notify("ref_complete", {"child": pointer(path)})
            except BaseException as exc:
                self.issue("publication", exc)
