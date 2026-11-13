"""Record nested synchronous scopes without changing native return or exception behavior."""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any


class Trace:
    def __init__(
        self, path: Path, run_id: str, profile: str, *, clock: Callable[[], int] = time.monotonic_ns
    ) -> None:
        if profile not in {"off", "stages", "detail"}:
            raise ValueError("unknown diagnostic profile")
        self.path, self.run_id, self.profile = path, run_id, profile
        self.closure_path = path.with_name(path.name + ".closure.json")
        if self.closure_path.exists():
            raise FileExistsError(self.closure_path)
        self.clock = clock
        self.errors: list[str] = []
        self._lock = threading.RLock()
        self._local = threading.local()
        self._next = 0
        self._open: set[int] = set()
        self._closed = False
        self._metadata: dict[str, Any] = {}
        self._fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC, 0o600)
        self._emit(
            "header",
            run_id=run_id,
            profile=profile,
            pid=os.getpid(),
            clock_domain="diagnostic-monotonic-ns-v1",
            schema_version=1,
        )

    def _emit(self, kind: str, **fields: Any) -> None:
        with self._lock:
            if self._closed:
                self.errors.append("write after diagnostic trace closed")
                return
            try:
                row = {"kind": kind, "time_ns": self.clock(), **fields}
                payload = (json.dumps(row, separators=(",", ":"), allow_nan=False) + "\n").encode()
                offset = 0
                while offset < len(payload):
                    count = os.write(self._fd, payload[offset:])
                    if count <= 0:
                        raise OSError("trace write made no progress")
                    offset += count
            except Exception as exc:
                self.errors.append(f"{type(exc).__name__}: {exc}")

    @contextmanager
    def span(self, stage: str) -> Iterator[None]:
        if self.profile == "off":
            yield
            return
        stack: list[int] = getattr(self._local, "stack", [])
        self._local.stack = stack
        with self._lock:
            self._next += 1
            identity = self._next
            self._open.add(identity)
            parent = stack[-1] if stack else None
            self._emit(
                "begin",
                span_id=identity,
                parent_span_id=parent,
                stage=stage,
                thread_id=threading.get_ident(),
            )
        stack.append(identity)
        outcome = "returned"
        exception = None
        try:
            yield
        except BaseException as exc:
            outcome, exception = "raised", type(exc).__name__
            raise
        finally:
            if not stack or stack.pop() != identity:
                self.errors.append("diagnostic span nesting changed")
            self._emit(
                "end",
                span_id=identity,
                stage=stage,
                thread_id=threading.get_ident(),
                outcome=outcome,
                exception_type=exception,
            )
            with self._lock:
                self._open.discard(identity)

    def checkpoint(self, name: str) -> None:
        if self.profile != "off":
            self._emit("checkpoint", name=name, thread_id=threading.get_ident())

    def close(self, **metadata: Any) -> dict[str, Any]:
        with self._lock:
            if not self._closed:
                self._metadata = metadata
                if self._open:
                    self.errors.append("close with unfinished diagnostic spans")
                self._emit("footer", errors=list(self.errors), **metadata)
                try:
                    os.fsync(self._fd)
                except OSError as exc:
                    self.errors.append(f"{type(exc).__name__}: {exc}")
                finally:
                    try:
                        os.close(self._fd)
                    except OSError as exc:
                        self.errors.append(f"{type(exc).__name__}: {exc}")
                    self._closed = True
                receipt = {
                    "run_id": self.run_id,
                    "profile": self.profile,
                    "complete": not self.errors,
                    "errors": list(self.errors),
                    "metadata": self._metadata,
                }
                try:
                    with self.closure_path.open("x") as stream:
                        json.dump(receipt, stream, allow_nan=False)
                        stream.write("\n")
                except Exception as exc:
                    self.errors.append(f"{type(exc).__name__}: {exc}")
            return {
                "run_id": self.run_id,
                "profile": self.profile,
                "complete": not self.errors,
                "errors": list(self.errors),
                "metadata": self._metadata,
            }


def summarize(path: Path) -> dict[str, Any]:
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    if not rows or rows[0].get("kind") != "header":
        raise ValueError("diagnostic header missing")
    if (
        rows[0].get("schema_version") != 1
        or rows[0].get("profile") not in {"off", "stages", "detail"}
        or rows[0].get("clock_domain") != "diagnostic-monotonic-ns-v1"
    ):
        raise ValueError("diagnostic header contract differs")
    active: dict[int, dict[str, Any]] = {}
    spans: dict[int, dict[str, Any]] = {}
    stacks: dict[int, list[int]] = {}
    issues: list[str] = []
    previous = -1
    footer = None
    for index, row in enumerate(rows):
        stamp = row.get("time_ns")
        if type(stamp) is not int or stamp < 0 or stamp < previous:
            raise ValueError("diagnostic timestamps are invalid or out of order")
        previous = stamp
        kind = row.get("kind")
        if kind in {"begin", "end"} and (
            type(row.get("span_id")) is not int
            or row["span_id"] <= 0
            or type(row.get("thread_id")) is not int
            or row["thread_id"] <= 0
            or not isinstance(row.get("stage"), str)
            or not row["stage"]
        ):
            raise ValueError("invalid diagnostic scope identity")
        if kind == "header":
            if index != 0:
                raise ValueError("duplicate diagnostic header")
        elif kind == "begin":
            identity, thread = row["span_id"], row["thread_id"]
            stack = stacks.setdefault(thread, [])
            parent = row.get("parent_span_id")
            if parent is not None and (type(parent) is not int or parent <= 0):
                raise ValueError("invalid diagnostic parent identity")
            if identity in active or identity in spans:
                raise ValueError("duplicate diagnostic span")
            if row["parent_span_id"] != (stack[-1] if stack else None):
                raise ValueError("diagnostic parent differs from thread stack")
            active[identity] = row
            stack.append(identity)
        elif kind == "end":
            identity, thread = row["span_id"], row["thread_id"]
            start = active.pop(identity, None)
            stack = stacks.get(thread, [])
            if start is None or not stack or stack.pop() != identity:
                raise ValueError("unmatched diagnostic end")
            if start["thread_id"] != thread or start["stage"] != row["stage"]:
                raise ValueError("diagnostic scope identity changed")
            if row.get("outcome") not in {"returned", "raised"}:
                raise ValueError("unknown diagnostic outcome")
            spans[identity] = {
                "span_id": identity,
                "parent_span_id": start["parent_span_id"],
                "stage": row["stage"],
                "thread_id": thread,
                "begin_ns": start["time_ns"],
                "end_ns": stamp,
                "inclusive_ns": stamp - start["time_ns"],
                "outcome": row["outcome"],
                "exception_type": row["exception_type"],
            }
        elif kind == "footer":
            if index != len(rows) - 1:
                raise ValueError("diagnostic footer is not the last event")
            footer = row
        elif kind != "checkpoint":
            raise ValueError("unknown diagnostic event")
    for span in spans.values():
        children = [s for s in spans.values() if s["parent_span_id"] == span["span_id"]]
        child_ns = sum(child["inclusive_ns"] for child in children)
        span["exclusive_ns"] = span["inclusive_ns"] - child_ns
        if span["exclusive_ns"] < 0:
            raise ValueError("child scopes exceed parent duration")
    if active:
        issues.append("unfinished diagnostic spans")
    if footer is None:
        issues.append("diagnostic footer missing")
    elif footer.get("errors"):
        issues.extend(footer["errors"])
    closure_path = path.with_name(path.name + ".closure.json")
    if not closure_path.is_file():
        issues.append("diagnostic closure receipt missing")
    else:
        closure = json.loads(closure_path.read_text())
        if any(closure.get(key) != rows[0].get(key) for key in ("run_id", "profile")):
            raise ValueError("diagnostic closure identity differs")
        metadata = {
            key: value
            for key, value in (footer or {}).items()
            if key not in {"kind", "time_ns", "errors"}
        }
        if footer is not None and closure.get("metadata") != metadata:
            raise ValueError("diagnostic closure metadata differs")
        if closure.get("complete") is not True or closure.get("errors") != []:
            issues.append("diagnostic writer did not close cleanly")
    return {
        "run_id": rows[0]["run_id"],
        "profile": rows[0]["profile"],
        "complete": not issues,
        "issues": issues,
        "spans": list(spans.values()),
        "unfinished_spans": list(active.values()),
        "metadata": {
            key: value
            for key, value in (footer or {}).items()
            if key not in {"kind", "time_ns", "errors"}
        },
        "exclusive_scope": "Same-thread direct children only; concurrent roots may overlap",
    }
