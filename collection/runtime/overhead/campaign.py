"""Retain calibration attempts, session readiness, and explicit gate reviews."""

from __future__ import annotations

import copy
import os
import re
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast

from harness.spec import names

from overhead import readiness
from overhead.ledger import Ledger, pinned, read
from overhead.model import Context, Identity, integer, text
from overhead.native_binding import read_control
from overhead.native_context import PreparedContext
from overhead.proc import ProcReader
from overhead.publication import pointer, publish

GATES = ("one-switch-wiring", "sixteen-switch-wiring")
STATUSES = ("completed", "failed", "timeout", "blocked", "interrupted")


def same(left: Any, right: Any) -> bool:
    import json

    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(
        right, sort_keys=True, allow_nan=False
    )


def verify_inputs(pin: dict[str, str]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    binding = pinned(pin)
    if (
        set(binding)
        != {
            "schema_version",
            "record_type",
            "mode",
            "allocation",
            "prepared_inputs",
            "native_binding",
            "fixture_binding",
            "preparation_boot_id",
            "previous_freeze",
            "collection_authorized",
            "native_backend_qualified",
        }
        or type(binding["schema_version"]) is not int
        or binding["schema_version"] != 1
        or binding["record_type"] != "diagnostic-overhead-controller-binding"
        or binding["mode"] not in {"pilot", "synthetic-validation"}
        or binding["collection_authorized"] is not False
        or type(binding["native_backend_qualified"]) is not bool
    ):
        raise ValueError("controller input contract differs")
    allocation = pinned(binding["allocation"])
    prepared = pinned(binding["prepared_inputs"])
    pinned(binding["previous_freeze"])
    text(binding["preparation_boot_id"], "preparation boot")
    rows = allocation["tasks"]
    if (
        len(rows) != 360
        or len(prepared["tasks"]) != 360
        or not same([item["allocation_row"] for item in prepared["tasks"]], rows)
    ):
        raise ValueError("prepared inputs differ from the frozen allocation")
    if prepared["native_binding"] != binding["native_binding"]:
        raise ValueError("controller and prepared native bindings differ")
    first_control = prepared["tasks"][0]["control"]
    read_control(first_control, full=True)
    fixture = pinned(binding["fixture_binding"])
    native = pinned(binding["native_binding"])
    if (
        fixture["runtime_files"] != native["runtime_files"]
        or fixture["execution_kind"] != "protected-synthetic"
    ):
        raise ValueError("controller fixture runtime differs")
    return binding, allocation, prepared


@dataclass(frozen=True)
class Attempt:
    directory: Path
    claim: dict[str, str]
    payload: dict[str, Any]
    control: dict[str, str]
    dispatch: dict[str, str]


class Backend(Protocol):
    mode: str

    def __call__(self, attempt: Attempt) -> dict[str, Any]: ...


def validate_result(value: dict[str, Any], claim: dict[str, str], payload: dict[str, Any]) -> None:
    if (
        set(value)
        != {
            "schema_version",
            "record_type",
            "claim",
            "context",
            "status",
            "native_ok",
            "measurement_complete",
            "diagnostic_complete",
            "guards_qualified",
            "artifacts",
            "reason",
            "synthetic_fixture",
        }
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["record_type"] != "diagnostic-overhead-attempt-result"
        or value["claim"] != claim
        or not same(value["context"], payload["context"])
        or value["status"] not in STATUSES
        or (value["native_ok"] is not None and type(value["native_ok"]) is not bool)
        or any(
            type(value[key]) is not bool
            for key in (
                "measurement_complete",
                "diagnostic_complete",
                "guards_qualified",
                "synthetic_fixture",
            )
        )
        or value["synthetic_fixture"] is not (payload["context"]["mode"] == "synthetic-validation")
        or not isinstance(value["artifacts"], dict)
    ):
        raise ValueError("attempt result contract differs")
    text(value["reason"], "result reason")
    if value["status"] == "completed" and value["native_ok"] is not True:
        raise ValueError("completed native outcome requires success")
    if value["status"] != "completed" and value["measurement_complete"]:
        raise ValueError("incomplete native task cannot supply complete measurements")
    for artifact in value["artifacts"].values():
        pinned(artifact)


def qualified(value: Mapping[str, Any]) -> bool:
    return value["status"] == "completed" and all(
        value[key] is True
        for key in ("native_ok", "measurement_complete", "diagnostic_complete", "guards_qualified")
    )


def result_for(
    attempt: Attempt,
    *,
    status: str = "completed",
    native_ok: bool | None = True,
    complete: bool = True,
    diagnostic: bool = True,
    guards: bool = True,
    reason: str = "synthetic functional check",
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "record_type": "diagnostic-overhead-attempt-result",
        "claim": attempt.claim,
        "context": copy.deepcopy(attempt.payload["context"]),
        "status": status,
        "native_ok": native_ok,
        "measurement_complete": complete,
        "diagnostic_complete": diagnostic,
        "guards_qualified": guards,
        "artifacts": {},
        "reason": reason,
        "synthetic_fixture": attempt.payload["context"]["mode"] == "synthetic-validation",
    }


class SyntheticBackend:
    mode = "synthetic-validation"

    def __init__(self, outcomes: Mapping[str, Mapping[str, Any]] | None = None):
        self.outcomes = {} if outcomes is None else copy.deepcopy(dict(outcomes))
        self.calls: list[str] = []

    def __call__(self, attempt: Attempt) -> dict[str, Any]:
        self.calls.append(attempt.payload["attempt_id"])
        return result_for(attempt, **self.outcomes.get(attempt.payload["planned_task_id"], {}))


class Campaign:
    def __init__(
        self,
        output: Path,
        binding_pin: dict[str, str],
        *,
        alive: Callable[[dict[str, Any]], bool] | None = None,
    ):
        self.binding_pin = copy.deepcopy(binding_pin)
        self.binding, self.allocation, self.prepared = verify_inputs(binding_pin)
        self.mode = self.binding["mode"]
        self.ledger = Ledger(output, self.binding_pin)
        self.rows = {row["planned_task_id"]: row for row in self.allocation["tasks"]}
        self.templates = {
            item["allocation_row"]["planned_task_id"]: item["control"]
            for item in self.prepared["tasks"]
        }
        self.alive = self.process_alive if alive is None else alive
        self.attempts: dict[str, list[dict[str, Any]]] = {}
        self.sessions: dict[int, tuple[dict[str, str], dict[str, Any]]] = {}
        self.reviews: dict[str, tuple[dict[str, str], dict[str, Any]]] = {}

    @staticmethod
    def process_alive(value: dict[str, Any]) -> bool:
        try:
            ProcReader().verify(Identity.from_dict(value))
            return True
        except (OSError, ProcessLookupError):
            return False

    def __enter__(self) -> Campaign:
        self.ledger.__enter__()
        try:
            self.replay()
        except BaseException:
            self.ledger.__exit__()
            raise
        return self

    def __exit__(self, *args: Any) -> None:
        self.ledger.__exit__()

    def replay(self, *, read_only: bool = False) -> None:
        self.ledger.reload(read_only=read_only)
        self.attempts, self.sessions, self.reviews = {}, {}, {}
        by_claim: dict[str, dict[str, Any]] = {}
        for pin, event in self.ledger.events:
            payload = event["payload"]
            kind = event["kind"]
            if kind == "session-ready":
                if set(payload) != {"session", "readiness"}:
                    raise ValueError("readiness event fields differ")
                session = integer(payload["session"], "session", 1)
                if session > 3:
                    raise ValueError("unknown calibration session")
                if any(
                    row["session"] < session
                    and (
                        planned not in self.attempts or self.attempts[planned][0]["result"] is None
                    )
                    for planned, row in self.rows.items()
                ):
                    raise ValueError("readiness precedes completion of an earlier session")
                value = pinned(payload["readiness"])
                readiness.validate(value, self.binding_pin, session, self.mode)
                if self.mode == "pilot" and (
                    value["boot_id"] == self.binding["preparation_boot_id"]
                    or any(
                        other != session and previous[1]["boot_id"] == value["boot_id"]
                        for other, previous in self.sessions.items()
                    )
                ):
                    raise ValueError("readiness reused another session's boot")
                self.sessions[session] = (pin, value)
            elif kind == "claim":
                self.validate_claim(payload)
                if any(
                    item["result"] is None for items in self.attempts.values() for item in items
                ):
                    raise ValueError("a preceding attempt is still open")
                planned = payload["planned_task_id"]
                previous = self.attempts.setdefault(planned, [])
                number = len(previous) + 1
                if (
                    payload["attempt_number"] != number
                    or payload["attempt_id"] != f"{planned}--a{number:04d}"
                    or payload["previous_attempt"]
                    != (None if not previous else previous[-1]["claim"])
                ):
                    raise ValueError("attempt numbering differs")
                if previous and previous[-1]["result"] is None:
                    raise ValueError("new attempt precedes the previous terminal result")
                session = self.rows[planned]["session"]
                if number == 1:
                    pending = next(
                        key
                        for key, row in self.rows.items()
                        if (row["session"] == session and key not in self.attempts)
                        or key == planned
                    )
                    if pending != planned:
                        raise ValueError("first attempts changed the frozen task order")
                if (
                    session not in self.sessions
                    or payload["readiness"] != self.sessions[session][0]
                ):
                    raise ValueError("claim has no current session confirmation")
                expected_reviews = self.review_pins(self.rows[planned])
                if payload["gate_reviews"] != expected_reviews:
                    raise ValueError("claim lacks its current reviewed gates")
                item = {
                    "claim": pin,
                    "payload": payload,
                    "dispatch": None,
                    "result": None,
                    "result_pin": None,
                }
                previous.append(item)
                by_claim[pin["sha256"]] = item
            elif kind == "dispatch":
                if set(payload) != {"claim", "control"}:
                    raise ValueError("dispatch fields differ")
                item = by_claim[payload["claim"]["sha256"]]
                if (
                    item["claim"] != payload["claim"]
                    or item["dispatch"] is not None
                    or item["result"] is not None
                ):
                    raise ValueError("invalid or repeated attempt dispatch")
                control, _, context = read_control(payload["control"])
                if not same(context.as_dict(), item["payload"]["context"]):
                    raise ValueError("dispatch control belongs to another attempt")
                if Path(control["manifest"]["path"]).parents[1] != self.attempt_path(
                    item["payload"]
                ):
                    raise ValueError("dispatch manifest escaped the attempt directory")
                item["dispatch"] = pin
            elif kind == "terminal":
                if (
                    set(payload) != {"claim", "result", "recovered"}
                    or type(payload["recovered"]) is not bool
                ):
                    raise ValueError("terminal event fields differ")
                item = by_claim[payload["claim"]["sha256"]]
                if item["claim"] != payload["claim"] or item["result"] is not None:
                    raise ValueError("invalid or repeated terminal result")
                if (
                    Path(payload["result"]["path"])
                    != self.attempt_path(item["payload"]) / "attempt-result.json"
                ):
                    raise ValueError("terminal result escaped the attempt directory")
                value = pinned(payload["result"])
                validate_result(value, item["claim"], item["payload"])
                item.update(result=value, result_pin=payload["result"])
            elif kind == "gate-review":
                self.validate_review(payload)
                self.reviews[payload["gate"]] = (pin, payload)
            else:
                raise ValueError("unknown calibration event kind")
        self.validate_workspaces()

    def validate_claim(self, value: dict[str, Any]) -> None:
        if (
            set(value)
            != {
                "planned_task_id",
                "attempt_number",
                "attempt_id",
                "previous_attempt",
                "context",
                "template",
                "readiness",
                "gate_reviews",
                "owner",
            }
            or value["planned_task_id"] not in self.rows
        ):
            raise ValueError("claim fields differ")
        integer(value["attempt_number"], "attempt number", 1)
        planned = value["planned_task_id"]
        context_type = Context if self.mode == "synthetic-validation" else PreparedContext
        context = context_type.from_dict(value["context"])
        row = self.rows[planned]
        if (
            not re.fullmatch(r"[0-9a-f]{32}", context.run_id)
            or (context.tool, context.diagnostic_profile, context.attempt_id)
            != (row["tool"], row["diagnostic_profile"], value["attempt_id"])
            or value["template"] != self.templates[planned]
        ):
            raise ValueError("claim differs from its frozen task")
        Identity.from_dict(value["owner"])

    def attempt_path(self, payload: dict[str, Any]) -> Path:
        directory = (
            Path(self.ledger.root)
            / "attempts"
            / str(payload["planned_task_id"])
            / f"{payload['attempt_number']:04d}"
        )
        for path in (directory.parent.parent, directory.parent, directory):
            if path.is_symlink() or (path.exists() and not path.is_dir()):
                raise ValueError("attempt path must contain real directories")
        return directory

    def validate_workspaces(self) -> None:
        expected = {
            self.attempt_path(item["payload"]) for items in self.attempts.values() for item in items
        }
        for parent in (self.ledger.root / "attempts").iterdir():
            if parent.is_symlink() or not parent.is_dir() or parent.name not in self.rows:
                raise ValueError("unknown attempt workspace")
            for directory in parent.iterdir():
                if directory.is_symlink() or not directory.is_dir() or directory not in expected:
                    raise ValueError("workspace has no durable attempt claim")

    def gate_tasks(self, gate: str) -> list[str]:
        if gate not in GATES:
            raise ValueError("unknown calibration gate")
        return [planned for planned, row in self.rows.items() if row["initial_stage_gate"] == gate]

    def review_pins(self, row: Mapping[str, Any]) -> list[dict[str, str]]:
        pins = []
        for gate in row["requires_reviewed_gates"]:
            if gate not in self.reviews:
                raise PermissionError("calibration stage requires gate review: " + gate)
            pin, review = self.reviews[gate]
            current = [self.attempts.get(planned, []) for planned in self.gate_tasks(gate)]
            if not review["qualified"] or any(
                not items or items[-1]["result_pin"] != selected
                for items, selected in zip(current, review["selected_results"], strict=True)
            ):
                raise PermissionError("calibration gate is failed or stale: " + gate)
            pins.append(pin)
        return pins

    def validate_review(self, value: dict[str, Any]) -> None:
        if (
            set(value)
            != {"gate", "review_number", "selection", "selected_results", "qualified", "reason"}
            or value["gate"] not in GATES
            or value["selection"] != "latest-attempt"
            or type(value["qualified"]) is not bool
        ):
            raise ValueError("gate review fields differ")
        prior = self.reviews.get(value["gate"])
        if type(value["review_number"]) is not int or value["review_number"] != (
            1 if prior is None else prior[1]["review_number"] + 1
        ):
            raise ValueError("gate review numbering differs")
        text(value["reason"], "gate review reason")
        selected = []
        outcomes = []
        for planned in self.gate_tasks(value["gate"]):
            items = self.attempts.get(planned, [])
            if not items or items[-1]["result"] is None:
                raise ValueError("gate requires a terminal result for every planned task")
            selected.append(items[-1]["result_pin"])
            outcomes.append(qualified(items[-1]["result"]))
        if value["selected_results"] != selected or value["qualified"] is not all(outcomes):
            raise ValueError("gate review differs from its selected result files")

    def confirm_session(self, session: int, *, confirmed: bool) -> dict[str, str]:
        self.replay()
        if any(item["result"] is None for items in self.attempts.values() for item in items):
            raise RuntimeError("resolve open attempts before session confirmation")
        for row in self.rows.values():
            if row["session"] < session and (
                row["planned_task_id"] not in self.attempts
                or self.attempts[row["planned_task_id"]][0]["result"] is None
            ):
                raise PermissionError("preceding session has unfinished first attempts")
        value = readiness.create(
            self.binding_pin,
            session,
            mode=self.mode,
            confirmed=confirmed,
            preparation_boot=self.binding["preparation_boot_id"],
            used_boots={key: item[1]["boot_id"] for key, item in self.sessions.items()},
        )
        path = self.ledger.root / "readiness" / (uuid.uuid4().hex + ".json")
        publish(path, value)
        pin = self.ledger.append("session-ready", {"session": session, "readiness": pointer(path)})
        self.replay()
        return pin

    def review(self, gate: str, *, reason: str) -> dict[str, Any]:
        self.replay()
        results = [self.attempts.get(planned, []) for planned in self.gate_tasks(gate)]
        if any(not items or items[-1]["result"] is None for items in results):
            raise ValueError("gate review requires all terminal results")
        previous = self.reviews.get(gate)
        payload = {
            "gate": gate,
            "review_number": 1 if previous is None else previous[1]["review_number"] + 1,
            "selection": "latest-attempt",
            "selected_results": [items[-1]["result_pin"] for items in results],
            "qualified": all(qualified(items[-1]["result"]) for items in results),
            "reason": reason,
        }
        self.validate_review(payload)
        self.ledger.append("gate-review", payload)
        self.replay()
        return copy.deepcopy(payload)

    def materialize(self, payload: dict[str, Any]) -> dict[str, str]:
        directory = self.attempt_path(payload)
        if directory.exists() or directory.is_symlink():
            raise FileExistsError("attempt workspace already exists")
        template = pinned(payload["template"])
        manifest = copy.deepcopy(pinned(template["manifest"]))
        context = payload["context"]
        manifest.update(
            run_id=context["run_id"],
            prefix="r" + context["run_id"][:6],
            output_dir=str(directory / "native"),
        )
        manifest["host_names"], manifest["switch_names"] = names(
            manifest["prefix"], manifest["groups"]
        )
        fixture = self.mode == "synthetic-validation"
        binding_pin = self.binding["fixture_binding"] if fixture else self.binding["native_binding"]
        if fixture:
            from harness.diagnostic_binding import ROOT, digest

            manifest.pop("diagnostic", None)
            manifest.pop("diagnostic_manifest_dir", None)
            manifest.update(
                fixture_profile=context["diagnostic_profile"],
                fixture_behavior="return",
                fixture_sha256=digest(ROOT / "overhead/protected_fixture.py"),
            )
        elif "diagnostic_manifest_dir" in manifest:
            manifest["diagnostic_manifest_dir"] = manifest["output_dir"]
        for name in ("native", "control", "measurement"):
            (directory / name).mkdir(parents=True)
        manifest_path = directory / "native/manifest.json"
        publish(manifest_path, manifest)
        control_path = directory / "control/task.json"
        publish(
            control_path,
            {
                **template,
                "binding": binding_pin,
                "manifest": pointer(manifest_path),
                "context": context,
                "planned_task_id": None if fixture else payload["planned_task_id"],
            },
        )
        pin = pointer(control_path)
        read_control(pin)
        return pin

    def terminal(
        self,
        claim: dict[str, str],
        payload: dict[str, Any],
        value: dict[str, Any],
        *,
        recovered: bool = False,
    ) -> None:
        validate_result(value, claim, payload)
        path = self.attempt_path(payload) / "attempt-result.json"
        publish(path, value)
        self.ledger.append(
            "terminal", {"claim": claim, "result": pointer(path), "recovered": recovered}
        )

    def reconcile(self) -> list[str]:
        self.replay()
        recovered = []
        for items in self.attempts.values():
            item = items[-1]
            if item["result"] is not None:
                continue
            payload = item["payload"]
            if self.alive(payload["owner"]):
                raise RuntimeError("open attempt still has a live owner")
            directory = self.attempt_path(payload)
            if directory.is_symlink():
                raise ValueError("attempt workspace cannot be a symlink")
            directory.mkdir(parents=True, exist_ok=True)
            recovered_resources = None
            if (directory / "ownership").exists():
                from overhead.native_backend import recover

                dispatch = pinned(item["dispatch"])
                recovered_resources = recover(directory, dispatch["payload"]["control"])
            path = directory / "attempt-result.json"
            if path.exists() or path.is_symlink():
                value = read(path)
                validate_result(value, item["claim"], payload)
                self.ledger.append(
                    "terminal", {"claim": item["claim"], "result": pointer(path), "recovered": True}
                )
            else:
                value = {
                    "schema_version": 1,
                    "record_type": "diagnostic-overhead-attempt-result",
                    "claim": item["claim"],
                    "context": payload["context"],
                    "status": "interrupted",
                    "native_ok": None,
                    "measurement_complete": False,
                    "diagnostic_complete": False,
                    "guards_qualified": False,
                    "artifacts": {},
                    "reason": "owner exited before a validated terminal result was published",
                    "synthetic_fixture": self.mode == "synthetic-validation",
                }
                if recovered_resources is not None:
                    value["native_ok"] = recovered_resources["native_ok"]
                    value["artifacts"].update(recovered_resources["artifacts"])
                    value["artifacts"]["resource_recovery"] = pointer(
                        directory / "ownership-recovery.json"
                    )
                self.terminal(item["claim"], payload, value, recovered=True)
            recovered.append(payload["attempt_id"])
        self.replay()
        return recovered

    def run(
        self, backend: Backend, *, session: int, limit: int | None = None, retry: Sequence[str] = ()
    ) -> dict[str, Any]:
        integer(session, "session", 1)
        if session > 3 or backend.mode != self.mode:
            raise ValueError("backend or session differs from the campaign")
        if self.mode == "pilot":
            from overhead.native_backend import NativeBackend

            if (
                not isinstance(backend, NativeBackend)
                or self.binding["native_backend_qualified"] is not True
            ):
                raise PermissionError("native calibration backend qualification is pending")
        if limit is not None:
            integer(limit, "task limit", 1)
        if isinstance(retry, (str, bytes)) or len(set(retry)) != len(retry):
            raise ValueError("retry selection must contain distinct task identifiers")
        verify_inputs(self.binding_pin)
        self.reconcile()
        if session not in self.sessions:
            raise PermissionError("session readiness has not been confirmed")
        ready_pin, ready = self.sessions[session]
        readiness.validate(ready, self.binding_pin, session, self.mode, current=True)
        if any(
            planned not in self.rows
            or self.rows[planned]["session"] != session
            or planned not in self.attempts
            for planned in retry
        ):
            raise ValueError("retry requires an earlier attempt in this session")
        if self.mode == "pilot":
            cast(Any, backend).preflight()
        executed: list[str] = []
        blocked = None
        for planned, row in self.rows.items():
            if (
                row["session"] != session
                or (retry and planned not in retry)
                or (planned in self.attempts and planned not in retry)
            ):
                continue
            if limit is not None and len(executed) >= limit:
                break
            try:
                reviews = self.review_pins(row)
            except PermissionError as exc:
                blocked = {"planned_task_id": planned, "reason": str(exc)}
                break
            previous = self.attempts.get(planned, [])
            number = len(previous) + 1
            attempt_id = f"{planned}--a{number:04d}"
            context = (
                Context(uuid.uuid4().hex, attempt_id, row["tool"], row["diagnostic_profile"])
                if self.mode == "synthetic-validation"
                else PreparedContext(
                    uuid.uuid4().hex,
                    attempt_id,
                    row["tool"],
                    row["diagnostic_profile"],
                    mode="pilot",
                )
            )
            payload = {
                "planned_task_id": planned,
                "attempt_number": number,
                "attempt_id": attempt_id,
                "previous_attempt": None if not previous else previous[-1]["claim"],
                "context": context.as_dict(),
                "template": self.templates[planned],
                "readiness": ready_pin,
                "gate_reviews": reviews,
                "owner": ProcReader().identity(os.getpid()).as_dict(),
            }
            claim = self.ledger.append("claim", payload)
            executed.append(attempt_id)
            attempt = None
            try:
                control = self.materialize(payload)
                dispatch = self.ledger.append("dispatch", {"claim": claim, "control": control})
                attempt = Attempt(self.attempt_path(payload), claim, payload, control, dispatch)
                response = backend(attempt)
                publish(attempt.directory / "backend-response.json", response)
                validate_result(response, claim, payload)
            except Exception as exc:
                response = {
                    "schema_version": 1,
                    "record_type": "diagnostic-overhead-attempt-result",
                    "claim": claim,
                    "context": context.as_dict(),
                    "status": "blocked",
                    "native_ok": None,
                    "measurement_complete": False,
                    "diagnostic_complete": False,
                    "guards_qualified": False,
                    "artifacts": {},
                    "reason": f"{type(exc).__name__}: {exc}"[:256],
                    "synthetic_fixture": self.mode == "synthetic-validation",
                }
            except BaseException:
                self.attempt_path(payload).mkdir(parents=True, exist_ok=True)
                response = {
                    "schema_version": 1,
                    "record_type": "diagnostic-overhead-attempt-result",
                    "claim": claim,
                    "context": context.as_dict(),
                    "status": "interrupted",
                    "native_ok": None,
                    "measurement_complete": False,
                    "diagnostic_complete": False,
                    "guards_qualified": False,
                    "artifacts": {},
                    "reason": "execution interrupted before validated backend completion",
                    "synthetic_fixture": self.mode == "synthetic-validation",
                }
                self.terminal(claim, payload, response)
                raise
            self.attempt_path(payload).mkdir(parents=True, exist_ok=True)
            self.terminal(claim, payload, response)
            self.attempts.setdefault(planned, []).append(
                {
                    "claim": claim,
                    "payload": payload,
                    "dispatch": None if attempt is None else attempt.dispatch,
                    "result": response,
                    "result_pin": pointer(self.attempt_path(payload) / "attempt-result.json"),
                }
            )
            if not qualified(response):
                break
        return {"executed": executed, "blocked_by_gate": blocked, "coverage": self.coverage()}

    def coverage(self) -> dict[str, Any]:
        self.replay()
        first = [
            items[0]["result"] for items in self.attempts.values() if items[0]["result"] is not None
        ]
        retries = [
            item["result"]
            for items in self.attempts.values()
            for item in items[1:]
            if item["result"] is not None
        ]
        return {
            "planned_first_attempts": 360,
            "terminal_first_attempts": len(first),
            "unobserved_first_attempts": 360 - len(first),
            "first_native_successes": sum(value["native_ok"] is True for value in first),
            "first_measurement_complete": sum(value["measurement_complete"] for value in first),
            "first_gate_qualified": sum(qualified(value) for value in first),
            "first_unknown_native_outcomes": sum(value["native_ok"] is None for value in first),
            "completion_intervals_available": len(first) == 360,
            "retries": len(retries),
            "retry_native_successes": sum(value["native_ok"] is True for value in retries),
            "first_attempts_primary": True,
            "retries_separate": True,
            "performance_samples": self.mode == "pilot",
        }
