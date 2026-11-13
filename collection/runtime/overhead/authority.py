"""Bind native dispatch to an open journal claim, source inputs, readiness, and reviews."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from overhead.campaign import Attempt, Campaign
from overhead.ledger import pinned
from overhead.native_binding import read_control
from overhead.publication import pointer, publish
from overhead.readiness import validate


def create(attempt: Attempt) -> dict[str, str]:
    event = pinned(attempt.claim)
    path = attempt.directory / "execution-permit.json"
    publish(
        path,
        {
            "schema_version": 1,
            "record_type": "diagnostic-native-execution-permit",
            "journal": str(attempt.directory.parents[2]),
            "binding": event["binding"],
            "claim": attempt.claim,
            "dispatch": attempt.dispatch,
            "control": attempt.control,
        },
    )
    pin = pointer(path)
    check(pin, attempt.control)
    return pin


def check(pin: dict[str, str], control_pin: dict[str, str]) -> dict[str, Any]:
    permit = pinned(pin)
    if (
        set(permit)
        != {"schema_version", "record_type", "journal", "binding", "claim", "dispatch", "control"}
        or type(permit["schema_version"]) is not int
        or permit["schema_version"] != 1
        or permit["record_type"] != "diagnostic-native-execution-permit"
        or permit["control"] != control_pin
    ):
        raise ValueError("native execution permit fields differ")
    campaign = Campaign(Path(permit["journal"]), permit["binding"])
    campaign.replay(read_only=True)
    claim = pinned(permit["claim"])
    if claim["kind"] != "claim" or claim["binding"] != permit["binding"]:
        raise ValueError("native permit has no matching campaign claim")
    payload = claim["payload"]
    items = campaign.attempts[payload["planned_task_id"]]
    item = items[-1]
    dispatch = pinned(permit["dispatch"])
    if (
        item["claim"] != permit["claim"]
        or item["result"] is not None
        or item["dispatch"] != permit["dispatch"]
        or dispatch["kind"] != "dispatch"
        or dispatch["payload"] != {"claim": permit["claim"], "control": control_pin}
    ):
        raise PermissionError("native permit is no longer an open dispatched attempt")
    _control, _binding, context = read_control(control_pin)
    if context.as_dict() != payload["context"]:
        raise ValueError("native permit identifies another worker context")
    row = campaign.rows[payload["planned_task_id"]]
    ready_pin, ready = campaign.sessions[row["session"]]
    if ready_pin != payload["readiness"] or payload["gate_reviews"] != campaign.review_pins(row):
        raise PermissionError("native permit has stale readiness or gate reviews")
    validate(ready, campaign.binding_pin, row["session"], campaign.mode, current=True)
    if campaign.mode == "pilot" and campaign.binding["native_backend_qualified"] is not True:
        raise PermissionError("native backend has not been qualified")
    return permit
