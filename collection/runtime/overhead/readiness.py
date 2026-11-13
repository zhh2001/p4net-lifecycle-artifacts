"""Bind each calibration session to its own restart and idle confirmation."""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path
from typing import Any

from overhead.model import integer, text


def boot_id() -> str:
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def create(
    binding: dict[str, str],
    session: int,
    *,
    mode: str,
    confirmed: bool,
    preparation_boot: str,
    used_boots: dict[int, str],
    current_boot: str | None = None,
) -> dict[str, Any]:
    integer(session, "session", 1)
    if session > 3 or confirmed is not True:
        raise ValueError("session readiness requires explicit confirmation")
    current = boot_id() if current_boot is None else current_boot
    text(current, "boot identity")
    if mode == "pilot":
        if current == preparation_boot:
            raise PermissionError("pilot session requires a restart after input preparation")
        if any(other != session and value == current for other, value in used_boots.items()):
            raise PermissionError("each pilot session requires a separate restart")
    elif mode != "synthetic-validation":
        raise ValueError("unknown readiness mode")
    return {
        "schema_version": 1,
        "record_type": "diagnostic-overhead-session-readiness",
        "binding": binding,
        "session": session,
        "mode": mode,
        "boot_id": current,
        "recorded_at": datetime.now().astimezone().isoformat(),
        "monotonic_ns": time.monotonic_ns(),
        "user_confirmed": mode == "pilot",
        "synthetic_confirmation": mode == "synthetic-validation",
        "computer_restarted": mode == "pilot",
        "extra_applications_closed": mode == "pilot",
        "computer_idle": mode == "pilot",
    }


def validate(
    value: dict[str, Any],
    binding: dict[str, str],
    session: int,
    mode: str,
    *,
    current: bool = False,
) -> None:
    if (
        set(value)
        != {
            "schema_version",
            "record_type",
            "binding",
            "session",
            "mode",
            "boot_id",
            "recorded_at",
            "monotonic_ns",
            "user_confirmed",
            "synthetic_confirmation",
            "computer_restarted",
            "extra_applications_closed",
            "computer_idle",
        }
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["record_type"] != "diagnostic-overhead-session-readiness"
        or value["binding"] != binding
        or type(value["session"]) is not int
        or value["session"] != session
        or value["mode"] != mode
        or any(
            value[key] is not (mode == "pilot")
            for key in (
                "user_confirmed",
                "computer_restarted",
                "extra_applications_closed",
                "computer_idle",
            )
        )
        or value["synthetic_confirmation"] is not (mode == "synthetic-validation")
    ):
        raise ValueError("session readiness identity differs")
    text(value["boot_id"], "boot identity")
    integer(value["monotonic_ns"], "readiness clock")
    timestamp = datetime.fromisoformat(value["recorded_at"])
    if timestamp.utcoffset() is None:
        raise ValueError("readiness timestamp requires a time zone")
    if current and mode == "pilot" and value["boot_id"] != boot_id():
        raise PermissionError("session readiness belongs to another boot")
