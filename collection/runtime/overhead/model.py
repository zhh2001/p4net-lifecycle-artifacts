"""Strict identities shared by the calibration entry and reference interface."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

PROFILES = ("native", "off", "stages", "detail")
TOOLS = ("p4net", "p4utils", "tutorial-components")
NAMESPACES = ("net", "mnt", "pid", "ipc", "uts")


def integer(value: Any, name: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name} must be an integer of at least {minimum}")
    return value


def text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ValueError(f"invalid {name}")
    if any(ord(character) < 32 for character in value):
        raise ValueError(f"invalid {name}")
    return value


@dataclass(frozen=True)
class Context:
    run_id: str
    attempt_id: str
    tool: str
    diagnostic_profile: str
    observer_profile: str = "T"
    mode: str = "synthetic-validation"

    def __post_init__(self) -> None:
        text(self.run_id, "run_id")
        text(self.attempt_id, "attempt_id")
        if self.tool not in TOOLS or self.diagnostic_profile not in PROFILES:
            raise ValueError("unknown calibration treatment")
        if self.observer_profile != "T":
            raise ValueError("all treatments require common observer T")
        if self.mode != "synthetic-validation":
            raise PermissionError("native pilot dispatch is not implemented")

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "attempt_id": self.attempt_id,
            "tool": self.tool,
            "diagnostic_profile": self.diagnostic_profile,
            "observer_profile": "T",
            "mode": self.mode,
            "performance_samples": False,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> Context:
        expected = {
            "run_id",
            "attempt_id",
            "tool",
            "diagnostic_profile",
            "observer_profile",
            "mode",
            "performance_samples",
        }
        if set(value) != expected or value["performance_samples"] is not False:
            raise ValueError("calibration context differs")
        return cls(**{key: value[key] for key in expected if key != "performance_samples"})


@dataclass(frozen=True)
class Identity:
    """pid is visible to the reader; namespace_pid is the innermost PID."""

    pid: int
    namespace_pid: int
    start_ticks: int
    boot_id: str
    namespaces: Mapping[str, str]

    def __post_init__(self) -> None:
        integer(self.pid, "pid", 1)
        integer(self.namespace_pid, "namespace_pid", 1)
        integer(self.start_ticks, "start_ticks")
        text(self.boot_id, "boot_id")
        if set(self.namespaces) != set(NAMESPACES):
            raise ValueError("five namespace identities are required")
        for key, value in self.namespaces.items():
            if (
                not isinstance(value, str)
                or not value.startswith(key + ":[")
                or not value.endswith("]")
                or not value[len(key) + 2 : -1].isdecimal()
            ):
                raise ValueError("invalid namespace identity")
        object.__setattr__(self, "namespaces", MappingProxyType(dict(self.namespaces)))

    def as_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "namespace_pid": self.namespace_pid,
            "start_ticks": self.start_ticks,
            "boot_id": self.boot_id,
            "namespaces": dict(self.namespaces),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> Identity:
        if set(value) != {"pid", "namespace_pid", "start_ticks", "boot_id", "namespaces"}:
            raise ValueError("process identity fields differ")
        return cls(**dict(value))

    def same_process(self, other: Identity) -> bool:
        return (self.namespace_pid, self.start_ticks, self.boot_id, dict(self.namespaces)) == (
            other.namespace_pid,
            other.start_ticks,
            other.boot_id,
            dict(other.namespaces),
        )
