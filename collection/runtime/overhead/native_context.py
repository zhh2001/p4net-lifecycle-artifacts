"""Represent prepared pilot contexts without granting collection authority."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from overhead.model import Context


@dataclass(frozen=True)
class PreparedContext(Context):
    def __post_init__(self) -> None:
        Context(
            self.run_id, self.attempt_id, self.tool, self.diagnostic_profile, self.observer_profile
        )
        if self.mode != "pilot":
            raise ValueError("prepared native contexts require pilot mode")

    def as_dict(self) -> dict[str, Any]:
        return {**super().as_dict(), "performance_samples": True}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> PreparedContext:
        candidate = dict(value)
        if candidate.get("performance_samples") is not True or candidate.get("mode") != "pilot":
            raise ValueError("prepared pilot context differs")
        candidate.update(mode="synthetic-validation", performance_samples=False)
        Context.from_dict(candidate)
        return cls(**{key: value[key] for key in candidate if key != "performance_samples"})
