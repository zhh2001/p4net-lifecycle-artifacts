# SPDX-License-Identifier: Apache-2.0
# Adapted for standalone package imports.
"""Resample paired differences within sessions and calculate binomial score intervals."""

from __future__ import annotations

import hashlib
import json
import math
import random
from collections.abc import Mapping, Sequence
from statistics import NormalDist
from typing import Any

SCHEMES = ("fixed-session", "hierarchical-session")
MAX_RESAMPLES = 1_000_000


def _finite(value: Any, name: str) -> float:
    if type(value) not in (int, float):
        raise ValueError(f"{name} must be a finite number")
    try:
        converted = float(value)
    except OverflowError as exc:
        raise ValueError(f"{name} must be representable as a finite float") from exc
    if not math.isfinite(converted):
        raise ValueError(f"{name} must be a finite number")
    return 0.0 if converted == 0 else converted


def _confidence(value: Any) -> float:
    converted = _finite(value, "confidence")
    if not 0 < converted < 1:
        raise ValueError("confidence must be between zero and one")
    return converted


def _interpolate(lower: float, upper: float, weight: float) -> float:
    if lower <= 0 <= upper:
        result = lower * (1 - weight) + upper * weight
    else:
        result = lower + (upper - lower) * weight
    if not math.isfinite(result):
        raise ValueError("interpolated statistic is not finite")
    return result


def _quantile(values: Sequence[float], probability: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower, upper = math.floor(position), math.ceil(position)
    return _interpolate(ordered[lower], ordered[upper], position - lower)


def median(values: Sequence[int | float]) -> float | None:
    """Return a finite midpoint median, or None when no observations are available."""
    finite = [_finite(value, "observation") for value in values]
    return _quantile(finite, 0.5) if finite else None


def bootstrap_median(
    strata: Mapping[int, Sequence[int | float]],
    *,
    expected_sessions: Sequence[int],
    scheme: str = "fixed-session",
    confidence: float = 0.95,
    resamples: int = 10_000,
    seed: int = 20261029,
) -> dict[str, Any]:
    """Use a pooled median while retaining paired observations inside their sessions."""
    confidence = _confidence(confidence)
    if scheme not in SCHEMES:
        raise ValueError("scheme must be fixed-session or hierarchical-session")
    if type(resamples) is not int or not 2 <= resamples <= MAX_RESAMPLES:
        raise ValueError(f"resamples must be an integer from 2 to {MAX_RESAMPLES}")
    if type(seed) is not int or not 0 <= seed <= 2**63 - 1:
        raise ValueError("seed must be an integer from zero to 2**63 - 1")
    if (
        not isinstance(expected_sessions, Sequence)
        or isinstance(expected_sessions, (str, bytes))
        or not expected_sessions
        or any(type(session) is not int or session < 1 for session in expected_sessions)
        or len(set(expected_sessions)) != len(expected_sessions)
    ):
        raise ValueError("expected_sessions must contain distinct positive integer sessions")
    sessions = sorted(expected_sessions)
    if not isinstance(strata, Mapping) or any(
        type(session) is not int or session not in sessions for session in strata
    ):
        raise ValueError("strata must map only expected integer sessions to observations")
    values = {}
    for session in sessions:
        source = strata.get(session, ())
        if not isinstance(source, Sequence) or isinstance(source, (str, bytes)):
            raise ValueError("each stratum must be a sequence of finite numbers")
        # Canonical ordering keeps a seed reproducible across equivalent input orders.
        values[session] = sorted(_finite(value, "observation") for value in source)
    pooled = [value for session in sessions for value in values[session]]
    result: dict[str, Any] = {
        "method": "percentile-bootstrap-median",
        "scheme": scheme,
        "confidence": confidence,
        "resamples": resamples,
        "resamples_performed": 0,
        "seed": seed,
        "rng": "python.random.Random/MT19937",
        "point_estimate": _quantile(pooled, 0.5) if pooled else None,
        "interval": None,
        "status": "unavailable",
        "reason": None,
        "planned_sessions": sessions,
        "counts": {str(session): len(values[session]) for session in sessions},
        "total_n": len(pooled),
        "singleton_sessions": [session for session in sessions if len(values[session]) == 1],
        "weighting": "pooled complete-case observations; session weights n_s / total_n",
        "distribution": None,
    }
    if any(not values[session] for session in sessions):
        result["reason"] = "missing-session-data"
        return result
    if len(pooled) < 2:
        result["reason"] = "insufficient-observations"
        return result
    if scheme == "hierarchical-session" and len(sessions) < 2:
        result["reason"] = "insufficient-sessions"
        return result
    if scheme == "fixed-session" and all(len(values[session]) == 1 for session in sessions):
        result["reason"] = "no-within-session-replication"
        return result
    rng = random.Random(seed)
    distribution = []
    for _ in range(resamples):
        sampled_sessions = (
            [rng.choice(sessions) for _ in sessions]
            if scheme == "hierarchical-session"
            else sessions
        )
        sample = [
            rng.choice(values[session]) for session in sampled_sessions for _ in values[session]
        ]
        distribution.append(_quantile(sample, 0.5))
    tail = (1 - confidence) / 2
    unique_values = len(set(distribution))
    result.update(
        {
            "interval": {
                "lower": _quantile(distribution, tail),
                "upper": _quantile(distribution, 1 - tail),
            },
            "status": "ok",
            "resamples_performed": resamples,
            "distribution": {
                "sha256": hashlib.sha256(
                    json.dumps(distribution, separators=(",", ":"), allow_nan=False).encode()
                ).hexdigest(),
                "unique_values": unique_values,
                "degenerate": unique_values == 1,
                "min": min(distribution),
                "max": max(distribution),
            },
        }
    )
    return result


def wilson_interval(successes: int, total: int, *, confidence: float = 0.95) -> dict[str, Any]:
    """Return a Wilson score interval under an explicitly named binomial model."""
    confidence = _confidence(confidence)
    if type(successes) is not int or type(total) is not int or not 0 <= successes <= total:
        raise ValueError("successes and total must be integers with 0 <= successes <= total")
    result: dict[str, Any] = {
        "method": "wilson-score",
        "confidence": confidence,
        "successes": successes,
        "total": total,
        "point_estimate": successes / total if total else None,
        "interval": None,
        "status": "unavailable" if total == 0 else "ok",
        "reason": "no-observed-trials" if total == 0 else None,
        "assumption": "independent Bernoulli trials with a common success probability",
    }
    if total == 0:
        return result
    n = _finite(total, "total")
    proportion = result["point_estimate"]
    # Computing z from the lower tail avoids rounding (1 + confidence) / 2 to one.
    z = -NormalDist().inv_cdf((1 - confidence) / 2)
    z2 = z * z
    denominator = n + z2
    center = (proportion * n + z2 / 2) / denominator
    margin = z * math.sqrt(proportion * (1 - proportion) * n + z2 / 4) / denominator
    lower, upper = max(0.0, center - margin), min(1.0, center + margin)
    if successes == 0:
        lower = 0.0
    if successes == total:
        upper = 1.0
    if not all(math.isfinite(value) for value in (lower, upper)):
        raise ValueError("Wilson interval is not finite")
    result["interval"] = {"lower": lower, "upper": upper}
    return result
