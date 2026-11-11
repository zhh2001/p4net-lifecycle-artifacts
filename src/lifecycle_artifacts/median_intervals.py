# SPDX-License-Identifier: Apache-2.0
# Adapted for standalone package imports.
"""Bound fixed-session mixture medians using independent Bernoulli rank tails."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from fractions import Fraction
from typing import Any

from . import resampling


def _finite(value: Any, name: str) -> float:
    if type(value) not in (int, float):
        raise ValueError(f"{name} must be a finite number")
    try:
        converted = float(value)
    except OverflowError as exc:
        raise ValueError(f"{name} must be a finite number") from exc
    if not math.isfinite(converted):
        raise ValueError(f"{name} must be a finite number")
    return 0.0 if converted == 0 else converted


def _directed_float(value: Fraction, *, lower: bool) -> float:
    """Round a reported probability in the conservative bound direction."""
    converted = float(value)
    represented = Fraction.from_float(converted)
    if (lower and represented > value) or (not lower and represented < value):
        converted = math.nextafter(converted, -math.inf if lower else math.inf)
    return converted


def _rank_bound(n: int, confidence: float) -> tuple[int, Fraction, Fraction] | None:
    denominator = 1 << n
    requested = Fraction.from_float(confidence)
    coefficient = 1
    tail = 0
    selected = None
    for rank in range(1, n // 2 + 1):
        tail += coefficient
        central = denominator - 2 * tail
        if central * requested.denominator < requested.numerator * denominator:
            break
        selected = rank, Fraction(central, denominator), Fraction(tail, denominator)
        coefficient = coefficient * (n - rank + 1) // rank
    return selected


def rank_median(
    strata: Mapping[int, Sequence[int | float]],
    *,
    expected_sessions: Sequence[int],
    confidence: float = 0.95,
) -> dict[str, Any]:
    """Return a closed rank interval for the observed-count-weighted mixture median."""
    confidence = _finite(confidence, "confidence")
    if not 0 < confidence < 1:
        raise ValueError("confidence must be between zero and one")
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
        values[session] = [_finite(value, "observation") for value in source]
    ordered = sorted(value for session in sessions for value in values[session])
    n = len(ordered)
    result: dict[str, Any] = {
        "method": "poisson-binomial-rank-median",
        "scheme": "fixed-session",
        "confidence": confidence,
        "point_estimate": resampling.median(ordered),
        "interval": None,
        "status": "unavailable",
        "reason": None,
        "planned_sessions": sessions,
        "counts": {str(session): len(values[session]) for session in sessions},
        "total_n": n,
        "singleton_sessions": [session for session in sessions if len(values[session]) == 1],
        "weighting": "pooled complete-case observations; session weights n_s / total_n",
        "rank_bounds": None,
        "coverage_lower_bound": None,
        "tail_probability_bound": None,
        "resamples_performed": 0,
        "assumption": (
            "independent paired differences; median of observed-count-weighted "
            "fixed-session population mixture"
        ),
        "probability_comparison": "exact rational binomial central mass",
    }
    if any(not values[session] for session in sessions):
        result["reason"] = "missing-session-data"
        return result
    if all(len(values[session]) == 1 for session in sessions):
        result["reason"] = "no-within-session-replication"
        return result
    bound = _rank_bound(n, confidence)
    if bound is None:
        result["reason"] = "insufficient-finite-rank-bound"
        return result
    rank, coverage, tail = bound
    result.update(
        {
            "interval": {"lower": ordered[rank - 1], "upper": ordered[n - rank]},
            "status": "ok",
            "rank_bounds": {"lower": rank, "upper": n - rank + 1},
            "coverage_lower_bound": _directed_float(coverage, lower=True),
            "tail_probability_bound": _directed_float(tail, lower=False),
        }
    )
    return result
