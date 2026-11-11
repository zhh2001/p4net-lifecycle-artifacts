# SPDX-License-Identifier: Apache-2.0
# Adapted for standalone package imports.
"""Invert exact binomial tails for small-sample completion proportions."""

from __future__ import annotations

import math
from fractions import Fraction
from typing import Any

# The campaign uses denominators of 10 and 30; larger plans remain explicitly bounded.
MAX_EXACT_TRIALS = 1000


def _confidence(value: Any) -> float:
    if type(value) not in (int, float):
        raise ValueError("confidence must be a finite number between zero and one")
    try:
        converted = float(value)
    except OverflowError as exc:
        raise ValueError("confidence must be a finite number between zero and one") from exc
    if not math.isfinite(converted) or not 0 < converted < 1:
        raise ValueError("confidence must be a finite number between zero and one")
    return converted


def _cdf_numerator(successes: int, total: int, numerator: int, denominator: int) -> int:
    """Represent a binomial CDF exactly over the denominator raised to total."""
    probability_denominator: int = denominator**total
    if successes < 0:
        return 0
    if successes >= total or numerator == 0:
        return probability_denominator
    if numerator == denominator:
        return 0
    if successes > total // 2:
        return probability_denominator - _cdf_numerator(
            total - successes - 1, total, denominator - numerator, denominator
        )
    complement = denominator - numerator
    term: int = complement**total
    result = term
    for observed in range(successes):
        term = term * (total - observed) * numerator // ((observed + 1) * complement)
        result += term
    return result


def _tail_comparison(
    successes: int, total: int, probability: float, tail: Fraction, *, upper: bool
) -> int:
    numerator, denominator = probability.as_integer_ratio()
    probability_denominator: int = denominator**total
    tail_numerator = (
        _cdf_numerator(successes, total, numerator, denominator)
        if upper
        else probability_denominator - _cdf_numerator(successes - 1, total, numerator, denominator)
    )
    difference = tail_numerator * tail.denominator - tail.numerator * probability_denominator
    return (difference > 0) - (difference < 0)


def _bound(successes: int, total: int, tail: Fraction, *, upper: bool) -> float:
    """Keep exact root inequalities until the enclosing binary64 values are adjacent."""
    lower, higher = 0.0, 1.0
    while True:
        middle = lower + (higher - lower) / 2
        if middle in (lower, higher):
            return higher if upper else lower
        comparison = _tail_comparison(successes, total, middle, tail, upper=upper)
        if comparison == 0:
            return middle
        if (upper and comparison > 0) or (not upper and comparison < 0):
            lower = middle
        else:
            higher = middle


def exact_interval(successes: int, total: int, *, confidence: float = 0.95) -> dict[str, Any]:
    """Return a closed Clopper-Pearson interval for at most 1,000 planned trials."""
    confidence = _confidence(confidence)
    if type(successes) is not int or type(total) is not int or not 0 <= successes <= total:
        raise ValueError("successes and total must be integers with 0 <= successes <= total")
    if total > MAX_EXACT_TRIALS:
        raise ValueError(f"total must not exceed {MAX_EXACT_TRIALS} for exact integer inversion")
    result: dict[str, Any] = {
        "method": "clopper-pearson-exact",
        "confidence": confidence,
        "successes": successes,
        "total": total,
        "point_estimate": successes / total if total else None,
        "interval": None,
        "status": "unavailable" if total == 0 else "ok",
        "reason": "no-observed-trials" if total == 0 else None,
        "assumption": "independent Bernoulli trials with a common success probability",
        "numerical_method": "exact integer binomial tails; outward binary64 root brackets",
    }
    if total == 0:
        return result
    tail = (1 - Fraction.from_float(confidence)) / 2
    result["interval"] = {
        "lower": 0.0 if successes == 0 else _bound(successes, total, tail, upper=False),
        "upper": 1.0 if successes == total else _bound(successes, total, tail, upper=True),
    }
    return result
