"""Small, dependency-free statistics: cluster bootstrap, Wilson intervals, calibration and drift.

The bootstrap resamples *units* (one tenant in one seeded scenario) with replacement, because incidents
on one tenant's timeline are not independent draws. Every metric is expressed through per-unit
sufficient statistics (a numerator and a denominator, a list of durations, or calibration bins), so a
resample is a sum over units rather than a recomputation over incidents. Paired differences between two
systems use the same resampled units for both, which is what makes "X better than the baseline" a
checkable statement: the interval of the difference either excludes zero or it does not."""

from __future__ import annotations

import math
import random
import statistics
from collections.abc import Callable, Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class Estimate:
    value: float | None
    lo: float | None
    hi: float | None
    n: int  # denominator behind the point estimate (incidents, stories, reviews ...)

    def fmt(self, digits: int = 1) -> str:
        if self.value is None:
            return "n/a"
        if self.lo is None or self.hi is None:
            return f"{self.value:.{digits}f}"
        return f"{self.value:.{digits}f} [{self.lo:.{digits}f}, {self.hi:.{digits}f}]"


def percentile(xs: Sequence[float], q: float) -> float:
    s = sorted(xs)
    if not s:
        raise ValueError("empty")
    k = (len(s) - 1) * q
    f, c = math.floor(k), math.ceil(k)
    return s[f] if f == c else s[f] + (s[c] - s[f]) * (k - f)


def resample_indices(n_units: int, resamples: int, seed: int) -> list[list[int]]:
    rng = random.Random(seed)
    return [[rng.randrange(n_units) for _ in range(n_units)] for _ in range(resamples)]


def bootstrap(units: Sequence, statistic: Callable[[Sequence], tuple[float | None, int]], draws: list[list[int]], confidence: float) -> Estimate:
    """`statistic(list_of_units) -> (value or None, n)`; resamples where it is None are skipped."""
    point, n = statistic(units)
    if point is None:
        return Estimate(None, None, None, n)
    vals = []
    for idx in draws:
        v, _ = statistic([units[i] for i in idx])
        if v is not None:
            vals.append(v)
    if not vals:
        return Estimate(point, None, None, n)
    a = (1 - confidence) / 2
    return Estimate(point, percentile(vals, a), percentile(vals, 1 - a), n)


def bootstrap_diff(
    units_a: Sequence, units_b: Sequence, statistic: Callable[[Sequence], tuple[float | None, int]], draws: list[list[int]], confidence: float
) -> Estimate:
    """Paired difference a - b over the same resampled units (both lists in the same unit order)."""
    va, n = statistic(units_a)
    vb, _ = statistic(units_b)
    if va is None or vb is None:
        return Estimate(None, None, None, n)
    vals = []
    for idx in draws:
        x, _ = statistic([units_a[i] for i in idx])
        y, _ = statistic([units_b[i] for i in idx])
        if x is not None and y is not None:
            vals.append(x - y)
    a = (1 - confidence) / 2
    return Estimate(va - vb, percentile(vals, a), percentile(vals, 1 - a), n)


def wilson(successes: int, n: int, confidence: float = 0.95) -> tuple[float, float]:
    """Wilson score interval for a proportion; used when there are too few units to bootstrap."""
    if n == 0:
        return (0.0, 1.0)
    z = statistics.NormalDist().inv_cdf(1 - (1 - confidence) / 2)
    p = successes / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    lo = 0.0 if successes == 0 else max(0.0, centre - half)
    hi = 1.0 if successes == n else min(1.0, centre + half)
    return (lo, hi)


def sample_size_for(margin: float, p: float = 0.5, confidence: float = 0.95) -> int:
    """Labelled cases needed to estimate a rate near `p` to within +/- `margin` (normal approximation)."""
    z = statistics.NormalDist().inv_cdf(1 - (1 - confidence) / 2)
    return math.ceil(z * z * p * (1 - p) / (margin * margin))


def calibration_bins(probs: Sequence[float], outcomes: Sequence[bool], bins: int) -> list[list[float]]:
    """Per bin: [count, sum of predicted probability, sum of outcomes]. Additive across units."""
    out = [[0.0, 0.0, 0.0] for _ in range(bins)]
    for p, y in zip(probs, outcomes, strict=True):
        b = min(int(p * bins), bins - 1)
        out[b][0] += 1
        out[b][1] += p
        out[b][2] += 1.0 if y else 0.0
    return out


def ece(binned: list[list[float]]) -> float | None:
    """Expected calibration error: count-weighted mean gap between confidence and frequency per bin."""
    n = sum(b[0] for b in binned)
    if not n:
        return None
    return sum(b[0] / n * abs(b[1] / b[0] - b[2] / b[0]) for b in binned if b[0])


def psi(reference: Sequence[float], current: Sequence[float], edges: Sequence[float]) -> float:
    """Population stability index between two samples over fixed bin edges (small floor avoids log 0)."""

    def dist(xs):
        counts = [0] * (len(edges) - 1)
        for x in xs:
            for i in range(len(edges) - 1):
                if edges[i] <= x < edges[i + 1] or (i == len(edges) - 2 and x == edges[-1]):
                    counts[i] += 1
                    break
        total = max(1, sum(counts))
        return [max(c / total, 1e-4) for c in counts]

    r, c = dist(reference), dist(current)
    return sum((ci - ri) * math.log(ci / ri) for ri, ci in zip(r, c, strict=True))
