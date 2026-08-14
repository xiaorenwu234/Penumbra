#!/usr/bin/env python3
"""Statistical analysis for RQ3 performance experiments.

Computes median, P95, P99, and 95% bootstrap confidence intervals
for latency measurements.
"""

import random
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class StatsResult:
    """Statistical summary of a set of latency measurements (in nanoseconds)."""
    name: str
    n: int = 0
    median_ns: float = 0.0
    p95_ns: float = 0.0
    p99_ns: float = 0.0
    mean_ns: float = 0.0
    min_ns: float = 0.0
    max_ns: float = 0.0
    ci_95_low_ns: float = 0.0
    ci_95_high_ns: float = 0.0
    excluded: int = 0  # number of excluded (failed/timeout) runs

    @property
    def median_us(self) -> float:
        return self.median_ns / 1000.0

    @property
    def median_ms(self) -> float:
        return self.median_ns / 1_000_000.0

    @property
    def p95_ms(self) -> float:
        return self.p95_ns / 1_000_000.0

    @property
    def p99_ms(self) -> float:
        return self.p99_ns / 1_000_000.0

    @property
    def ci_95_low_ms(self) -> float:
        return self.ci_95_low_ns / 1_000_000.0

    @property
    def ci_95_high_ms(self) -> float:
        return self.ci_95_high_ns / 1_000_000.0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "n": self.n,
            "excluded": self.excluded,
            "median_ns": round(self.median_ns, 1),
            "p95_ns": round(self.p95_ns, 1),
            "p99_ns": round(self.p99_ns, 1),
            "mean_ns": round(self.mean_ns, 1),
            "min_ns": round(self.min_ns, 1),
            "max_ns": round(self.max_ns, 1),
            "ci_95_low_ns": round(self.ci_95_low_ns, 1),
            "ci_95_high_ns": round(self.ci_95_high_ns, 1),
            "median_ms": round(self.median_ms, 4),
            "p95_ms": round(self.p95_ms, 4),
            "p99_ms": round(self.p99_ms, 4),
            "ci_95_ms": [round(self.ci_95_low_ms, 4), round(self.ci_95_high_ms, 4)],
        }

    def summary_line(self) -> str:
        ci_lo = self.ci_95_low_ms
        ci_hi = self.ci_95_high_ms
        return (f"{self.name}: median={self.median_ms:.3f}ms "
                f"P95={self.p95_ms:.3f}ms P99={self.p99_ms:.3f}ms "
                f"CI95=[{ci_lo:.3f}, {ci_hi:.3f}]ms (n={self.n})")


def percentile(sorted_data: List[float], p: float) -> float:
    """Compute the p-th percentile from sorted data (0 <= p <= 100)."""
    if not sorted_data:
        return 0.0
    n = len(sorted_data)
    if n == 1:
        return sorted_data[0]
    # Linear interpolation method
    rank = (p / 100.0) * (n - 1)
    lo = int(rank)
    hi = lo + 1
    if hi >= n:
        return sorted_data[-1]
    frac = rank - lo
    return sorted_data[lo] * (1 - frac) + sorted_data[hi] * frac


def bootstrap_ci(data: List[float], n_bootstrap: int = 10000,
                 confidence: float = 0.95, seed: int = 42) -> Tuple[float, float]:
    """Compute bootstrap confidence interval for the median.

    Uses resampling with replacement to estimate the sampling distribution
    of the median, then returns the (alpha/2, 1-alpha/2) percentiles.
    """
    if not data:
        return (0.0, 0.0)
    if len(data) <= 2:
        med = sorted(data)[len(data) // 2]
        return (med, med)

    rng = random.Random(seed)
    n = len(data)
    medians = []
    for _ in range(n_bootstrap):
        sample = [data[rng.randint(0, n - 1)] for _ in range(n)]
        sample.sort()
        medians.append(percentile(sample, 50))
    medians.sort()
    alpha = 1.0 - confidence
    lo = percentile(medians, 100 * alpha / 2)
    hi = percentile(medians, 100 * (1 - alpha / 2))
    return (lo, hi)


def compute_stats(name: str, samples_ns: List[float],
                  excluded: int = 0,
                  n_bootstrap: int = 10000) -> StatsResult:
    """Compute full statistical summary from a list of latency samples (ns).

    Args:
        name: Metric name for reporting.
        samples_ns: List of latency measurements in nanoseconds.
                    Failed/timeout runs should already be removed.
        excluded: Number of excluded (failed) runs for reporting.
        n_bootstrap: Number of bootstrap resamples for CI.

    Returns:
        StatsResult with median, P95, P99, mean, and 95% bootstrap CI.
    """
    if not samples_ns:
        return StatsResult(name=name, n=0, excluded=excluded)

    sorted_data = sorted(samples_ns)
    n = len(sorted_data)

    med = percentile(sorted_data, 50)
    p95 = percentile(sorted_data, 95)
    p99 = percentile(sorted_data, 99)
    mean = sum(sorted_data) / n
    ci_lo, ci_hi = bootstrap_ci(sorted_data, n_bootstrap=n_bootstrap)

    return StatsResult(
        name=name,
        n=n,
        median_ns=med,
        p95_ns=p95,
        p99_ns=p99,
        mean_ns=mean,
        min_ns=sorted_data[0],
        max_ns=sorted_data[-1],
        ci_95_low_ns=ci_lo,
        ci_95_high_ns=ci_hi,
        excluded=excluded,
    )
