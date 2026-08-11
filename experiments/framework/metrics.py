#!/usr/bin/env python3
"""Metrics collection and statistical reporting for RQ2 experiments.

Provides:
  - Absolute count tracking (e.g., 0/13500 escaped effects)
  - Exact binomial confidence intervals (Clopper-Pearson)
  - JSON + human-readable table output
"""

import json
import math
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


def binomial_ci(successes: int, trials: int,
                confidence: float = 0.95) -> Tuple[float, float]:
    """Compute exact Clopper-Pearson binomial confidence interval.

    Returns (lower, upper) bounds for the true success probability.
    Uses the F-distribution relationship for exact intervals.
    """
    if trials == 0:
        return (0.0, 1.0)

    alpha = 1.0 - confidence

    if successes == 0:
        lower = 0.0
    else:
        # Lower bound via F-distribution
        lower = _beta_ppf(alpha / 2, successes, trials - successes + 1)

    if successes == trials:
        upper = 1.0
    else:
        # Upper bound via F-distribution
        upper = _beta_ppf(1 - alpha / 2, successes + 1, trials - successes)

    return (lower, upper)


def _beta_ppf(p: float, a: int, b: int) -> float:
    """Compute the p-th quantile of Beta(a, b) distribution.

    Uses scipy if available, otherwise implements the regularized
    incomplete beta function via continued fraction (Lentz's method)
    with bisection inversion. This gives true Clopper-Pearson intervals.
    """
    try:
        from scipy.stats import beta as beta_dist
        return float(beta_dist.ppf(p, a, b))
    except ImportError:
        pass

    # Fallback: bisection on the regularized incomplete beta function
    if a <= 0 or b <= 0:
        return 0.5

    def _betacf(x: float, a: float, b: float) -> float:
        """Continued fraction for incomplete beta (Lentz's method)."""
        MAXIT = 200
        EPS = 3.0e-12
        FPMIN = 1.0e-30
        qab = a + b
        qap = a + 1.0
        qam = a - 1.0
        c = 1.0
        d = 1.0 - qab * x / qap
        if abs(d) < FPMIN:
            d = FPMIN
        d = 1.0 / d
        h = d
        for m in range(1, MAXIT + 1):
            m2 = 2 * m
            # Even step
            aa = m * (b - m) * x / ((qam + m2) * (a + m2))
            d = 1.0 + aa * d
            if abs(d) < FPMIN:
                d = FPMIN
            c = 1.0 + aa / c
            if abs(c) < FPMIN:
                c = FPMIN
            d = 1.0 / d
            h *= d * c
            # Odd step
            aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
            d = 1.0 + aa * d
            if abs(d) < FPMIN:
                d = FPMIN
            c = 1.0 + aa / c
            if abs(c) < FPMIN:
                c = FPMIN
            d = 1.0 / d
            delta = d * c
            h *= delta
            if abs(delta - 1.0) < EPS:
                break
        return h

    def _betai(x: float, a: float, b: float) -> float:
        """Regularized incomplete beta function I_x(a,b)."""
        if x <= 0.0:
            return 0.0
        if x >= 1.0:
            return 1.0
        # Use the symmetry relation for numerical stability
        lbeta = (math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) +
                 a * math.log(x) + b * math.log(1.0 - x))
        front = math.exp(lbeta)
        if x < (a + 1.0) / (a + b + 2.0):
            return front * _betacf(x, a, b) / a
        else:
            return 1.0 - front * _betacf(1.0 - x, b, a) / b

    # Bisection to find x such that I_x(a,b) = p
    lo, hi = 0.0, 1.0
    for _ in range(100):  # 100 iterations gives ~1e-30 precision
        mid = (lo + hi) / 2.0
        if _betai(mid, float(a), float(b)) < p:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2.0


def _norm_ppf(p: float) -> float:
    """Approximate inverse normal CDF (Abramowitz & Stegun 26.2.23)."""
    if p <= 0:
        return -float("inf")
    if p >= 1:
        return float("inf")
    if p == 0.5:
        return 0.0
    if p < 0.5:
        return -_norm_ppf(1 - p)
    # Rational approximation for 0.5 < p < 1
    t = math.sqrt(-2 * math.log(1 - p))
    c0, c1, c2 = 2.515517, 0.802853, 0.010328
    d1, d2, d3 = 1.432788, 0.189269, 0.001308
    return t - (c0 + c1 * t + c2 * t * t) / (1 + d1 * t + d2 * t * t + d3 * t * t * t)


@dataclass
class Counter:
    """A single named metric counter."""
    name: str
    count: int = 0
    total: int = 0
    details: List[str] = field(default_factory=list)

    def record(self, violated: bool, detail: str = ""):
        """Record one trial. violated=True means the safety property was broken."""
        self.total += 1
        if violated:
            self.count += 1
            if detail:
                self.details.append(detail)

    @property
    def rate(self) -> float:
        return self.count / self.total if self.total > 0 else 0.0

    def ci(self, confidence: float = 0.95) -> Tuple[float, float]:
        return binomial_ci(self.count, self.total, confidence)

    def summary(self) -> str:
        lo, hi = self.ci()
        return (f"{self.name}: {self.count}/{self.total} "
                f"(rate={self.rate:.6f}, 95% CI=[{lo:.6f}, {hi:.6f}])")


class MetricsCollector:
    """Collects and reports experiment metrics.

    Tracks multiple named counters and produces both JSON and human-readable
    reports suitable for paper tables.
    """

    def __init__(self, experiment_name: str):
        self.experiment_name = experiment_name
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self.counters: Dict[str, Counter] = {}
        self.metadata: Dict[str, Any] = {}
        self.trial_results: List[Dict[str, Any]] = []

    def add_counter(self, name: str) -> Counter:
        """Register a new metric counter."""
        if name not in self.counters:
            self.counters[name] = Counter(name=name)
        return self.counters[name]

    def record(self, counter_name: str, violated: bool, detail: str = "",
               trial_info: Dict = None):
        """Record a measurement for a named counter.

        If trial_info contains 'skipped': True, the trial is NOT counted
        in the denominator (does not affect pass/fail statistics).
        """
        # Skipped trials do NOT increase the denominator
        is_skipped = trial_info and trial_info.get("skipped", False)
        if not is_skipped:
            counter = self.add_counter(counter_name)
            counter.record(violated, detail)
        if trial_info is not None:
            trial_info["metric"] = counter_name
            trial_info["violated"] = violated
            self.trial_results.append(trial_info)

    def record_trial(self, trial: Dict[str, Any]):
        """Record a complete trial result with multiple metrics."""
        self.trial_results.append(trial)

    def finish(self):
        """Mark the experiment as complete."""
        self.end_time = time.time()

    @property
    def duration(self) -> float:
        end = self.end_time or time.time()
        return end - self.start_time

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        # Count skipped trials
        skipped_count = sum(
            1 for t in self.trial_results if t.get("skipped", False))
        # Identify 0/0 counters (no effective observations)
        empty_counters = [
            name for name, c in self.counters.items() if c.total == 0]
        return {
            "experiment": self.experiment_name,
            "duration_seconds": round(self.duration, 2),
            "start_time": self.start_time,
            "end_time": self.end_time,
            "metadata": self.metadata,
            "counters": {
                name: {
                    "count": c.count,
                    "total": c.total,
                    "rate": c.rate,
                    "ci_95": list(c.ci()),
                    "details": c.details[:100],  # Cap detail list
                }
                for name, c in self.counters.items()
            },
            "total_trials": len(self.trial_results),
            "skipped_trials": skipped_count,
            "empty_counters": empty_counters,
        }

    def to_json(self, path: str = None) -> str:
        """Serialize to JSON string, optionally writing to a file."""
        data = json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
        if path:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "w") as f:
                f.write(data)
        return data

    def print_report(self, file=None):
        """Print a human-readable report table."""
        out = file or sys.stdout
        width = 72
        print("=" * width, file=out)
        print(f"  EXPERIMENT: {self.experiment_name}", file=out)
        print(f"  Duration: {self.duration:.1f}s", file=out)
        print("=" * width, file=out)

        if not self.counters:
            print("  (no metrics recorded)", file=out)
            return

        # Find max name length for alignment
        max_name = max(len(c.name) for c in self.counters.values())
        max_name = max(max_name, 20)

        print(f"\n  {'Metric':<{max_name}}  {'Count':>12}  {'Rate':>10}  "
              f"{'95% CI':>20}", file=out)
        print(f"  {'-' * max_name}  {'-' * 12}  {'-' * 10}  {'-' * 20}",
              file=out)

        for name, counter in self.counters.items():
            lo, hi = counter.ci()
            count_str = f"{counter.count}/{counter.total}"
            rate_str = f"{counter.rate:.6f}"
            ci_str = f"[{lo:.6f}, {hi:.6f}]"
            print(f"  {name:<{max_name}}  {count_str:>12}  {rate_str:>10}  "
                  f"{ci_str:>20}", file=out)

        print("\n" + "=" * width, file=out)

        # Print violation details if any
        total_violations = sum(c.count for c in self.counters.values())
        if total_violations > 0:
            print(f"\n  VIOLATIONS DETECTED: {total_violations}", file=out)
            for name, counter in self.counters.items():
                if counter.count > 0:
                    print(f"\n  {name} ({counter.count} violations):", file=out)
                    for detail in counter.details[:10]:
                        print(f"    - {detail}", file=out)
                    if len(counter.details) > 10:
                        print(f"    ... and {len(counter.details) - 10} more",
                              file=out)
        else:
            print("\n  RESULT: ALL SAFETY PROPERTIES HELD", file=out)
        print("=" * width, file=out)

    def save_report(self, output_dir: str):
        """Save both JSON and text reports to output_dir."""
        os.makedirs(output_dir, exist_ok=True)
        base = self.experiment_name.replace(" ", "_").lower()

        json_path = os.path.join(output_dir, f"{base}.json")
        self.to_json(json_path)

        txt_path = os.path.join(output_dir, f"{base}.txt")
        with open(txt_path, "w") as f:
            self.print_report(file=f)

        return json_path, txt_path
