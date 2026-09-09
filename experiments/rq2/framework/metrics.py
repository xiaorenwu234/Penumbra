#!/usr/bin/env python3
"""Metrics collection and statistical reporting for RQ2 experiments.

Two different things are counted, and the reports keep them apart:

  * a **trial** is one execution of one test point (e.g. "deny CONNECT,
    repetition 17"). It has exactly one status: ``completed``, ``skipped`` or
    ``infra_error``.
  * an **assertion** (property check) is one safety property evaluated inside a
    trial. A trial normally carries several of them ("tool denied", "receiver
    saw no effect", "audit record present").

The old collector appended one entry to ``trial_results`` per ``record()`` call,
so its ``total_trials`` was really a property-check count. ``to_dict()`` now
reports both explicitly:

    {"attempted_trials": 150, "completed_trials": 150, "skipped_trials": 0,
     "infrastructure_errors": 0, "property_checks": 450, "violations": 0}

Also provides:
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

# Trial identity fields. Two record() calls that agree on all of these belong to
# the SAME trial (their assertions are grouped); anything else in trial_info is
# per-assertion metadata. Deliberately excludes fine-grained fields such as
# "event", "node", "case" and "file", which vary within one trial.
TRIAL_GROUP_KEYS = ("trial_id", "scenario", "trial", "probe", "fault",
                    "topology", "reject", "kind")

# Cap on how many trial records are serialized into the JSON report. Exp5 runs
# tens of thousands of trials; every non-completed trial is always kept.
MAX_SERIALIZED_TRIALS = 500


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


@dataclass
class Assertion:
    """One property check inside a trial."""
    property: str
    passed: bool
    detail: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        out = {"property": self.property, "passed": self.passed}
        if self.detail:
            out["detail"] = self.detail
        if self.meta:
            out["meta"] = self.meta
        return out


@dataclass
class TrialRecord:
    """One execution of one test point, with all of its property checks."""
    trial_id: str
    scenario: str = ""
    status: str = "completed"      # completed | skipped | infra_error
    meta: Dict[str, Any] = field(default_factory=dict)
    assertions: List[Assertion] = field(default_factory=list)
    error: Optional[Dict[str, Any]] = None
    skip_reason: str = ""

    @property
    def violations(self) -> int:
        return sum(1 for a in self.assertions if not a.passed)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "trial_id": self.trial_id,
            "status": self.status,
            "assertions": [a.to_dict() for a in self.assertions],
        }
        if self.scenario:
            out["scenario"] = self.scenario
        if self.meta:
            out["meta"] = self.meta
        if self.error:
            out["error"] = self.error
        if self.skip_reason:
            out["skip_reason"] = self.skip_reason
        return out


class TrialHandle:
    """Handle returned by :meth:`MetricsCollector.open_trial`.

    Collects the assertions of exactly one trial and fixes its status:

        with metrics.open_trial("network-connect-deny-17",
                                scenario="deny_future") as t:
            t.check("tool_denied", denied)
            t.check("receiver_saw_no_effect", not received)

    An exception escaping the ``with`` body is recorded as an INFRA_ERROR and
    re-raised: a lifecycle failure is never silently turned into a pass.
    """

    def __init__(self, collector: "MetricsCollector", record: TrialRecord):
        self._collector = collector
        self._record = record
        self._closed = False

    @property
    def trial_id(self) -> str:
        return self._record.trial_id

    @property
    def record(self) -> TrialRecord:
        return self._record

    def check(self, property_name: str, passed: bool, detail: str = "",
              counter: Optional[str] = None, **meta) -> bool:
        """Record one property check. Returns ``passed`` for inline asserts."""
        self._collector._add_assertion(
            self._record,
            Assertion(property=property_name, passed=passed, detail=detail,
                      meta=meta),
            counter or property_name)
        return passed

    def violated(self, counter_name: str, detail: str = "", **meta):
        """Shorthand for a failed safety property."""
        return self.check(counter_name, False, detail, counter=counter_name,
                          **meta)

    def held(self, counter_name: str, detail: str = "", **meta):
        """Shorthand for a satisfied safety property."""
        return self.check(counter_name, True, detail, counter=counter_name,
                          **meta)

    def skip(self, reason: str):
        """Mark the trial SKIPPED. Only for tests that do not apply here."""
        if not reason:
            raise ValueError("skip() requires an explicit reason")
        self._record.status = "skipped"
        self._record.skip_reason = reason
        self._collector._drop_assertions(self._record)
        self._closed = True

    def infra_error(self, exc: Any, stage: str = ""):
        """Mark the trial INFRA_ERROR. The caller must still propagate/exit."""
        self._collector.record_infra_error(
            self._record.trial_id, exc, stage=stage, record=self._record)
        self._closed = True

    def close(self):
        self._closed = True

    def __enter__(self) -> "TrialHandle":
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None and self._record.status == "completed":
            self.infra_error(exc, stage=exc_type.__name__)
        self._closed = True
        return False  # never swallow


class MetricsCollector:
    """Collects and reports experiment metrics.

    Tracks named property counters plus one record per trial, and produces both
    JSON and human-readable reports suitable for paper tables.
    """

    def __init__(self, experiment_name: str):
        self.experiment_name = experiment_name
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self.counters: Dict[str, Counter] = {}
        self.metadata: Dict[str, Any] = {}
        self.trials: List[TrialRecord] = []
        self.infra_errors: List[Dict[str, Any]] = []
        self._trial_index: Dict[Any, TrialRecord] = {}
        self._open_handles: List[TrialHandle] = []
        self._auto_trial_seq = 0

    # ── counters ─────────────────────────────────────────────────────────

    def add_counter(self, name: str) -> Counter:
        """Register a new metric counter."""
        if name not in self.counters:
            self.counters[name] = Counter(name=name)
        return self.counters[name]

    # ── trials ───────────────────────────────────────────────────────────

    def open_trial(self, trial_id: str, scenario: str = "",
                   **meta) -> TrialHandle:
        """Start an explicitly named trial (one record, many assertions)."""
        record = TrialRecord(trial_id=trial_id, scenario=scenario,
                             meta=dict(meta))
        self.trials.append(record)
        self._trial_index[("id", trial_id)] = record
        handle = TrialHandle(self, record)
        self._open_handles.append(handle)
        return handle

    def current_trial(self) -> Optional[TrialHandle]:
        """Innermost open trial handle, if any."""
        for handle in reversed(self._open_handles):
            if not handle._closed:
                return handle
        return None

    def _group_key(self, trial_info: Optional[Dict]) -> Any:
        """Identity of the trial a ``record()`` call belongs to."""
        if not trial_info:
            return None
        key = tuple(sorted((k, str(trial_info[k])) for k in TRIAL_GROUP_KEYS
                           if k in trial_info))
        return key or None

    def _trial_for(self, trial_info: Optional[Dict]) -> TrialRecord:
        """Find (or create) the trial record a ``record()`` call belongs to."""
        handle = self.current_trial()
        if handle is not None:
            return handle.record
        key = self._group_key(trial_info)
        if key is not None and key in self._trial_index:
            return self._trial_index[key]
        if key is None:
            # No trial identity at all: this measurement stands alone.
            self._auto_trial_seq += 1
            key = ("auto", self._auto_trial_seq)
        scenario = str((trial_info or {}).get("scenario", ""))
        record = TrialRecord(
            trial_id="-".join(v for _, v in key),
            scenario=scenario,
            meta={k: v for k, v in (trial_info or {}).items()
                  if k not in TRIAL_GROUP_KEYS and k != "skipped"})
        self.trials.append(record)
        self._trial_index[key] = record
        return record

    def _add_assertion(self, record: TrialRecord, assertion: Assertion,
                       counter_name: str):
        record.assertions.append(assertion)
        counter = self.add_counter(counter_name)
        counter.record(not assertion.passed, assertion.detail)

    def _drop_assertions(self, record: TrialRecord):
        """Undo the counter effects of a trial that turned out to be skipped."""
        for assertion in record.assertions:
            counter = self.counters.get(assertion.property)
            if counter is None:
                continue
            counter.total = max(0, counter.total - 1)
            if not assertion.passed:
                counter.count = max(0, counter.count - 1)
                if assertion.detail and assertion.detail in counter.details:
                    counter.details.remove(assertion.detail)
        record.assertions = []

    # ── legacy recording API ─────────────────────────────────────────────

    def record(self, counter_name: str, violated: bool, detail: str = "",
               trial_info: Dict = None):
        """Record one property check.

        Kept for the existing call sites. The check is attached to the trial
        identified by ``trial_info`` (or to the innermost open trial), so one
        trial accumulates several assertions instead of producing several
        "trials".

        ``trial_info={'skipped': True, 'reason': ...}`` marks the whole trial
        SKIPPED and keeps it out of the denominator.
        """
        record = self._trial_for(trial_info)
        if trial_info and trial_info.get("skipped", False):
            if record.status == "completed":
                record.status = "skipped"
                record.skip_reason = str(trial_info.get("reason", ""))
                self._drop_assertions(record)
            return
        meta = {k: v for k, v in (trial_info or {}).items()
                if k not in TRIAL_GROUP_KEYS and k != "skipped"}
        self._add_assertion(
            record,
            Assertion(property=counter_name, passed=not violated,
                      detail=detail, meta=meta),
            counter_name)

    def record_trial(self, trial: Dict[str, Any]):
        """Record a complete, pre-built trial result."""
        record = TrialRecord(
            trial_id=str(trial.get("trial_id") or trial.get("scenario") or
                         f"trial-{len(self.trials)}"),
            scenario=str(trial.get("scenario", "")),
            status=str(trial.get("status", "completed")),
            meta={k: v for k, v in trial.items()
                  if k not in ("trial_id", "scenario", "status",
                               "assertions", "error")})
        for assertion in trial.get("assertions", []) or []:
            record.assertions.append(Assertion(
                property=str(assertion.get("property", "")),
                passed=bool(assertion.get("passed", False)),
                detail=str(assertion.get("detail", ""))))
        if trial.get("error"):
            record.error = trial["error"]
        self.trials.append(record)

    # ── outcomes ─────────────────────────────────────────────────────────

    def record_infra_error(self, scope: str, exc: Any, stage: str = "",
                           record: Optional[TrialRecord] = None):
        """Record an INFRA_ERROR. Never a pass; makes the run exit non-zero."""
        from .errors import InfrastructureError  # local: avoid import cycle
        if isinstance(exc, InfrastructureError):
            stage = stage or exc.stage
            message = str(exc)
        elif isinstance(exc, BaseException):
            stage = stage or type(exc).__name__
            message = f"{type(exc).__name__}: {exc}"
        else:
            stage = stage or "unspecified"
            message = str(exc)
        entry = {"scope": scope, "stage": stage, "message": message}
        self.infra_errors.append(entry)
        if record is None:
            record = TrialRecord(trial_id=scope, status="infra_error",
                                 error=entry)
            self.trials.append(record)
        else:
            record.status = "infra_error"
            record.error = entry
            self._drop_assertions(record)
        # NOTE: deliberately NOT recorded into a Counter -- infra errors are not
        # property checks, and mixing them in would inflate `violations`.
        return entry

    def record_skip(self, trial_id: str, reason: str, scenario: str = "",
                    **meta):
        """Record a SKIPPED trial (explicitly not applicable)."""
        if not reason:
            raise ValueError("record_skip() requires an explicit reason")
        self.trials.append(TrialRecord(trial_id=trial_id, scenario=scenario,
                                       status="skipped", meta=dict(meta),
                                       skip_reason=reason))

    def finish(self):
        """Mark the experiment as complete."""
        self.end_time = time.time()
        for handle in self._open_handles:
            handle.close()
        self._open_handles.clear()

    @property
    def duration(self) -> float:
        end = self.end_time or time.time()
        return end - self.start_time

    # ── aggregates ───────────────────────────────────────────────────────

    @property
    def attempted_trials(self) -> int:
        return len(self.trials)

    @property
    def completed_trials(self) -> int:
        return sum(1 for t in self.trials if t.status == "completed")

    @property
    def skipped_trials(self) -> int:
        return sum(1 for t in self.trials if t.status == "skipped")

    @property
    def infra_error_trials(self) -> int:
        return sum(1 for t in self.trials if t.status == "infra_error")

    @property
    def property_checks(self) -> int:
        return sum(c.total for c in self.counters.values())

    @property
    def violations(self) -> int:
        return sum(c.count for c in self.counters.values())

    @property
    def has_infra_errors(self) -> bool:
        return bool(self.infra_errors)

    @property
    def exit_code(self) -> int:
        """Non-zero when the run cannot support its claims.

        2 = infrastructure errors (the experiment did not actually run),
        1 = safety violations observed, 0 = clean.
        """
        if self.has_infra_errors:
            return 2
        if self.violations > 0:
            return 1
        return 0

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        # Identify 0/0 counters (no effective observations)
        empty_counters = [
            name for name, c in self.counters.items() if c.total == 0]
        # Always keep every non-completed trial; cap the completed ones.
        notable = [t for t in self.trials if t.status != "completed"]
        completed = [t for t in self.trials if t.status == "completed"]
        budget = max(0, MAX_SERIALIZED_TRIALS - len(notable))
        serialized = notable + completed[:budget]
        return {
            "experiment": self.experiment_name,
            "duration_seconds": round(self.duration, 2),
            "start_time": self.start_time,
            "end_time": self.end_time,
            "metadata": self.metadata,
            # Headline counts: trials and property checks are DIFFERENT units.
            "attempted_trials": self.attempted_trials,
            "completed_trials": self.completed_trials,
            "skipped_trials": self.skipped_trials,
            "infra_error_trials": self.infra_error_trials,
            "infrastructure_errors": len(self.infra_errors),
            "property_checks": self.property_checks,
            "violations": self.violations,
            "has_infra_errors": self.has_infra_errors,
            "exit_code": self.exit_code,
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
            "empty_counters": empty_counters,
            "infra_errors": self.infra_errors[:100],
            "trials": [t.to_dict() for t in serialized],
            "trials_truncated": len(serialized) < len(self.trials),
            # Legacy alias (older tooling read this as a trial count; it is now
            # the number of attempted trials, not of property checks).
            "total_trials": self.attempted_trials,
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
        print(f"  Trials: {self.completed_trials} completed / "
              f"{self.attempted_trials} attempted "
              f"({self.skipped_trials} skipped, "
              f"{self.infra_error_trials} infra_error)", file=out)
        print(f"  Property checks: {self.property_checks}", file=out)
        print("=" * width, file=out)

        if not self.counters:
            print("  (no metrics recorded)", file=out)
        else:
            # Find max name length for alignment
            max_name = max(len(c.name) for c in self.counters.values())
            max_name = max(max_name, 20)

            print(f"\n  {'Property':<{max_name}}  {'Violations':>12}  "
                  f"{'Rate':>10}  {'95% CI':>20}", file=out)
            print(f"  {'-' * max_name}  {'-' * 12}  {'-' * 10}  {'-' * 20}",
                  file=out)

            for name, counter in self.counters.items():
                lo, hi = counter.ci()
                count_str = f"{counter.count}/{counter.total}"
                rate_str = f"{counter.rate:.6f}"
                ci_str = f"[{lo:.6f}, {hi:.6f}]"
                print(f"  {name:<{max_name}}  {count_str:>12}  "
                      f"{rate_str:>10}  {ci_str:>20}", file=out)

            print("\n" + "=" * width, file=out)
            print(f"\n  {self.violations} violations across "
                  f"{self.property_checks} property checks in "
                  f"{self.completed_trials} completed trials", file=out)

        # Infrastructure errors are reported FIRST: they invalidate everything.
        if self.infra_errors:
            print(f"\n  INFRASTRUCTURE ERRORS: {len(self.infra_errors)}", file=out)
            by_stage: Dict[str, int] = {}
            for entry in self.infra_errors:
                by_stage[entry["stage"]] = by_stage.get(entry["stage"], 0) + 1
            for stage, count in sorted(by_stage.items(),
                                       key=lambda kv: -kv[1]):
                print(f"    - {stage}: {count}", file=out)
            for entry in self.infra_errors[:10]:
                print(f"      [{entry['scope']}] {entry['message']}", file=out)
            if len(self.infra_errors) > 10:
                print(f"      ... and {len(self.infra_errors) - 10} more",
                      file=out)
            print("\n  RESULT: INVALID RUN - infrastructure failed, the safety "
                  "properties were NOT established", file=out)
        elif self.violations > 0:
            print(f"\n  VIOLATIONS DETECTED: {self.violations}", file=out)
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
        if self.skipped_trials:
            print(f"  (note: {self.skipped_trials} trials were SKIPPED and are "
                  f"excluded from the denominator)", file=out)
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
