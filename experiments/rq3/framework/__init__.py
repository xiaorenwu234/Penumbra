#!/usr/bin/env python3
"""RQ3 experiment framework for Speculative Shadow performance measurement.

Provides shared infrastructure for the ten workload groups (W1-W10):
  - orch_client: Orchestrator session API client
  - timing: High-resolution timing utilities
  - stats: Statistical analysis (median, P95, P99, bootstrap CI)
  - harness: Common experiment harness logic
"""

from .orch_client import OrchClient
from .timing import Timer, time_ns
from .stats import compute_stats, StatsResult
from .harness import WorkloadHarness

__all__ = [
    "OrchClient",
    "Timer",
    "time_ns",
    "compute_stats",
    "StatsResult",
    "WorkloadHarness",
]
