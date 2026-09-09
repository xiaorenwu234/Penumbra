#!/usr/bin/env python3
"""RQ3 experiment framework for Speculative Shadow performance measurement.

Provides shared infrastructure for the ten workload groups (W1-W10) and for the
scalability experiments (multi-agent, dependency-graph shape):
  - orch_client: Orchestrator session API client + dependency-graph observation
  - timing: High-resolution timing utilities
  - stats: Statistical analysis (median, P95, P99, bootstrap CI)
  - harness: Common experiment harness logic
  - resources: Daemon CPU/RSS sampling (ShadowFS, ShadowProc, orchestrator)
"""

from .orch_client import (OrchClient, graph_delta, GRAPH_COUNTER_KEYS,
                          GRAPH_SHAPE_KEYS, GRAPH_MEMORY_KEYS)
from .timing import Timer, time_ns
from .stats import compute_stats, StatsResult
from .harness import WorkloadHarness
from .resources import (DaemonResources, ProcDelta, ProcSample, summarize,
                        aggregate_resources)

__all__ = [
    "OrchClient",
    "graph_delta",
    "GRAPH_COUNTER_KEYS",
    "GRAPH_SHAPE_KEYS",
    "GRAPH_MEMORY_KEYS",
    "Timer",
    "time_ns",
    "compute_stats",
    "StatsResult",
    "WorkloadHarness",
    "DaemonResources",
    "ProcDelta",
    "ProcSample",
    "summarize",
    "aggregate_resources",
]
