#!/usr/bin/env python3
"""RQ2 experiment framework for Speculative Shadow.

Provides shared infrastructure for the five experiment groups:
  - client: Unix socket JSON-line clients for ShadowProc/ShadowFS/ShadowObserve
  - orch: ShadowOrchestrator session API client (the real lifecycle path)
  - cgroup: cgroup v2 lifecycle management
  - oracle: external effect verification
  - metrics: trial/assertion measurement collection and reporting
  - runner: probe process management and synchronization
  - errors: PASS / VIOLATION / INFRA_ERROR / SKIPPED outcome classification
"""

from .client import ShadowProcClient, ShadowFSClient, ShadowObserveClient
from .cgroup import CgroupManager
from .errors import (
    InfrastructureError, infra, reraise_as_infra,
    PASS, VIOLATION, INFRA_ERROR, SKIPPED,
)
from .orch import OrchClient, orch_sock_path
from .oracle import EffectOracle
from .metrics import MetricsCollector, binomial_ci
from .runner import ProbeRunner
from .paths import (
    SHADOWFS_MNT, SHADOWFS_ORIG, SHADOWFS_STAGING,
    fuse_path, orig_path, harness_path, ensure_fuse_dirs, is_fuse_mounted,
)

__all__ = [
    "ShadowProcClient",
    "ShadowFSClient",
    "ShadowObserveClient",
    "OrchClient",
    "orch_sock_path",
    "CgroupManager",
    "EffectOracle",
    "MetricsCollector",
    "binomial_ci",
    "ProbeRunner",
    "InfrastructureError",
    "infra",
    "reraise_as_infra",
    "PASS",
    "VIOLATION",
    "INFRA_ERROR",
    "SKIPPED",
    "SHADOWFS_MNT",
    "SHADOWFS_ORIG",
    "SHADOWFS_STAGING",
    "fuse_path",
    "orig_path",
    "harness_path",
    "ensure_fuse_dirs",
    "is_fuse_mounted",
]
