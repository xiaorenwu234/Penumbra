#!/usr/bin/env python3
"""RQ2 experiment framework for Speculative Shadow.

Provides shared infrastructure for the five experiment groups:
  - client: Unix socket JSON-line clients for ShadowProc/ShadowFS/ShadowObserve
  - cgroup: cgroup v2 lifecycle management
  - oracle: external effect verification
  - metrics: measurement collection and reporting
  - runner: probe process management and synchronization
"""

from .client import ShadowProcClient, ShadowFSClient, ShadowObserveClient
from .cgroup import CgroupManager
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
    "CgroupManager",
    "EffectOracle",
    "MetricsCollector",
    "binomial_ci",
    "ProbeRunner",
    "SHADOWFS_MNT",
    "SHADOWFS_ORIG",
    "SHADOWFS_STAGING",
    "fuse_path",
    "orig_path",
    "harness_path",
    "ensure_fuse_dirs",
    "is_fuse_mounted",
]
