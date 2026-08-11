#!/usr/bin/env python3
"""Centralized path configuration for RQ2 experiments.

Path strategy:
  - harness_path(): For experiment harness file setup (creating test files,
    snapshots, etc). Uses the ShadowFS backing store (orig/) directly,
    because the harness process is NOT in a monitored cgroup with an active
    epoch, so writing through FUSE would fail with EIO.
  - fuse_path(): For probe programs that ARE in a cgroup with an active
    ShadowFS epoch. These operations go through FUSE interception.

Environment variables:
    SHADOWFS_MNT    ShadowFS FUSE mount point (default: /tmp/shadow-rq2-test/mnt)
    SHADOWFS_ORIG   ShadowFS backing store (default: /tmp/shadow-rq2-test/orig)
    SHADOWFS_STAGING ShadowFS staging area (default: /tmp/shadow-rq2-test/staging)
"""

import os

# ShadowFS FUSE mount point - probes with active epochs operate here
SHADOWFS_MNT = os.environ.get("SHADOWFS_MNT", "/tmp/shadow-rq2-test/mnt")

# ShadowFS backing store (original files)
# The harness uses this for file setup since it's not in a monitored cgroup
SHADOWFS_ORIG = os.environ.get("SHADOWFS_ORIG", "/tmp/shadow-rq2-test/orig")

# ShadowFS staging area
SHADOWFS_STAGING = os.environ.get("SHADOWFS_STAGING", "/tmp/shadow-rq2-test/staging")


def harness_path(relative: str) -> str:
    """Get a path in the backing store for harness file operations.

    Use this for:
      - Creating test files before running probes
      - Reading/verifying file state after probes
      - Any file operation done by the experiment Python process itself

    Files created here are visible through the FUSE mount at the same
    relative path (ShadowFS overlays orig/ onto mnt/).

    Example:
        harness_path("exp2/hist-0.txt") -> "/tmp/shadow-rq2-test/orig/exp2/hist-0.txt"
    """
    rel = relative.lstrip("/")
    return os.path.join(SHADOWFS_ORIG, rel)


def fuse_path(relative: str) -> str:
    """Get a path under the FUSE mount for probe operations.

    Use this ONLY for paths that will be passed to probe programs
    running inside a cgroup with an active ShadowFS epoch.

    Example:
        fuse_path("exp1/fs_write-0.txt") -> "/tmp/shadow-rq2-test/mnt/exp1/fs_write-0.txt"
    """
    rel = relative.lstrip("/")
    return os.path.join(SHADOWFS_MNT, rel)


def orig_path(relative: str) -> str:
    """Alias for harness_path (backward compat)."""
    return harness_path(relative)


def ensure_fuse_dirs(*dirs: str):
    """Ensure directories exist in the backing store.

    Creates them in orig/ so they appear through FUSE mount.
    """
    for d in dirs:
        full_orig = harness_path(d)
        os.makedirs(full_orig, exist_ok=True)


def is_fuse_mounted() -> bool:
    """Check if the ShadowFS FUSE mount is active.

    Primary check: /proc/mounts (always accessible, no FUSE permission needed).
    Secondary: os.path.isdir() as a sanity check (may fail with EPERM if
    allow_other is not set, so we do NOT let it veto the /proc/mounts result).
    """
    # Primary: check /proc/mounts for the mount point
    try:
        with open("/proc/mounts", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == SHADOWFS_MNT:
                    return True
    except OSError:
        pass
    return False
