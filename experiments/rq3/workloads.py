#!/usr/bin/env python3
"""Shared RQ3 workload definitions for Penumbra (run_all.py) and the
overlayfs+CRIU baseline (run_baseline.py).

Workloads are constructed against an abstract (orig_dir, mnt_dir) pair:
  - Penumbra passes the ShadowFS backing store and its FUSE mount point.
  - The baseline passes the overlayfs lowerdir and its merged mount point.

Both systems execute IDENTICAL commands against their respective directory
pair, so the resulting measurements are directly comparable.

Note: build_workloads() has side effects (it recreates the work directory
for W3/W5/W6 and pre-creates W7 subdirectories), mirroring the behavior of
the original run_all.py run_wX() functions.
"""

import os
import re
import shutil
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Union

from framework.harness import BENCHMARKS_BIN

# Default repeat counts per workload (keyed by workload number)
# W10's counts are far lower than the file-axis workloads: its samples run
# seconds (CRIU must move the whole payload per epoch on the baseline), so
# a few dozen suffice for stable medians.
DEFAULT_REPEATS = {
    1: 1000, 2: 1000, 3: 200, 4: 200, 5: 200,
    6: 200, 7: 100, 8: 100, 9: 200, 10: 50,
}
QUICK_REPEATS = {
    1: 50, 2: 50, 3: 20, 4: 20, 5: 20,
    6: 20, 7: 10, 8: 10, 9: 20, 10: 5,
}
WARMUP = 10


@dataclass
class WorkloadSpec:
    """One fully-parameterized workload configuration."""
    wl_num: int                     # workload number (repeats lookup key)
    workload_id: str                # e.g. "W1", "W3a", "W9b"
    config: str                     # human-readable config description
    params: dict                    # free-form parameters for the report
    raw_cmd: List[str]              # direct-execution baseline command
    spec_command: Union[str, List[str]]  # command(s) inside ONE epoch
    setup_fn: Optional[Callable] = None
    teardown_fn: Optional[Callable] = None
    verify_fn: Optional[Callable] = None
    finalize_modes: List[str] = field(
        default_factory=lambda: ["commit", "rollback"])
    new_session_per_run: bool = False   # Penumbra-only: fresh session/run
    pin_once: bool = False              # epoch-level CPU pin, no per-cmd taskset
    # W10 only: resident-memory payload (MiB) the SESSION PROCESS carries
    # before begin_epoch. Penumbra parks it in the session bash (untimed
    # setup right after session_open); the baseline swaps its sleeper for
    # w10_memhold. None/0 = no payload (all other workloads).
    session_mem_mb: Optional[int] = None


def make_verify(pattern: str):
    """Build a verify_fn for WorkloadHarness: the command output must match
    `pattern` (regex), otherwise the sample is excluded. Guards against
    silently-failed runs (non-zero exit is checked separately via exit_code;
    this catches tools that exit 0 with a truncated/partial report, e.g.
    `written=N` with N < requested).
    """
    rx = re.compile(pattern)

    def verify(output: str):
        if not rx.search(output or ""):
            return (f"output {output[:120]!r} does not match {pattern!r}")
        return None
    return verify


def bin_path(name: str) -> str:
    """Get path to a compiled benchmark binary."""
    p = os.path.join(BENCHMARKS_BIN, name)
    if not os.path.exists(p):
        raise FileNotFoundError(f"Benchmark binary not found: {p} (run make)")
    return p


# ─── Work-directory helpers (parameterized by the backing dir) ───────────────

def work_dir(base_dir: str) -> str:
    return os.path.join(base_dir, "rq3-work")


def ensure_work_dirs(orig_dir: str):
    """Create the work directory in the backing store."""
    os.makedirs(work_dir(orig_dir), exist_ok=True)


def cleanup_work_dir(orig_dir: str):
    """Remove all files in the work directory (backing-store side)."""
    wd = work_dir(orig_dir)
    if os.path.isdir(wd):
        shutil.rmtree(wd, ignore_errors=True)
    os.makedirs(wd, exist_ok=True)


def create_file(base_dir: str, rel_path: str, size: int):
    """Create a file of given size under the backing-store work directory."""
    full = os.path.join(work_dir(base_dir), rel_path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "wb") as f:
        # Write in 1 MiB chunks
        chunk = min(size, 1024 * 1024)
        buf = bytes(range(256)) * (chunk // 256 + 1)
        buf = buf[:chunk]
        written = 0
        while written < size:
            n = min(chunk, size - written)
            f.write(buf[:n])
            written += n


# ─── Workload construction ───────────────────────────────────────────────────

def build_workloads(orig_dir: str, mnt_dir: str) -> List[WorkloadSpec]:
    """Build all RQ3 workload specs against a (backing store, merged view)
    directory pair. `orig_dir` is where setup creates input files and where
    committed state lands; `mnt_dir` is the merged/sandboxed view the
    workload commands operate on.
    """
    WORK_ORIG = work_dir(orig_dir)
    WORK_MNT = work_dir(mnt_dir)

    def mnt_work_path(rel_path: str) -> str:
        return os.path.join(WORK_MNT, rel_path)

    specs: List[WorkloadSpec] = []

    # ═══════════════════════════════════════════════════════════════════════
    # W1: No-op — fixed epoch management cost
    # ═══════════════════════════════════════════════════════════════════════
    noop = bin_path("w1_noop")
    specs.append(WorkloadSpec(
        wl_num=1, workload_id="W1", config="noop",
        params={"description": "C_fixed = T_begin + T_finalize"},
        raw_cmd=[noop], spec_command=noop,
    ))

    # ═══════════════════════════════════════════════════════════════════════
    # W2: CPU-only computation at 10ms, 100ms, 1s
    # ═══════════════════════════════════════════════════════════════════════
    cpu_bin = bin_path("w2_cpu")
    for target_ms in [10, 100, 1000]:
        specs.append(WorkloadSpec(
            wl_num=2, workload_id="W2", config=f"{target_ms}ms",
            params={"target_ms": target_ms},
            raw_cmd=[cpu_bin, str(target_ms)],
            spec_command=f"{cpu_bin} {target_ms}",
            verify_fn=make_verify(r"iterations=\d+ checksum=\d+"),
        ))

    # ═══════════════════════════════════════════════════════════════════════
    # W3: Sequential file read (single + repeated)
    # ═══════════════════════════════════════════════════════════════════════
    read_bin = bin_path("w3_read")
    cleanup_work_dir(orig_dir)

    # W3-a: Single read at different sizes
    for size_label, size_bytes in [("4KiB", 4096), ("1MiB", 1048576),
                                    ("64MiB", 67108864)]:
        fname = f"input_{size_label}.bin"
        create_file(orig_dir, fname, size_bytes)

        # Read-only input: create ONCE, but re-create if a later workload's
        # cleanup_work_dir() (W5/W6 wipe the work dir at build time, which
        # happens before any measurement when specs are pre-built) removed
        # it. The per-invocation check is an untimed stat.
        def ensure_input(fn=fname, sz=size_bytes):
            if not os.path.exists(os.path.join(WORK_ORIG, fn)):
                create_file(orig_dir, fn, sz)

        specs.append(WorkloadSpec(
            wl_num=3, workload_id="W3a", config=f"read_{size_label}",
            params={"file_size": size_bytes, "variant": "single_read"},
            raw_cmd=[read_bin, os.path.join(WORK_ORIG, fname)],
            spec_command=f"{read_bin} {mnt_work_path(fname)}",
            setup_fn=ensure_input,
            verify_fn=make_verify(
                rf"bytes={size_bytes} checksum=\d+ repeats=1"),
        ))

    # W3-b: Repeated read (1MiB × 100 times)
    fname = "input_1MiB_repeat.bin"
    create_file(orig_dir, fname, 1048576)

    def ensure_repeat_input(fn=fname):
        if not os.path.exists(os.path.join(WORK_ORIG, fn)):
            create_file(orig_dir, fn, 1048576)

    specs.append(WorkloadSpec(
        wl_num=3, workload_id="W3b", config="repeat_read_1MiB_x100",
        params={"file_size": 1048576, "repeat_count": 100,
                "variant": "repeated_read"},
        raw_cmd=[read_bin, os.path.join(WORK_ORIG, fname), "100"],
        spec_command=f"{read_bin} {mnt_work_path(fname)} 100",
        setup_fn=ensure_repeat_input,
        # w3_read reports TOTAL bytes across all repeats (1 MiB × 100),
        # not the single-pass size.
        verify_fn=make_verify(r"bytes=104857600 checksum=\d+ repeats=100"),
    ))

    # ═══════════════════════════════════════════════════════════════════════
    # W4: Create new file (staging/upper write, no copy-up)
    # ═══════════════════════════════════════════════════════════════════════
    write_bin = bin_path("w4_write_new")
    for size_label, size_bytes in [("4KiB", 4096), ("1MiB", 1048576),
                                    ("16MiB", 16777216)]:
        fname = f"newfile_{size_label}.bin"
        fpath_orig = os.path.join(WORK_ORIG, fname)

        def teardown(fp=fpath_orig):
            try:
                os.unlink(fp)
            except FileNotFoundError:
                pass

        specs.append(WorkloadSpec(
            wl_num=4, workload_id="W4", config=f"new_{size_label}",
            params={"file_size": size_bytes},
            raw_cmd=[write_bin, fpath_orig, str(size_bytes)],
            spec_command=f"{write_bin} {mnt_work_path(fname)} {size_bytes}",
            teardown_fn=teardown,
            verify_fn=make_verify(rf"written={size_bytes}"),
        ))

    # ═══════════════════════════════════════════════════════════════════════
    # W5: Modify existing file (copy-up cost)
    # ═══════════════════════════════════════════════════════════════════════
    overwrite_bin = bin_path("w5_overwrite")
    cleanup_work_dir(orig_dir)
    for orig_label, orig_size in [("4KiB", 4096), ("1MiB", 1048576),
                                   ("16MiB", 16777216)]:
        fname = f"existing_{orig_label}.bin"
        create_file(orig_dir, fname, orig_size)
        fpath_orig = os.path.join(WORK_ORIG, fname)

        # Setup: recreate the file before each epoch (since commit modifies it)
        def setup(fn=fname, sz=orig_size):
            create_file(orig_dir, fn, sz)

        specs.append(WorkloadSpec(
            wl_num=5, workload_id="W5",
            config=f"overwrite4K_orig{orig_label}",
            params={"orig_size": orig_size, "write_size": 4096, "offset": 0},
            raw_cmd=[overwrite_bin, fpath_orig, "0", "4096"],
            spec_command=f"{overwrite_bin} {mnt_work_path(fname)} 0 4096",
            setup_fn=setup,
            verify_fn=make_verify(r"written=4096 offset=0"),
        ))

    # ═══════════════════════════════════════════════════════════════════════
    # W6: Repeated writes to same file
    # ═══════════════════════════════════════════════════════════════════════
    repeat_bin = bin_path("w6_repeat_write")
    cleanup_work_dir(orig_dir)

    # Create a 1 MiB file for repeated writes
    fname = "repeat_target.bin"
    create_file(orig_dir, fname, 1048576)
    fpath_orig = os.path.join(WORK_ORIG, fname)

    for count in [1, 10, 100, 1000]:
        def setup():
            create_file(orig_dir, fname, 1048576)

        specs.append(WorkloadSpec(
            wl_num=6, workload_id="W6", config=f"writes_x{count}",
            params={"write_count": count, "write_size": 4096,
                    "file_size": 1048576},
            raw_cmd=[repeat_bin, fpath_orig, str(count)],
            spec_command=f"{repeat_bin} {mnt_work_path(fname)} {count}",
            setup_fn=setup,
            verify_fn=make_verify(
                rf"writes={count} total_bytes={count * 4096}"),
        ))

    # ═══════════════════════════════════════════════════════════════════════
    # W7: Multi-file creation (finalization scaling)
    # ═══════════════════════════════════════════════════════════════════════
    multi_bin = bin_path("w7_multifile")
    for count in [1, 10, 100, 500]:
        subdir = f"multi_{count}"
        subdir_orig = os.path.join(WORK_ORIG, subdir)
        # Raw phase runs before setup_fn is ever called, so the directory
        # must already exist (w7_multifile fails open() without it).
        os.makedirs(subdir_orig, exist_ok=True)

        def setup(sd=subdir_orig):
            os.makedirs(sd, exist_ok=True)

        def teardown(sd=subdir_orig):
            shutil.rmtree(sd, ignore_errors=True)
            os.makedirs(sd, exist_ok=True)

        specs.append(WorkloadSpec(
            wl_num=7, workload_id="W7", config=f"files_x{count}",
            params={"file_count": count, "write_size": 4096},
            raw_cmd=[multi_bin, subdir_orig, str(count)],
            spec_command=f"{multi_bin} {mnt_work_path(subdir)} {count}",
            setup_fn=setup, teardown_fn=teardown,
            verify_fn=make_verify(rf"created={count} write_size=4096"),
        ))

    # ═══════════════════════════════════════════════════════════════════════
    # W8: Rename operations (namespace versioning)
    # ═══════════════════════════════════════════════════════════════════════
    rename_bin = bin_path("w8_rename")
    for count in [1, 10, 100, 500]:
        subdir = f"rename_{count}"
        subdir_orig = os.path.join(WORK_ORIG, subdir)

        def setup(sd=subdir_orig, cnt=count):
            """Create source files for rename."""
            shutil.rmtree(sd, ignore_errors=True)
            os.makedirs(sd, exist_ok=True)
            for i in range(cnt):
                fpath = os.path.join(sd, f"old-{i:04d}.bin")
                with open(fpath, "wb") as f:
                    f.write(b"\x00" * 64)

        def teardown(sd=subdir_orig):
            shutil.rmtree(sd, ignore_errors=True)

        specs.append(WorkloadSpec(
            wl_num=8, workload_id="W8", config=f"rename_x{count}",
            params={"file_count": count},
            raw_cmd=[rename_bin, subdir_orig, str(count)],
            spec_command=f"{rename_bin} {mnt_work_path(subdir)} {count}",
            setup_fn=setup, teardown_fn=teardown,
            verify_fn=make_verify(rf"renamed={count}"),
        ))

    # ═══════════════════════════════════════════════════════════════════════
    # W9: Tool output (transcript management)
    # (was "W10" until the session-memory workload took the W10 slot — see
    # the W10 section below for why the numbers moved)
    # ═══════════════════════════════════════════════════════════════════════
    output_bin = bin_path("w10_output")

    # W9-a: Single large output (one transcript entry), fresh session each
    # run so the sample is not contaminated by earlier epochs' output.
    for size_label, size_bytes in [("1KiB", 1024), ("10KiB", 10240),
                                    ("100KiB", 102400), ("1MiB", 1048576)]:
        specs.append(WorkloadSpec(
            wl_num=9, workload_id="W9a", config=f"single_{size_label}",
            params={"total_bytes": size_bytes, "variant": "single"},
            raw_cmd=[output_bin, str(size_bytes)],
            spec_command=f"{output_bin} {size_bytes}",
            new_session_per_run=True,
            verify_fn=make_verify(rf"total={size_bytes} writes=1"),
        ))

    # W9-b: N tool invocations inside ONE epoch — each invocation appends
    # one transcript entry. The entry-count axis is what differs from W9-a
    # (which varies the per-entry size).
    for entries in [10, 100, 1000]:
        specs.append(WorkloadSpec(
            wl_num=9, workload_id="W9b", config=f"entries_x{entries}",
            params={"entries": entries, "per_entry_bytes": 1024,
                    "variant": "multi"},
            raw_cmd=["bash", "-c",
                     f"for i in $(seq 1 {entries}); do "
                     f"{output_bin} 1024; done"],
            spec_command=[f"{output_bin} 1024"] * entries,
            new_session_per_run=True,
            # Pin the candidate ONCE per epoch instead of wrapping each of
            # the N runs in `taskset`: the raw baseline pays one wrapper for
            # its whole bash loop, so per-run taskset would add N× ~1.3 ms
            # of startup that has no raw counterpart (skews the entry axis).
            pin_once=True,
            verify_fn=make_verify(r"total=1024 writes=1"),
        ))

    # ═══════════════════════════════════════════════════════════════════════
    # W10: Session-resident memory (process-state snapshot scaling)
    # ═══════════════════════════════════════════════════════════════════════
    # The session process carries N bytes of dirty anonymous memory BEFORE
    # begin_epoch — the payload both engines must snapshot. Penumbra forks
    # the session shell (COW: cost independent of N while pages stay
    # clean); the baseline's CRIU dump writes every byte to image files and
    # restore reads it back (cost linear in N). The epoch command is the W1
    # noop so the axis isolates process-state cost from file effects.
    #
    # This is the retry of the removed old-W9 idea, fixed: that workload
    # allocated its working set inside a per-epoch CHILD after begin_epoch,
    # so the session process was never big and the "COW overhead" numbers
    # measured allocation cost only. Here the payload lives in the session
    # process itself, on BOTH engines:
    #   Penumbra — a shell variable parked in the session bash (untimed
    #              setup right after session_open; printf builtin fills the
    #              heap at ~1 GiB/s — see harness.session_mem_setup_command)
    #   baseline — w10_memhold replaces `sleep infinity` as the process CRIU
    #              dumps (malloc + touch every page, then park)
    # Fresh session per run so every sample snapshots exactly N bytes
    # (no transcript/heap growth across epochs).
    for size_label, size_bytes in [("16MiB", 16777216), ("64MiB", 67108864),
                                    ("256MiB", 268435456),
                                    ("1GiB", 1073741824)]:
        specs.append(WorkloadSpec(
            wl_num=10, workload_id="W10", config=f"mem_{size_label}",
            params={"session_resident_bytes": size_bytes,
                    "description": "snapshot cost vs session RSS"},
            raw_cmd=[noop], spec_command=noop,
            new_session_per_run=True,
            session_mem_mb=size_bytes // (1024 * 1024),
        ))

    return specs
