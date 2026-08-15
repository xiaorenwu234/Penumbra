#!/usr/bin/env python3
"""
RQ3 Experiment Runner — Performance overhead measurement for Penumbra.

Measures the overhead of speculative execution across 9 workload categories:
  W1:  No-op (fixed epoch management cost)
  W2:  CPU-only computation (process versioning overhead)
  W3:  Sequential file read (ShadowFS read path)
  W4:  New file creation (staging write, no copy-up)
  W5:  Modify existing file (copy-up cost)
  W6:  Repeated writes to same file (epoch-owned head reuse)
  W7:  Multi-file creation (finalization scaling)
  W8:  Rename operations (namespace versioning)
  W10: Tool output (transcript management)

(Note: W9 — process memory COW — was removed: the worker allocated its
working set AFTER begin_epoch inside a fresh child, so no baseline pages
were ever COW-forked; the measurements reflected allocation/touch time
only and did not support the claimed COW overhead.)

Usage:
    SHADOW_RUN_RQ3_EXPERIMENTS=1 python3 run_all.py [options]

Options:
    --output-dir DIR   Output directory (default: ./results)
    --workload W       Run only workload W (1-8,10) or "all" (default: all)
    --skip-build       Skip benchmark compilation
    --quick            Use reduced repeat counts for quick testing

Prerequisites:
    - Root privileges
    - Running orchestrator daemon (/tmp/shadow-orch.sock)
    - ShadowFS FUSE mounted at /tmp/shadow-rq2-test/mnt

Environment:
    SHADOW_RUN_RQ3_EXPERIMENTS=1  Required gate
    SHADOW_ORCH_SOCK              Orchestrator socket path
    SHADOWFS_MNT                  ShadowFS FUSE mount point
    SHADOWFS_ORIG                 ShadowFS backing store
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import time

# Add framework to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from framework import OrchClient, WorkloadHarness, compute_stats
from framework.harness import (
    WorkloadResult, EpochMeasurement, RawMeasurement,
    BENCHMARKS_BIN, SHADOWFS_MNT, SHADOWFS_ORIG,
)

EXPERIMENTS_DIR = os.path.dirname(os.path.abspath(__file__))
RUN_EXPERIMENTS = os.environ.get("SHADOW_RUN_RQ3_EXPERIMENTS") == "1"

# Workload-specific work directory under the FUSE mount
WORK_DIR_FUSE = os.path.join(SHADOWFS_MNT, "rq3-work")
WORK_DIR_ORIG = os.path.join(SHADOWFS_ORIG, "rq3-work")

# Default repeat counts per workload
DEFAULT_REPEATS = {
    1: 1000, 2: 1000, 3: 200, 4: 200, 5: 200,
    6: 200, 7: 100, 8: 100, 10: 200,
}
QUICK_REPEATS = {
    1: 50, 2: 50, 3: 20, 4: 20, 5: 20,
    6: 20, 7: 10, 8: 10, 10: 20,
}
WARMUP = 10


def make_verify(pattern: str):
    """Build a verify_fn for WorkloadHarness: the speculative command's
    output must match `pattern` (regex), otherwise the sample is excluded.
    Guards against silently-failed runs (non-zero exit is checked separately
    via session_run's exit_code; this catches tools that exit 0 with a
    truncated/partial report, e.g. `written=N` with N < requested).
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


def ensure_work_dirs():
    """Create work directories in both orig and FUSE mount."""
    os.makedirs(WORK_DIR_ORIG, exist_ok=True)
    # FUSE dir will be visible through the mount if orig exists


def cleanup_work_dir():
    """Remove all files in the work directory (orig side)."""
    if os.path.isdir(WORK_DIR_ORIG):
        shutil.rmtree(WORK_DIR_ORIG, ignore_errors=True)
    os.makedirs(WORK_DIR_ORIG, exist_ok=True)


def create_file_orig(rel_path: str, size: int):
    """Create a file of given size in the orig (backing store) directory."""
    full = os.path.join(WORK_DIR_ORIG, rel_path)
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


def fuse_work_path(rel_path: str) -> str:
    """Get the FUSE-visible path for a work file."""
    return os.path.join(WORK_DIR_FUSE, rel_path)


# ═══════════════════════════════════════════════════════════════════════════
# W1: No-op
# ═══════════════════════════════════════════════════════════════════════════

def run_w1(harness: WorkloadHarness, repeats: int) -> list:
    """W1: Empty operation — measures fixed epoch management cost."""
    print("\n[W1] No-op workload (fixed epoch cost)")
    noop = bin_path("w1_noop")
    results = []

    # Raw: just run the binary
    r = harness.run_workload(
        workload_id="W1",
        config="noop",
        raw_cmd=[noop],
        spec_command=noop,
        repeats=repeats,
        params={"description": "C_fixed = T_begin + T_finalize"},
    )
    results.append(r)
    return results


# ═══════════════════════════════════════════════════════════════════════════
# W2: CPU-only computation
# ═══════════════════════════════════════════════════════════════════════════

def run_w2(harness: WorkloadHarness, repeats: int) -> list:
    """W2: CPU-only computation at 10ms, 100ms, 1s."""
    print("\n[W2] CPU-only computation")
    cpu_bin = bin_path("w2_cpu")
    results = []

    for target_ms in [10, 100, 1000]:
        config = f"{target_ms}ms"
        r = harness.run_workload(
            workload_id="W2",
            config=config,
            raw_cmd=[cpu_bin, str(target_ms)],
            spec_command=f"{cpu_bin} {target_ms}",
            repeats=repeats,
            params={"target_ms": target_ms},
            verify_fn=make_verify(r"iterations=\d+ checksum=\d+"),
        )
        results.append(r)
    return results


# ═══════════════════════════════════════════════════════════════════════════
# W3: Sequential file read
# ═══════════════════════════════════════════════════════════════════════════

def run_w3(harness: WorkloadHarness, repeats: int) -> list:
    """W3: Sequential read at 4KiB, 1MiB, 64MiB + repeated read variant."""
    print("\n[W3] Sequential file read")
    read_bin = bin_path("w3_read")
    results = []
    cleanup_work_dir()

    # W3-a: Single read at different sizes
    for size_label, size_bytes in [("4KiB", 4096), ("1MiB", 1048576),
                                    ("64MiB", 67108864)]:
        fname = f"input_{size_label}.bin"
        create_file_orig(fname, size_bytes)
        fpath = fuse_work_path(fname)

        r = harness.run_workload(
            workload_id="W3a",
            config=f"read_{size_label}",
            raw_cmd=[read_bin, os.path.join(WORK_DIR_ORIG, fname)],
            spec_command=f"{read_bin} {fpath}",
            repeats=repeats,
            params={"file_size": size_bytes, "variant": "single_read"},
            verify_fn=make_verify(
                rf"bytes={size_bytes} checksum=\d+ repeats=1"),
        )
        results.append(r)

    # W3-b: Repeated read (1MiB × 100 times)
    fname = "input_1MiB_repeat.bin"
    create_file_orig(fname, 1048576)
    fpath = fuse_work_path(fname)

    r = harness.run_workload(
        workload_id="W3b",
        config="repeat_read_1MiB_x100",
        raw_cmd=[read_bin, os.path.join(WORK_DIR_ORIG, fname), "100"],
        spec_command=f"{read_bin} {fpath} 100",
        repeats=repeats,
        params={"file_size": 1048576, "repeat_count": 100,
                "variant": "repeated_read"},
        # w3_read reports TOTAL bytes across all repeats (1 MiB × 100),
        # not the single-pass size.
        verify_fn=make_verify(r"bytes=104857600 checksum=\d+ repeats=100"),
    )
    results.append(r)
    return results


# ═══════════════════════════════════════════════════════════════════════════
# W4: Create new file
# ═══════════════════════════════════════════════════════════════════════════

def run_w4(harness: WorkloadHarness, repeats: int) -> list:
    """W4: New file creation at 4KiB, 1MiB, 16MiB."""
    print("\n[W4] Create new file")
    write_bin = bin_path("w4_write_new")
    results = []

    for size_label, size_bytes in [("4KiB", 4096), ("1MiB", 1048576),
                                    ("16MiB", 16777216)]:
        config = f"new_{size_label}"
        # Each iteration creates a unique file to avoid conflicts
        # Use a setup/teardown to clean the file between runs
        fname = f"newfile_{size_label}.bin"
        fpath_fuse = fuse_work_path(fname)
        fpath_orig = os.path.join(WORK_DIR_ORIG, fname)

        def teardown(fp=fpath_orig):
            try:
                os.unlink(fp)
            except FileNotFoundError:
                pass

        r = harness.run_workload(
            workload_id="W4",
            config=config,
            raw_cmd=[write_bin, fpath_orig, str(size_bytes)],
            spec_command=f"{write_bin} {fpath_fuse} {size_bytes}",
            repeats=repeats,
            params={"file_size": size_bytes},
            teardown_fn=teardown,
            verify_fn=make_verify(rf"written={size_bytes}"),
        )
        results.append(r)
    return results


# ═══════════════════════════════════════════════════════════════════════════
# W5: Modify existing file (copy-up)
# ═══════════════════════════════════════════════════════════════════════════

def run_w5(harness: WorkloadHarness, repeats: int) -> list:
    """W5: Overwrite 4KiB of existing files (4KiB, 1MiB, 16MiB)."""
    print("\n[W5] Modify existing file (copy-up cost)")
    overwrite_bin = bin_path("w5_overwrite")
    results = []
    cleanup_work_dir()

    for orig_label, orig_size in [("4KiB", 4096), ("1MiB", 1048576),
                                   ("16MiB", 16777216)]:
        fname = f"existing_{orig_label}.bin"
        create_file_orig(fname, orig_size)
        fpath_fuse = fuse_work_path(fname)
        fpath_orig = os.path.join(WORK_DIR_ORIG, fname)

        # Setup: recreate the file before each epoch (since commit modifies it)
        def setup(fn=fname, sz=orig_size):
            create_file_orig(fn, sz)

        config = f"overwrite4K_orig{orig_label}"
        r = harness.run_workload(
            workload_id="W5",
            config=config,
            raw_cmd=[overwrite_bin, fpath_orig, "0", "4096"],
            spec_command=f"{overwrite_bin} {fpath_fuse} 0 4096",
            repeats=repeats,
            params={"orig_size": orig_size, "write_size": 4096, "offset": 0},
            setup_fn=setup,
            verify_fn=make_verify(r"written=4096 offset=0"),
        )
        results.append(r)
    return results


# ═══════════════════════════════════════════════════════════════════════════
# W6: Repeated writes to same file
# ═══════════════════════════════════════════════════════════════════════════

def run_w6(harness: WorkloadHarness, repeats: int) -> list:
    """W6: Repeated writes (1, 10, 100, 1000) to a 1MiB file."""
    print("\n[W6] Repeated writes to same file")
    repeat_bin = bin_path("w6_repeat_write")
    results = []
    cleanup_work_dir()

    # Create a 1 MiB file for repeated writes
    fname = "repeat_target.bin"
    create_file_orig(fname, 1048576)
    fpath_fuse = fuse_work_path(fname)
    fpath_orig = os.path.join(WORK_DIR_ORIG, fname)

    for count in [1, 10, 100, 1000]:
        config = f"writes_x{count}"

        def setup():
            create_file_orig(fname, 1048576)

        r = harness.run_workload(
            workload_id="W6",
            config=config,
            raw_cmd=[repeat_bin, fpath_orig, str(count)],
            spec_command=f"{repeat_bin} {fpath_fuse} {count}",
            repeats=repeats,
            params={"write_count": count, "write_size": 4096,
                    "file_size": 1048576},
            setup_fn=setup,
            verify_fn=make_verify(
                rf"writes={count} total_bytes={count * 4096}"),
        )
        results.append(r)
    return results


# ═══════════════════════════════════════════════════════════════════════════
# W7: Multi-file creation
# ═══════════════════════════════════════════════════════════════════════════

def run_w7(harness: WorkloadHarness, repeats: int) -> list:
    """W7: Multi-file creation (1, 10, 100, 500 files)."""
    print("\n[W7] Multi-file creation")
    multi_bin = bin_path("w7_multifile")
    results = []

    for count in [1, 10, 100, 500]:
        config = f"files_x{count}"
        # Use a subdirectory for each config
        subdir = f"multi_{count}"
        subdir_orig = os.path.join(WORK_DIR_ORIG, subdir)
        subdir_fuse = fuse_work_path(subdir)
        # Raw phase runs before setup_fn is ever called, so the directory
        # must already exist (w7_multifile fails open() without it).
        os.makedirs(subdir_orig, exist_ok=True)

        def setup(sd=subdir_orig):
            os.makedirs(sd, exist_ok=True)

        def teardown(sd=subdir_orig):
            shutil.rmtree(sd, ignore_errors=True)
            os.makedirs(sd, exist_ok=True)

        r = harness.run_workload(
            workload_id="W7",
            config=config,
            raw_cmd=[multi_bin, subdir_orig, str(count)],
            spec_command=f"{multi_bin} {subdir_fuse} {count}",
            repeats=repeats,
            params={"file_count": count, "write_size": 4096},
            setup_fn=setup,
            teardown_fn=teardown,
            verify_fn=make_verify(rf"created={count} write_size=4096"),
        )
        results.append(r)
    return results


# ═══════════════════════════════════════════════════════════════════════════
# W8: Rename operations
# ═══════════════════════════════════════════════════════════════════════════

def run_w8(harness: WorkloadHarness, repeats: int) -> list:
    """W8: Rename operations (1, 10, 100, 500 files)."""
    print("\n[W8] Rename operations")
    rename_bin = bin_path("w8_rename")
    results = []

    for count in [1, 10, 100, 500]:
        config = f"rename_x{count}"
        subdir = f"rename_{count}"
        subdir_orig = os.path.join(WORK_DIR_ORIG, subdir)
        subdir_fuse = fuse_work_path(subdir)

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

        r = harness.run_workload(
            workload_id="W8",
            config=config,
            raw_cmd=[rename_bin, subdir_orig, str(count)],
            spec_command=f"{rename_bin} {subdir_fuse} {count}",
            repeats=repeats,
            params={"file_count": count},
            setup_fn=setup,
            teardown_fn=teardown,
            finalize_modes=["commit", "rollback"],
            verify_fn=make_verify(rf"renamed={count}"),
        )
        results.append(r)
    return results


# ═══════════════════════════════════════════════════════════════════════════
# W10: Tool output
# ═══════════════════════════════════════════════════════════════════════════

def run_w10(harness: WorkloadHarness, repeats: int) -> list:
    """W10: Tool output — W10a: single output of increasing size;
    W10b: N separate tool invocations in ONE epoch (N transcript entries).

    W10a uses a FRESH session per run so its samples isolate the per-epoch
    output cost; W10b runs N commands inside the same epoch, so each
    command appends exactly one transcript entry (the entry-count axis).
    """
    print("\n[W10] Tool output")
    output_bin = bin_path("w10_output")
    results = []

    # W10-a: Single large output (one transcript entry), fresh session each
    # run so the measurement is not contaminated by earlier epochs' output
    # accumulated in the same session.
    for size_label, size_bytes in [("1KiB", 1024), ("10KiB", 10240),
                                    ("100KiB", 102400), ("1MiB", 1048576)]:
        config = f"single_{size_label}"
        r = harness.run_workload(
            workload_id="W10a",
            config=config,
            raw_cmd=[output_bin, str(size_bytes)],
            spec_command=f"{output_bin} {size_bytes}",
            repeats=repeats,
            params={"total_bytes": size_bytes, "variant": "single"},
            new_session_per_run=True,
            verify_fn=make_verify(rf"total={size_bytes} writes=1"),
        )
        results.append(r)

    # W10-b: N tool invocations inside ONE epoch — each invocation is a
    # separate session_run and appends one transcript entry. Total output
    # grows with N (1 KiB per entry); the entry-count axis is what differs
    # from W10a (which varies the per-entry size).
    for entries in [10, 100, 1000]:
        config = f"entries_x{entries}"
        r = harness.run_workload(
            workload_id="W10b",
            config=config,
            raw_cmd=["bash", "-c",
                     f"for i in $(seq 1 {entries}); do "
                     f"{output_bin} 1024; done"],
            spec_command=[f"{output_bin} 1024"] * entries,
            repeats=repeats,
            params={"entries": entries, "per_entry_bytes": 1024,
                    "variant": "multi"},
            new_session_per_run=True,
            verify_fn=make_verify(r"total=1024 writes=1"),
        )
        results.append(r)
    return results


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

def check_prerequisites(skip_orch: bool = False):
    """Verify all prerequisites are met."""
    errors = []
    if os.geteuid() != 0:
        errors.append("Must run as root")
    if not RUN_EXPERIMENTS:
        errors.append("Set SHADOW_RUN_RQ3_EXPERIMENTS=1")
    if not skip_orch:
        orch_sock = os.environ.get("SHADOW_ORCH_SOCK", "/tmp/shadow-orch.sock")
        if not os.path.exists(orch_sock):
            errors.append(f"Orchestrator socket not found: {orch_sock}")
    if not os.path.isdir(BENCHMARKS_BIN):
        errors.append(f"Benchmark binaries not found: {BENCHMARKS_BIN}")
    return errors


def build_benchmarks():
    """Compile benchmark programs."""
    print("[build] Compiling benchmarks ...")
    result = subprocess.run(
        ["make", "-C", os.path.join(EXPERIMENTS_DIR, "benchmarks"), "all"],
        capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[build] FAILED:\n{result.stderr}")
        return False
    print("[build] Done")
    return True


WORKLOAD_FUNCS = {
    1: run_w1, 2: run_w2, 3: run_w3, 4: run_w4, 5: run_w5,
    6: run_w6, 7: run_w7, 8: run_w8, 10: run_w10,
}


def merge_save_results(new_results, output_dir: str, experiment_name: str = "rq3"):
    """Save results, merging with an existing JSON report instead of
    overwriting it wholesale.

    Runs can target a workload subset (e.g. only W10 to re-collect data
    after a fix); overwriting would silently drop the other workloads'
    measurements from the report. Entries are keyed by (workload_id,
    config): existing entries with the same key are replaced by the new
    measurements, all others are preserved.
    """
    import json as _json
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, f"{experiment_name}.json")
    merged = [r.to_dict() for r in new_results]
    new_keys = {(r.workload_id, r.config) for r in new_results}
    if os.path.exists(path):
        try:
            with open(path) as f:
                old = _json.load(f)
            merged = ([w for w in old.get("workloads", [])
                       if (w.get("workload_id"), w.get("config"))
                       not in new_keys] + merged)
        except Exception:
            print(f"[save] existing {path} unreadable/corrupt -- overwriting")
    data = {
        "experiment": experiment_name,
        "timestamp": time.time(),
        "workloads": merged,
    }
    with open(path, "w") as f:
        _json.dump(data, f, indent=2, ensure_ascii=False)


def main():
    parser = argparse.ArgumentParser(
        description="RQ3 Performance Experiment Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output-dir", default="./results",
                        help="Output directory")
    parser.add_argument("--workload", default="all",
                        help="Workload number (1-10) or 'all'")
    parser.add_argument("--skip-build", action="store_true",
                        help="Skip benchmark compilation")
    parser.add_argument("--quick", action="store_true",
                        help="Use reduced repeat counts")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print configuration without running")
    args = parser.parse_args()

    errors = check_prerequisites(skip_orch=args.dry_run)
    if errors:
        print("PREREQUISITE FAILURES:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)

    if not args.skip_build and not args.dry_run:
        if not build_benchmarks():
            sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)
    ensure_work_dirs()

    # Determine workloads
    if args.workload == "all":
        wl_nums = [1, 2, 3, 4, 5, 6, 7, 8, 10]  # W9 removed (no COW measured)
    else:
        # Comma-separated subset, e.g. "5,6,7,8,10"
        wl_nums = [int(x) for x in args.workload.split(",")]

    repeats_map = QUICK_REPEATS if args.quick else DEFAULT_REPEATS

    # Dry-run: just print what would be done
    if args.dry_run:
        print("\n[DRY RUN] Would execute:")
        for wl in wl_nums:
            repeats = repeats_map.get(wl, 100)
            print(f"  W{wl}: repeats={repeats}, warmup={WARMUP}")
        print(f"\n  Output: {args.output_dir}")
        print(f"  Benchmarks: {BENCHMARKS_BIN}")
        print(f"  FUSE mount: {SHADOWFS_MNT}")
        print(f"  Backing store: {SHADOWFS_ORIG}")
        sys.exit(0)

    harness = WorkloadHarness(warmup=WARMUP)

    all_results = []
    try:
        for wl in wl_nums:
            repeats = repeats_map.get(wl, 100)
            print(f"\n{'#'*70}")
            print(f"  WORKLOAD W{wl} (repeats={repeats})")
            print(f"{'#'*70}")
            try:
                results = WORKLOAD_FUNCS[wl](harness, repeats)
                all_results.extend(results)
            except KeyboardInterrupt:
                print(f"\n[runner] Interrupted during W{wl}")
                break
            except Exception as e:
                print(f"\n[runner] W{wl} failed: {e}")
                import traceback
                traceback.print_exc()
    finally:
        harness.close()

    # Save and print results
    if all_results:
        merge_save_results(all_results, args.output_dir, "rq3")
        WorkloadHarness.print_summary(all_results)

    # Cleanup
    cleanup_work_dir()
    print("\n[done] RQ3 experiments complete.")


if __name__ == "__main__":
    main()
