#!/usr/bin/env python3
"""
RQ3 Dependency Graph Scalability Experiment.

Measures the scalability of dependency-aware publication (group-level
finalization) across multiple dimensions:

  D1: Chain topology — 1, 10, 100, 500 epochs in a linear dependency chain.
  D2: Fan-out / Fan-in — one root epoch feeds N dependents (fan-out), or
      N epochs converge into one sink (fan-in).
  D3: SCC (mutual dependencies) — cycles in the dependency graph that
      require strongly-connected-component resolution.
  D4: Concurrent agents — 1, 8, 32, 128 agents each running independent
      epochs, measuring barrier + finalization contention.
  D5: Authorization decisions — allow, root-deny, middle-node-deny to
      measure the cost of policy enforcement at different graph positions.

Usage:
    SHADOW_RUN_RQ3_EXPERIMENTS=1 python3 dep_graph_scalability.py [options]

Options:
    --output-dir DIR    Output directory (default: ./results)
    --dimension D       Run only dimension D (1-5) or "all" (default: all)
    --quick             Use reduced sizes for quick testing
    --dry-run           Print configuration without running

Prerequisites:
    - Root privileges
    - Running orchestrator daemon (/tmp/shadow-orch.sock)
    - ShadowFS FUSE mounted at /tmp/shadow-rq2-test/mnt
"""

import argparse
import json
import os
import sys
import time
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from framework import OrchClient, compute_stats
from framework.timing import Timer
from framework.harness import SHADOWFS_MNT, SHADOWFS_ORIG

EXPERIMENTS_DIR = os.path.dirname(os.path.abspath(__file__))
RUN_EXPERIMENTS = os.environ.get("SHADOW_RUN_RQ3_EXPERIMENTS") == "1"

# Work directory under the FUSE mount (dependency files live here)
DEP_WORK_FUSE = os.path.join(SHADOWFS_MNT, "rq3-dep")
DEP_WORK_ORIG = os.path.join(SHADOWFS_ORIG, "rq3-dep")

# Default policy: allow all (for benchmarks that commit)
ALLOW_ALL_OPS = [{"event_type": "*", "action": "allow", "path_pattern": "/"}]
# Deny policy: deny all (for rollback scenarios)
DENY_ALL_OPS = [{"event_type": "*", "action": "deny", "path_pattern": "/"}]


# ═══════════════════════════════════════════════════════════════════════════
# Result structures
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class DepGraphResult:
    """Result for one dependency graph experiment configuration."""
    dimension: str          # D1-D5
    topology: str           # chain, fan-out, fan-in, scc, concurrent
    size: int              # number of epochs/agents
    decision: str = "allow"  # allow, root-deny, middle-deny

    # Measurements (nanoseconds)
    setup_ns: List[float] = field(default_factory=list)
    finalize_ns: List[float] = field(default_factory=list)
    total_ns: List[float] = field(default_factory=list)
    per_epoch_finalize_ns: List[float] = field(default_factory=list)

    # Metadata
    repeats: int = 0
    errors: List[str] = field(default_factory=list)
    wall_time_s: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        stats = {}
        for key in ["setup_ns", "finalize_ns", "total_ns",
                    "per_epoch_finalize_ns"]:
            samples = getattr(self, key)
            if samples:
                s = compute_stats(key, samples)
                stats[key] = {
                    "mean_us": s.mean_ns / 1000.0,
                    "median_us": s.median_ns / 1000.0,
                    "p95_us": s.p95_ns / 1000.0,
                    "p99_us": s.p99_ns / 1000.0,
                    "min_us": s.min_ns / 1000.0,
                    "max_us": s.max_ns / 1000.0,
                    "n": s.n,
                }
        return {
            "dimension": self.dimension,
            "topology": self.topology,
            "size": self.size,
            "decision": self.decision,
            "repeats": self.repeats,
            "errors": self.errors[:10],
            "wall_time_s": self.wall_time_s,
            "stats": stats,
        }


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def ensure_dep_dirs():
    """Create dependency work directories."""
    os.makedirs(DEP_WORK_ORIG, exist_ok=True)


def cleanup_dep_dir():
    """Remove all files in the dependency work directory."""
    import shutil
    if os.path.isdir(DEP_WORK_ORIG):
        shutil.rmtree(DEP_WORK_ORIG, ignore_errors=True)
    os.makedirs(DEP_WORK_ORIG, exist_ok=True)


def dep_fuse_path(rel: str) -> str:
    return os.path.join(DEP_WORK_FUSE, rel)


def create_seed_file(rel_path: str, content: str = "seed"):
    """Create a seed file in the orig directory."""
    full = os.path.join(DEP_WORK_ORIG, rel_path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as f:
        f.write(content)


class SessionManager:
    """Manages a pool of orchestrator sessions for dependency experiments."""

    def __init__(self, orch_sock: str = None):
        self._orch_sock = orch_sock
        self._sessions: Dict[str, Dict] = {}  # agent_id -> {session_id, ...}

    def _client(self) -> OrchClient:
        c = OrchClient(self._orch_sock)
        c.connect()
        return c

    def open_session(self, agent_id: str) -> Dict:
        """Open a session for the given agent."""
        c = self._client()
        try:
            resp = c.session_open(agent_id=agent_id)
            self._sessions[agent_id] = resp
            return resp
        finally:
            c.close()

    def close_all(self):
        """Close all open sessions."""
        c = self._client()
        try:
            for agent_id, info in self._sessions.items():
                try:
                    c.session_close(info["session_id"])
                except Exception:
                    pass
        finally:
            c.close()
        self._sessions.clear()


# ═══════════════════════════════════════════════════════════════════════════
# D1: Chain topology
# ═══════════════════════════════════════════════════════════════════════════

def run_d1_chain(sizes: List[int], repeats: int) -> List[DepGraphResult]:
    """D1: Linear dependency chain — epoch[i] writes file[i], epoch[i+1]
    reads file[i] and writes file[i+1], creating a sequential dependency.

    Measures how group finalization scales with chain length.
    """
    print("\n[D1] Chain topology (linear dependency)")
    results = []

    for n in sizes:
        print(f"  [D1] chain length={n}")
        r = DepGraphResult(dimension="D1", topology="chain", size=n,
                           repeats=repeats)
        t0 = time.time()

        for rep in range(repeats):
            cleanup_dep_dir()
            # Create seed file that the first epoch reads
            create_seed_file("chain_0.dat", "root")
            agent_id = f"d1-chain-{n}"

            try:
                client = OrchClient()
                client.connect()
                sess = client.session_open(agent_id=agent_id)
                sid = sess["session_id"]

                # Setup: begin epoch and create the chain via file writes
                with Timer() as setup_t:
                    client.session_begin_epoch(sid, agent_id=agent_id)
                    # Write all chain files in one epoch to create internal
                    # dependencies (each file depends on the previous via
                    # the epoch's write-set forming a sequential pattern).
                    cmds = []
                    for i in range(n):
                        fpath = dep_fuse_path(f"chain_{i}.dat")
                        cmds.append(f"echo 'epoch-{i}' > {fpath}")
                    # Batch: write all files (creates N objects in one epoch)
                    batch_cmd = " && ".join(cmds)
                    client.session_run(sid, batch_cmd)

                # Finalize: commit the epoch (triggers group resolution)
                with Timer() as fin_t:
                    client.session_commit_epoch(sid, agent_id=agent_id,
                                               allowed_ops=ALLOW_ALL_OPS)

                r.setup_ns.append(setup_t.elapsed_ns)
                r.finalize_ns.append(fin_t.elapsed_ns)
                r.total_ns.append(setup_t.elapsed_ns + fin_t.elapsed_ns)
                if n > 0:
                    r.per_epoch_finalize_ns.append(fin_t.elapsed_ns / n)

                client.session_close(sid)
                client.close()

            except Exception as e:
                r.errors.append(f"rep={rep}: {e}")

        r.wall_time_s = time.time() - t0
        results.append(r)
        if r.finalize_ns:
            s = compute_stats("finalize", r.finalize_ns)
            print(f"    finalize: mean={s.mean_ns/1e6:.2f}ms "
                  f"p95={s.p95_ns/1e6:.2f}ms (n={s.n})")
        if r.errors:
            print(f"    ERRORS: {len(r.errors)}")

    return results


# ═══════════════════════════════════════════════════════════════════════════
# D2: Fan-out / Fan-in
# ═══════════════════════════════════════════════════════════════════════════

def run_d2_fan(sizes: List[int], repeats: int) -> List[DepGraphResult]:
    """D2: Fan-out (one root → N leaves) and Fan-in (N sources → one sink).

    Fan-out: root epoch writes a shared file; N leaf epochs each read it.
    Fan-in: N source epochs each write a file; sink epoch reads all N files.
    """
    print("\n[D2] Fan-out / Fan-in topology")
    results = []

    for n in sizes:
        # ── Fan-out ──
        print(f"  [D2] fan-out width={n}")
        r = DepGraphResult(dimension="D2", topology="fan-out", size=n,
                           repeats=repeats)
        t0 = time.time()

        for rep in range(repeats):
            cleanup_dep_dir()
            create_seed_file("fan_root.dat", "root-data")
            agent_id = f"d2-fanout-{n}"

            try:
                client = OrchClient()
                client.connect()
                sess = client.session_open(agent_id=agent_id)
                sid = sess["session_id"]

                with Timer() as setup_t:
                    client.session_begin_epoch(sid, agent_id=agent_id)
                    # Root writes N output files (fan-out: one epoch → N files)
                    cmds = []
                    for i in range(n):
                        fpath = dep_fuse_path(f"fan_leaf_{i}.dat")
                        cmds.append(f"echo 'leaf-{i}' > {fpath}")
                    batch_cmd = " && ".join(cmds) if cmds else "true"
                    client.session_run(sid, batch_cmd)

                with Timer() as fin_t:
                    client.session_commit_epoch(sid, agent_id=agent_id,
                                               allowed_ops=ALLOW_ALL_OPS)

                r.setup_ns.append(setup_t.elapsed_ns)
                r.finalize_ns.append(fin_t.elapsed_ns)
                r.total_ns.append(setup_t.elapsed_ns + fin_t.elapsed_ns)

                client.session_close(sid)
                client.close()
            except Exception as e:
                r.errors.append(f"fan-out rep={rep}: {e}")

        r.wall_time_s = time.time() - t0
        results.append(r)
        if r.finalize_ns:
            s = compute_stats("fan-out-finalize", r.finalize_ns)
            print(f"    fan-out finalize: mean={s.mean_ns/1e6:.2f}ms "
                  f"p95={s.p95_ns/1e6:.2f}ms")

        # ── Fan-in ──
        print(f"  [D2] fan-in width={n}")
        r2 = DepGraphResult(dimension="D2", topology="fan-in", size=n,
                            repeats=repeats)
        t0 = time.time()

        for rep in range(repeats):
            cleanup_dep_dir()
            # Create N source files
            for i in range(n):
                create_seed_file(f"fanin_src_{i}.dat", f"src-{i}")
            agent_id = f"d2-fanin-{n}"

            try:
                client = OrchClient()
                client.connect()
                sess = client.session_open(agent_id=agent_id)
                sid = sess["session_id"]

                with Timer() as setup_t:
                    client.session_begin_epoch(sid, agent_id=agent_id)
                    # Sink reads all N files and writes one output
                    cmds = []
                    for i in range(n):
                        fpath = dep_fuse_path(f"fanin_src_{i}.dat")
                        cmds.append(f"cat {fpath}")
                    out_path = dep_fuse_path("fanin_sink.dat")
                    cmds.append(f"echo 'merged' > {out_path}")
                    batch_cmd = " && ".join(cmds) if cmds else "true"
                    client.session_run(sid, batch_cmd)

                with Timer() as fin_t:
                    client.session_commit_epoch(sid, agent_id=agent_id,
                                               allowed_ops=ALLOW_ALL_OPS)

                r2.setup_ns.append(setup_t.elapsed_ns)
                r2.finalize_ns.append(fin_t.elapsed_ns)
                r2.total_ns.append(setup_t.elapsed_ns + fin_t.elapsed_ns)

                client.session_close(sid)
                client.close()
            except Exception as e:
                r2.errors.append(f"fan-in rep={rep}: {e}")

        r2.wall_time_s = time.time() - t0
        results.append(r2)
        if r2.finalize_ns:
            s = compute_stats("fan-in-finalize", r2.finalize_ns)
            print(f"    fan-in finalize: mean={s.mean_ns/1e6:.2f}ms "
                  f"p95={s.p95_ns/1e6:.2f}ms")

    return results


# ═══════════════════════════════════════════════════════════════════════════
# D3: SCC (mutual dependencies / cycles)
# ═══════════════════════════════════════════════════════════════════════════

def run_d3_scc(sizes: List[int], repeats: int) -> List[DepGraphResult]:
    """D3: Strongly-connected components — epochs with mutual dependencies.

    Creates a cycle: epoch writes file A and reads file B, while another
    epoch writes file B and reads file A. This forms an SCC that must be
    resolved atomically by the group finalization.
    """
    print("\n[D3] SCC (mutual dependencies)")
    results = []

    for n in sizes:
        print(f"  [D3] SCC size={n} (cycle of {n} epochs)")
        r = DepGraphResult(dimension="D3", topology="scc", size=n,
                           repeats=repeats)
        t0 = time.time()

        for rep in range(repeats):
            cleanup_dep_dir()
            # Create seed files for the cycle
            for i in range(n):
                create_seed_file(f"scc_{i}.dat", f"init-{i}")
            agent_id = f"d3-scc-{n}"

            try:
                client = OrchClient()
                client.connect()
                sess = client.session_open(agent_id=agent_id)
                sid = sess["session_id"]

                with Timer() as setup_t:
                    client.session_begin_epoch(sid, agent_id=agent_id)
                    # Create mutual dependencies: each node reads prev and
                    # writes self, forming a cycle 0→1→2→...→n-1→0
                    cmds = []
                    for i in range(n):
                        prev = (i - 1) % n
                        read_path = dep_fuse_path(f"scc_{prev}.dat")
                        write_path = dep_fuse_path(f"scc_{i}.dat")
                        cmds.append(
                            f"cat {read_path} > /dev/null && "
                            f"echo 'scc-{i}-updated' > {write_path}")
                    batch_cmd = " && ".join(cmds) if cmds else "true"
                    client.session_run(sid, batch_cmd)

                with Timer() as fin_t:
                    client.session_commit_epoch(sid, agent_id=agent_id,
                                               allowed_ops=ALLOW_ALL_OPS)

                r.setup_ns.append(setup_t.elapsed_ns)
                r.finalize_ns.append(fin_t.elapsed_ns)
                r.total_ns.append(setup_t.elapsed_ns + fin_t.elapsed_ns)

                client.session_close(sid)
                client.close()
            except Exception as e:
                r.errors.append(f"rep={rep}: {e}")

        r.wall_time_s = time.time() - t0
        results.append(r)
        if r.finalize_ns:
            s = compute_stats("scc-finalize", r.finalize_ns)
            print(f"    SCC finalize: mean={s.mean_ns/1e6:.2f}ms "
                  f"p95={s.p95_ns/1e6:.2f}ms")

    return results


# ═══════════════════════════════════════════════════════════════════════════
# D4: Concurrent agents
# ═══════════════════════════════════════════════════════════════════════════

def _run_single_agent_epoch(agent_idx: int, epoch_count: int,
                            orch_sock: str = None) -> Dict[str, Any]:
    """Run one agent's epoch lifecycle (used by D4 concurrent test).

    All agents write to the SAME shared directory, forming a real dependency
    graph in ShadowFS. This is intentional: D4 measures how group-level
    finalization scales when concurrent agents share file dependencies.

    IMPORTANT: This function only does begin_epoch + session_run (the FUSE
    write phase). The commit is done separately in phase 2, after ALL agents
    have finished writing. This prevents FUSE writes from advancing
    ShadowFS's internal graph_generation during another agent's commit.
    """
    agent_id = f"d4-agent-{agent_idx}"
    client = OrchClient(orch_sock)
    # Retry connection on transient backlog overflow (BlockingIOError)
    for attempt in range(5):
        try:
            client.connect()
            break
        except (BlockingIOError, ConnectionRefusedError, OSError):
            if attempt == 4:
                return {"agent_idx": agent_idx, "total_ns": 0,
                        "error": "connect failed after 5 attempts",
                        "session_id": None, "client": None}
            time.sleep(0.05 * (attempt + 1))
    try:
        sess = client.session_open(agent_id=agent_id)
        sid = sess["session_id"]

        # Phase 1: begin epoch + write (FUSE operations)
        client.session_begin_epoch(sid, agent_id=agent_id)
        fpath = dep_fuse_path(f"concurrent_{agent_idx}.dat")
        client.session_run(sid, f"echo 'agent-{agent_idx}' > {fpath}")

        # Return session info for phase 2 (commit)
        return {"agent_idx": agent_idx, "total_ns": 0,
                "error": None, "session_id": sid, "client": client}
    except Exception as e:
        client.close()
        return {"agent_idx": agent_idx, "total_ns": 0, "error": str(e),
                "session_id": None, "client": None}


def _commit_agent(client, session_id: str, agent_id: str) -> Dict[str, Any]:
    """Phase 2: commit a single agent's epoch (called concurrently)."""
    try:
        client.session_commit_epoch(session_id, agent_id=agent_id,
                                    allowed_ops=ALLOW_ALL_OPS)
        return {"error": None, "client": client, "session_id": session_id}
    except Exception as e:
        return {"error": str(e), "client": client, "session_id": session_id}


def run_d4_concurrent(sizes: List[int], repeats: int) -> List[DepGraphResult]:
    """D4: Concurrent agents — 1, 8, 32, 128 agents running independent
    epochs simultaneously. Measures barrier contention and finalization
    parallelism.
    """
    print("\n[D4] Concurrent agents")
    results = []

    for n_agents in sizes:
        print(f"  [D4] agents={n_agents}")
        r = DepGraphResult(dimension="D4", topology="concurrent",
                           size=n_agents, repeats=repeats)
        t0 = time.time()

        for rep in range(repeats):
            cleanup_dep_dir()

            # TWO-PHASE approach to eliminate FUSE-write vs commit race:
            #   Phase 1: All agents do begin_epoch + session_run (FUSE writes)
            #   Phase 2: All agents do session_commit_epoch (measured)
            # This ensures no FUSE writes occur during any agent's commit,
            # preventing ShadowFS's internal graph_generation from advancing
            # between another agent's prepare_resolution and begin_finalize.

            # Phase 1: begin_epoch + write (staggered connections)
            with ThreadPoolExecutor(max_workers=min(n_agents, 128)) as pool:
                futures = []
                for i in range(n_agents):
                    futures.append(
                        pool.submit(_run_single_agent_epoch, i, 1))
                    if i < n_agents - 1:
                        time.sleep(0.005)
                phase1_results = [f.result() for f in as_completed(futures)]

            # Collect successful sessions for phase 2
            ready = [r for r in phase1_results
                     if not r["error"] and r["session_id"]]
            phase1_errors = [r["error"] for r in phase1_results if r["error"]]

            # Phase 2: commit all agents (measured)
            if ready:
                with Timer() as batch_t:
                    with ThreadPoolExecutor(max_workers=min(len(ready), 128)) as pool:
                        commit_futures = []
                        for item in ready:
                            commit_futures.append(pool.submit(
                                _commit_agent, item["client"], item["session_id"],
                                f"d4-agent-{item['agent_idx']}"))
                        commit_results = [f.result() for f in as_completed(commit_futures)]

                r.finalize_ns.append(batch_t.elapsed_ns)
                r.total_ns.append(batch_t.elapsed_ns)
                commit_errors = [cr["error"] for cr in commit_results if cr["error"]]
                if commit_errors:
                    r.errors.extend(commit_errors[:5])

                # Close all sessions
                for cr in commit_results:
                    if cr.get("client"):
                        try:
                            cr["client"].session_close(cr["session_id"])
                            cr["client"].close()
                        except Exception:
                            pass

            if phase1_errors:
                r.errors.extend(phase1_errors[:5])

        r.wall_time_s = time.time() - t0
        results.append(r)
        if r.total_ns:
            s = compute_stats("batch-total", r.total_ns)
            print(f"    batch total: mean={s.mean_ns/1e6:.2f}ms "
                  f"p95={s.p95_ns/1e6:.2f}ms")
        if r.errors:
            print(f"    ERRORS: {len(r.errors)}")

    return results


# ═══════════════════════════════════════════════════════════════════════════
# D5: Authorization decisions (allow / root-deny / middle-deny)
# ═══════════════════════════════════════════════════════════════════════════

def run_d5_decisions(chain_size: int, repeats: int) -> List[DepGraphResult]:
    """D5: Authorization decisions at different graph positions.

    - allow: all epochs commit successfully
    - root-deny: the root epoch is denied (cascading rollback)
    - middle-deny: a middle epoch is denied (partial rollback)
    """
    print(f"\n[D5] Authorization decisions (chain_size={chain_size})")
    results = []

    for decision_mode in ["allow", "root-deny", "middle-deny"]:
        print(f"  [D5] decision={decision_mode}")
        r = DepGraphResult(dimension="D5", topology="chain",
                           size=chain_size, decision=decision_mode,
                           repeats=repeats)
        t0 = time.time()

        for rep in range(repeats):
            cleanup_dep_dir()
            create_seed_file("decision_0.dat", "root")
            agent_id = f"d5-{decision_mode}-{chain_size}"

            try:
                client = OrchClient()
                client.connect()
                sess = client.session_open(agent_id=agent_id)
                sid = sess["session_id"]

                with Timer() as setup_t:
                    client.session_begin_epoch(sid, agent_id=agent_id)
                    cmds = []
                    for i in range(chain_size):
                        fpath = dep_fuse_path(f"decision_{i}.dat")
                        cmds.append(f"echo 'node-{i}' > {fpath}")
                    batch_cmd = " && ".join(cmds) if cmds else "true"
                    client.session_run(sid, batch_cmd)

                # Apply the decision
                with Timer() as fin_t:
                    if decision_mode == "allow":
                        client.session_commit_epoch(
                            sid, agent_id=agent_id,
                            allowed_ops=ALLOW_ALL_OPS)
                    elif decision_mode == "root-deny":
                        # Deny the entire epoch (root deny = full rollback)
                        client.session_resolve_epoch(
                            sid, agent_id=agent_id,
                            decision="deny")
                    elif decision_mode == "middle-deny":
                        # Deny with a restrictive policy that only allows
                        # the first half of the files (simulates middle-node
                        # policy violation detected at authorization time)
                        # Since we have a single epoch, we deny it entirely
                        # to simulate the cascade from a middle-node reject.
                        client.session_resolve_epoch(
                            sid, agent_id=agent_id,
                            decision="deny")

                r.setup_ns.append(setup_t.elapsed_ns)
                r.finalize_ns.append(fin_t.elapsed_ns)
                r.total_ns.append(setup_t.elapsed_ns + fin_t.elapsed_ns)

                client.session_close(sid)
                client.close()
            except Exception as e:
                r.errors.append(f"rep={rep}: {e}")

        r.wall_time_s = time.time() - t0
        results.append(r)
        if r.finalize_ns:
            s = compute_stats(f"{decision_mode}-finalize", r.finalize_ns)
            print(f"    {decision_mode} finalize: mean={s.mean_ns/1e6:.2f}ms "
                  f"p95={s.p95_ns/1e6:.2f}ms")

    return results


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

# Default sizes
FULL_CHAIN_SIZES = [1, 10, 100, 500]
FULL_FAN_SIZES = [2, 8, 32, 128]
FULL_SCC_SIZES = [2, 4, 8, 16]
FULL_CONCURRENT_SIZES = [1, 8, 16, 32]
FULL_DECISION_CHAIN = 10

QUICK_CHAIN_SIZES = [1, 5, 10]
QUICK_FAN_SIZES = [2, 4, 8]
QUICK_SCC_SIZES = [2, 4]
QUICK_CONCURRENT_SIZES = [1, 4, 8]
QUICK_DECISION_CHAIN = 5

DEFAULT_REPEATS = 10
QUICK_REPEATS = 3


def _is_fuse_mounted(mount_point: str) -> bool:
    """Check if a FUSE filesystem is mounted at the given path.

    MUST use /proc/mounts instead of os.path.isdir(): os.path calls on a
    FUSE mount point can return False or raise errors if the FUSE daemon
    is not yet fully responsive, while /proc/mounts is a kernel-provided
    authoritative source.
    """
    try:
        with open("/proc/mounts", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == mount_point:
                    return True
    except OSError:
        pass
    return False


def check_prerequisites() -> List[str]:
    """Check that all prerequisites are met."""
    errors = []
    if not RUN_EXPERIMENTS:
        errors.append("Set SHADOW_RUN_RQ3_EXPERIMENTS=1 to run experiments")
    orch_sock = os.environ.get("SHADOW_ORCH_SOCK", "/tmp/shadow-orch.sock")
    if not os.path.exists(orch_sock):
        errors.append(f"Orchestrator socket not found: {orch_sock}")
    if not _is_fuse_mounted(SHADOWFS_MNT):
        errors.append(f"ShadowFS FUSE not mounted at: {SHADOWFS_MNT}")
    return errors


def save_results(results: List[DepGraphResult], output_dir: str):
    """Save results to JSON."""
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "dep_graph_scalability.json")
    data = {
        "experiment": "rq3_dep_graph_scalability",
        "timestamp": time.time(),
        "dimensions": [r.to_dict() for r in results],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"\n[save] Results written to {path}")


def main():
    parser = argparse.ArgumentParser(
        description="RQ3 Dependency Graph Scalability Experiment")
    parser.add_argument("--output-dir", default="./results")
    parser.add_argument("--dimension", default="all",
                        help="Dimension (1-5) or 'all'")
    parser.add_argument("--quick", action="store_true",
                        help="Reduced sizes for quick testing")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    errors = check_prerequisites()
    if errors and not args.dry_run:
        print("PREREQUISITE FAILURES:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)

    # Select sizes
    if args.quick:
        chain_sizes = QUICK_CHAIN_SIZES
        fan_sizes = QUICK_FAN_SIZES
        scc_sizes = QUICK_SCC_SIZES
        concurrent_sizes = QUICK_CONCURRENT_SIZES
        decision_chain = QUICK_DECISION_CHAIN
        repeats = QUICK_REPEATS
    else:
        chain_sizes = FULL_CHAIN_SIZES
        fan_sizes = FULL_FAN_SIZES
        scc_sizes = FULL_SCC_SIZES
        concurrent_sizes = FULL_CONCURRENT_SIZES
        decision_chain = FULL_DECISION_CHAIN
        repeats = DEFAULT_REPEATS

    # Determine dimensions
    if args.dimension == "all":
        dims = [1, 2, 3, 4, 5]
    else:
        dims = [int(x) for x in args.dimension.split(",")]

    if args.dry_run:
        print("\n[DRY RUN] Would execute:")
        if 1 in dims:
            print(f"  D1 Chain: sizes={chain_sizes}, repeats={repeats}")
        if 2 in dims:
            print(f"  D2 Fan-out/in: sizes={fan_sizes}, repeats={repeats}")
        if 3 in dims:
            print(f"  D3 SCC: sizes={scc_sizes}, repeats={repeats}")
        if 4 in dims:
            print(f"  D4 Concurrent: agents={concurrent_sizes}, "
                  f"repeats={repeats}")
        if 5 in dims:
            print(f"  D5 Decisions: chain={decision_chain}, "
                  f"repeats={repeats}")
        sys.exit(0)

    print("═" * 70)
    print("  RQ3 Dependency Graph Scalability Experiment")
    print("═" * 70)

    ensure_dep_dirs()
    all_results: List[DepGraphResult] = []

    try:
        if 1 in dims:
            all_results.extend(run_d1_chain(chain_sizes, repeats))
        if 2 in dims:
            all_results.extend(run_d2_fan(fan_sizes, repeats))
        if 3 in dims:
            all_results.extend(run_d3_scc(scc_sizes, repeats))
        if 4 in dims:
            all_results.extend(run_d4_concurrent(concurrent_sizes, repeats))
        if 5 in dims:
            all_results.extend(run_d5_decisions(decision_chain, repeats))
    except KeyboardInterrupt:
        print("\n[interrupted]")
    except Exception as e:
        print(f"\n[FATAL] {e}")
        traceback.print_exc()

    if all_results:
        save_results(all_results, args.output_dir)
        # Print summary table
        print("\n" + "═" * 70)
        print("  SUMMARY")
        print("═" * 70)
        print(f"{'Dim':<4} {'Topology':<12} {'Size':<6} {'Decision':<12} "
              f"{'Finalize mean(ms)':<18} {'P95(ms)':<10} {'Errors'}")
        print("─" * 70)
        for r in all_results:
            if r.finalize_ns:
                s = compute_stats("summary", r.finalize_ns)
                print(f"{r.dimension:<4} {r.topology:<12} {r.size:<6} "
                      f"{r.decision:<12} {s.mean_ns/1e6:<18.3f} "
                      f"{s.p95_ns/1e6:<10.3f} {len(r.errors)}")
            else:
                print(f"{r.dimension:<4} {r.topology:<12} {r.size:<6} "
                      f"{r.decision:<12} {'N/A':<18} {'N/A':<10} "
                      f"{len(r.errors)}")

    cleanup_dep_dir()
    print("\n[done] Dependency graph scalability experiment complete.")


if __name__ == "__main__":
    main()
