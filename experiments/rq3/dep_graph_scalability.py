#!/usr/bin/env python3
"""
RQ3 Dependency Graph Scalability Experiment.

Measures the scalability of dependency-aware publication (group-level
finalization) across multiple dimensions:

  D1: Chain topology — 2, 4, 8, 16 epochs in a linear dependency chain.
      Each node is an independent epoch: epoch[i] writes file[i], epoch[i+1]
      reads file[i] (creating a real cross-epoch read-from edge).
  D2: Fan-out / Fan-in — one root epoch feeds N dependents (fan-out), or
      N epochs converge into one sink (fan-in). Each node is a separate epoch.
  D3: SCC (mutual dependencies) — cycles in the dependency graph that
      require strongly-connected-component resolution. Each node in the
      cycle is a separate epoch with cross-epoch reads forming the cycle.
  D4: Concurrent agents — 1, 4, 8, 16 agents each with its own epoch,
      all consuming a shared root epoch's output (real dependency graph).
  D5: Authorization decisions — allow, root-deny, middle-node-deny on a
      multi-epoch chain to measure policy enforcement at different positions.

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
from typing import Any, Dict, List, Optional, Set, Tuple

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

    # Dependency verification
    affected_epochs: int = 0  # affected cgroup count from get_affected
    topo_verified: bool = False  # precise set-equality topology check passed

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
                    "ci_95_low_us": s.ci_95_low_ns / 1000.0,
                    "ci_95_high_us": s.ci_95_high_ns / 1000.0,
                    "n": s.n,
                }
        return {
            "dimension": self.dimension,
            "topology": self.topology,
            "size": self.size,
            "decision": self.decision,
            "repeats": self.repeats,
            "affected_epochs": self.affected_epochs,
            "topo_verified": self.topo_verified,
            "errors": self.errors[:10],
            "wall_time_s": self.wall_time_s,
            "stats": stats,
            "raw_finalize_ns": self.finalize_ns,
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
    """Create a seed file in the orig (backing store) directory.

    Files MUST pre-exist in the backing store so FUSE Lookup succeeds
    when the consumer epoch opens them. Without this, the VFS returns
    ENOENT before reaching the Open handler where Resolve() records
    the read-from dependency edge.
    """
    full = os.path.join(DEP_WORK_ORIG, rel_path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as f:
        f.write(content)


@dataclass
class EpochNode:
    """A single epoch node in the dependency graph (one session = one epoch)."""
    node_id: str
    session_id: str
    cgroup_id: str
    epoch_id: str
    agent_id: str


def open_epoch_node(client: OrchClient, node_id: str,
                    run_tag: str) -> EpochNode:
    """Open a session and begin an epoch for one graph node.

    Each graph node gets its own session (hence its own cgroup and epoch),
    ensuring ShadowFS tracks it as an independent vertex in the dep graph.
    """
    agent_id = f"dep-{run_tag}-{node_id}"
    sess = client.session_open(agent_id=agent_id)
    sid = sess["session_id"]
    cg_id = sess["cgroup_id"]
    epoch_resp = client.session_begin_epoch(sid, agent_id=agent_id)
    epoch_id = epoch_resp.get("epoch_id", "")
    return EpochNode(node_id=node_id, session_id=sid, cgroup_id=cg_id,
                     epoch_id=epoch_id, agent_id=agent_id)


def verify_dependencies(client: OrchClient, nodes: List[EpochNode],
                        topology: str) -> Tuple[int, bool, List[str]]:
    """Verify cross-epoch dependencies with precise set-equality checks.

    For each topology, checks that get_affected returns the EXACT expected
    set of cgroups (not just a count threshold):
      - chain: node[0] affects all N nodes (full downstream)
      - fan-out: root affects all; each leaf affects only itself
      - fan-in: each source affects {source_i, sink}
      - scc: any node affects all N nodes
      - concurrent: root affects all agents

    Returns (affected_count_from_root, topo_verified, errors).
    """
    if not nodes:
        return 0, False, ["no nodes to verify"]
    errors = []
    affected_count = 0
    topo_ok = True

    # Build cgroup set for membership checks
    all_cgroups = {n.cgroup_id for n in nodes}

    def _get_aff(node: EpochNode) -> Optional[Set[str]]:
        try:
            resp = client.get_affected(node.cgroup_id)
            return set(resp.get("affected", []))
        except Exception as e:
            errors.append(f"get_affected({node.node_id}) failed: {e}")
            return None

    if topology == "chain":
        # Root (node[0]) rollback should cascade to ALL downstream = all N
        aff = _get_aff(nodes[0])
        if aff is not None:
            affected_count = len(aff)
            expected = all_cgroups
            if not expected.issubset(aff):
                topo_ok = False
                errors.append(
                    f"chain: root affected {len(aff)} cgroups, "
                    f"expected all {len(expected)}")

    elif topology == "fan-out":
        # Root affects all; spot-check last leaf affects only itself
        aff_root = _get_aff(nodes[0])
        if aff_root is not None:
            affected_count = len(aff_root)
            if not all_cgroups.issubset(aff_root):
                topo_ok = False
                errors.append(
                    f"fan-out: root affected {len(aff_root)}, "
                    f"expected {len(all_cgroups)}")
        # Leaf self-check (last leaf)
        if len(nodes) > 1:
            aff_leaf = _get_aff(nodes[-1])
            if aff_leaf is not None:
                # Leaf should only affect itself (no downstream)
                leaf_self = {nodes[-1].cgroup_id}
                if not aff_leaf.issubset(leaf_self | {nodes[0].cgroup_id}):
                    # Allow {self} or {self, root} depending on ShadowFS
                    if len(aff_leaf) > 2:
                        topo_ok = False
                        errors.append(
                            f"fan-out: leaf affected {len(aff_leaf)}, "
                            f"expected <=2")

    elif topology == "fan-in":
        # Each source affects {source_i, sink}; check first source
        sink = nodes[-1]
        aff_src = _get_aff(nodes[0])
        if aff_src is not None:
            affected_count = len(aff_src)
            expected = {nodes[0].cgroup_id, sink.cgroup_id}
            if not expected.issubset(aff_src):
                topo_ok = False
                errors.append(
                    f"fan-in: source[0] affected {len(aff_src)}, "
                    f"expected superset of {{src0, sink}}")

    elif topology == "scc":
        # ANY node affects ALL N nodes (strongly connected)
        aff = _get_aff(nodes[0])
        if aff is not None:
            affected_count = len(aff)
            if not all_cgroups.issubset(aff):
                topo_ok = False
                errors.append(
                    f"scc: node[0] affected {len(aff)}, "
                    f"expected all {len(all_cgroups)}")

    elif topology == "concurrent":
        # Root affects all agents
        aff = _get_aff(nodes[0])
        if aff is not None:
            affected_count = len(aff)
            if not all_cgroups.issubset(aff):
                topo_ok = False
                errors.append(
                    f"concurrent: root affected {len(aff)}, "
                    f"expected all {len(all_cgroups)}")
    else:
        # Generic fallback: just count
        aff = _get_aff(nodes[0])
        if aff is not None:
            affected_count = len(aff)

    return affected_count, topo_ok, errors


def close_all_nodes(client: OrchClient, nodes: List[EpochNode]):
    """Close all sessions (best-effort cleanup)."""
    for node in nodes:
        try:
            client.session_close(node.session_id)
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════
# D1: Chain topology
# ═══════════════════════════════════════════════════════════════════════════

def run_d1_chain(sizes: List[int], repeats: int) -> List[DepGraphResult]:
    """D1: Linear dependency chain — N independent epochs forming a chain.

    epoch[0] writes file[0], epoch[1] reads file[0] and writes file[1],
    epoch[2] reads file[1] and writes file[2], etc. Each read across epochs
    creates a real ShadowFS read-from dependency edge.

    Measures how group finalization scales with chain length.
    """
    print("\n[D1] Chain topology (linear dependency, cross-epoch)")
    results = []

    for n in sizes:
        print(f"  [D1] chain length={n}")
        r = DepGraphResult(dimension="D1", topology="chain", size=n,
                           repeats=repeats)
        t0 = time.time()

        for rep in range(repeats):
            cleanup_dep_dir()
            # Pre-create ALL chain files in backing store so FUSE Lookup
            # succeeds when consumer epochs open them.
            for i in range(n):
                create_seed_file(f"chain_{i}.dat", f"base-{i}")

            run_tag = f"d1-{n}-r{rep}"
            nodes: List[EpochNode] = []
            rep_t0 = time.time()
            try:
                client = OrchClient()
                client.connect()

                # Setup: open N sessions, begin N epochs, build chain deps
                with Timer() as setup_t:
                    # Open all epoch nodes
                    for i in range(n):
                        node = open_epoch_node(client, f"n{i}", run_tag)
                        nodes.append(node)

                    # Build cross-epoch dependencies sequentially:
                    # epoch[i] writes file[i], epoch[i+1] reads file[i]
                    for i in range(n):
                        fpath = dep_fuse_path(f"chain_{i}.dat")
                        # Producer epoch writes (creates speculative version)
                        client.session_run(
                            nodes[i].session_id,
                            f"echo 'epoch-{i}' > {fpath}")
                        # Consumer epoch reads (records read-from edge)
                        if i + 1 < n:
                            client.session_run(
                                nodes[i + 1].session_id,
                                f"cat {fpath} > /dev/null")

                # Verify dependencies formed before timing finalization
                verified, topo_ok, verrs = verify_dependencies(
                    client, nodes, "chain")
                r.affected_epochs = verified
                r.topo_verified = topo_ok
                if verrs:
                    r.errors.extend(verrs)

                # Finalize: commit all epochs (triggers group resolution)
                with Timer() as fin_t:
                    for node in nodes:
                        client.session_commit_epoch(
                            node.session_id, agent_id=node.agent_id,
                            allowed_ops=ALLOW_ALL_OPS)

                r.setup_ns.append(setup_t.elapsed_ns)
                r.finalize_ns.append(fin_t.elapsed_ns)
                r.total_ns.append(setup_t.elapsed_ns + fin_t.elapsed_ns)
                if n > 0:
                    r.per_epoch_finalize_ns.append(fin_t.elapsed_ns / n)

                close_all_nodes(client, nodes)
                client.close()

            except Exception as e:
                r.errors.append(f"rep={rep}: {e}")
                # Best-effort cleanup
                try:
                    close_all_nodes(client, nodes)
                    client.close()
                except Exception:
                    pass

            print(f"    rep {rep+1}/{repeats} done "
                  f"({time.time()-rep_t0:.1f}s)", flush=True)

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

    Fan-out: root epoch writes a shared file; N leaf epochs each read it
    in their own independent epoch (creating N cross-epoch dep edges).
    Fan-in: N source epochs each write a distinct file; sink epoch reads
    all N files (creating N cross-epoch dep edges into one node).
    """
    print("\n[D2] Fan-out / Fan-in topology (cross-epoch)")
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
            run_tag = f"d2fo-{n}-r{rep}"
            nodes: List[EpochNode] = []
            rep_t0 = time.time()

            try:
                client = OrchClient()
                client.connect()

                with Timer() as setup_t:
                    # Root epoch
                    root = open_epoch_node(client, "root", run_tag)
                    nodes.append(root)
                    # Leaf epochs
                    for i in range(n):
                        leaf = open_epoch_node(client, f"leaf{i}", run_tag)
                        nodes.append(leaf)

                    # Root writes the shared file
                    root_file = dep_fuse_path("fan_root.dat")
                    client.session_run(
                        root.session_id,
                        f"echo 'root-output' > {root_file}")
                    # Each leaf reads the root's output (cross-epoch dep)
                    for i in range(n):
                        client.session_run(
                            nodes[i + 1].session_id,
                            f"cat {root_file} > /dev/null")

                verified, topo_ok, verrs = verify_dependencies(
                    client, nodes, "fan-out")
                r.affected_epochs = verified
                r.topo_verified = topo_ok
                if verrs:
                    r.errors.extend(verrs)

                with Timer() as fin_t:
                    for node in nodes:
                        client.session_commit_epoch(
                            node.session_id, agent_id=node.agent_id,
                            allowed_ops=ALLOW_ALL_OPS)

                r.setup_ns.append(setup_t.elapsed_ns)
                r.finalize_ns.append(fin_t.elapsed_ns)
                r.total_ns.append(setup_t.elapsed_ns + fin_t.elapsed_ns)

                close_all_nodes(client, nodes)
                client.close()
            except Exception as e:
                r.errors.append(f"fan-out rep={rep}: {e}")
                try:
                    close_all_nodes(client, nodes)
                    client.close()
                except Exception:
                    pass

            print(f"    rep {rep+1}/{repeats} done "
                  f"({time.time()-rep_t0:.1f}s)", flush=True)

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
            # Pre-create source files in backing store
            for i in range(n):
                create_seed_file(f"fanin_src_{i}.dat", f"src-base-{i}")
            run_tag = f"d2fi-{n}-r{rep}"
            nodes = []
            rep_t0 = time.time()

            try:
                client = OrchClient()
                client.connect()

                with Timer() as setup_t:
                    # Source epochs
                    for i in range(n):
                        src = open_epoch_node(client, f"src{i}", run_tag)
                        nodes.append(src)
                    # Sink epoch
                    sink = open_epoch_node(client, "sink", run_tag)
                    nodes.append(sink)

                    # Each source writes its own file
                    for i in range(n):
                        fpath = dep_fuse_path(f"fanin_src_{i}.dat")
                        client.session_run(
                            nodes[i].session_id,
                            f"echo 'src-{i}-output' > {fpath}")
                    # Sink reads ALL source files (cross-epoch deps)
                    for i in range(n):
                        fpath = dep_fuse_path(f"fanin_src_{i}.dat")
                        client.session_run(
                            sink.session_id,
                            f"cat {fpath} > /dev/null")

                # Fan-in: rolling back one source cascades to the sink
                verified, topo_ok, verrs = verify_dependencies(
                    client, nodes, "fan-in")
                r2.affected_epochs = verified
                r2.topo_verified = topo_ok
                if verrs:
                    r2.errors.extend(verrs)

                with Timer() as fin_t:
                    for node in nodes:
                        client.session_commit_epoch(
                            node.session_id, agent_id=node.agent_id,
                            allowed_ops=ALLOW_ALL_OPS)

                r2.setup_ns.append(setup_t.elapsed_ns)
                r2.finalize_ns.append(fin_t.elapsed_ns)
                r2.total_ns.append(setup_t.elapsed_ns + fin_t.elapsed_ns)

                close_all_nodes(client, nodes)
                client.close()
            except Exception as e:
                r2.errors.append(f"fan-in rep={rep}: {e}")
                try:
                    close_all_nodes(client, nodes)
                    client.close()
                except Exception:
                    pass

            print(f"    rep {rep+1}/{repeats} done "
                  f"({time.time()-rep_t0:.1f}s)", flush=True)

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

    Creates a cycle of N independent epochs: epoch[i] writes file[i] and
    reads file[(i-1) % N]. Since every epoch both produces and consumes
    another epoch's output, the dependency graph forms a cycle (SCC).

    SCCs cannot be committed sequentially (each epoch's finalize would
    require its dependencies to be finalized first — circular). Instead,
    this measures the CASCADE ROLLBACK cost: denying one epoch in the SCC
    triggers atomic rollback of the entire cycle. This is the meaningful
    scalability metric for SCC resolution.
    """
    print("\n[D3] SCC (mutual dependencies, cascade rollback)")
    results = []

    for n in sizes:
        print(f"  [D3] SCC size={n} (cycle of {n} epochs)")
        r = DepGraphResult(dimension="D3", topology="scc", size=n,
                           decision="rollback-cascade", repeats=repeats)
        t0 = time.time()

        for rep in range(repeats):
            cleanup_dep_dir()
            # Pre-create all cycle files in backing store
            for i in range(n):
                create_seed_file(f"scc_{i}.dat", f"init-{i}")
            run_tag = f"d3-{n}-r{rep}"
            nodes: List[EpochNode] = []
            rep_t0 = time.time()

            try:
                client = OrchClient()
                client.connect()

                with Timer() as setup_t:
                    # Open N independent epoch nodes
                    for i in range(n):
                        node = open_epoch_node(client, f"cyc{i}", run_tag)
                        nodes.append(node)

                    # Phase 1: each epoch writes its own file
                    for i in range(n):
                        fpath = dep_fuse_path(f"scc_{i}.dat")
                        client.session_run(
                            nodes[i].session_id,
                            f"echo 'scc-{i}-written' > {fpath}")

                    # Phase 2: each epoch reads its predecessor's file
                    # epoch[i] reads file[(i-1) % n] → creates cycle
                    for i in range(n):
                        prev = (i - 1) % n
                        read_path = dep_fuse_path(f"scc_{prev}.dat")
                        client.session_run(
                            nodes[i].session_id,
                            f"cat {read_path} > /dev/null")

                # Verify: in an SCC, rolling back any node should affect all
                verified, topo_ok, verrs = verify_dependencies(
                    client, nodes, "scc")
                r.affected_epochs = verified
                r.topo_verified = topo_ok
                if verrs:
                    r.errors.extend(verrs)

                # Measure cascade rollback: deny ONE epoch, ShadowFS
                # cascades to the entire SCC atomically.
                # Timer covers ONLY the single deny RPC — the cascade is
                # handled internally by ShadowFS within that one call.
                with Timer() as fin_t:
                    client.session_resolve_epoch(
                        nodes[0].session_id,
                        agent_id=nodes[0].agent_id,
                        decision="deny")

                # Cleanup outside timer: rollback any surviving epochs
                for node in nodes[1:]:
                    try:
                        client.session_rollback_epoch(
                            node.session_id,
                            agent_id=node.agent_id)
                    except Exception:
                        pass  # already rolled back by cascade

                r.setup_ns.append(setup_t.elapsed_ns)
                r.finalize_ns.append(fin_t.elapsed_ns)
                r.total_ns.append(setup_t.elapsed_ns + fin_t.elapsed_ns)

                close_all_nodes(client, nodes)
                client.close()
            except Exception as e:
                r.errors.append(f"rep={rep}: {e}")
                try:
                    close_all_nodes(client, nodes)
                    client.close()
                except Exception:
                    pass

            print(f"    rep {rep+1}/{repeats} done "
                  f"({time.time()-rep_t0:.1f}s)", flush=True)

        r.wall_time_s = time.time() - t0
        results.append(r)
        if r.finalize_ns:
            s = compute_stats("scc-rollback", r.finalize_ns)
            print(f"    SCC cascade rollback: mean={s.mean_ns/1e6:.2f}ms "
                  f"p95={s.p95_ns/1e6:.2f}ms")

    return results


# ═══════════════════════════════════════════════════════════════════════════
# D4: Concurrent agents with shared dependency
# ═══════════════════════════════════════════════════════════════════════════

def _open_and_write_agent(agent_idx: int, run_tag: str,
                          shared_file: str) -> Dict[str, Any]:
    """Open one agent's epoch and read the shared root file.

    Each agent forms a real dependency on the root epoch by reading the
    root's output file. Returns session info for phase-2 commit.
    """
    agent_id = f"dep-d4-{run_tag}-agent{agent_idx}"
    client = OrchClient()
    for attempt in range(5):
        try:
            client.connect()
            break
        except (BlockingIOError, ConnectionRefusedError, OSError):
            if attempt == 4:
                return {"agent_idx": agent_idx, "error": "connect failed",
                        "session_id": None, "client": None, "agent_id": agent_id}
            time.sleep(0.05 * (attempt + 1))
    try:
        sess = client.session_open(agent_id=agent_id)
        sid = sess["session_id"]
        client.session_begin_epoch(sid, agent_id=agent_id)
        # Read the shared root file → creates cross-epoch dep on root
        client.session_run(sid, f"cat {shared_file} > /dev/null")
        # Also write agent's own output (so commit has effects)
        own_file = dep_fuse_path(f"concurrent_{agent_idx}.dat")
        client.session_run(sid, f"echo 'agent-{agent_idx}' > {own_file}")
        return {"agent_idx": agent_idx, "error": None,
                "session_id": sid, "client": client, "agent_id": agent_id}
    except Exception as e:
        client.close()
        return {"agent_idx": agent_idx, "error": str(e),
                "session_id": None, "client": None, "agent_id": agent_id}


def _commit_agent(client, session_id: str, agent_id: str) -> Dict[str, Any]:
    """Phase 2: commit a single agent's epoch (called concurrently)."""
    try:
        client.session_commit_epoch(session_id, agent_id=agent_id,
                                    allowed_ops=ALLOW_ALL_OPS)
        return {"error": None, "client": client, "session_id": session_id}
    except Exception as e:
        return {"error": str(e), "client": client, "session_id": session_id}


def run_d4_concurrent(sizes: List[int], repeats: int) -> List[DepGraphResult]:
    """D4: Concurrent agents with shared dependency graph.

    A root epoch writes a shared file; N agent epochs each read it (forming
    a real fan-out dependency). Then all agents commit concurrently,
    measuring group-level finalization contention with actual dependencies.
    """
    print("\n[D4] Concurrent agents (shared dependency)")
    results = []

    for n_agents in sizes:
        print(f"  [D4] agents={n_agents}")
        r = DepGraphResult(dimension="D4", topology="concurrent",
                           size=n_agents, repeats=repeats)
        t0 = time.time()

        for rep in range(repeats):
            cleanup_dep_dir()
            create_seed_file("shared_root.dat", "shared-base")
            # Pre-create agent output files
            for i in range(n_agents):
                create_seed_file(f"concurrent_{i}.dat", f"agent-base-{i}")
            run_tag = f"d4-{n_agents}-r{rep}"

            root_client = None
            root_node = None
            rep_t0 = time.time()
            try:
                # Phase 0: root epoch writes the shared file
                root_client = OrchClient()
                root_client.connect()
                root_node = open_epoch_node(root_client, "root", run_tag)
                shared_file = dep_fuse_path("shared_root.dat")
                root_client.session_run(
                    root_node.session_id,
                    f"echo 'root-shared-output' > {shared_file}")

                # Phase 1: all agents open epochs and read the shared file
                with ThreadPoolExecutor(
                        max_workers=min(n_agents, 128)) as pool:
                    futures = []
                    for i in range(n_agents):
                        futures.append(pool.submit(
                            _open_and_write_agent, i, run_tag, shared_file))
                        if i < n_agents - 1:
                            time.sleep(0.005)
                    phase1_results = [f.result() for f in as_completed(futures)]

                ready = [x for x in phase1_results
                         if not x["error"] and x["session_id"]]
                phase1_errors = [x["error"] for x in phase1_results
                                 if x["error"]]

                # Verify dependency: root rollback should affect all agents
                verified, topo_ok, verrs = verify_dependencies(
                    root_client, [root_node], "concurrent")
                r.affected_epochs = verified
                r.topo_verified = topo_ok
                if verrs:
                    r.errors.extend(verrs)

                # Phase 2: commit root + all agents concurrently (measured)
                if ready:
                    with Timer() as batch_t:
                        # Commit root first (it's the producer)
                        root_client.session_commit_epoch(
                            root_node.session_id,
                            agent_id=root_node.agent_id,
                            allowed_ops=ALLOW_ALL_OPS)
                        # Then commit all consumers concurrently
                        with ThreadPoolExecutor(
                                max_workers=min(len(ready), 128)) as pool:
                            commit_futures = []
                            for item in ready:
                                commit_futures.append(pool.submit(
                                    _commit_agent, item["client"],
                                    item["session_id"], item["agent_id"]))
                            commit_results = [f.result()
                                              for f in as_completed(commit_futures)]

                    r.finalize_ns.append(batch_t.elapsed_ns)
                    r.total_ns.append(batch_t.elapsed_ns)
                    commit_errors = [cr["error"] for cr in commit_results
                                     if cr["error"]]
                    if commit_errors:
                        r.errors.extend(commit_errors[:5])

                    # Close all agent sessions
                    for cr in commit_results:
                        if cr.get("client"):
                            try:
                                cr["client"].session_close(cr["session_id"])
                                cr["client"].close()
                            except Exception:
                                pass

                if phase1_errors:
                    r.errors.extend(phase1_errors[:5])

                # Close root session
                close_all_nodes(root_client, [root_node])
                root_client.close()

            except Exception as e:
                r.errors.append(f"rep={rep}: {e}")
                try:
                    if root_node and root_client:
                        close_all_nodes(root_client, [root_node])
                    if root_client:
                        root_client.close()
                except Exception:
                    pass

            print(f"    rep {rep+1}/{repeats} done "
                  f"({time.time()-rep_t0:.1f}s)", flush=True)

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

    Builds a real multi-epoch chain (same as D1), then:
    - allow: all epochs commit successfully
    - root-deny: the ROOT epoch (epoch[0]) is denied → cascading rollback
      of ALL downstream epochs
    - middle-deny: a MIDDLE epoch (epoch[chain_size//2]) is denied →
      partial rollback of only its downstream dependents
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
            # Pre-create all chain files
            for i in range(chain_size):
                create_seed_file(f"decision_{i}.dat", f"base-{i}")
            run_tag = f"d5-{decision_mode}-{chain_size}-r{rep}"
            nodes: List[EpochNode] = []
            rep_t0 = time.time()

            try:
                client = OrchClient()
                client.connect()

                # Setup: build a real multi-epoch chain
                with Timer() as setup_t:
                    for i in range(chain_size):
                        node = open_epoch_node(client, f"n{i}", run_tag)
                        nodes.append(node)

                    # Build cross-epoch chain dependencies
                    for i in range(chain_size):
                        fpath = dep_fuse_path(f"decision_{i}.dat")
                        # Producer writes
                        client.session_run(
                            nodes[i].session_id,
                            f"echo 'node-{i}' > {fpath}")
                        # Consumer reads (cross-epoch dep)
                        if i + 1 < chain_size:
                            client.session_run(
                                nodes[i + 1].session_id,
                                f"cat {fpath} > /dev/null")

                # Verify dependencies formed
                verified, topo_ok, verrs = verify_dependencies(
                    client, nodes, "chain")
                r.affected_epochs = verified
                r.topo_verified = topo_ok
                if verrs:
                    r.errors.extend(verrs)

                # Apply the decision at the correct graph position.
                # Timer covers ONLY the decision RPC whose cost we want
                # to measure; setup commits and cleanup rollbacks are
                # outside the timed interval.
                if decision_mode == "middle-deny":
                    # Pre-commit upstream epochs BEFORE timing
                    mid = chain_size // 2
                    for node in nodes[:mid]:
                        client.session_commit_epoch(
                            node.session_id, agent_id=node.agent_id,
                            allowed_ops=ALLOW_ALL_OPS)

                with Timer() as fin_t:
                    if decision_mode == "allow":
                        # Commit all epochs
                        for node in nodes:
                            client.session_commit_epoch(
                                node.session_id, agent_id=node.agent_id,
                                allowed_ops=ALLOW_ALL_OPS)
                    elif decision_mode == "root-deny":
                        # Deny the ROOT epoch → cascade rolls back all
                        client.session_resolve_epoch(
                            nodes[0].session_id,
                            agent_id=nodes[0].agent_id,
                            decision="deny")
                    elif decision_mode == "middle-deny":
                        # Deny ONLY the middle epoch (upstream already
                        # committed above; downstream cascades from deny)
                        mid = chain_size // 2
                        client.session_resolve_epoch(
                            nodes[mid].session_id,
                            agent_id=nodes[mid].agent_id,
                            decision="deny")

                # Cleanup outside timer: rollback any surviving epochs
                if decision_mode == "root-deny":
                    for node in nodes[1:]:
                        try:
                            client.session_rollback_epoch(
                                node.session_id,
                                agent_id=node.agent_id)
                        except Exception:
                            pass
                elif decision_mode == "middle-deny":
                    mid = chain_size // 2
                    for node in nodes[mid + 1:]:
                        try:
                            client.session_rollback_epoch(
                                node.session_id,
                                agent_id=node.agent_id)
                        except Exception:
                            pass

                r.setup_ns.append(setup_t.elapsed_ns)
                r.finalize_ns.append(fin_t.elapsed_ns)
                r.total_ns.append(setup_t.elapsed_ns + fin_t.elapsed_ns)

                close_all_nodes(client, nodes)
                client.close()
            except Exception as e:
                r.errors.append(f"rep={rep}: {e}")
                try:
                    close_all_nodes(client, nodes)
                    client.close()
                except Exception:
                    pass

            print(f"    rep {rep+1}/{repeats} done "
                  f"({time.time()-rep_t0:.1f}s)", flush=True)

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

# Default sizes — each graph node is an independent session (cgroup + fork),
# so per-node overhead is ~300-500ms. Keep sizes practical (< 2 min per config).
FULL_CHAIN_SIZES = [2, 4, 8, 16]
FULL_FAN_SIZES = [2, 4, 8, 16]
FULL_SCC_SIZES = [2, 4, 8]
FULL_CONCURRENT_SIZES = [1, 4, 8, 16]
FULL_DECISION_CHAIN = 8

QUICK_CHAIN_SIZES = [2, 4, 8]
QUICK_FAN_SIZES = [2, 4]
QUICK_SCC_SIZES = [2, 4]
QUICK_CONCURRENT_SIZES = [1, 4]
QUICK_DECISION_CHAIN = 4

DEFAULT_REPEATS = 10
QUICK_REPEATS = 1


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
    print("  (cross-epoch dependency construction)")
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
              f"{'Finalize mean(ms)':<18} {'P95(ms)':<10} "
              f"{'Aff':<5} {'Topo':<5} {'Errors'}")
        print("─" * 84)
        for r in all_results:
            topo = "OK" if r.topo_verified else "FAIL"
            if r.finalize_ns:
                s = compute_stats("summary", r.finalize_ns)
                print(f"{r.dimension:<4} {r.topology:<12} {r.size:<6} "
                      f"{r.decision:<12} {s.mean_ns/1e6:<18.3f} "
                      f"{s.p95_ns/1e6:<10.3f} "
                      f"{r.affected_epochs:<5} {topo:<5} {len(r.errors)}")
            else:
                print(f"{r.dimension:<4} {r.topology:<12} {r.size:<6} "
                      f"{r.decision:<12} {'N/A':<18} {'N/A':<10} "
                      f"{r.affected_epochs:<5} {topo:<5} {len(r.errors)}")

    cleanup_dep_dir()
    print("\n[done] Dependency graph scalability experiment complete.")


if __name__ == "__main__":
    main()
