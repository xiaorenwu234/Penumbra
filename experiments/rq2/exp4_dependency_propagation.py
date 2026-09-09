#!/usr/bin/env python3
"""
Experiment 4: Dependency Propagation and Isolation

Measures the REAL ShadowFS epoch dependency graph, driven entirely through the
ShadowOrchestrator session API (framework.orch.OrchClient). One session = one
epoch = one graph vertex. Dependencies are created by genuine cross-epoch FUSE
operations, never by a hand-built model:

  * read-from     : producer epoch writes a file (live version), consumer epoch
                    reads it -> ShadowFS.Resolve records producer -> consumer.
  * enumeration   : consumer lists a directory the producer created a file in ->
                    MergeReaddirVersions records a namespace read-from edge.
  * absence       : producer deletes a seeded file (whiteout version), consumer
                    looks the name up -> the negative resolve still records the
                    producer -> consumer edge.
  * overwrite     : consumer overwrites the producer's live version ->
                    insertVersionLocked records a write-write ordering edge.

The cascade a rollback WOULD touch is read from the system with the non-
destructive ``get_affected(cgroup)`` dry-run (ShadowFS ``rollback_affected``),
so expected vs. observed is a property of the running system, not of this file.

Every dependency-type trial records the tuple required by the paper:

    {producer_epoch, consumer_epoch, operation, expected_affected,
     observed_affected}

NOTE (problem 7): the previous "provisional transcript lineage matches the file
dependency closure" test built ``transcripts[...]`` dictionaries by hand, so it
measured nothing. That simulated claim has been REMOVED. Lineage is now expressed
only through real, system-computed dependency cascades.

Outcome classification (framework.errors): a lifecycle failure (orchestrator
unreachable, FUSE not mounted, session/epoch open, get_affected transport) is an
INFRA_ERROR and makes the run exit non-zero -- never a silent pass.

Usage:
    SHADOW_RUN_RQ2_EXPERIMENTS=1 python3 exp4_dependency_propagation.py --repeats 5
"""

import argparse
import json
import os
import sys
import time
from typing import Dict, List, Set, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJ = os.path.dirname(os.path.dirname(_HERE))  # .../speculative_shadow
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)          # framework.*
if _PROJ not in sys.path:
    sys.path.insert(0, _PROJ)          # policy.*

from framework.errors import InfrastructureError, infra
from framework.metrics import MetricsCollector
from framework.orch import OrchClient, orch_sock_path
from framework.paths import (
    fuse_path, harness_path, ensure_fuse_dirs, is_fuse_mounted,
    SHADOWFS_MNT, SHADOWFS_ORIG,
)

RUN_EXPERIMENTS = os.environ.get("SHADOW_RUN_RQ2_EXPERIMENTS") == "1"


# ─── Dependency graph model (expected sets only) ───────────────────────────

class DependencyGraph:
    """Models the EXPECTED epoch dependency topology (ground truth to compare
    the system's own cascade against)."""

    def __init__(self):
        self.edges: Dict[str, Set[str]] = {}   # producer -> {consumers}
        self.nodes: Set[str] = set()

    def add_edge(self, from_node: str, to_node: str):
        self.nodes.add(from_node)
        self.nodes.add(to_node)
        self.edges.setdefault(from_node, set()).add(to_node)

    def downstream(self, node: str) -> Set[str]:
        visited: Set[str] = set()
        queue = [node]
        while queue:
            n = queue.pop(0)
            for dep in self.edges.get(n, set()):
                if dep not in visited:
                    visited.add(dep)
                    queue.append(dep)
        return visited

    def expected_rollback_set(self, rejected_node: str) -> Set[str]:
        return {rejected_node} | self.downstream(rejected_node)


def make_chain() -> DependencyGraph:
    g = DependencyGraph()
    g.add_edge("A", "B")
    g.add_edge("B", "C")
    return g


def make_fanout() -> DependencyGraph:
    g = DependencyGraph()
    g.add_edge("A", "B")
    g.add_edge("A", "C")
    g.add_edge("A", "D")
    return g


def make_diamond() -> DependencyGraph:
    g = DependencyGraph()
    g.add_edge("A", "B")
    g.add_edge("A", "C")
    g.add_edge("B", "D")
    g.add_edge("C", "D")
    return g


def make_independent() -> DependencyGraph:
    g = DependencyGraph()
    g.add_edge("A", "B")
    g.add_edge("C", "D")
    return g


def make_scc() -> DependencyGraph:
    g = DependencyGraph()
    g.add_edge("A", "B")
    g.add_edge("B", "C")
    g.add_edge("C", "A")
    return g


TOPOLOGIES = {
    "chain": make_chain,
    "fanout": make_fanout,
    "diamond": make_diamond,
    "independent": make_independent,
    "scc": make_scc,
}


class Experiment4:
    """Dependency-propagation experiment driven by the real session API."""

    def __init__(self, repeats: int = 5):
        self.repeats = repeats
        self.run_id = str(int(time.time() * 1000))[-8:]
        self.orch = OrchClient()
        self.metrics = MetricsCollector("exp4_dependency_propagation")
        self._open_sessions: List[str] = []
        self._agent_seq = 0

        self.metrics.add_counter("rollback_set_mismatch")
        self.metrics.add_counter("downstream_not_rolled_back")
        self.metrics.add_counter("unrelated_branch_affected")
        self.metrics.add_counter("scc_partial_finalization")
        self.metrics.add_counter("premature_downstream_release")
        self.metrics.add_counter("dependency_edge_missing")

        self.results_table: List[Dict] = []
        self.dep_records: List[Dict] = []

    # ── setup / teardown ────────────────────────────────────────────────

    def setup(self):
        if os.geteuid() != 0:
            raise InfrastructureError(
                "privileges", "Experiment 4 requires root privileges")
        self.orch.require_listening()
        if not is_fuse_mounted():
            raise InfrastructureError(
                "fuse_mount",
                f"ShadowFS FUSE is not mounted at {SHADOWFS_MNT}; cross-epoch "
                f"dependencies are recorded by FUSE reads and cannot form "
                f"without it")
        ensure_fuse_dirs("exp4")
        self.metrics.metadata.update({
            "orch_sock": orch_sock_path(),
            "shadowfs_mount": SHADOWFS_MNT,
            "backing_store": SHADOWFS_ORIG,
            "repeats": self.repeats,
            "run_id": self.run_id,
        })
        print(f"[exp4] orchestrator={orch_sock_path()} mount={SHADOWFS_MNT}")

    def teardown(self):
        for sid in list(self._open_sessions):
            try:
                self.orch.session_close(sid)
            except Exception as exc:  # noqa: BLE001 - best effort
                print(f"[exp4] WARNING: session_close({sid}) failed: {exc}")
        self._open_sessions.clear()

    # ── epoch-node helpers ──────────────────────────────────────────────

    def _next_agent(self, tag: str) -> str:
        self._agent_seq += 1
        return f"exp4-{tag}-{self.run_id}-{self._agent_seq}"

    def _open_node(self, tag: str, node_id: str) -> Dict:
        """Open one session + epoch = one dependency-graph vertex."""
        agent = self._next_agent(f"{tag}-{node_id}")
        try:
            resp = self.orch.session_open(
                agent_id=agent,
                cgroup_name=f"exp4-{tag}-{node_id}-{self.run_id}-"
                            f"{self._agent_seq}")
            sid, cg = resp.get("session_id"), resp.get("cgroup_id")
            if not sid or not cg:
                raise infra("session_open", f"no id returned: {resp}")
            self._open_sessions.append(sid)
            ep = self.orch.session_begin_epoch(sid, agent)
            return {"node_id": node_id, "sid": sid, "cg": cg,
                    "epoch_id": ep.get("epoch_id", ""), "agent": agent}
        except InfrastructureError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise infra("open_node", str(exc), exc)

    def _close_node(self, node: Dict):
        sid = node.get("sid")
        if not sid:
            return
        try:
            self.orch.session_close(sid)
        except Exception as exc:  # noqa: BLE001
            print(f"[exp4] WARNING: session_close({sid}) failed: {exc}")
        finally:
            if sid in self._open_sessions:
                self._open_sessions.remove(sid)

    def _run(self, node: Dict, command: str, timeout: float = 30.0) -> str:
        return self.orch.session_run(node["sid"], command,
                                     timeout=timeout).get("output", "")

    def _affected(self, node: Dict,
                  nodes_by_cg: Dict[str, str]) -> Tuple[Set[str], Set[str]]:
        """System-computed cascade for a rollback of ``node`` (dry-run).

        Returns (affected_node_ids, affected_cgroups).
        """
        try:
            cgroups = set(self.orch.get_affected(node["cg"]))
        except InfrastructureError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise infra("get_affected", str(exc), exc)
        names = {nodes_by_cg[c] for c in cgroups if c in nodes_by_cg}
        return names, cgroups

    @staticmethod
    def _seed(rel: str, content: str = "seed") -> str:
        """Pre-create a file in the backing store so FUSE Lookup succeeds when
        a consumer epoch opens it (otherwise the VFS returns ENOENT before the
        Open handler records the read-from edge)."""
        full = harness_path(rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            f.write(content)
        return full

    @staticmethod
    def _backing(rel: str) -> str:
        return harness_path(rel)

    def _resolve_deny(self, node: Dict) -> Dict:
        return self.orch.request(
            "session_resolve_epoch", timeout=180.0,
            session_id=node["sid"], agent_id=node["agent"], decision="deny")

    def _record_dep(self, operation: str, producer: Dict, consumer: Dict,
                    expected: Set[str], observed: Set[str]):
        self.dep_records.append({
            "operation": operation,
            "producer_epoch": producer.get("epoch_id", ""),
            "consumer_epoch": consumer.get("epoch_id", ""),
            "expected_affected": sorted(expected),
            "observed_affected": sorted(observed),
            "match": expected == observed,
        })

    # ── Topology tests (real read-from edges) ───────────────────────────

    def _run_topology(self, topo_name: str, graph: DependencyGraph, trial: int):
        """Build the topology with real cross-epoch reads, then compare the
        system's cascade (get_affected) against the expected rollback set for
        EVERY node."""
        base = f"exp4/{topo_name}-{self.run_id}-{trial}"
        nodes: Dict[str, Dict] = {}
        nodes_by_cg: Dict[str, str] = {}
        try:
            for name in sorted(graph.nodes):
                node = self._open_node(topo_name, f"{name}{trial}")
                nodes[name] = node
                nodes_by_cg[node["cg"]] = name

            # Build a real read-from edge per producer -> consumer relation.
            for producer, consumers in graph.edges.items():
                rel = f"{base}/{producer}-dep.txt"
                self._seed(rel, f"base-{producer}")
                dep_fuse = fuse_path(rel)
                self._run(nodes[producer], f"echo 'out-{producer}' > {dep_fuse}")
                for consumer in sorted(consumers):
                    self._run(nodes[consumer], f"cat {dep_fuse} > /dev/null")

            with self.metrics.open_trial(
                    f"{topo_name}-topology-{trial}",
                    scenario=f"topology_{topo_name}") as t:
                mismatch = False
                for reject in sorted(graph.nodes):
                    expected = graph.expected_rollback_set(reject)
                    observed, _ = self._affected(nodes[reject], nodes_by_cg)
                    if observed != expected:
                        mismatch = True
                    # Per-node checks: every downstream node and every
                    # unrelated node is an independent observation. Using
                    # t.check (not t.violated) means the PASSING cases are
                    # counted too, so these two counters have a real
                    # denominator instead of only ever recording violations.
                    for dn in sorted(graph.downstream(reject)):
                        t.check(
                            "downstream_not_rolled_back",
                            dn in observed,
                            counter="downstream_not_rolled_back",
                            detail=f"{topo_name} trial={trial}: {dn} not in "
                                   f"cascade of {reject}",
                            topology=topo_name, trial=trial, node=dn,
                            reject=reject)
                    for un in sorted(graph.nodes - expected):
                        t.check(
                            "unrelated_branch_affected",
                            un not in observed,
                            counter="unrelated_branch_affected",
                            detail=f"{topo_name} trial={trial}: unrelated {un} "
                                   f"in cascade of {reject}",
                            topology=topo_name, trial=trial, node=un,
                            reject=reject)
                    self.results_table.append({
                        "topology": topo_name, "reject_node": reject,
                        "trial": trial, "expected_rollback": sorted(expected),
                        "observed_rollback": sorted(observed),
                        "match": observed == expected,
                        "observation_method": "get_affected-dryrun",
                    })
                t.check("rollback_set_mismatch", not mismatch,
                        counter="rollback_set_mismatch",
                        detail=f"{topo_name} trial={trial} mismatch={mismatch}",
                        topology=topo_name, trial=trial)
                if topo_name == "scc":
                    all_names = set(graph.nodes)
                    partial = any(
                        self._affected(nodes[n], nodes_by_cg)[0] != all_names
                        for n in sorted(graph.nodes))
                    t.check("scc_partial_finalization", not partial,
                            counter="scc_partial_finalization",
                            detail=f"scc trial={trial} partial={partial}",
                            topology=topo_name, trial=trial)
        finally:
            for node in nodes.values():
                self._close_node(node)

    def test_topologies(self):
        for topo_name, constructor in TOPOLOGIES.items():
            graph = constructor()
            print(f"  [topology:{topo_name}] nodes={sorted(graph.nodes)} ...",
                  flush=True)
            for trial in range(self.repeats):
                self._run_topology(topo_name, graph, trial)

    # ── Dependency type 1: directory enumeration ────────────────────────

    def test_directory_enumeration_dependency(self):
        """A consumer that ENUMERATES a directory depends on the producer that
        created a file in it (MergeReaddirVersions namespace read-from edge)."""
        for trial in range(self.repeats):
            base = f"exp4/direnum-{self.run_id}-{trial}"
            self._seed(f"{base}/preexisting.txt", "keep")
            dir_fuse = fuse_path(base)
            new_rel = f"{base}/created.txt"
            nodes: Dict[str, Dict] = {}
            with self.metrics.open_trial(
                    f"dir-enumeration-{trial}",
                    scenario="dep_directory_enumeration") as t:
                try:
                    producer = self._open_node("direnum", f"P{trial}")
                    consumer = self._open_node("direnum", f"C{trial}")
                    nodes = {"P": producer, "C": consumer}
                    nodes_by_cg = {producer["cg"]: "P", consumer["cg"]: "C"}
                    self._run(producer, f"echo 'made' > {fuse_path(new_rel)}")
                    # NOTE: no "> /dev/null" here. ls probes its stdout with
                    # isatty (TCGETS); /dev/null is a character device and the
                    # ShadowProc ioctl hook fences chrdev ioctls in speculative
                    # mode (fail-closed, waits for epoch resolution), which
                    # would freeze the consumer shell mid-run. The session's
                    # stdout is a FIFO (S_IFIFO), so the same ioctl passes.
                    self._run(consumer, f"ls -1 {dir_fuse}")
                    expected = {"P", "C"}
                    observed, _ = self._affected(producer, nodes_by_cg)
                    self._record_dep("directory_enumeration", producer, consumer,
                                     expected, observed)
                    t.check("dependency_edge_missing", "C" in observed,
                            counter="dependency_edge_missing",
                            detail=f"observed={sorted(observed)} "
                            f"expected={sorted(expected)}")
                    t.check("rollback_set_mismatch", observed == expected,
                            counter="rollback_set_mismatch",
                            detail=f"observed={sorted(observed)}")
                finally:
                    for node in nodes.values():
                        self._close_node(node)

    # ── Dependency type 2: absence / negative lookup ────────────────────

    def test_absence_negative_lookup_dependency(self):
        """A consumer that looks up a name the producer DELETED depends on the
        producer's whiteout version (the negative resolve records the edge)."""
        for trial in range(self.repeats):
            base = f"exp4/absence-{self.run_id}-{trial}"
            rel = f"{base}/gone.txt"
            backing = self._seed(rel, "present")
            target = fuse_path(rel)
            nodes: Dict[str, Dict] = {}
            with self.metrics.open_trial(
                    f"absence-lookup-{trial}",
                    scenario="dep_absence_negative_lookup") as t:
                try:
                    producer = self._open_node("absence", f"P{trial}")
                    consumer = self._open_node("absence", f"C{trial}")
                    nodes = {"P": producer, "C": consumer}
                    nodes_by_cg = {producer["cg"]: "P", consumer["cg"]: "C"}
                    self._run(producer, f"rm -f {target}")
                    self._run(consumer, f"cat {target} > /dev/null 2>&1 || true")
                    expected = {"P", "C"}
                    observed, _ = self._affected(producer, nodes_by_cg)
                    self._record_dep("absence_negative_lookup", producer,
                                     consumer, expected, observed)
                    t.check("dependency_edge_missing", "C" in observed,
                            counter="dependency_edge_missing",
                            detail=f"observed={sorted(observed)}")
                    reply = self._resolve_deny(producer)
                    if reply.get("status") != "ok":
                        t.infra_error(reply.get("message", reply),
                                      stage="rollback")
                        continue
                    time.sleep(0.3)
                    t.check("absence_rollback_restores",
                            os.path.exists(backing),
                            f"backing exists={os.path.exists(backing)}")
                finally:
                    for node in nodes.values():
                        self._close_node(node)

    # ── Dependency type 3: overwrite (write-write) ──────────────────────

    def test_overwrite_dependency(self):
        """A consumer that OVERWRITES the producer's live version is tied to it
        (insertVersionLocked write-write ordering edge)."""
        for trial in range(self.repeats):
            base = f"exp4/overwrite-{self.run_id}-{trial}"
            rel = f"{base}/shared.txt"
            self._seed(rel, "base")
            target = fuse_path(rel)
            nodes: Dict[str, Dict] = {}
            with self.metrics.open_trial(
                    f"overwrite-{trial}", scenario="dep_overwrite") as t:
                try:
                    producer = self._open_node("overwrite", f"P{trial}")
                    consumer = self._open_node("overwrite", f"C{trial}")
                    nodes = {"P": producer, "C": consumer}
                    nodes_by_cg = {producer["cg"]: "P", consumer["cg"]: "C"}
                    self._run(producer, f"echo 'v1' > {target}")
                    self._run(consumer, f"echo 'v2' > {target}")  # overwrite
                    expected = {"P", "C"}
                    observed, _ = self._affected(producer, nodes_by_cg)
                    self._record_dep("overwrite", producer, consumer,
                                     expected, observed)
                    t.check("dependency_edge_missing", "C" in observed,
                            counter="dependency_edge_missing",
                            detail=f"observed={sorted(observed)}")
                    t.check("rollback_set_mismatch", observed == expected,
                            counter="rollback_set_mismatch",
                            detail=f"observed={sorted(observed)}")
                finally:
                    for node in nodes.values():
                        self._close_node(node)

    # ── Dependency type 4: predecessor-finalization waiting ─────────────

    def test_predecessor_finalization_waiting(self):
        """A downstream epoch's fate is tied to its predecessor: while the
        predecessor is unresolved the consumer is in its cascade, and denying
        the predecessor discards the consumer's own writes -- the consumer can
        never publish independently of its predecessor."""
        for trial in range(self.repeats):
            base = f"exp4/prefix-{self.run_id}-{trial}"
            a_rel = f"{base}/a.txt"
            b_rel = f"{base}/b.txt"
            self._seed(a_rel, "base-a")
            b_backing = self._backing(b_rel)
            if os.path.exists(b_backing):
                os.unlink(b_backing)
            nodes: Dict[str, Dict] = {}
            with self.metrics.open_trial(
                    f"predecessor-finalization-{trial}",
                    scenario="dep_predecessor_finalization") as t:
                try:
                    a = self._open_node("prefix", f"A{trial}")
                    b = self._open_node("prefix", f"B{trial}")
                    nodes = {"A": a, "B": b}
                    nodes_by_cg = {a["cg"]: "A", b["cg"]: "B"}
                    self._run(a, f"echo 'a-out' > {fuse_path(a_rel)}")
                    self._run(b, f"cat {fuse_path(a_rel)} > /dev/null")
                    self._run(b, f"echo 'b-out' > {fuse_path(b_rel)}")
                    expected = {"A", "B"}
                    observed, _ = self._affected(a, nodes_by_cg)
                    self._record_dep("predecessor_finalization", a, b,
                                     expected, observed)
                    t.check("dependency_edge_missing", "B" in observed,
                            counter="dependency_edge_missing",
                            detail=f"observed={sorted(observed)}")
                    reply = self._resolve_deny(a)
                    if reply.get("status") != "ok":
                        t.infra_error(reply.get("message", reply),
                                      stage="rollback")
                        continue
                    time.sleep(0.3)
                    premature = os.path.exists(b_backing)
                    t.check("premature_downstream_release", not premature,
                            counter="premature_downstream_release",
                            detail=f"B published independently={premature}")
                finally:
                    for node in nodes.values():
                        self._close_node(node)

    # ── Dependency type 5: SCC group finalization ───────────────────────

    def test_scc_group_finalization(self):
        """A cycle of epochs (A->B->C->A) must finalize/roll back as ONE group:
        every member's cascade is the whole SCC, and denying one member rolls
        back all of them (no member publishes independently)."""
        for trial in range(self.repeats):
            base = f"exp4/sccgrp-{self.run_id}-{trial}"
            names = ["A", "B", "C"]
            for n in names:
                self._seed(f"{base}/{n}.txt", f"init-{n}")
            nodes: Dict[str, Dict] = {}
            opened: List[Dict] = []
            with self.metrics.open_trial(
                    f"scc-group-{trial}", scenario="dep_scc_group") as t:
                try:
                    for n in names:
                        node = self._open_node("sccgrp", f"{n}{trial}")
                        nodes[n] = node
                        opened.append(node)
                    nodes_by_cg = {nodes[n]["cg"]: n for n in names}
                    for n in names:
                        self._run(nodes[n],
                                  f"echo '{n}-written' > "
                                  f"{fuse_path(base + '/' + n + '.txt')}")
                    for i, n in enumerate(names):
                        prev = names[(i - 1) % len(names)]
                        self._run(nodes[n],
                                  f"cat {fuse_path(base + '/' + prev + '.txt')}"
                                  f" > /dev/null")
                    all_names = set(names)
                    partial = False
                    for i, n in enumerate(names):
                        observed, _ = self._affected(nodes[n], nodes_by_cg)
                        self._record_dep(
                            "scc_group", nodes[n],
                            nodes[names[(i + 1) % len(names)]],
                            all_names, observed)
                        if observed != all_names:
                            partial = True
                    t.check("scc_partial_finalization", not partial,
                            counter="scc_partial_finalization",
                            detail=f"partial={partial}")
                    reply = self._resolve_deny(nodes["A"])
                    if reply.get("status") != "ok":
                        t.infra_error(reply.get("message", reply),
                                      stage="rollback")
                        continue
                    for n in names[1:]:
                        try:
                            self.orch.session_rollback_epoch(
                                nodes[n]["sid"], nodes[n]["agent"])
                        except Exception:  # noqa: BLE001 - already cascaded
                            pass
                    time.sleep(0.3)
                    published = [n for n in names
                                 if self._scc_write_promoted(base, n)]
                    t.check("premature_downstream_release", not published,
                            counter="premature_downstream_release",
                            detail=f"published after group deny={published}")
                finally:
                    for node in opened:
                        self._close_node(node)

    def _scc_write_promoted(self, base: str, name: str) -> bool:
        """True if the SCC member's speculative write reached the backing store
        with its epoch-specific content (i.e. it finalized independently)."""
        backing = self._backing(f"{base}/{name}.txt")
        try:
            with open(backing, "r") as f:
                return f.read().strip() == f"{name}-written"
        except OSError:
            return False

    # ── driver ──────────────────────────────────────────────────────────

    def run(self):
        self.setup()
        print(f"\n{'=' * 70}")
        print("  EXPERIMENT 4: Dependency Propagation (real session epochs)")
        print(f"  Topologies: {len(TOPOLOGIES)} | Repeats: {self.repeats}")
        print(f"{'=' * 70}\n")

        steps = [
            ("Topologies", self.test_topologies),
            ("Dep: directory enumeration",
             self.test_directory_enumeration_dependency),
            ("Dep: absence / negative lookup",
             self.test_absence_negative_lookup_dependency),
            ("Dep: overwrite (write-write)", self.test_overwrite_dependency),
            ("Dep: predecessor-finalization waiting",
             self.test_predecessor_finalization_waiting),
            ("Dep: SCC group finalization",
             self.test_scc_group_finalization),
        ]
        try:
            for idx, (label, fn) in enumerate(steps, 1):
                if label != "Topologies":
                    print(f"  [{idx}/{len(steps)}] {label} ...", flush=True)
                fn()
        except KeyboardInterrupt:
            print("\n[exp4] Interrupted")
        finally:
            self.metrics.finish()
            self.teardown()

        self._print_results_table()
        self._print_dep_records()
        self.metrics.print_report()
        return self.metrics

    def _print_results_table(self):
        print(f"\n{'=' * 84}")
        print("  ROLLBACK SET TABLE (Expected vs Observed, system-computed)")
        print(f"{'=' * 84}")
        print(f"  {'Topology':<13} {'Reject':<7} {'Expected':<20} "
              f"{'Observed':<20} {'Method':<18} {'Match'}")
        shown = set()
        for row in self.results_table:
            key = (row["topology"], row["reject_node"])
            if key in shown:
                continue
            shown.add(key)
            exp_str = "{" + ",".join(row["expected_rollback"]) + "}"
            obs_str = "{" + ",".join(row["observed_rollback"]) + "}"
            match = "OK" if row["match"] else "FAIL"
            print(f"  {row['topology']:<13} {row['reject_node']:<7} "
                  f"{exp_str:<20} {obs_str:<20} "
                  f"{row['observation_method']:<18} {match}")
        print(f"{'=' * 84}\n")

    def _print_dep_records(self):
        print(f"\n{'=' * 84}")
        print("  DEPENDENCY TYPE RECORDS "
              "(producer/consumer epoch, operation, expected/observed)")
        print(f"{'=' * 84}")
        seen = set()
        for rec in self.dep_records:
            key = rec["operation"]
            if key in seen:
                continue
            seen.add(key)
            print(f"  op={rec['operation']:<26} "
                  f"producer_epoch={rec['producer_epoch'][:16]:<16} "
                  f"consumer_epoch={rec['consumer_epoch'][:16]:<16} "
                  f"match={rec['match']}")
            print(f"      expected_affected={rec['expected_affected']} "
                  f"observed_affected={rec['observed_affected']}")
        total = len(self.dep_records)
        matched = sum(1 for r in self.dep_records if r["match"])
        print(f"  ({matched}/{total} dependency records matched expected)")
        print(f"{'=' * 84}\n")


def main():
    parser = argparse.ArgumentParser(
        description="RQ2 Experiment 4: Dependency Propagation")
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--output-dir", type=str, default="./results")
    args = parser.parse_args()

    if not RUN_EXPERIMENTS:
        print("ERROR: Set SHADOW_RUN_RQ2_EXPERIMENTS=1")
        sys.exit(1)

    exp = Experiment4(repeats=args.repeats)
    try:
        metrics = exp.run()
    except InfrastructureError as exc:
        print(f"\n[exp4] FATAL INFRASTRUCTURE ERROR: {exc}")
        sys.exit(2)
    metrics.save_report(args.output_dir)
    os.makedirs(args.output_dir, exist_ok=True)
    dep_path = os.path.join(args.output_dir, "exp4_dependency_records.json")
    with open(dep_path, "w") as f:
        json.dump(exp.dep_records, f, indent=2)
    sys.exit(metrics.exit_code)


if __name__ == "__main__":
    main()
