#!/usr/bin/env python3
"""Turn the two RQ3 scaling result files into the tables and curves a paper needs.

Reads (whichever exist):
    results/multi_agent_scaling.json    Experiment A — agent-count scaling
    results/dep_graph_scalability.json  Experiment B — dependency-graph shape

Writes, into --output-dir:
    scaling_agent.csv     one row per (workload, agent count)
    scaling_graph.csv     one row per (dimension, topology, node count, decision)
    scaling_curves.csv    long form: metric × topology × node count. This is the
                          reviewer-facing "dependency nodes → finalization
                          latency / rollback latency / metadata memory" table.
    scaling_agent.tex     booktabs versions of the two wide tables (--latex)
    scaling_graph.tex

No figures are rendered. scaling_curves.csv IS the three curves, in long form
(metric x topology x nodes x value), so plotting is a separate step done
wherever the paper is written -- and a host that has no matplotlib still gets
every number. The same curves are also printed as text for the same reason.

Everything is read with .get(): a results file from before the instrumentation
has no graph_peak / nodes / resources keys, and the summarizer must drop those
columns rather than refuse to summarize the latency data that IS there.

Usage:
    python3 summarize_scaling.py [--results-dir DIR] [--output-dir DIR] [--latex]
    ./start_and_run.sh summarize
"""

import argparse
import csv
import json
import math
import os
import sys
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

A_FILE = "multi_agent_scaling.json"
B_FILE = "dep_graph_scalability.json"

# Metric names used in scaling_curves.csv. Kept as constants because the ASCII
# plot, the LaTeX table and the PNG all select on them.
M_FINALIZATION = "finalization_latency_ms"
M_ROLLBACK = "rollback_latency_ms"
M_WAIT = "finalization_wait_ms"
M_DRAIN = "graph_drain_ms"
M_HEAP = "metadata_heap_mb"
M_PER_NODE = "metadata_bytes_per_node"
M_EDGES = "graph_edges"

CURVE_METRICS = (M_FINALIZATION, M_ROLLBACK, M_WAIT, M_DRAIN, M_HEAP,
                 M_PER_NODE, M_EDGES)


# ═══════════════════════════════════════════════════════════════════════════
# Loading
# ═══════════════════════════════════════════════════════════════════════════

def load_json(path: str) -> Optional[Dict[str, Any]]:
    """Load one results file; None (with a printed reason) when it is absent.

    A missing file is not an error: the two experiments are run separately and
    an hour apart, and summarizing whichever one exists is the common case.
    """
    if not os.path.exists(path):
        print(f"[skip] {path} not found")
        return None
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[skip] {path}: {type(e).__name__}: {e}")
        return None


def get(d: Any, *path: str) -> Any:
    """Walk nested dicts, returning None at the first missing level.

    Used instead of chained .get() because every column here is optional: a
    configuration that crashed before its graph snapshot has no graph_peak, and
    that must cost one empty cell, not a traceback.
    """
    cur = d
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _from_block(block: Any, key: str) -> Optional[float]:
    """One number out of a stats block, also accepting the legacy `*_us` spelling.

    The results file that predates the stats module standardizing on `*_ns`
    reports the same series in microseconds. Without this a summarize run
    against an existing results/ directory prints a table that is entirely
    dashes -- which looks like a summarizer bug rather than like stale data.
    """
    if not isinstance(block, dict):
        return None
    v = block.get(key)
    if v is not None:
        return float(v)
    if key.endswith("_ns"):
        v = block.get(key[:-3] + "_us")
        if v is not None:
            return float(v) * 1000.0
    return None


def stat(cfg: Dict[str, Any], name: str, key: str = "mean_ns") -> Optional[float]:
    """One statistic, in nanoseconds, from a configuration's `stats` block."""
    return _from_block(get(cfg, "stats", name), key)


def ms(cfg: Dict[str, Any], name: str, key: str = "mean_ns") -> Optional[float]:
    """The same statistic in milliseconds (all *_ns series are nanoseconds)."""
    v = stat(cfg, name, key)
    return None if v is None else v / 1e6


def timing_ms(cfg: Dict[str, Any], phase: str, key: str,
              which: str = "median_ns") -> Optional[float]:
    """An orchestrator per-phase timing, in milliseconds.

    `{phase}_timings_ms.{key}` is a literal dotted key -- both experiments build
    it with an f-string -- and its block still carries the standard `*_ns` /
    `*_ms` suffixes, because _ms_stats scales the daemon's milliseconds up into
    nanoseconds to reuse compute_stats' percentile code. So the `median_ns`
    read here is divided back down; returning it unchanged would overstate every
    commit-path phase by 1e6.
    """
    v = _from_block(get(cfg, "stats", f"{phase}_timings_ms.{key}"), which)
    return None if v is None else v / 1e6


def node_count(cfg: Dict[str, Any]) -> Optional[int]:
    """Graph nodes for one configuration.

    `nodes` is the field the instrumented run writes; `size` is the shape
    parameter and is what an older results file has. For fan-out/fan-in/
    diamond/concurrent those differ by the root and/or sink, so a file without
    `nodes` gets its x-axis corrected here rather than being plotted wrong.
    """
    n = cfg.get("nodes")
    if n is not None:
        return int(n)
    size = cfg.get("size")
    if size is None:
        return None
    size = int(size)
    topo = cfg.get("topology", "")
    if topo in ("fan-out", "fan-in", "concurrent"):
        return size + 1
    if topo == "diamond":
        return size + 2
    return size


def fmt(v: Any, spec: str = ".3f") -> str:
    """Format for a printed table: a dash, never 'None' and never '0.000'."""
    if v is None:
        return "-"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
        return "-"
    return format(v, spec)


# ═══════════════════════════════════════════════════════════════════════════
# Experiment A — agent-count scaling
# ═══════════════════════════════════════════════════════════════════════════

AGENT_COLUMNS = (
    "workload", "agents", "repeats", "total_invocations",
    "throughput_inv_per_s", "speedup", "parallel_efficiency_pct",
    "epoch_begin_p50_ms", "epoch_begin_p95_ms",
    "run_p50_ms", "run_p95_ms",
    "commit_p50_ms", "commit_p95_ms",
    "authz_to_finalized_p50_ms", "authz_to_finalized_p95_ms",
    "rollback_p50_ms", "rollback_p95_ms", "rollback_affected_mean",
    "finalization_wait_p50_ms", "finalization_wait_p95_ms",
    "pending_commits",
    "insertion_latency_us_client", "insertion_latency_us_daemon",
    "edges_per_invocation", "modelled_graph_overhead_us_per_inv",
    "graph_edges_peak", "graph_epochs_peak",
    "orchestrator_cpu_pct", "shadowfs_cpu_pct", "shadowproc_cpu_pct",
    "daemons_cpu_pct", "orchestrator_rss_peak_mb", "shadowfs_rss_peak_mb",
    "shadowproc_rss_peak_mb",
    "structure_ok", "structure_error", "branch_preservation_ok",
    "branch_error", "error_count",
)


def summarize_agent(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """One row per (workload, agent count), with speedup against 1 agent.

    Speedup is computed per workload from the measured throughput, not from the
    agent count: for the contended workload the interesting result IS that it
    does not scale, and deriving the column would hide exactly that.
    """
    cfgs = data.get("configurations") or []
    base: Dict[str, float] = {}
    for c in cfgs:
        if int(c.get("agents") or 0) == 1:
            tp = get(c, "throughput_inv_per_s", "median")
            if tp:
                base[c.get("workload", "")] = float(tp)

    rows: List[Dict[str, Any]] = []
    for c in cfgs:
        agents = int(c.get("agents") or 0)
        tp = get(c, "throughput_inv_per_s", "median")
        tp = float(tp) if tp else None
        ref = base.get(c.get("workload", ""))
        speedup = (tp / ref) if (tp and ref) else None
        rows.append({
            "workload": c.get("workload"),
            "agents": agents,
            "repeats": c.get("repeats"),
            "total_invocations": c.get("total_invocations"),
            "throughput_inv_per_s": tp,
            "speedup": speedup,
            "parallel_efficiency_pct": (100.0 * speedup / agents
                                        if speedup and agents else None),
            "epoch_begin_p50_ms": ms(c, "epoch_begin_ns", "median_ns"),
            "epoch_begin_p95_ms": ms(c, "epoch_begin_ns", "p95_ns"),
            "run_p50_ms": ms(c, "run_ns", "median_ns"),
            "run_p95_ms": ms(c, "run_ns", "p95_ns"),
            "commit_p50_ms": ms(c, "commit_ns", "median_ns"),
            "commit_p95_ms": ms(c, "commit_ns", "p95_ns"),
            "authz_to_finalized_p50_ms": timing_ms(c, "commit",
                                                   "authz_to_finalized_ms",
                                                   "median_ns"),
            "authz_to_finalized_p95_ms": timing_ms(c, "commit",
                                                   "authz_to_finalized_ms",
                                                   "p95_ns"),
            "rollback_p50_ms": ms(c, "rollback_ns", "median_ns"),
            "rollback_p95_ms": ms(c, "rollback_ns", "p95_ns"),
            "rollback_affected_mean": c.get("rollback_affected_mean"),
            "finalization_wait_p50_ms": ms(c, "finalization_wait_ns",
                                           "median_ns"),
            "finalization_wait_p95_ms": ms(c, "finalization_wait_ns", "p95_ns"),
            "pending_commits": c.get("pending_commits"),
            "insertion_latency_us_client": _us(
                c.get("insertion_latency_ns_client")),
            "insertion_latency_us_daemon": _us(
                c.get("insertion_latency_ns_daemon")),
            "edges_per_invocation": c.get("edges_per_invocation"),
            "modelled_graph_overhead_us_per_inv":
                c.get("modelled_graph_overhead_us_per_invocation"),
            "graph_edges_peak": get(c, "structure_graph", "edges"),
            "graph_epochs_peak": get(c, "structure_graph", "epochs"),
            "orchestrator_cpu_pct": get(c, "resources", "orchestrator_cpu_pct"),
            "shadowfs_cpu_pct": get(c, "resources", "shadowfs_cpu_pct"),
            "shadowproc_cpu_pct": get(c, "resources", "shadowproc_cpu_pct"),
            "daemons_cpu_pct": get(c, "resources", "daemons_cpu_pct"),
            "orchestrator_rss_peak_mb":
                get(c, "resources", "orchestrator_rss_peak_mb"),
            "shadowfs_rss_peak_mb": get(c, "resources", "shadowfs_rss_peak_mb"),
            "shadowproc_rss_peak_mb": get(c, "resources", "shadowproc_rss_peak_mb"),
            "structure_ok": get(c, "structure", "ok"),
            "branch_preservation_ok": c.get("branch_preservation_ok"),
            # The first reason, not the count: the experiment already wrote down
            # WHY a check failed, and a warning that says only "FAILED" makes the
            # reader open the JSON to find the one line that explains it. Note
            # the checks report None (not False) when they do not apply to a
            # workload, and None must stay silent -- "n/a: one agent has no
            # unrelated branch" is not a failure.
            "structure_error": _first(get(c, "structure", "errors")),
            "branch_error": _first(c.get("branch_errors")),
            "error_count": c.get("error_count"),
        })
    return rows


def _us(v: Any) -> Optional[float]:
    return None if v is None else float(v) / 1000.0


def _first(seq: Any) -> Optional[str]:
    """First entry of an error list, or None."""
    if not seq:
        return None
    return str(seq[0])


def print_agent_table(rows: Sequence[Dict[str, Any]]):
    """The throughput verdict: does it scale, and where does it stop."""
    # The rules are sized to the row, not to a round number: the columns below
    # add up to 122, and a 100-wide rule leaves the last four columns hanging
    # off the end of the box. Experiment B's table is the same width, so the two
    # tables line up when they are printed one after the other.
    width = 122
    print("\n" + "═" * width)
    print("  EXPERIMENT A — agent-count scaling")
    print("═" * width)
    hdr = (f"{'workload':<17}{'ag':>4}{'inv/s':>10}{'speedup':>9}{'eff%':>7}"
           f"{'begin_p50':>11}{'run_p50':>9}{'commit_p50':>11}"
           f"{'authz→fin':>11}{'rollback_p50':>13}{'E/inv':>7} "
           f"{'cpu%':>7}{'err':>5}")
    print(hdr)
    print("─" * width)
    for r in rows:
        print(f"{str(r['workload']):<17}{r['agents']:>4}"
              f"{fmt(r['throughput_inv_per_s'], '.2f'):>10}"
              f"{fmt(r['speedup'], '.2f'):>9}"
              f"{fmt(r['parallel_efficiency_pct'], '.0f'):>7}"
              f"{fmt(r['epoch_begin_p50_ms']):>11}"
              f"{fmt(r['run_p50_ms']):>9}"
              f"{fmt(r['commit_p50_ms']):>11}"
              f"{fmt(r['authz_to_finalized_p50_ms']):>11}"
              f"{fmt(r['rollback_p50_ms']):>13}"
              f"{fmt(r['edges_per_invocation'], '.2f'):>7} "
              f"{fmt(r['daemons_cpu_pct'], '.0f'):>7}"
              f"{r['error_count'] if r['error_count'] is not None else '-':>5}")
    print("  (latencies in ms; E/inv = dependency-graph edges per invocation;"
          " cpu% = all three daemons)")

    # structure_ok is tri-state exactly like branch_preservation_ok below: False
    # is a failed check, None means the structure phase never ran (--phases
    # throughput). Printing FAILED for a check that did not happen sends the
    # reader hunting a bug that does not exist, so the two are reported
    # separately -- and the unchecked case is one line, not one per row, because
    # a run without the phase has every row in it.
    unchecked = [r for r in rows if r["structure_ok"] is None]
    if unchecked:
        print(f"  [warn] {len(unchecked)} row(s) carry NO structure check (the "
              f"structure phase did not run) — their throughput is unvalidated, "
              f"not wrong")
    for r in rows:
        if r["structure_ok"] is False:
            print(f"  [warn] {r['workload']} agents={r['agents']}: dependency "
                  f"structure check FAILED — its throughput row measures the "
                  f"wrong workload"
                  + (f"\n         reason: {r['structure_error']}"
                     if r["structure_error"] else ""))
        if r["branch_preservation_ok"] is False:
            print(f"  [warn] {r['workload']} agents={r['agents']}: independent "
                  f"branch NOT preserved — a rollback reached an agent it "
                  f"should not have"
                  + (f"\n         reason: {r['branch_error']}"
                     if r["branch_error"] else ""))


# ═══════════════════════════════════════════════════════════════════════════
# Experiment B — dependency-graph shape
# ═══════════════════════════════════════════════════════════════════════════

GRAPH_COLUMNS = (
    "dimension", "topology", "size", "nodes", "decision", "resolution_op",
    "repeats", "topo_verified", "error_count", "first_error",
    "resolution_p50_ms", "resolution_p95_ms", "resolution_n",
    "per_node_resolution_us",
    "rollback_p50_ms", "rollback_p95_ms",
    "rollback_affected_mean", "rollback_affected_max",
    "finalization_wait_p50_ms", "finalization_wait_p95_ms",
    "graph_drain_p50_ms", "pending_commits", "commit_attempts_max",
    "graph_revalidations", "finalize_rejected_toctou",
    "authz_to_finalized_p50_ms", "fs_begin_finalize_p50_ms",
    "fs_wait_finalized_p50_ms", "finalize_lock_wait_p50_ms",
    "finalize_lock_held_p50_ms", "fs_prepare_resolution_p50_ms",
    "fs_rollback_p50_ms",
    "setup_p50_ms", "open_p50_us", "begin_p50_ms", "run_p50_us",
    "epochs_peak", "edges_peak", "versions_peak", "objects_peak",
    "scc_count_peak", "cyclic_scc_count_peak", "max_scc_size_peak",
    "heap_alloc_mb_peak", "metadata_bytes_per_node",
    "edge_insertions", "invocations", "edges_per_invocation",
    "scc_computations", "scc_compute_us_per_sweep",
    "affected_queries", "affected_query_us_per_query",
    "finalized_nodes_total", "rollbacks", "rollback_nodes_total",
    "orchestrator_cpu_pct", "shadowfs_cpu_pct", "shadowproc_cpu_pct",
    "daemons_cpu_pct", "shadowfs_rss_peak_mb", "wall_time_s",
)


def summarize_graph(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """One row per measured configuration, flattened for a spreadsheet."""
    rows: List[Dict[str, Any]] = []
    for c in data.get("dimensions") or []:
        g = c.get("graph") or {}
        peak = c.get("graph_peak") or {}
        res = c.get("resources") or {}
        scc_comps = g.get("scc_computations") or 0
        aff_q = g.get("affected_queries") or 0
        rbs = g.get("rollbacks") or 0
        nodes = node_count(c)
        resolution = ms(c, "finalize_ns", "median_ns")
        # `resolution_op` is what the instrumented run writes. A results file
        # from before it has only the decision string, so the operation is
        # inferred from that -- otherwise a `rollback-cascade` row prints
        # "op=commit", and the two columns contradict each other on the line a
        # reviewer reads first. Both spellings a deny can take are checked:
        # D5 uses "root-deny"/"middle-deny", D3 uses "rollback-cascade".
        decision = str(c.get("decision", ""))
        rows.append({
            "dimension": c.get("dimension"),
            "topology": c.get("topology"),
            "size": c.get("size"),
            "nodes": nodes,
            "decision": c.get("decision"),
            "resolution_op": c.get("resolution_op") or (
                "cascade-rollback"
                if ("deny" in decision or "rollback" in decision)
                else "commit"),
            "repeats": c.get("repeats"),
            "topo_verified": c.get("topo_verified"),
            "error_count": c.get("error_count"),
            "first_error": _first(c.get("errors")),
            "resolution_p50_ms": resolution,
            "resolution_p95_ms": ms(c, "finalize_ns", "p95_ns"),
            "resolution_n": get(c, "stats", "finalize_ns", "n"),
            "per_node_resolution_us": (
                resolution * 1000.0 / nodes if resolution and nodes else None),
            "rollback_p50_ms": ms(c, "rollback_ns", "median_ns"),
            "rollback_p95_ms": ms(c, "rollback_ns", "p95_ns"),
            "rollback_affected_mean": c.get("rollback_affected_mean"),
            "rollback_affected_max": c.get("rollback_affected_max"),
            "finalization_wait_p50_ms": ms(c, "finalization_wait_ns",
                                           "median_ns"),
            "finalization_wait_p95_ms": ms(c, "finalization_wait_ns", "p95_ns"),
            "graph_drain_p50_ms": ms(c, "drain_ns", "median_ns"),
            "pending_commits": c.get("pending_commits"),
            "commit_attempts_max": c.get("commit_attempts_max"),
            "graph_revalidations": c.get("graph_revalidations"),
            "finalize_rejected_toctou": g.get("finalize_rejected_toctou"),
            "authz_to_finalized_p50_ms": timing_ms(c, "commit",
                                                   "authz_to_finalized_ms",
                                                   "median_ns"),
            "fs_begin_finalize_p50_ms": timing_ms(c, "commit",
                                                  "fs_begin_finalize_ms",
                                                  "median_ns"),
            "fs_wait_finalized_p50_ms": timing_ms(c, "commit",
                                                  "fs_wait_finalized_ms",
                                                  "median_ns"),
            "finalize_lock_wait_p50_ms": timing_ms(c, "commit",
                                                   "finalize_lock_wait_ms"),
            # Wait vs. hold is the contended-workload distinction: a rising wait
            # beside a flat hold means the per-commit graph work is constant and
            # the queue is what costs.
            "finalize_lock_held_p50_ms": timing_ms(c, "commit",
                                                  "finalize_lock_held_ms"),
            "fs_prepare_resolution_p50_ms": timing_ms(c, "commit",
                                                     "fs_prepare_resolution_ms"),
            "fs_rollback_p50_ms": timing_ms(c, "rollback", "fs_rollback_ms",
                                            "median_ns"),
            "setup_p50_ms": ms(c, "setup_ns", "median_ns"),
            "open_p50_us": _us(stat(c, "open_ns", "median_ns")),
            "begin_p50_ms": ms(c, "begin_ns", "median_ns"),
            "run_p50_us": _us(stat(c, "run_ns", "median_ns")),
            "epochs_peak": peak.get("epochs"),
            "edges_peak": peak.get("edges"),
            "versions_peak": peak.get("versions"),
            "objects_peak": peak.get("objects"),
            "scc_count_peak": peak.get("scc_count"),
            "cyclic_scc_count_peak": peak.get("cyclic_scc_count"),
            "max_scc_size_peak": peak.get("max_scc_size"),
            "heap_alloc_mb_peak": (
                float(peak["heap_alloc_bytes"]) / 1048576.0
                if peak.get("heap_alloc_bytes") else None),
            "metadata_bytes_per_node": c.get("metadata_bytes_per_node"),
            "edge_insertions": g.get("edge_insertions"),
            "invocations": c.get("invocations"),
            "edges_per_invocation": c.get("edges_per_invocation"),
            "scc_computations": scc_comps,
            "scc_compute_us_per_sweep": (
                (g.get("scc_compute_ns") or 0) / scc_comps / 1000.0
                if scc_comps else None),
            "affected_queries": aff_q,
            "affected_query_us_per_query": (
                (g.get("affected_query_ns") or 0) / aff_q / 1000.0
                if aff_q else None),
            "finalized_nodes_total": g.get("finalized_nodes_total"),
            "rollbacks": rbs,
            "rollback_nodes_total": g.get("rollback_nodes_total"),
            "orchestrator_cpu_pct": res.get("orchestrator_cpu_pct"),
            "shadowfs_cpu_pct": res.get("shadowfs_cpu_pct"),
            "shadowproc_cpu_pct": res.get("shadowproc_cpu_pct"),
            "daemons_cpu_pct": res.get("daemons_cpu_pct"),
            "shadowfs_rss_peak_mb": res.get("shadowfs_rss_peak_mb"),
            "wall_time_s": c.get("wall_time_s"),
        })
    return rows


def print_graph_table(rows: Sequence[Dict[str, Any]]):
    # Column widths are sized to the longest value each can hold, not to the
    # common case: "rollback-cascade" is 16 characters and a 14-wide decision
    # column runs it into the operation next to it, which is exactly the pair of
    # columns that says what a row measured.
    width = 122
    print("\n" + "═" * width)
    print("  EXPERIMENT B — dependency-graph shape scaling")
    print("═" * width)
    hdr = (f"{'Dim':<4}{'topology':<11}{'nd':>4} {'decision':<17}"
           f"{'op':<18}{'p50(ms)':>9}{'p95(ms)':>9}{'us/node':>9}"
           f"{'edges':>7}{'scc':>7}{'heapMB':>8}{'E/inv':>7} "
           f"{'topo':<6}{'err':>4}")
    print(hdr)
    print("─" * width)
    for r in rows:
        scc = (f"{r['cyclic_scc_count_peak'] or 0}/"
               f"{r['max_scc_size_peak'] or 0}"
               if r["epochs_peak"] is not None else None)
        print(f"{str(r['dimension']):<4}{str(r['topology']):<11}"
              f"{(r['nodes'] if r['nodes'] is not None else '-'):>4} "
              f"{str(r['decision']):<17}{str(r['resolution_op']):<18}"
              f"{fmt(r['resolution_p50_ms']):>9}"
              f"{fmt(r['resolution_p95_ms']):>9}"
              f"{fmt(r['per_node_resolution_us'], '.1f'):>9}"
              f"{(r['edges_peak'] if r['edges_peak'] is not None else '-'):>7}"
              f"{(scc or '-'):>7}{fmt(r['heap_alloc_mb_peak'], '.1f'):>8}"
              f"{fmt(r['edges_per_invocation'], '.2f'):>7} "
              f"{fmt(r['topo_verified']):<6}"
              f"{r['error_count'] if r['error_count'] is not None else '-':>4}")
    print("  (op = what the timed interval measured; us/node = resolution cost"
          " per dependency node; scc = cyclic components / largest one)")

    bad = [r for r in rows if not r["topo_verified"]]
    if bad:
        print(f"\n  [warn] {len(bad)} configuration(s) did NOT verify their "
              f"dependency topology — their latencies describe a graph that was "
              f"not the one intended:")
        for r in bad[:12]:
            print(f"         {r['dimension']} {r['topology']} "
                  f"nodes={r['nodes']} decision={r['decision']}")
    errs = [r for r in rows if r["error_count"]]
    if errs:
        # One reason per configuration, not just a total: "22 errors" is a number
        # to worry about, "SCC detected with max_scc_size=4, expected 8" is a
        # diagnosis.
        print(f"  [warn] {len(errs)} configuration(s) recorded errors "
              f"({sum(r['error_count'] for r in errs)} total); first of each:")
        for r in errs[:8]:
            print(f"         {r['dimension']} {r['topology']} "
                  f"nodes={r['nodes']}: {r['first_error']}")


# ═══════════════════════════════════════════════════════════════════════════
# The reviewer-facing curves
# ═══════════════════════════════════════════════════════════════════════════

CURVE_COLUMNS = ("metric", "unit", "topology", "dimension", "nodes", "value",
                 "p95", "n", "decision", "topo_verified")


def build_curves(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Long-form (metric, topology, nodes, value) points.

    The publication curve and the rollback curve come from `resolution_op`, not
    from the decision string: D1 measures the same chain twice, once committing
    and once cascading a rollback, and only the operation says which curve a row
    belongs to. Rows whose topology did not verify are still emitted (dropping
    them would silently shorten a curve) but carry topo_verified=no so a plot
    can mark them.
    """
    out: List[Dict[str, Any]] = []

    def add(metric: str, unit: str, r: Dict[str, Any], value: Any,
            p95: Any = None, n: Any = None):
        if value is None or r["nodes"] is None:
            return
        out.append({"metric": metric, "unit": unit,
                    "topology": r["topology"], "dimension": r["dimension"],
                    "nodes": r["nodes"], "value": value, "p95": p95, "n": n,
                    "decision": r["decision"],
                    "topo_verified": bool(r["topo_verified"])})

    for r in rows:
        op = r["resolution_op"]
        if op == "commit":
            add(M_FINALIZATION, "ms", r, r["resolution_p50_ms"],
                r["resolution_p95_ms"], r["resolution_n"])
        elif op == "cascade-rollback":
            add(M_ROLLBACK, "ms", r,
                r["rollback_p50_ms"] if r["rollback_p50_ms"] is not None
                else r["resolution_p50_ms"],
                r["rollback_p95_ms"] if r["rollback_p95_ms"] is not None
                else r["resolution_p95_ms"], r["resolution_n"])
        add(M_WAIT, "ms", r, r["finalization_wait_p50_ms"],
            r["finalization_wait_p95_ms"])
        add(M_DRAIN, "ms", r, r["graph_drain_p50_ms"])
        add(M_HEAP, "MB", r, r["heap_alloc_mb_peak"])
        add(M_PER_NODE, "bytes", r, r["metadata_bytes_per_node"])
        add(M_EDGES, "edges", r, r["edges_peak"])
    out.sort(key=lambda d: (d["metric"], str(d["topology"]), d["nodes"]))
    return out


def group_curves(curves: Sequence[Dict[str, Any]]
                 ) -> Dict[str, Dict[str, List[Tuple[int, float]]]]:
    """metric → topology → [(nodes, value)], de-duplicated and sorted.

    A node count can appear twice for one topology (D1 and D5 both build
    chains); the median is taken rather than the last one, so a re-run that
    added a dimension does not silently pick a winner.
    """
    acc: Dict[str, Dict[str, Dict[int, List[float]]]] = {}
    for c in curves:
        bucket = acc.setdefault(c["metric"], {}).setdefault(
            str(c["topology"]), {}).setdefault(int(c["nodes"]), [])
        bucket.append(float(c["value"]))
    out: Dict[str, Dict[str, List[Tuple[int, float]]]] = {}
    for metric, topos in acc.items():
        out[metric] = {}
        for topo, points in topos.items():
            vals = sorted(points.items())
            out[metric][topo] = [(n, _median(v)) for n, v in vals]
    return out


def _median(vals: List[float]) -> float:
    s = sorted(vals)
    mid = len(s) // 2
    return s[mid] if len(s) % 2 else (s[mid - 1] + s[mid]) / 2.0


def print_curves(curves: Sequence[Dict[str, Any]]):
    print("\n" + "═" * 78)
    print("  THE THREE CURVES — dependency nodes vs. cost")
    print("═" * 78)
    grouped = group_curves(curves)
    for metric, unit in ((M_FINALIZATION, "ms"), (M_ROLLBACK, "ms"),
                         (M_HEAP, "MB")):
        topos = grouped.get(metric) or {}
        if not topos:
            print(f"\n  {metric}: no data")
            continue
        print(f"\n  {metric} ({unit})")
        for topo in sorted(topos):
            pts = topos[topo]
            line = "  ".join(f"{n}:{v:.2f}" for n, v in pts)
            print(f"    {topo:<10} {line}")


# ═══════════════════════════════════════════════════════════════════════════
# Output writers
# ═══════════════════════════════════════════════════════════════════════════

def write_csv(path: str, columns: Sequence[str],
              rows: Iterable[Dict[str, Any]]) -> bool:
    try:
        written = 0
        with open(path, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(columns),
                               extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow({k: ("" if r.get(k) is None else r.get(k))
                            for k in columns})
                written += 1
        print(f"[csv ] {path} ({written} rows)")
        return True
    except OSError as e:
        print(f"[fail] {path}: {type(e).__name__}: {e}\n"
              f"       (results/ is often root-owned after a sudo run — use "
              f"--output-dir to write somewhere writable)")
        return False


def _tex_escape(v: Any) -> str:
    return str(v).replace("_", r"\_").replace("%", r"\%")


def write_latex(path: str, caption: str, label: str,
                columns: Sequence[Tuple[str, str]],
                rows: Sequence[Dict[str, Any]],
                specs: Sequence[Tuple[str, str]]) -> bool:
    """One booktabs table. `specs` is [(column, printf), ...].

    `columns` supplies the header text and `specs` the per-column format, so the
    two must name the same columns in the same order; a mismatch is caught here
    rather than surfacing as a LaTeX "extra alignment tab" error three
    compilations later.
    """
    if [k for k, _ in columns] != [k for k, _ in specs]:
        raise ValueError(
            f"write_latex({label}): columns and specs disagree: "
            f"{[k for k, _ in columns]} vs {[k for k, _ in specs]}")
    head = " & ".join(h for _, h in columns)
    # Text columns left, numbers right: an "l" under a latency column makes the
    # digits ragged, which is the one thing a results table must not be.
    align = "".join("l" if spec == "s" else "r" for _, spec in specs)
    lines = [
        r"% Generated by summarize_scaling.py — do not edit by hand.",
        r"\begin{table}[t]",
        r"  \centering",
        f"  \\caption{{{caption}}}",
        f"  \\label{{tab:{label}}}",
        f"  \\begin{{tabular}}{{{align}}}",
        r"    \toprule",
        f"    {head} \\\\",
        r"    \midrule",
    ]
    for r in rows:
        cells = []
        for key, spec in specs:
            v = r.get(key)
            if v is None:
                cells.append("-")
            elif isinstance(v, (int, float)):
                # bool takes this branch too -- it is an int subclass -- and fmt
                # turns it into yes/no before looking at the spec, so a
                # topo_verified column reads as a verdict rather than as 1/0.
                # That guard lives in fmt and nowhere else, so that there is one
                # answer to "how is a bool rendered"; test_summarize_scaling
                # pins it at both ends.
                cells.append(fmt(v, spec))
            else:
                cells.append(_tex_escape(v))
        lines.append("    " + " & ".join(cells) + r" \\")
    lines += [r"    \bottomrule", r"  \end{tabular}", r"\end{table}", ""]
    try:
        with open(path, "w") as fh:
            fh.write("\n".join(lines))
        print(f"[tex ] {path}")
        return True
    except OSError as e:
        print(f"[fail] {path}: {type(e).__name__}: {e}")
        return False


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(
        description="Summarize the RQ3 multi-agent and dependency-graph "
                    "scaling results")
    parser.add_argument("--results-dir", default=os.path.join(here, "results"))
    parser.add_argument("--output-dir", default=None,
                        help="where to write the CSVs and the LaTeX tables "
                             "(default: --results-dir)")
    parser.add_argument("--latex", action="store_true",
                        help="also write the booktabs tables")
    args = parser.parse_args()

    out_dir = args.output_dir or args.results_dir
    os.makedirs(out_dir, exist_ok=True)

    a = load_json(os.path.join(args.results_dir, A_FILE))
    b = load_json(os.path.join(args.results_dir, B_FILE))
    if not a and not b:
        print("\nNothing to summarize. Run the experiments first:\n"
              "  sudo ./start_and_run.sh scaling\n"
              "or individually:\n"
              "  sudo ./start_and_run.sh multi\n"
              "  sudo ./start_and_run.sh dep")
        return 1

    ok = True
    curves: List[Dict[str, Any]] = []
    # Hoisted out of the two blocks below because the closing warnings re-read
    # them: re-deriving the rows would flatten the same JSON a second time for
    # nothing, and -- worse -- could disagree with what was just printed.
    agent_rows: List[Dict[str, Any]] = []
    graph_rows: List[Dict[str, Any]] = []

    if a:
        agent_rows = summarize_agent(a)
        print_agent_table(agent_rows)
        ok &= write_csv(os.path.join(out_dir, "scaling_agent.csv"),
                        AGENT_COLUMNS, agent_rows)
        if args.latex:
            ok &= write_latex(
                os.path.join(out_dir, "scaling_agent.tex"),
                "Multi-agent scaling: throughput and per-phase latency by "
                "workload and concurrent agent count.",
                "rq3:agent-scaling",
                (("workload", "Workload"), ("agents", "Agents"),
                 ("throughput_inv_per_s", "inv/s"), ("speedup", "Speedup"),
                 ("parallel_efficiency_pct", "Eff.\\ \\%"),
                 ("epoch_begin_p50_ms", "Begin (ms)"),
                 ("commit_p50_ms", "Commit (ms)"),
                 ("authz_to_finalized_p50_ms", "Authz$\\to$fin.\\ (ms)"),
                 ("rollback_p50_ms", "Rollback (ms)"),
                 ("edges_per_invocation", "Edges/inv."),
                 ("daemons_cpu_pct", "Daemon CPU \\%"),
                 ("error_count", "Err.")
                 ),
                agent_rows,
                (("workload", "s"), ("agents", "d"),
                 ("throughput_inv_per_s", ".2f"), ("speedup", ".2f"),
                 ("parallel_efficiency_pct", ".0f"),
                 ("epoch_begin_p50_ms", ".3f"), ("commit_p50_ms", ".3f"),
                 ("authz_to_finalized_p50_ms", ".3f"),
                 ("rollback_p50_ms", ".3f"),
                 ("edges_per_invocation", ".2f"),
                 ("daemons_cpu_pct", ".0f"), ("error_count", "d")))

    if b:
        graph_rows = summarize_graph(b)
        print_graph_table(graph_rows)
        curves = build_curves(graph_rows)
        print_curves(curves)
        ok &= write_csv(os.path.join(out_dir, "scaling_graph.csv"),
                        GRAPH_COLUMNS, graph_rows)
        ok &= write_csv(os.path.join(out_dir, "scaling_curves.csv"),
                        CURVE_COLUMNS, curves)
        if args.latex:
            ok &= write_latex(
                os.path.join(out_dir, "scaling_graph.tex"),
                "Dependency-graph shape scaling: resolution cost against the "
                "number of dependency nodes, with the graph that was actually "
                "present at full population.",
                "rq3:graph-scaling",
                (("dimension", "Dim"), ("topology", "Topology"),
                 ("nodes", "Nodes"), ("resolution_op", "Operation"),
                 ("resolution_p50_ms", "p50 (ms)"),
                 ("resolution_p95_ms", "p95 (ms)"),
                 ("per_node_resolution_us", "$\\mu$s/node"),
                 ("edges_peak", "Edges"),
                 ("heap_alloc_mb_peak", "Heap (MB)"),
                 ("edges_per_invocation", "Edges/inv."),
                 ("topo_verified", "Verified")),
                graph_rows,
                (("dimension", "s"), ("topology", "s"), ("nodes", "d"),
                 ("resolution_op", "s"), ("resolution_p50_ms", ".3f"),
                 ("resolution_p95_ms", ".3f"),
                 ("per_node_resolution_us", ".1f"), ("edges_peak", "d"),
                 ("heap_alloc_mb_peak", ".1f"),
                 ("edges_per_invocation", ".2f"), ("topo_verified", "s")))

    # A scaling claim rests on the topology checks: a curve whose edges never
    # formed is a measurement of an empty graph, so say it once, at the end.
    print("\n" + "═" * 78)
    print(f"  output directory: {out_dir}")
    unverified = sum(1 for r in graph_rows if not r["topo_verified"])
    if unverified:
        print(f"  [warn] {unverified} graph configuration(s) FAILED their "
              f"topology check — treat their latency rows as unvalidated")
    errs = sum(int(r["error_count"] or 0) for r in agent_rows)
    if errs:
        print(f"  [warn] experiment A recorded {errs} error(s)")
    print("═" * 78)
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
