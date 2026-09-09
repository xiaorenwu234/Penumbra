#!/usr/bin/env python3
"""Unit tests for summarize_scaling.py, the reporting layer of RQ3 scaling.

The summarizer is the only part of the scaling experiments that runs WITHOUT
root, three daemons and a FUSE mount -- so it is the part that gets run most
often, and its tables are what a reviewer actually reads. That combination makes
its bugs expensive in a specific way: every one of the bugs pinned below
produced output that looked plausible.

  * timing_ms returned the orchestrator's per-phase medians unchanged. Those
    blocks are named `*_timings_ms` but carry `*_ns` inner keys, because
    _ms_stats scales the daemon's milliseconds UP into nanoseconds to reuse
    compute_stats' percentile code. Reading `median_ns` as if it were already
    milliseconds overstated every commit-path phase by 1e6: a 4 ms
    authorization-to-finalization interval printed as 4000 ms, which reads as
    "finalization dominates the commit" rather than as a unit error.
  * write_csv counted its rows with len() AFTER iterating them, so a generator
    reported "(0 rows)" for a file that had been written perfectly.
  * write_latex formatted every non-None cell with its printf spec, so a string
    column raised `ValueError: Unknown format code 'f'`. Bool columns survive
    only because fmt intercepts them before the spec -- which a mutation check
    proved is the ONE place that guard lives, so it is tested there and its
    effect is tested here.
  * resolution_op was inferred from the decision string by testing for "deny"
    alone, so a legacy `rollback-cascade` row printed op=commit: the two columns
    that say WHAT a row measured contradicted each other, on the row a reviewer
    reads first.
  * structure_ok is tri-state (None = the phase did not run) and was tested with
    `not`, so a `--phases throughput` run reported every row as FAILED.

What is deliberately NOT pinned: the exact spacing of a printed table, beyond
the row/rule width equality. That is a rendering choice; what matters is that
the rows and the rules agree on how wide the table is. No figure is rendered at
all -- scaling_curves.csv is the deliverable, and plotting happens elsewhere.

Run: python3 -m unittest discover -s experiments/rq3 -p "test_summarize*.py" -t .
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import summarize_scaling as ss


# ─── fixtures ──────────────────────────────────────────────────────────────
#
# Hand-built dicts rather than the experiments' own save_results: importing
# dep_graph_scalability pulls in the framework and its daemon client, and a
# reporting test should not need any of it. The shapes here are the shapes the
# two experiments write, checked field by field against their to_dict().

def _ns_block(median_ns: float, p95_ns: float = None, n: int = 60) -> dict:
    """A stats block in the CURRENT spelling (`*_ns` inner keys)."""
    return {"name": "x", "n": n, "excluded": 0,
            "median_ns": median_ns,
            "p95_ns": median_ns if p95_ns is None else p95_ns,
            "mean_ns": median_ns, "min_ns": median_ns, "max_ns": median_ns}


def _us_block(median_us: float, p95_us: float = None, n: int = 60) -> dict:
    """The same block in the LEGACY spelling, which reported microseconds."""
    return {"name": "x", "n": n,
            "median_us": median_us,
            "p95_us": median_us if p95_us is None else p95_us,
            "mean_us": median_us}


def _agent_cfg(workload: str = "independent", agents: int = 1,
               tp: float = 100.0, **over) -> dict:
    cfg = {
        "workload": workload,
        "agents": agents,
        "repeats": 3,
        "total_invocations": agents * 20 * 3,
        "throughput_inv_per_s": {"median": tp, "mean": tp},
        "edges_per_invocation": 1.5,
        "error_count": 0,
        "structure": {"ok": True, "edges": agents, "errors": []},
        "structure_graph": {"edges": agents, "epochs": agents},
        "branch_preservation_ok": True,
        "branch_errors": [],
        "resources": {"orchestrator_cpu_pct": 12.0, "shadowfs_cpu_pct": 30.0,
                      "shadowproc_cpu_pct": 4.0, "daemons_cpu_pct": 46.0,
                      "orchestrator_rss_peak_mb": 90.0,
                      "shadowfs_rss_peak_mb": 55.0},
        "stats": {
            "epoch_begin_ns": _ns_block(1.5e6, 3.0e6),
            "run_ns": _ns_block(8.0e6),
            "commit_ns": _ns_block(12.0e6, 20.0e6),
            "rollback_ns": _ns_block(6.0e6),
            "finalization_wait_ns": _ns_block(0.5e6),
            # The literal dotted key, holding nanoseconds -- see timing_ms.
            "commit_timings_ms.authz_to_finalized_ms": _ns_block(4.0e6, 7.0e6),
        },
    }
    cfg.update(over)
    return cfg


def _a_file(*cfgs) -> dict:
    return {"experiment": "multi_agent_scaling", "configurations": list(cfgs)}


def _dim(dimension: str = "D2", topology: str = "chain", size: int = 8,
         nodes: int = None, decision: str = "allow", op: str = None,
         finalize_ms: float = 2.0, stats_extra: dict = None, **over) -> dict:
    """One experiment-B dimension, in the shape the instrumented run writes."""
    d = {
        "dimension": dimension,
        "topology": topology,
        "size": size,
        "decision": decision,
        "repeats": 3,
        "topo_verified": True,
        "errors": [],
        "error_count": 0,
        "invocations": 24,
        "edges_per_invocation": 1.0,
        "graph": {"edge_insertions": 24, "scc_computations": 8,
                  "scc_compute_ns": 4_000_000, "affected_queries": 6,
                  "affected_query_ns": 900_000, "rollbacks": 0,
                  "finalized_nodes_total": size, "rollback_nodes_total": 0,
                  "finalize_rejected_toctou": 0},
        "graph_peak": {"epochs": size, "edges": size - 1, "versions": size,
                       "objects": size, "scc_count": size,
                       "cyclic_scc_count": 0, "max_scc_size": 1,
                       "heap_alloc_bytes": 8 * 1048576},
        "resources": {"orchestrator_cpu_pct": 10.0, "shadowfs_cpu_pct": 20.0,
                      "shadowproc_cpu_pct": 3.0, "daemons_cpu_pct": 33.0,
                      "shadowfs_rss_peak_mb": 40.0},
        "stats": {
            "finalize_ns": _ns_block(finalize_ms * 1e6, finalize_ms * 2e6),
            "commit_timings_ms.authz_to_finalized_ms": _ns_block(4.0e6),
            "commit_timings_ms.finalize_lock_wait_ms": _ns_block(0.25e6),
            "commit_timings_ms.finalize_lock_held_ms": _ns_block(1.0e6),
        },
        "wall_time_s": 12.0,
    }
    if nodes is not None:
        d["nodes"] = nodes
    if op is not None:
        d["resolution_op"] = op
    if stats_extra:
        d["stats"].update(stats_extra)
    d.update(over)
    return d


def _b_file(*dims) -> dict:
    return {"experiment": "dep_graph_scalability", "dimensions": list(dims)}


def _capture(fn, *a, **kw):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rv = fn(*a, **kw)
    return rv, buf.getvalue()


def _rows_of(dim) -> dict:
    """summarize_graph for a single dimension, returning its only row."""
    rows = ss.summarize_graph(_b_file(dim))
    assert len(rows) == 1
    return rows[0]


# ═══════════════════════════════════════════════════════════════════════════
# Unit handling -- the 1e6 bug and the legacy microsecond spelling
# ═══════════════════════════════════════════════════════════════════════════

class TestUnitConversion(unittest.TestCase):

    def test_timing_ms_undoes_the_ms_to_ns_scaling(self):
        """THE bug: a per-phase block is named _ms but stores nanoseconds.

        _ms_stats multiplies the daemon's milliseconds by 1e6 so that
        compute_stats' percentile code (which is written against nanoseconds)
        can be reused. So `median_ns` here is genuinely nanoseconds, and the
        4.0 ms the daemon reported must come back out as 4.0 -- not 4e6.
        """
        cfg = _agent_cfg()
        got = ss.timing_ms(cfg, "commit", "authz_to_finalized_ms")
        self.assertAlmostEqual(got, 4.0, places=9)
        self.assertLess(got, 1000.0, "returned nanoseconds, not milliseconds")

    def test_timing_ms_p95_uses_the_same_scaling(self):
        cfg = _agent_cfg()
        got = ss.timing_ms(cfg, "commit", "authz_to_finalized_ms", "p95_ns")
        self.assertAlmostEqual(got, 7.0, places=9)

    def test_timing_ms_key_is_a_literal_dot_not_a_nesting(self):
        """`{phase}_timings_ms.{key}` is ONE dict key containing a dot.

        Both experiments build it with an f-string. If a future refactor nests
        it instead, reading the flat key must fail loudly (None -> a dash in the
        table) rather than silently: a nested block would make every commit-path
        column empty, which is indistinguishable from "the daemon reported
        nothing".
        """
        cfg = {"stats": {"commit_timings_ms": {
            "authz_to_finalized_ms": _ns_block(4.0e6)}}}
        self.assertIsNone(ss.timing_ms(cfg, "commit", "authz_to_finalized_ms"))

    def test_timing_ms_missing_phase_is_none(self):
        self.assertIsNone(ss.timing_ms(_agent_cfg(), "rollback", "fs_rollback_ms"))

    def test_timing_ms_accepts_the_legacy_microsecond_block(self):
        """4000 us == 4 ms, whichever spelling the results file uses."""
        cfg = {"stats": {"commit_timings_ms.finalize_lock_wait_ms":
                         _us_block(4000.0)}}
        self.assertAlmostEqual(
            ss.timing_ms(cfg, "commit", "finalize_lock_wait_ms"), 4.0, places=9)

    def test_ms_divides_nanoseconds_by_a_million(self):
        self.assertAlmostEqual(ss.ms(_agent_cfg(), "commit_ns", "median_ns"),
                               12.0, places=9)

    def test_stat_returns_raw_nanoseconds(self):
        self.assertAlmostEqual(ss.stat(_agent_cfg(), "commit_ns"), 12.0e6)

    def test_from_block_prefers_ns_when_both_spellings_exist(self):
        block = {"median_ns": 5000.0, "median_us": 99.0}
        self.assertEqual(ss._from_block(block, "median_ns"), 5000.0)

    def test_from_block_falls_back_to_us_scaled_by_a_thousand(self):
        """Without this a pre-standardization results file is ALL dashes.

        That failure mode is the reason this test exists: a table of dashes
        looks like a summarizer bug, not like stale data, and costs an hour.
        """
        self.assertEqual(ss._from_block(_us_block(250.0), "median_ns"),
                         250_000.0)

    def test_from_block_does_not_guess_for_non_ns_keys(self):
        """The fallback is _ns -> _us only; it must not invent other pairs."""
        self.assertIsNone(ss._from_block({"median_us": 1.0}, "median_ms"))

    def test_from_block_on_a_non_dict_is_none(self):
        self.assertIsNone(ss._from_block(None, "median_ns"))
        self.assertIsNone(ss._from_block(3.0, "median_ns"))
        self.assertIsNone(ss._from_block([1, 2], "median_ns"))

    def test_get_walks_nested_dicts_and_stops_at_the_first_gap(self):
        d = {"a": {"b": {"c": 7}}}
        self.assertEqual(ss.get(d, "a", "b", "c"), 7)
        self.assertIsNone(ss.get(d, "a", "x", "c"))
        self.assertIsNone(ss.get(d, "a", "b", "c", "d"))
        self.assertIsNone(ss.get(None, "a"))

    def test_us_helper_converts_nanoseconds_to_microseconds(self):
        self.assertAlmostEqual(ss._us(4500.0), 4.5)
        self.assertIsNone(ss._us(None))


class TestNodeCount(unittest.TestCase):
    """The x-axis of every curve. Getting it wrong shifts a whole topology."""

    def test_nodes_field_wins_over_the_shape_parameter(self):
        self.assertEqual(ss.node_count({"nodes": 34, "size": 32,
                                        "topology": "chain"}), 34)

    def test_fan_out_holds_one_more_node_than_its_size(self):
        for topo in ("fan-out", "fan-in", "concurrent"):
            with self.subTest(topology=topo):
                self.assertEqual(ss.node_count({"size": 8, "topology": topo}), 9)

    def test_diamond_holds_two_more_than_its_size(self):
        self.assertEqual(ss.node_count({"size": 8, "topology": "diamond"}), 10)

    def test_chain_and_scc_are_their_own_size(self):
        self.assertEqual(ss.node_count({"size": 32, "topology": "chain"}), 32)
        self.assertEqual(ss.node_count({"size": 16, "topology": "scc"}), 16)

    def test_unknown_topology_falls_back_to_the_size(self):
        self.assertEqual(ss.node_count({"size": 5, "topology": "star"}), 5)
        self.assertEqual(ss.node_count({"size": 5}), 5)

    def test_no_nodes_and_no_size_is_none(self):
        self.assertIsNone(ss.node_count({"topology": "chain"}))
        self.assertIsNone(ss.node_count({}))

    def test_size_is_coerced_to_int(self):
        self.assertEqual(ss.node_count({"size": "8", "topology": "chain"}), 8)


class TestFmt(unittest.TestCase):
    """A table cell must never read as 'None', and never as a number when it
    is a verdict."""

    def test_none_is_a_dash(self):
        self.assertEqual(ss.fmt(None), "-")

    def test_bool_is_a_word_even_under_a_numeric_spec(self):
        """Checked before the numeric branch: bool IS an int subclass."""
        self.assertEqual(ss.fmt(True), "yes")
        self.assertEqual(ss.fmt(False), "no")
        self.assertEqual(ss.fmt(True, "d"), "yes")
        self.assertEqual(ss.fmt(False, ".3f"), "no")

    def test_nan_and_inf_are_dashes(self):
        self.assertEqual(ss.fmt(float("nan")), "-")
        self.assertEqual(ss.fmt(float("inf")), "-")
        self.assertEqual(ss.fmt(float("-inf")), "-")

    def test_a_real_zero_is_not_a_dash(self):
        """0 ms wait and 0 errors are measurements, not missing data."""
        self.assertEqual(ss.fmt(0.0), "0.000")
        self.assertEqual(ss.fmt(0, "d"), "0")

    def test_spec_is_honoured(self):
        self.assertEqual(ss.fmt(1.23456), "1.235")
        self.assertEqual(ss.fmt(1.23456, ".1f"), "1.2")
        self.assertEqual(ss.fmt(7, "d"), "7")


# ═══════════════════════════════════════════════════════════════════════════
# Experiment A rows
# ═══════════════════════════════════════════════════════════════════════════

class TestExperimentARows(unittest.TestCase):

    def test_speedup_is_measured_against_the_one_agent_row(self):
        rows = ss.summarize_agent(_a_file(
            _agent_cfg(agents=1, tp=100.0),
            _agent_cfg(agents=4, tp=380.0)))
        self.assertAlmostEqual(rows[0]["speedup"], 1.0)
        self.assertAlmostEqual(rows[1]["speedup"], 3.8)

    def test_parallel_efficiency_is_speedup_over_agents(self):
        rows = ss.summarize_agent(_a_file(
            _agent_cfg(agents=1, tp=100.0), _agent_cfg(agents=4, tp=380.0)))
        self.assertAlmostEqual(rows[1]["parallel_efficiency_pct"], 95.0)

    def test_the_contended_workload_is_allowed_not_to_scale(self):
        """The point of the column: 32 agents buying 1.04x must be visible.

        Deriving speedup from the agent count would report 32.0 here and hide
        the single most interesting result in experiment A.
        """
        rows = ss.summarize_agent(_a_file(
            _agent_cfg("contended", agents=1, tp=100.0),
            _agent_cfg("contended", agents=32, tp=104.0)))
        self.assertAlmostEqual(rows[1]["speedup"], 1.04)
        self.assertAlmostEqual(rows[1]["parallel_efficiency_pct"], 3.25)

    def test_baselines_are_per_workload_not_global(self):
        """independent's 1-agent row must not become contended's denominator."""
        rows = ss.summarize_agent(_a_file(
            _agent_cfg("independent", agents=1, tp=100.0),
            _agent_cfg("independent", agents=2, tp=190.0),
            _agent_cfg("contended", agents=1, tp=40.0),
            _agent_cfg("contended", agents=2, tp=44.0)))
        by = {(r["workload"], r["agents"]): r for r in rows}
        self.assertAlmostEqual(by[("independent", 2)]["speedup"], 1.9)
        self.assertAlmostEqual(by[("contended", 2)]["speedup"], 1.1)

    def test_no_baseline_means_no_speedup(self):
        rows = ss.summarize_agent(_a_file(_agent_cfg(agents=8, tp=400.0)))
        self.assertIsNone(rows[0]["speedup"])
        self.assertIsNone(rows[0]["parallel_efficiency_pct"])

    def test_zero_throughput_is_missing_not_a_divisor(self):
        rows = ss.summarize_agent(_a_file(_agent_cfg(agents=1, tp=0.0)))
        self.assertIsNone(rows[0]["throughput_inv_per_s"])
        self.assertIsNone(rows[0]["speedup"])

    def test_latency_columns_come_out_in_milliseconds(self):
        r = ss.summarize_agent(_a_file(_agent_cfg()))[0]
        self.assertAlmostEqual(r["epoch_begin_p50_ms"], 1.5)
        self.assertAlmostEqual(r["epoch_begin_p95_ms"], 3.0)
        self.assertAlmostEqual(r["commit_p50_ms"], 12.0)
        self.assertAlmostEqual(r["rollback_p50_ms"], 6.0)
        self.assertAlmostEqual(r["authz_to_finalized_p50_ms"], 4.0)

    def test_insertion_latency_is_reported_in_microseconds(self):
        r = ss.summarize_agent(_a_file(_agent_cfg(
            insertion_latency_ns_client=45_000,
            insertion_latency_ns_daemon=12_000)))[0]
        self.assertAlmostEqual(r["insertion_latency_us_client"], 45.0)
        self.assertAlmostEqual(r["insertion_latency_us_daemon"], 12.0)

    def test_resources_are_flattened_from_their_own_block(self):
        r = ss.summarize_agent(_a_file(_agent_cfg()))[0]
        self.assertAlmostEqual(r["daemons_cpu_pct"], 46.0)
        self.assertAlmostEqual(r["shadowfs_rss_peak_mb"], 55.0)

    def test_graph_size_comes_from_the_structure_phase_snapshot(self):
        r = ss.summarize_agent(_a_file(_agent_cfg(agents=8)))[0]
        self.assertEqual(r["graph_edges_peak"], 8)
        self.assertEqual(r["graph_epochs_peak"], 8)

    def test_the_first_reason_is_carried_not_just_the_count(self):
        """'22 errors' is a number to worry about; the reason is a diagnosis."""
        r = ss.summarize_agent(_a_file(_agent_cfg(structure={
            "ok": False, "edges": 0,
            "errors": ["graph has 0 edges, want 8", "second one"]})))[0]
        self.assertEqual(r["structure_error"], "graph has 0 edges, want 8")
        self.assertIs(r["structure_ok"], False)

    def test_an_absent_error_list_gives_no_reason(self):
        r = ss.summarize_agent(_a_file(_agent_cfg()))[0]
        self.assertIsNone(r["structure_error"])
        self.assertIsNone(r["branch_error"])

    def test_every_declared_column_is_present_in_every_row(self):
        """The CSV writer indexes by column name; a typo here is a silent gap."""
        for r in ss.summarize_agent(_a_file(_agent_cfg())):
            for col in ss.AGENT_COLUMNS:
                self.assertIn(col, r)


# ═══════════════════════════════════════════════════════════════════════════
# Experiment B rows
# ═══════════════════════════════════════════════════════════════════════════

class TestExperimentBRows(unittest.TestCase):

    def test_an_explicit_resolution_op_is_used_verbatim(self):
        r = _rows_of(_dim(op="cascade-rollback", decision="allow"))
        self.assertEqual(r["resolution_op"], "cascade-rollback")

    def test_op_is_inferred_as_commit_for_an_allowed_configuration(self):
        self.assertEqual(_rows_of(_dim(decision="allow"))["resolution_op"],
                         "commit")

    def test_op_is_inferred_as_rollback_for_every_deny_spelling(self):
        """The bug: only 'deny' was tested, so D3's rollback-cascade printed
        op=commit next to decision=rollback-cascade."""
        for decision in ("root-deny", "middle-deny", "rollback-cascade",
                         "deny", "cascade-rollback"):
            with self.subTest(decision=decision):
                self.assertEqual(_rows_of(_dim(decision=decision))[
                    "resolution_op"], "cascade-rollback")

    def test_a_publish_decision_is_inferred_as_commit(self):
        """D7 publishes an SCC: decision="publish", resolution_op="commit".
        'publish' is not a denial, and reading it as one would put the atomic
        publication of a cycle on the rollback curve."""
        self.assertEqual(_rows_of(_dim(decision="publish"))["resolution_op"],
                         "commit")

    def test_the_decision_column_is_never_rewritten(self):
        """Inference fills the OP column only; the decision is what was asked
        for and must stay exactly as the experiment recorded it."""
        r = _rows_of(_dim(decision="rollback-cascade"))
        self.assertEqual(r["decision"], "rollback-cascade")

    def test_resolution_latency_is_in_milliseconds(self):
        r = _rows_of(_dim(finalize_ms=2.5))
        self.assertAlmostEqual(r["resolution_p50_ms"], 2.5)
        self.assertAlmostEqual(r["resolution_p95_ms"], 5.0)

    def test_per_node_cost_is_microseconds_per_node(self):
        """2 ms over 8 nodes = 250 us/node: the slope of the whole claim."""
        r = _rows_of(_dim(finalize_ms=2.0, nodes=8))
        self.assertAlmostEqual(r["per_node_resolution_us"], 250.0)

    def test_per_node_cost_is_none_when_the_graph_is_empty(self):
        r = _rows_of(_dim(finalize_ms=2.0, nodes=0))
        self.assertIsNone(r["per_node_resolution_us"])

    def test_heap_peak_is_converted_from_bytes(self):
        r = _rows_of(_dim())
        self.assertAlmostEqual(r["heap_alloc_mb_peak"], 8.0)

    def test_a_missing_heap_snapshot_is_none_not_zero(self):
        d = _dim()
        d["graph_peak"].pop("heap_alloc_bytes")
        self.assertIsNone(_rows_of(d)["heap_alloc_mb_peak"])

    def test_scc_and_affected_costs_are_per_operation(self):
        r = _rows_of(_dim())
        # 4 ms of SCC work over 8 sweeps = 500 us each.
        self.assertAlmostEqual(r["scc_compute_us_per_sweep"], 500.0)
        # 0.9 ms over 6 queries = 150 us each.
        self.assertAlmostEqual(r["affected_query_us_per_query"], 150.0)

    def test_zero_counters_do_not_divide(self):
        d = _dim()
        d["graph"].update({"scc_computations": 0, "affected_queries": 0})
        r = _rows_of(d)
        self.assertIsNone(r["scc_compute_us_per_sweep"])
        self.assertIsNone(r["affected_query_us_per_query"])

    def test_nodes_falls_back_to_the_corrected_size(self):
        """A legacy file has `size` only; fan-out's root must still be counted."""
        d = _dim(topology="fan-out", size=8)
        d.pop("nodes", None)
        self.assertEqual(_rows_of(d)["nodes"], 9)

    def test_lock_wait_and_hold_are_separate_columns(self):
        """Wait rising beside a flat hold is the contention signature."""
        r = _rows_of(_dim())
        self.assertAlmostEqual(r["finalize_lock_wait_p50_ms"], 0.25)
        self.assertAlmostEqual(r["finalize_lock_held_p50_ms"], 1.0)

    def test_a_configuration_with_no_stats_block_at_all(self):
        """A crash before the first repeat must cost empty cells, not a
        traceback -- this is the case that made every accessor use .get()."""
        d = _dim()
        d["stats"] = {}
        d.pop("graph_peak")
        d.pop("graph")
        d.pop("resources")
        r = _rows_of(d)
        self.assertIsNone(r["resolution_p50_ms"])
        self.assertIsNone(r["edges_peak"])
        self.assertIsNone(r["heap_alloc_mb_peak"])
        self.assertEqual(r["scc_computations"], 0)

    def test_every_declared_column_is_present_in_every_row(self):
        for r in ss.summarize_graph(_b_file(_dim())):
            for col in ss.GRAPH_COLUMNS:
                self.assertIn(col, r)


# ═══════════════════════════════════════════════════════════════════════════
# The reviewer-facing curves
# ═══════════════════════════════════════════════════════════════════════════

class TestCurves(unittest.TestCase):

    def test_a_commit_row_lands_on_the_finalization_curve(self):
        curves = ss.build_curves(ss.summarize_graph(_b_file(
            _dim(op="commit", finalize_ms=2.0, nodes=8))))
        fin = [c for c in curves if c["metric"] == ss.M_FINALIZATION]
        self.assertEqual(len(fin), 1)
        self.assertAlmostEqual(fin[0]["value"], 2.0)
        self.assertEqual(fin[0]["nodes"], 8)

    def test_a_cascade_row_lands_on_the_rollback_curve_only(self):
        """D1 measures the same chain twice -- once committing, once cascading.
        Only resolution_op says which curve a row belongs to; dispatching on the
        topology or the decision would put both points on one curve."""
        curves = ss.build_curves(ss.summarize_graph(_b_file(
            _dim(op="cascade-rollback", decision="rollback-cascade",
                 stats_extra={"rollback_ns": _ns_block(9.0e6)}))))
        by_metric = {}
        for c in curves:
            by_metric.setdefault(c["metric"], []).append(c)
        self.assertNotIn(ss.M_FINALIZATION, by_metric)
        self.assertAlmostEqual(by_metric[ss.M_ROLLBACK][0]["value"], 9.0)

    def test_the_same_chain_committing_and_cascading_gives_two_curves(self):
        curves = ss.build_curves(ss.summarize_graph(_b_file(
            _dim(dimension="D1", op="commit", finalize_ms=2.0, nodes=8),
            _dim(dimension="D1", op="cascade-rollback", decision="root-deny",
                 finalize_ms=2.0, nodes=8,
                 stats_extra={"rollback_ns": _ns_block(9.0e6)}))))
        fin = [c for c in curves if c["metric"] == ss.M_FINALIZATION]
        rb = [c for c in curves if c["metric"] == ss.M_ROLLBACK]
        self.assertEqual(len(fin), 1)
        self.assertEqual(len(rb), 1)
        self.assertAlmostEqual(rb[0]["value"], 9.0)

    def test_the_rollback_curve_falls_back_to_the_resolution_interval(self):
        """A rollback row with no separate rollback_ns still measured a
        cascading resolution; dropping it would silently shorten the curve."""
        curves = ss.build_curves(ss.summarize_graph(_b_file(
            _dim(op="cascade-rollback", finalize_ms=9.0, nodes=8))))
        rb = [c for c in curves if c["metric"] == ss.M_ROLLBACK]
        self.assertAlmostEqual(rb[0]["value"], 9.0)

    def test_unverified_rows_are_emitted_but_flagged(self):
        """Dropping them would shorten a curve with no trace; keeping them
        unflagged would plot a graph that was never the intended one."""
        curves = ss.build_curves(ss.summarize_graph(_b_file(
            _dim(op="commit", topo_verified=False))))
        fin = [c for c in curves if c["metric"] == ss.M_FINALIZATION]
        self.assertEqual(len(fin), 1)
        self.assertIs(fin[0]["topo_verified"], False)

    def test_a_pure_decision_row_lands_on_neither_curve(self):
        """resolution_op's third value is `decision`: the timed interval measured
        an authorization decision, with no publication and no rollback in it.

        This is the case that separates dispatching on the operation from
        dispatching on the decision string. A row like this carries a deny in
        its decision -- so inferring the curve from the decision would plot an
        authorization latency as a cascading rollback, on the curve that is
        supposed to show what a rollback COSTS.
        """
        curves = ss.build_curves(ss.summarize_graph(_b_file(
            _dim(op="decision", decision="root-deny", finalize_ms=0.4,
                 nodes=8))))
        metrics = {c["metric"] for c in curves}
        self.assertNotIn(ss.M_FINALIZATION, metrics)
        self.assertNotIn(ss.M_ROLLBACK, metrics)
        # The graph-shape series are still real for this row: the graph existed
        # and was populated, it just was not resolved by this measurement.
        self.assertIn(ss.M_HEAP, metrics)
        self.assertIn(ss.M_EDGES, metrics)

    def test_a_row_with_no_node_count_emits_nothing(self):
        """There is no x to plot against, and inventing one would be worse."""
        d = _dim(op="commit")
        d.pop("size", None)
        curves = ss.build_curves(ss.summarize_graph(_b_file(d)))
        self.assertEqual(curves, [])

    def test_memory_and_edge_metrics_are_emitted_for_every_row(self):
        curves = ss.build_curves(ss.summarize_graph(_b_file(_dim())))
        metrics = {c["metric"] for c in curves}
        self.assertIn(ss.M_HEAP, metrics)
        self.assertIn(ss.M_EDGES, metrics)

    def test_only_known_metrics_are_emitted(self):
        curves = ss.build_curves(ss.summarize_graph(_b_file(
            _dim(op="commit"), _dim(op="cascade-rollback"))))
        self.assertLessEqual({c["metric"] for c in curves},
                             set(ss.CURVE_METRICS))

    def test_curves_are_sorted_by_metric_topology_then_nodes(self):
        curves = ss.build_curves(ss.summarize_graph(_b_file(
            _dim(topology="chain", op="commit", nodes=32, size=32),
            _dim(topology="chain", op="commit", nodes=8, size=8),
            _dim(topology="diamond", op="commit", nodes=4, size=2))))
        keys = [(c["metric"], c["topology"], c["nodes"]) for c in curves]
        self.assertEqual(keys, sorted(keys, key=lambda k: (k[0], k[1], k[2])))

    def test_group_curves_takes_the_median_of_a_repeated_node_count(self):
        """D1 and D5 both build chains, so one node count can appear twice.
        Last-one-wins would let a re-run that adds a dimension silently pick a
        winner; the median does not depend on the file's ordering."""
        curves = [
            {"metric": ss.M_FINALIZATION, "topology": "chain", "nodes": 8,
             "value": 1.0},
            {"metric": ss.M_FINALIZATION, "topology": "chain", "nodes": 8,
             "value": 3.0},
            {"metric": ss.M_FINALIZATION, "topology": "chain", "nodes": 4,
             "value": 0.5},
        ]
        grouped = ss.group_curves(curves)
        self.assertEqual(grouped[ss.M_FINALIZATION]["chain"],
                         [(4, 0.5), (8, 2.0)])

    def test_group_curves_separates_topologies_and_sorts_the_axis(self):
        curves = [
            {"metric": ss.M_HEAP, "topology": "scc", "nodes": 16, "value": 2.0},
            {"metric": ss.M_HEAP, "topology": "chain", "nodes": 8, "value": 1.0},
        ]
        grouped = ss.group_curves(curves)
        self.assertEqual(set(grouped[ss.M_HEAP]), {"scc", "chain"})
        self.assertEqual(grouped[ss.M_HEAP]["chain"], [(8, 1.0)])

    def test_median_helper_handles_both_parities(self):
        self.assertEqual(ss._median([3.0]), 3.0)
        self.assertEqual(ss._median([3.0, 1.0]), 2.0)
        self.assertEqual(ss._median([5.0, 1.0, 3.0]), 3.0)


class TestPrintedTables(unittest.TestCase):

    def _agent_table(self, **over):
        rows = ss.summarize_agent(_a_file(_agent_cfg(**over)))
        _, out = _capture(ss.print_agent_table, rows)
        return out

    def test_a_failed_structure_check_is_reported_with_its_reason(self):
        out = self._agent_table(structure={
            "ok": False, "edges": 0, "errors": ["graph has 0 edges, want 8"]})
        self.assertIn("structure check FAILED", out)
        self.assertIn("graph has 0 edges, want 8", out)

    def test_a_structure_check_that_never_ran_is_not_called_a_failure(self):
        """--phases throughput leaves structure_ok None. Claiming FAILED sends
        the reader after a bug that does not exist."""
        out = self._agent_table(structure=None)
        self.assertNotIn("FAILED", out)
        self.assertIn("NO structure check", out)

    def test_a_passing_structure_check_is_silent(self):
        self.assertNotIn("[warn]", self._agent_table())

    def test_a_preserved_branch_is_silent(self):
        self.assertNotIn("branch NOT preserved", self._agent_table())

    def test_an_inapplicable_branch_check_is_silent(self):
        """None with an 'n/a: ...' reason is not a failure -- contended couples
        every agent by construction, and one agent has no unrelated branch."""
        out = self._agent_table(
            branch_preservation_ok=None,
            branch_errors=["n/a: one agent has no unrelated branch"])
        self.assertNotIn("branch NOT preserved", out)
        self.assertNotIn("[warn]", out)

    def test_a_broken_branch_is_reported_with_its_reason(self):
        out = self._agent_table(
            branch_preservation_ok=False,
            branch_errors=["victim commit after unrelated rollback: conflict"])
        self.assertIn("branch NOT preserved", out)
        self.assertIn("victim commit after unrelated rollback", out)

    def test_agent_rows_and_rules_agree_on_the_width(self):
        """The columns add up to more than the round number the rules used to
        be drawn at, which leaves the last few columns hanging off the box."""
        rows = ss.summarize_agent(_a_file(
            _agent_cfg("partially_shared", agents=32, tp=104.0)))
        _, out = _capture(ss.print_agent_table, rows)
        lines = out.split("\n")
        rule = next(l for l in lines if l and set(l) == {"─"})
        note = next(i for i, l in enumerate(lines)
                    if l.startswith("  (latencies in ms"))
        body = [l for l in lines[lines.index(rule) + 1:note] if l.strip()]
        self.assertEqual(len(body), 1)
        self.assertEqual(len(body[0]), len(rule))

    def test_graph_rows_and_rules_agree_on_the_width(self):
        """'rollback-cascade' is 16 characters: a 14-wide decision column ran it
        into the operation beside it, producing '64allow' -- the two columns
        that say what a row measured, merged."""
        dims = [_dim(dimension="D3", topology="chain", nodes=64, size=64,
                     decision="rollback-cascade", op="cascade-rollback"),
                _dim(dimension="D5", topology="diamond", nodes=10, size=8,
                     decision="middle-deny", op="cascade-rollback")]
        _, out = _capture(ss.print_graph_table, ss.summarize_graph(_b_file(*dims)))
        lines = out.split("\n")
        rule = next(l for l in lines if l and set(l) == {"─"})
        note = next(i for i, l in enumerate(lines) if l.startswith("  (op ="))
        body = [l for l in lines[lines.index(rule) + 1:note] if l.strip()]
        self.assertEqual(len(body), len(dims))
        for line in body:
            self.assertEqual(len(line), len(rule), f"misaligned: {line!r}")
        self.assertNotIn("64allow", out)

    def test_an_unverified_topology_is_called_out(self):
        _, out = _capture(ss.print_graph_table,
                          ss.summarize_graph(_b_file(_dim(topo_verified=False))))
        self.assertIn("did NOT verify", out)

    def test_a_recorded_error_is_called_out_with_its_first_reason(self):
        _, out = _capture(ss.print_graph_table, ss.summarize_graph(_b_file(
            _dim(errors=["SCC detected with max_scc_size=4, expected 8"],
                 error_count=1))))
        self.assertIn("max_scc_size=4, expected 8", out)

    def test_a_clean_run_prints_no_graph_warnings(self):
        _, out = _capture(ss.print_graph_table,
                          ss.summarize_graph(_b_file(_dim())))
        self.assertNotIn("[warn]", out)

    def test_print_curves_lists_the_three_reviewer_facing_metrics(self):
        curves = ss.build_curves(ss.summarize_graph(_b_file(_dim(op="commit"))))
        _, out = _capture(ss.print_curves, curves)
        self.assertIn(ss.M_FINALIZATION, out)
        self.assertIn(ss.M_HEAP, out)

    def test_print_curves_says_so_when_a_metric_has_no_data(self):
        _, out = _capture(ss.print_curves, [])
        self.assertIn("no data", out)


# ═══════════════════════════════════════════════════════════════════════════
# Output writers
# ═══════════════════════════════════════════════════════════════════════════

class TestCsvWriter(unittest.TestCase):

    def test_a_generator_is_counted_correctly(self):
        """The bug: len() was taken AFTER the for loop had drained it, so a
        generator reported '(0 rows)' for a file that was written correctly."""
        rows = [{"a": i, "b": None} for i in range(5)]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.csv")
            _, out = _capture(ss.write_csv, path, ("a", "b"), iter(rows))
            self.assertIn("(5 rows)", out)
            with open(path) as fh:
                body = fh.read().strip().split("\n")
        self.assertEqual(len(body), 6)  # header + 5

    def test_a_list_is_counted_correctly_too(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.csv")
            _, out = _capture(ss.write_csv, path, ("a",), [{"a": 1}, {"a": 2}])
            self.assertIn("(2 rows)", out)

    def test_none_becomes_an_empty_cell_not_the_word_none(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.csv")
            _capture(ss.write_csv, path, ("a", "b"), [{"a": None, "b": 1.5}])
            import csv as _csv
            with open(path, newline="") as fh:
                row = next(_csv.DictReader(fh))
        self.assertEqual(row["a"], "")
        self.assertEqual(row["b"], "1.5")

    def test_extra_keys_in_a_row_are_ignored(self):
        """extrasaction='ignore': the flattening carries more than any one
        table shows, and a writer that raised on that would be unusable."""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.csv")
            ok, _ = _capture(ss.write_csv, path, ("a",),
                             [{"a": 1, "surplus": 2}])
            self.assertTrue(ok)
            with open(path) as fh:
                self.assertNotIn("surplus", fh.read())

    def test_an_empty_row_set_still_writes_a_header(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.csv")
            _, out = _capture(ss.write_csv, path, ("a", "b"), [])
            self.assertIn("(0 rows)", out)
            with open(path) as fh:
                self.assertEqual(fh.read().strip(), "a,b")

    def test_an_unwritable_path_returns_false_instead_of_raising(self):
        """results/ is often root-owned after a sudo run; the summarizer must
        keep printing the tables it already printed."""
        ok, out = _capture(ss.write_csv, "/nonexistent-dir/x.csv", ("a",),
                           [{"a": 1}])
        self.assertFalse(ok)
        self.assertIn("--output-dir", out)


class TestLatexWriter(unittest.TestCase):

    COLS = (("workload", "Workload"), ("nodes", "Nodes"),
            ("latency", "p50 (ms)"), ("verified", "Verified"))
    SPECS = (("workload", "s"), ("nodes", "d"),
             ("latency", ".3f"), ("verified", "s"))

    def _write(self, rows, cols=None, specs=None, label="t"):
        # TemporaryDirectory, not mkdtemp: twelve tests each writing a .tex
        # would otherwise leave twelve directories behind in a suite that is
        # meant to be run repeatedly.
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.tex")
            ok, _ = _capture(ss.write_latex, path, "cap", label,
                             cols if cols is not None else self.COLS,
                             rows,
                             specs if specs is not None else self.SPECS)
            with open(path) as fh:
                text = fh.read()
        return ok, text

    def test_mismatched_columns_and_specs_raise_here_not_in_latex(self):
        """A mismatch surfaces as an 'extra alignment tab' error three
        compilations later if it is not caught at write time."""
        with self.assertRaises(ValueError) as cm:
            self._write([], specs=(("workload", "s"), ("nodes", "d")))
        self.assertIn("disagree", str(cm.exception))

    def test_the_same_columns_in_a_different_order_also_raise(self):
        with self.assertRaises(ValueError):
            self._write([], specs=tuple(reversed(self.SPECS)))

    def test_text_columns_are_left_aligned_and_numbers_right(self):
        _, text = self._write([])
        self.assertIn(r"\begin{tabular}{lrrl}", text)

    def test_a_string_cell_is_not_passed_through_a_numeric_spec(self):
        """The bug: ValueError: Unknown format code 'f' for object of type
        'str' -- raised on the first row of the first table."""
        _, text = self._write([{"workload": "contended", "nodes": 4,
                                "latency": 1.5, "verified": True}])
        self.assertIn("contended", text)

    def test_a_bool_cell_is_a_word_not_a_one_or_zero(self):
        """bool reaches write_latex' numeric branch (it is an int subclass) and
        comes out as yes/no only because fmt intercepts it first. Without that,
        a Verified column of 1/0 reads as a measurement in a table full of
        measurements."""
        _, text = self._write([{"workload": "w", "nodes": 1, "latency": 1.0,
                                "verified": True},
                               {"workload": "w", "nodes": 1, "latency": 1.0,
                                "verified": False}])
        self.assertIn("yes", text)
        self.assertIn("no", text)
        body = [l for l in text.split("\n") if l.startswith("    w &")]
        self.assertEqual(len(body), 2)
        for line in body:
            self.assertNotIn("True", line)
            self.assertNotIn("False", line)
            self.assertNotIn(" & 1 \\\\", line)
            self.assertNotIn(" & 0 \\\\", line)

    def test_a_missing_cell_is_a_dash(self):
        _, text = self._write([{"workload": "w", "nodes": 1,
                                "latency": None, "verified": None}])
        self.assertIn("-", text)

    def test_numbers_use_their_own_spec(self):
        _, text = self._write([{"workload": "w", "nodes": 64,
                                "latency": 1.23456, "verified": True}])
        self.assertIn("1.235", text)
        self.assertIn("64", text)

    def test_underscores_and_percent_signs_are_escaped(self):
        _, text = self._write([{"workload": "partially_shared", "nodes": 1,
                                "latency": 50.0, "verified": True}])
        self.assertIn(r"partially\_shared", text)
        self.assertNotIn("partially_shared &", text)

    def test_the_booktabs_skeleton_is_complete(self):
        _, text = self._write([{"workload": "w", "nodes": 1, "latency": 1.0,
                                "verified": True}])
        for token in (r"\begin{table}[t]", r"\centering", r"\caption{cap}",
                      r"\label{tab:t}", r"\toprule", r"\midrule",
                      r"\bottomrule", r"\end{tabular}", r"\end{table}"):
            self.assertIn(token, text)

    def test_one_output_line_per_row(self):
        rows = [{"workload": f"w{i}", "nodes": i, "latency": float(i),
                 "verified": True} for i in range(4)]
        _, text = self._write(rows)
        body = [l for l in text.split("\n")
                if l.strip().endswith(r"\\") and "&" in l]
        # 4 data rows plus the header line
        self.assertEqual(len(body), 5)

    def test_a_caption_with_a_percent_sign_is_written_verbatim(self):
        """The caption is not escaped: the caller writes LaTeX in it on purpose
        (Eff.\\ \\%, $\\to$), and escaping would double every backslash."""
        _, text = self._write([], cols=self.COLS, specs=self.SPECS)
        self.assertIn(r"\caption{cap}", text)

    def test_an_unwritable_path_returns_false(self):
        ok, out = _capture(ss.write_latex, "/nonexistent-dir/t.tex", "c", "l",
                           self.COLS, [], self.SPECS)
        self.assertFalse(ok)
        self.assertIn("[fail]", out)


# ═══════════════════════════════════════════════════════════════════════════
# main()
# ═══════════════════════════════════════════════════════════════════════════

class TestMain(unittest.TestCase):

    def _run(self, results_dir, output_dir=None, *extra):
        argv = ["summarize_scaling.py", "--results-dir", results_dir,
                "--output-dir", output_dir or results_dir, *extra]
        with patch.object(sys, "argv", argv):
            return _capture(ss.main)

    def test_nothing_to_summarize_exits_nonzero_and_says_how_to_run_it(self):
        """A summarizer that exits 0 on an empty directory gets wired into a
        pipeline and silently produces no tables."""
        with tempfile.TemporaryDirectory() as d:
            rc, out = self._run(d)
        self.assertEqual(rc, 1)
        self.assertIn("start_and_run.sh scaling", out)

    def test_experiment_a_alone_produces_its_csv(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, ss.A_FILE), "w") as fh:
                json.dump(_a_file(_agent_cfg(agents=1, tp=100.0),
                                  _agent_cfg(agents=8, tp=700.0)), fh)
            rc, out = self._run(d, None)
            self.assertEqual(rc, 0, out)
            self.assertTrue(os.path.exists(os.path.join(d, "scaling_agent.csv")))
            self.assertFalse(os.path.exists(os.path.join(d, "scaling_graph.csv")))
            self.assertIn("EXPERIMENT A", out)
            self.assertNotIn("EXPERIMENT B", out)

    def test_experiment_b_alone_produces_both_of_its_csvs(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, ss.B_FILE), "w") as fh:
                json.dump(_b_file(
                    _dim(op="commit", nodes=8, size=8),
                    _dim(op="cascade-rollback", decision="rollback-cascade",
                         nodes=32, size=32,
                         stats_extra={"rollback_ns": _ns_block(9.0e6)})), fh)
            rc, out = self._run(d, None)
            self.assertEqual(rc, 0, out)
            self.assertTrue(os.path.exists(os.path.join(d, "scaling_graph.csv")))
            curves_csv = os.path.join(d, "scaling_curves.csv")
            self.assertTrue(os.path.exists(curves_csv))
            with open(curves_csv) as fh:
                body = fh.read()
            self.assertIn(ss.M_FINALIZATION, body)
            self.assertIn(ss.M_ROLLBACK, body)

    def test_the_curves_csv_header_is_the_declared_one(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, ss.B_FILE), "w") as fh:
                json.dump(_b_file(_dim(op="commit", nodes=8, size=8)), fh)
            self._run(d, None)
            with open(os.path.join(d, "scaling_curves.csv")) as fh:
                header = fh.readline().strip()
        self.assertEqual(header, ",".join(ss.CURVE_COLUMNS))

    def test_a_corrupt_results_file_is_skipped_not_fatal(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, ss.A_FILE), "w") as fh:
                fh.write("{not json")
            rc, out = self._run(d, None)
        self.assertEqual(rc, 1)
        self.assertIn("JSONDecodeError", out)

    def test_latex_flag_writes_the_tables(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, ss.A_FILE), "w") as fh:
                json.dump(_a_file(_agent_cfg()), fh)
            with open(os.path.join(d, ss.B_FILE), "w") as fh:
                json.dump(_b_file(_dim(op="commit", nodes=8, size=8)), fh)
            rc, out = self._run(d, None, "--latex")
            self.assertEqual(rc, 0, out)
            self.assertTrue(os.path.exists(os.path.join(d, "scaling_agent.tex")))
            self.assertTrue(os.path.exists(os.path.join(d, "scaling_graph.tex")))

    def test_output_dir_can_differ_from_results_dir(self):
        """The escape hatch for a root-owned results/ directory."""
        with tempfile.TemporaryDirectory() as rd, \
                tempfile.TemporaryDirectory() as od:
            with open(os.path.join(rd, ss.A_FILE), "w") as fh:
                json.dump(_a_file(_agent_cfg()), fh)
            rc, _ = self._run(rd, od)
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(os.path.join(od, "scaling_agent.csv")))
            self.assertFalse(os.path.exists(os.path.join(rd, "scaling_agent.csv")))

    def test_load_json_reports_a_missing_file_without_raising(self):
        _, out = _capture(ss.load_json, "/nonexistent-dir/nope.json")
        self.assertIn("[skip]", out)

    def test_a_summary_of_no_data_at_all_is_still_not_a_crash(self):
        """An empty configurations list means the run died before its first
        repeat; the tables must print empty rather than raise."""
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, ss.A_FILE), "w") as fh:
                json.dump({"configurations": []}, fh)
            with open(os.path.join(d, ss.B_FILE), "w") as fh:
                json.dump({"dimensions": []}, fh)
            rc, out = self._run(d, None, "--latex")
        self.assertEqual(rc, 0, out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
