#!/usr/bin/env python3
"""Unit tests for framework.stats.

Every latency number in the RQ3 results goes through compute_stats, so a
regression here does not crash anything -- it quietly moves a published
percentile or confidence interval. These tests therefore pin the things that
must not drift:

  percentile        the interpolation rule and its edge cases.
  compute_stats     the exact summaries (n/min/max/mean) and the unit
                    conversions in to_dict, which the summarizer divides by
                    again; a wrong suffix would show up as a 1e6 error in a
                    table and nothing else.
  _bootstrap_resamples
                    the cost policy. The scaling experiments grow their sample
                    lists along the swept axis (32 agents x 20 invocations x 3
                    repeats = 1920 for one series), and the bootstrap work is
                    resamples x samples, so an uncapped resample count makes
                    reporting slower than the measurement. Two rules are pinned:
                    the cap bounds the work, and it never RAISES a request that
                    was already cheaper than the floor -- otherwise n_bootstrap
                    stops being a knob a quick mode can turn. The policy is
                    asserted as a WORK bound rather than as a wall-clock bound: a
                    timing assertion would be flaky on a loaded host and would
                    say nothing about why it passed.

Deliberately NOT pinned: the numeric endpoints of a confidence interval. They
are Monte Carlo estimates whose value depends on the resampling primitive, so
asserting them would make the test fail on any speedup that changes the random
stream -- exactly the change it should permit. What is asserted instead is that
the interval is deterministic for a fixed seed, brackets the sample median, and
narrows as the sample grows.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework import stats as S
from framework.stats import (StatsResult, bootstrap_ci, compute_stats,
                             percentile, _bootstrap_resamples)


class TestPercentile(unittest.TestCase):
    def test_empty_is_zero(self):
        self.assertEqual(percentile([], 50), 0.0)

    def test_single_element_at_any_p(self):
        for p in (0, 50, 95, 100):
            self.assertEqual(percentile([7.0], p), 7.0)

    def test_median_of_odd_count_is_the_middle(self):
        self.assertEqual(percentile([1.0, 2.0, 3.0, 4.0, 5.0], 50), 3.0)

    def test_median_of_even_count_interpolates(self):
        # rank = 0.5 * 3 = 1.5 -> halfway between the 2nd and 3rd values
        self.assertAlmostEqual(percentile([1.0, 2.0, 3.0, 4.0], 50), 2.5)

    def test_endpoints_are_the_extremes(self):
        data = [1.0, 2.0, 3.0, 4.0, 5.0]
        self.assertEqual(percentile(data, 0), 1.0)
        self.assertEqual(percentile(data, 100), 5.0)

    def test_p95_interpolates_rather_than_truncating(self):
        data = [float(i) for i in range(1, 101)]   # 1..100
        # rank = 0.95 * 99 = 94.05 -> between 95 and 96
        self.assertAlmostEqual(percentile(data, 95), 95.05)

    def test_is_monotonic_in_p(self):
        data = [float(i) for i in range(1, 51)]
        vals = [percentile(data, p) for p in (0, 25, 50, 75, 95, 100)]
        self.assertEqual(vals, sorted(vals))

    def test_does_not_sort_its_input(self):
        """Documented contract: the caller passes sorted data.

        Pinned because compute_stats sorts once and then asks for four
        percentiles; if percentile started sorting internally the cost would be
        paid four times per series with no visible symptom.
        """
        data = [3.0, 1.0, 2.0]
        percentile(data, 50)
        self.assertEqual(data, [3.0, 1.0, 2.0])


class TestBootstrapResamplePolicy(unittest.TestCase):
    def test_small_series_get_the_full_requested_count(self):
        """The published RQ3 results top out at n=1000; they must be untouched."""
        for n in (1, 10, 100, 1000):
            self.assertEqual(_bootstrap_resamples(n, 10000), 10000,
                             f"n={n} should draw the requested count")

    def test_large_series_are_capped_by_the_work_budget(self):
        n = 1920
        draws = _bootstrap_resamples(n, 10000)
        self.assertLess(draws, 10000)
        self.assertLessEqual(draws * n, S.BOOTSTRAP_WORK_BUDGET)

    def test_work_stays_within_budget_across_the_scaling_axis(self):
        """The whole point of the cap: work must not grow with the swept axis.

        Sample counts here are the real ones the two experiments produce --
        experiment A's per-invocation series is agents x invocations x repeats,
        experiment B's per-node series is nodes x repeats.
        """
        for n in (32, 64, 128, 256, 512, 1024, 1920, 3840, 6400, 20480):
            draws = _bootstrap_resamples(n, 10000)
            work = draws * n
            bound = max(S.BOOTSTRAP_WORK_BUDGET, S.MIN_BOOTSTRAP * n)
            self.assertLessEqual(work, bound, f"n={n}: {draws}x{n}={work}")

    def test_the_floor_stops_the_cap_collapsing_to_nothing(self):
        huge = 10_000_000
        self.assertEqual(_bootstrap_resamples(huge, 10000), S.MIN_BOOTSTRAP)

    def test_a_smaller_request_is_respected(self):
        """The cap only ever lowers the count; it never raises a cheap ask.

        Without this, MIN_BOOTSTRAP would overrule an explicit request and turn
        n_bootstrap into a knob that does nothing below 1000 -- which is exactly
        what a quick mode or a smoke test wants to set.
        """
        self.assertEqual(_bootstrap_resamples(10, 500), 500)
        self.assertEqual(_bootstrap_resamples(10, 1), 1)
        self.assertEqual(_bootstrap_resamples(10, S.MIN_BOOTSTRAP),
                         S.MIN_BOOTSTRAP)
        # Even on a series the budget would reduce to a single resample.
        self.assertEqual(_bootstrap_resamples(10_000_000, 500), 500)

    def test_a_request_just_above_the_floor_is_still_capped(self):
        """The floor applies to the cap, so a huge series cannot be talked into
        an expensive bootstrap by asking for slightly more than MIN_BOOTSTRAP."""
        self.assertEqual(_bootstrap_resamples(10_000_000, S.MIN_BOOTSTRAP + 1),
                         S.MIN_BOOTSTRAP)

    def test_a_non_positive_request_draws_nothing(self):
        self.assertEqual(_bootstrap_resamples(10, 0), 0)
        self.assertEqual(_bootstrap_resamples(10, -5), 0)

    def test_zero_resamples_yields_a_zero_width_interval(self):
        """Pinned because it is the documented degenerate case: a caller that
        switches the bootstrap off gets the same (0.0, 0.0) the empty-data path
        returns, not a crash and not a silently full-price interval."""
        data = [float(i) for i in range(200)]
        self.assertEqual(bootstrap_ci(data, n_bootstrap=0), (0.0, 0.0))

    def test_zero_length_does_not_divide_by_zero(self):
        self.assertEqual(_bootstrap_resamples(0, 10000), 10000)


class TestBootstrapCI(unittest.TestCase):
    def test_empty_is_zero_width(self):
        self.assertEqual(bootstrap_ci([]), (0.0, 0.0))

    def test_one_and_two_samples_return_the_median(self):
        self.assertEqual(bootstrap_ci([5.0]), (5.0, 5.0))
        lo, hi = bootstrap_ci([4.0, 6.0])
        self.assertEqual(lo, hi)
        self.assertEqual(lo, 6.0)      # sorted[2 // 2] == sorted[1]

    def test_is_deterministic_for_a_fixed_seed(self):
        data = [float(i) for i in range(200)]
        self.assertEqual(bootstrap_ci(data, seed=42),
                         bootstrap_ci(data, seed=42))

    def test_a_different_seed_moves_the_interval(self):
        """Guards the determinism claim: same seed is reproducible, and the
        interval really is a random estimate rather than a formula."""
        data = [float(i) for i in range(200)]
        self.assertNotEqual(bootstrap_ci(data, seed=1),
                            bootstrap_ci(data, seed=2))

    def test_interval_brackets_the_sample_median(self):
        data = [float(i) for i in range(500)]
        med = percentile(sorted(data), 50)
        lo, hi = bootstrap_ci(data)
        self.assertLessEqual(lo, med)
        self.assertLessEqual(med, hi)

    def test_interval_has_positive_width_for_dispersed_data(self):
        data = [1.0, 2.0, 3.0, 100.0, 200.0, 300.0, 7.0, 9.0] * 10
        lo, hi = bootstrap_ci(data)
        self.assertLess(lo, hi)

    def test_interval_collapses_for_constant_data(self):
        data = [42.0] * 300
        lo, hi = bootstrap_ci(data)
        self.assertEqual((lo, hi), (42.0, 42.0))

    def test_interval_narrows_as_the_sample_grows(self):
        """The statistical property the cost policy relies on: for the same
        underlying spread, more samples means a tighter interval. If this ever
        stops holding, reducing the resample count for large n is no longer
        justified by the density argument in stats.py."""
        base = [float(i % 97) for i in range(64)]
        small = base * 4                      # n = 256
        large = base * 32                     # n = 2048
        lo_s, hi_s = bootstrap_ci(small)
        lo_l, hi_l = bootstrap_ci(large)
        self.assertLess(hi_l - lo_l, hi_s - lo_s)

    def test_higher_confidence_gives_a_wider_interval(self):
        data = [float(i % 53) for i in range(600)]
        lo90, hi90 = bootstrap_ci(data, confidence=0.90)
        lo99, hi99 = bootstrap_ci(data, confidence=0.99)
        self.assertLessEqual(lo99, lo90)
        self.assertGreaterEqual(hi99, hi90)

    def test_does_not_mutate_its_input(self):
        """compute_stats passes the sorted series it goes on to report min/max
        from, so a resample that sorted in place would be harmless there -- but
        bootstrap_ci is public, and an unsorted caller would get its list
        silently reordered."""
        data = [5.0, 1.0, 3.0, 2.0, 4.0] * 20
        before = list(data)
        bootstrap_ci(data)
        self.assertEqual(data, before)

    def test_fewer_resamples_still_brackets_the_median(self):
        data = [float(i) for i in range(300)]
        med = percentile(sorted(data), 50)
        lo, hi = bootstrap_ci(data, n_bootstrap=50)
        self.assertLessEqual(lo, med)
        self.assertLessEqual(med, hi)


class TestComputeStats(unittest.TestCase):
    def test_empty_returns_a_zeroed_result(self):
        r = compute_stats("nothing", [])
        self.assertEqual(r.n, 0)
        self.assertEqual(r.median_ns, 0.0)
        self.assertEqual(r.p95_ns, 0.0)
        self.assertEqual((r.ci_95_low_ns, r.ci_95_high_ns), (0.0, 0.0))

    def test_exact_summaries(self):
        data = [10.0, 20.0, 30.0, 40.0, 50.0]
        r = compute_stats("m", data)
        self.assertEqual(r.n, 5)
        self.assertEqual(r.min_ns, 10.0)
        self.assertEqual(r.max_ns, 50.0)
        self.assertEqual(r.mean_ns, 30.0)
        self.assertEqual(r.median_ns, 30.0)

    def test_excluded_is_carried_through(self):
        r = compute_stats("m", [1.0, 2.0, 3.0], excluded=7)
        self.assertEqual(r.excluded, 7)
        self.assertEqual(r.n, 3)

    def test_percentile_ordering(self):
        data = [float(i) for i in range(1, 201)]
        r = compute_stats("m", data)
        self.assertLessEqual(r.median_ns, r.p95_ns)
        self.assertLessEqual(r.p95_ns, r.p99_ns)
        self.assertLessEqual(r.p99_ns, r.max_ns)

    def test_sorts_unsorted_input(self):
        """Callers append samples in completion order, which under concurrency
        is not value order."""
        ordered = compute_stats("m", [1.0, 2.0, 3.0, 4.0, 5.0])
        shuffled = compute_stats("m", [3.0, 1.0, 5.0, 2.0, 4.0])
        self.assertEqual(ordered.median_ns, shuffled.median_ns)
        self.assertEqual(ordered.min_ns, shuffled.min_ns)
        self.assertEqual(ordered.max_ns, shuffled.max_ns)

    def test_name_is_preserved(self):
        self.assertEqual(compute_stats("commit_ns", [1.0]).name, "commit_ns")


class TestStatsResultSerialization(unittest.TestCase):
    """The summarizer reads these keys back, so the ns/ms relationship is
    load-bearing rather than cosmetic.

    The fixtures use millisecond-scale nanosecond values because that is what
    the experiments actually record; to_dict rounds the *_ms fields to four
    decimals, which is 100 ns of resolution and ample at that scale.
    """

    def setUp(self):
        # 1 ms .. 1000 ms
        self.r = compute_stats("run_ns", [float(i) * 1e6
                                          for i in range(1, 1001)])
        self.d = self.r.to_dict()

    def test_to_dict_has_every_key_the_summarizer_reads(self):
        for key in ("name", "n", "excluded", "median_ns", "p95_ns", "p99_ns",
                    "mean_ns", "min_ns", "max_ns", "ci_95_low_ns",
                    "ci_95_high_ns", "median_ms", "p95_ms", "p99_ms",
                    "ci_95_ms"):
            self.assertIn(key, self.d)

    def test_ms_fields_are_the_ns_fields_divided_by_a_million(self):
        self.assertAlmostEqual(self.d["median_ms"], self.d["median_ns"] / 1e6,
                               places=4)
        self.assertAlmostEqual(self.d["p95_ms"], self.d["p95_ns"] / 1e6,
                               places=4)
        self.assertAlmostEqual(self.d["p99_ms"], self.d["p99_ns"] / 1e6,
                               places=4)

    def test_ms_fields_are_rounded_to_four_decimals(self):
        """The precision the serialization actually offers.

        Pinned because it is the reason summarize_scaling.py divides the *_ns
        fields itself instead of reading *_ms: four decimals of a millisecond is
        100 ns, so a sub-microsecond phase would be reported as 0.0. Latency
        series here are milliseconds wide and unaffected.
        """
        for key in ("median_ms", "p95_ms", "p99_ms"):
            self.assertEqual(self.d[key], round(self.d[key], 4))
        sub = compute_stats("fast", [500.0, 600.0, 700.0]).to_dict()
        self.assertEqual(sub["median_ns"], 600.0)
        self.assertEqual(sub["median_ms"], 0.0006)
        # ...and 40 ns of it is simply gone at this precision.
        lossy = compute_stats("fast", [500.0, 540.0, 700.0]).to_dict()
        self.assertEqual(lossy["median_ms"], round(540.0 / 1e6, 4))

    def test_ci_ms_pair_matches_the_ns_fields(self):
        lo, hi = self.d["ci_95_ms"]
        self.assertAlmostEqual(lo, self.d["ci_95_low_ns"] / 1e6, places=4)
        self.assertAlmostEqual(hi, self.d["ci_95_high_ns"] / 1e6, places=4)
        self.assertLessEqual(lo, hi)

    def test_us_property(self):
        self.assertAlmostEqual(self.r.median_us, self.r.median_ns / 1000.0)

    def test_n_matches_the_sample_count(self):
        self.assertEqual(self.d["n"], 1000)

    def test_summary_line_carries_the_headline_numbers(self):
        line = self.r.summary_line()
        self.assertIn("run_ns", line)
        self.assertIn("median=", line)
        self.assertIn("P95=", line)
        self.assertIn("P99=", line)
        self.assertIn("CI95=", line)
        self.assertIn("n=1000", line)

    def test_defaults_make_an_unmeasured_phase_visible_as_zero(self):
        d = StatsResult(name="unused").to_dict()
        self.assertEqual(d["n"], 0)
        self.assertEqual(d["median_ns"], 0.0)


class TestCostOfTheScalingAxis(unittest.TestCase):
    """A real regression guard for the failure that motivated the cost policy.

    The largest series experiment A produces is 32 agents x 20 invocations x 3
    repeats = 1920 samples, and it builds about five such series per
    configuration. Before the cap and the C-level resampling primitive, one
    1920-sample series took ~7.6 s, so reporting alone cost minutes per
    configuration on top of an hour-long run.
    """

    def test_a_full_size_series_costs_bounded_work(self):
        n = 32 * 20 * 3
        draws = _bootstrap_resamples(n, 10000)
        self.assertLessEqual(draws * n, S.BOOTSTRAP_WORK_BUDGET)

    def test_reporting_a_whole_configuration_is_bounded(self):
        """All of experiment A's largest configuration, as one bound.

        Counted in resampled elements rather than seconds so the assertion is
        exact and host-independent.
        """
        series = {
            "session_open_ns": 32 * 3,
            "epoch_begin_ns": 32 * 20 * 3,
            "run_ns": 32 * 20 * 3,
            "commit_ns": 32 * 20 * 3,
            "invocation_ns": 32 * 20 * 3,
            "rollback_ns": 32 * 5 * 3,
            "finalization_wait_ns": 32 * 20 * 3,
        }
        total = sum(_bootstrap_resamples(n, 10000) * n
                    for n in series.values())
        uncapped = 10000 * sum(series.values())
        # Each series is bounded by the budget, so the configuration is bounded
        # by series_count x budget. Stated as a bound rather than as a speedup
        # ratio: five of these seven series sit at 1920 samples and are trimmed
        # to 5208 resamples, the two short ones keep the full 10000, and the
        # honest total saving is therefore ~1.8x -- not the ~6x that a single
        # large series shows on its own.
        self.assertLessEqual(total, len(series) * S.BOOTSTRAP_WORK_BUDGET)
        self.assertLess(total, uncapped)

    def test_compute_stats_on_a_full_size_series_completes(self):
        """End-to-end smoke check that the policy is actually wired in."""
        data = [1000.0 + (i % 137) for i in range(32 * 20 * 3)]
        r = compute_stats("run_ns", data, n_bootstrap=200)
        self.assertEqual(r.n, 1920)
        self.assertLess(r.ci_95_low_ns, r.ci_95_high_ns)


if __name__ == "__main__":
    unittest.main()
