"""Statistics: intervals, bootstrap determinism, calibration and drift indices."""

import math

import pytest

from socassure import stats


def test_wilson_matches_the_textbook_value():
    lo, hi = stats.wilson(87, 100)
    assert lo == pytest.approx(0.7902, abs=1e-3) and hi == pytest.approx(0.9224, abs=1e-3)


def test_wilson_handles_zero_and_all():
    assert stats.wilson(0, 10)[0] == 0.0
    assert stats.wilson(10, 10)[1] == pytest.approx(1.0)
    assert stats.wilson(0, 0) == (0.0, 1.0)


def test_sample_size_grows_as_margin_shrinks():
    assert stats.sample_size_for(0.05) == 385
    assert stats.sample_size_for(0.02, 0.87) > stats.sample_size_for(0.05, 0.87)


def test_bootstrap_is_deterministic_and_brackets_the_point():
    units = [(k, 10) for k in (8, 9, 10, 7, 9, 10, 8, 9)]
    stat = lambda us: (100 * sum(u[0] for u in us) / sum(u[1] for u in us), len(us))  # noqa: E731
    draws = stats.resample_indices(len(units), 500, 7)
    a = stats.bootstrap(units, stat, draws, 0.95)
    b = stats.bootstrap(units, stat, stats.resample_indices(len(units), 500, 7), 0.95)
    assert a == b
    assert a.lo <= a.value <= a.hi


def test_paired_difference_of_identical_systems_is_zero():
    units = [(k, 10) for k in (8, 9, 10, 7)]
    stat = lambda us: (sum(u[0] for u in us) / len(us), len(us))  # noqa: E731
    d = stats.bootstrap_diff(units, units, stat, stats.resample_indices(4, 200, 1), 0.95)
    assert d.value == 0 and d.lo == 0 and d.hi == 0


def test_psi_is_zero_for_the_same_distribution_and_large_for_a_shift():
    edges = [i / 10 for i in range(11)]
    ref = [0.05, 0.15, 0.25, 0.95] * 25
    assert stats.psi(ref, ref, edges) == pytest.approx(0.0)
    assert stats.psi(ref, [0.55] * 100, edges) > 0.25


def test_ece_is_zero_when_probabilities_match_outcomes():
    probs = [0.0] * 10 + [1.0] * 10
    outs = [False] * 10 + [True] * 10
    assert stats.ece(stats.calibration_bins(probs, outs, 10)) == pytest.approx(0.0)


def test_estimate_formatting():
    assert stats.Estimate(12.345, 10.0, 14.0, 5).fmt(1) == "12.3 [10.0, 14.0]"
    assert stats.Estimate(None, None, None, 0).fmt() == "n/a"
    assert not math.isnan(stats.percentile([1, 2, 3], 0.5))
