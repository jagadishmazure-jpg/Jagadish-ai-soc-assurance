"""Benchmark metrics, the baseline comparison, model-risk validation, drift and the challenger."""

from socassure import benchmark, modelrisk


def test_every_metric_has_an_interval_for_the_sut():
    card = benchmark.scorecard(["azure-ai-soc"])
    assert card["units"] == 30
    for m, e in card["estimates"]["azure-ai-soc"].items():
        assert e.value is not None, m
        assert e.lo <= e.value <= e.hi, m


def test_sut_never_auto_closes_a_synthetic_attack_and_beats_always_escalate_on_minutes():
    card = benchmark.scorecard(["azure-ai-soc", "always-escalate", "severity-rules"])
    assert card["counts"]["azure-ai-soc"]["auto_closed_attacks"] == 0
    assert card["counts"]["severity-rules"]["auto_closed_attacks"] > 0
    d = benchmark.diff(card, "azure-ai-soc", "always-escalate", "analyst_minutes")
    assert d.hi < 0


def test_baselines_have_no_calibration_or_model_cost():
    card = benchmark.scorecard(["always-escalate"])
    assert card["estimates"]["always-escalate"]["ece"].value is None
    assert card["estimates"]["always-escalate"]["cost_per_1k_alerts"].value == 0


def test_inventory_covers_three_agents_with_framework_references():
    inv = modelrisk.inventory()
    assert set(inv["agents"]) == {"triage", "investigation", "response"}
    for a in inv["agents"].values():
        assert a["criteria"] and a["risk_tier"] and a["decision_rights"]


def test_validation_judges_on_the_conservative_bound():
    rows = modelrisk.validate("triage")
    otrf = next(c for c in rows if c.metric == "detection_recall" and c.suite == "otrf")
    assert not otrf.passed and otrf.bound_used == otrf.estimate.lo
    assert all(c.passed for c in rows if c.suite == "synthetic")


def test_investigation_and_response_criteria_pass():
    for agent in ("investigation", "response"):
        assert all(c.passed for c in modelrisk.validate(agent)), agent


def test_drift_monitor_separates_new_seeds_from_a_shift():
    d = modelrisk.drift_report()
    assert d["comparison"]["status"] == "stable" and d["drifted"]["status"] == "drift"


def test_challenger_shows_what_the_feedback_loop_buys():
    c = modelrisk.challenger()
    row = next(r for r in c["rows"] if r["metric"].startswith("analyst min"))
    assert row["diff"].hi < 0


def test_claim_check_helper():
    r = benchmark.claim_check(2, 9, 87)
    assert not r["claim_inside"] and r["hi"] < 87
