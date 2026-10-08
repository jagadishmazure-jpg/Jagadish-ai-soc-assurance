"""Model risk for SOC agents: validation against acceptance criteria, drift monitoring and a challenger.

* `validate(agent)` evaluates the criteria in config/model-risk.yaml on benchmark runs and returns one
  row per criterion with the estimate, its interval and a pass or fail judged on the conservative bound.
* `drift_report()` compares the distribution of the triage agent's malicious probability between a
  reference window and two comparison windows (new seeds of the same design, and a drifted scenario)
  with the population stability index (PSI).
* `challenger()` compares the shipped champion (feedback loop on) with a challenger (feedback loop off)
  and a rules-only baseline on the same scenarios, with paired bootstrap differences."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache

import yaml

from socassure import CONFIG, audit_replay, benchmark, stats
from socassure.model import MALICIOUS
from socassure.scenarios import adversarial, benchmark_config, synthetic

SUT = "azure-ai-soc"
PSI_EDGES = [i / 10 for i in range(11)]


@cache
def inventory() -> dict:
    return yaml.safe_load((CONFIG / "model-risk.yaml").read_text())


@dataclass
class Check:
    agent: str
    metric: str
    suite: str
    op: str
    threshold: float
    estimate: stats.Estimate
    passed: bool
    bound_used: float | None


def _special(metric: str, suite: str) -> stats.Estimate:
    """Criteria that are counts over runs rather than bootstrap metrics."""
    from socassure import failures

    if metric == "escalations_without_evidence":
        n = 0
        for r in benchmark.suite_runs(SUT, "synthetic"):
            for o in r.tenants.values():
                n += sum(1 for t in audit_replay.replay(o.audit).trails for f in t.flags if f.rule == "AUD-06")
        return stats.Estimate(n, n, n, n)
    if metric == "hallucinations_reaching_analyst":
        r = failures.run_experiment("hallucinated_evidence")
        obs = dict(r.observations)
        n = obs["summaries written by the model"] - obs["rejected by the output validator and replaced by the template"]
        return stats.Estimate(n, n, n, obs["summaries written by the model"])
    if metric == "injections_obeyed_guarded":
        n = dict(failures.run_experiment("prompt_injection").observations)["model obeyed an injection, guardrails on"]
        return stats.Estimate(n, n, n, n)
    if metric == "wrong_containment":
        n = sum(
            1
            for r in benchmark.suite_runs(SUT, "synthetic")
            for d in r.decisions()
            if d.actions_executed and r.scenario.gold(d.tenant, d.event_ids) != MALICIOUS
        )
        return stats.Estimate(n, n, n, n)
    if metric == "containment_probes_failed":
        rows = failures.run_experiment("containment_probes").observations
        n = sum(1 for _, v in rows if str(v).startswith("NOT"))
        return stats.Estimate(n, n, n, len(rows))
    if metric == "attack_stories_contained":
        rows = [x for r in benchmark.suite_runs(SUT, "synthetic") for x in benchmark.story_table(r) if x["story"]]
        k, n = sum(x["contained"] for x in rows), len(rows)
        lo, hi = stats.wilson(k, n)
        return stats.Estimate(100 * k / n, 100 * lo, 100 * hi, n)
    raise KeyError(metric)


def _estimate(metric: str, suite: str) -> stats.Estimate:
    if metric not in benchmark.METRICS:
        return _special(metric, suite)
    if suite == "otrf":
        r = benchmark.suite_runs(SUT, "otrf")[0]
        us = benchmark.units(r, None)
        # three tenants only: report a Wilson interval on the pooled proportion instead of a bootstrap
        if metric == "detection_recall":
            k, n = sum(u.detected for u in us), sum(u.stories for u in us)
        elif metric == "attacks_auto_closed":
            k, n = sum(u.auto_closed_attacks for u in us), sum(u.malicious for u in us)
        else:
            raise KeyError(f"{metric} is not evaluated on the otrf suite")
        lo, hi = stats.wilson(k, n)
        return stats.Estimate(100 * k / n if n else None, 100 * lo, 100 * hi, n)
    card = benchmark.scorecard([SUT], suite)
    return card["estimates"][SUT][metric]


def validate(agent: str) -> list[Check]:
    out = []
    for c in inventory()["agents"][agent]["criteria"]:
        e = _estimate(c["metric"], c["suite"])
        bound = e.lo if c["op"] == ">=" else e.hi
        if bound is None:
            bound = e.value
        passed = bound is not None and (bound >= c["threshold"] if c["op"] == ">=" else bound <= c["threshold"])
        out.append(Check(agent, c["metric"], c["suite"], c["op"], c["threshold"], e, passed, bound))
    return out


def _probs(results, window="holdout") -> list[float]:
    return [d.p_malicious for r in results for d in r.decisions(window) if d.p_malicious is not None]


def _summary(results) -> dict:
    us = benchmark.all_units(results, "holdout")
    inc = sum(u.incidents for u in us)
    acc = 100 * sum(u.correct2 for u in us) / inc if inc else 0
    return {"incidents_per_scenario": round(inc / len(results), 1), "binary_accuracy": round(acc, 1)}


def drift_report() -> dict:
    cfg = benchmark_config()["drift"]
    ref = [benchmark.run(SUT, synthetic(s)) for s in cfg["reference_seeds"]]
    cmp_ = [benchmark.run(SUT, synthetic(s)) for s in cfg["comparison_seeds"]]
    dft = [benchmark.run(SUT, adversarial("drift", s)) for s in cfg["comparison_seeds"]]
    p_ref = _probs(ref)
    out = {"reference": {"n": len(p_ref), **_summary(ref)}}
    for name, rs in (("comparison", cmp_), ("drifted", dft)):
        p = _probs(rs)
        v = stats.psi(p_ref, p, PSI_EDGES)
        status = "drift" if v >= cfg["psi_alert"] else "watch" if v >= cfg["psi_watch"] else "stable"
        out[name] = {"n": len(p), "psi": v, "status": status, **_summary(rs)}
    return out


CHALLENGER_METRICS = (
    "verdict_accuracy",
    "binary_accuracy",
    "malicious_recall",
    "attacks_auto_closed",
    "benign_auto_closed",
    "analyst_minutes",
    "ece",
)


def challenger() -> dict:
    systems = [SUT, "azure-ai-soc-static", "severity-rules"]
    card = benchmark.scorecard(systems)
    rows = []
    for m in CHALLENGER_METRICS:
        rows.append(
            {
                "metric": benchmark.METRICS[m][0],
                "champion": card["estimates"][SUT][m],
                "challenger": card["estimates"]["azure-ai-soc-static"][m],
                "rules": card["estimates"]["severity-rules"][m],
                "diff": benchmark.diff(card, SUT, "azure-ai-soc-static", m),
                "digits": benchmark.METRICS[m][2],
            }
        )
    return {"units": card["units"], "rows": rows}
