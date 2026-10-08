"""Product scorecard: weighted criteria, evidence-level caps and caps computed from this repository's runs.

A product file scores each criterion 0-5 with an evidence level. The effective score is the minimum of
the claimed score, the evidence level's ceiling and any result-driven cap that fires. Products with no
scores are listed as not scored; this repository never invents numbers for real products."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache

import yaml

from socassure import CONFIG

SC = CONFIG / "scorecard"


@cache
def criteria() -> dict:
    return yaml.safe_load((SC / "criteria.yaml").read_text())


def products() -> dict[str, dict]:
    return {p.stem: yaml.safe_load(p.read_text()) for p in sorted((SC / "products").glob("*.yaml"))}


# ---------------------------------------------------------------- caps from live results


def _otrf_recall() -> tuple[int, int]:
    from socassure import benchmark

    r = benchmark.suite_runs("azure-ai-soc", "otrf")[0]
    rows = benchmark.story_table(r)
    return sum(x["detected"] for x in rows), len(rows)


def cap_results(product: str) -> dict[str, tuple[bool, int, str]]:
    """cap id -> (fires, max score, evidence). Only the system under test has live results."""
    if product != "azure-ai-soc":
        return {}
    from socassure import audit_replay, benchmark, failures, modelrisk, residency

    k, n = _otrf_recall()
    otrf = benchmark.suite_runs("azure-ai-soc", "otrf")[0]
    otrf_closed = sum(1 for x in benchmark.story_table(otrf) if x["auto_closed"])
    fm11 = failures.run_experiment("approval_fatigue")
    outage = dict(failures.run_experiment("llm_outage").observations)
    healthy_t1 = outage.get("errored incidents the healthy run closed at tier 1", 0)
    flags = sum(
        (audit_replay.replay(o.audit).flags() for r in benchmark.suite_runs("azure-ai-soc", "synthetic")[:1] for o in r.tenants.values()),
        start=__import__("collections").Counter(),
    )
    shipped = residency.summary(residency.check(residency.load_deployment("azure-ai-soc-as-shipped")))
    failed = [c for a in modelrisk.inventory()["agents"] for c in modelrisk.validate(a) if not c.passed]
    return {
        "otrf_recall_below_half": (k / n < 0.5, 2, f"public recordings detected {k}/{n}"),
        "independent_attack_auto_closed": (otrf_closed > 0, 2, f"{otrf_closed} replayed public attack(s) auto-closed"),
        "rubber_stamp_wrong_containment": (not fm11.safe, 3, "FM-11: rubber-stamp approvers let wrong containment through"),
        "no_degraded_mode": (healthy_t1 > 0, 3, f"model outage: {healthy_t1} incidents the healthy run auto-closed errored instead"),
        "model_output_not_recorded": (flags.get("AUD-09", 0) > 0, 3, f"AUD-09 on {flags.get('AUD-09', 0)} escalated decisions (one seed)"),
        "shipped_layout_violates": (
            shipped["violation"] + shipped["unknown"] > 0,
            1,
            f"as shipped: {shipped['violation']} violations, {shipped['unknown']} unknown",
        ),
        "validation_criterion_failed": (
            bool(failed),
            2,
            f"{len(failed)} validation criteria failed: " + ", ".join(f"{c.agent}.{c.metric}" for c in failed),
        ),
        "illustrative_prices": (True, 3, "token prices are illustrative inputs"),
        "never_deployed": (True, 3, "never deployed; IaC tested offline only"),
    }


@dataclass
class Row:
    criterion: str
    weight: int
    claimed: int | None
    level: str
    effective: int | None
    reasons: list[str]


def score(product: str) -> tuple[list[Row], float | None]:
    crit = criteria()
    p = products()[product]
    caps = cap_results(product)
    rows, total, any_scored = [], 0.0, False
    for c in crit["criteria"]:
        s = (p.get("scores") or {}).get(c["id"]) or {}
        claimed, level = s.get("score"), s.get("evidence_level", "claimed")
        reasons = []
        eff = claimed
        if claimed is not None:
            any_scored = True
            ceiling = crit["evidence_levels"][level]
            if eff > ceiling:
                eff = ceiling
                reasons.append(f"evidence level {level} caps at {ceiling}")
            for cap in c.get("caps", []):
                fires, mx, why = caps.get(cap, (False, 5, ""))
                if fires and eff > mx:
                    eff = mx
                    reasons.append(f"{why} (cap {mx})")
            total += c["weight"] * eff / 5
        rows.append(Row(c["id"], c["weight"], claimed, level, eff, reasons))
    return rows, (round(total, 1) if any_scored else None)
