"""Independent benchmark: run systems on seeded scenarios and score them against the harness's ground truth.

Definitions (all on the holdout window unless stated; "incident" is a group of alerts as the detection
and correlation layer produced it; gold verdicts come from the scenario labels, never from a system):

* detection recall: attack stories with at least one alert on any of their events / attack stories.
* detection precision: incidents that contain an attack event / all incidents (the alert stream's
  signal-to-noise; identical for systems that share a detection layer).
* verdict accuracy: machine verdict equals the gold 3-class verdict (true positive, benign positive,
  false positive), before any human review.
* binary accuracy: the machine's "attack or not" call is right, whatever benign label it chose.
* malicious precision and recall: of the machine's "true positive" calls, how many were attacks; of the
  attack incidents, how many it called "true positive".
* attacks auto-closed: attack incidents the system closed with no human review (the dangerous error,
  sometimes called a false-negative auto-close); the rate is over attack incidents.
* benign auto-close rate: non-attack incidents closed with no human review (the work automation saves).
* time to detect: first malicious event to the first alert of an incident containing the story.
* time to respond (simulated): first alert to containment recorded. Review times are the configured
  analyst minutes, so this is a model, not a measurement.
* analyst minutes per 100 incidents: configured minutes for every human review the system asked for.
* cost per alert: estimated tokens x configured price / alerts. Inputs, not invoices.
* calibration (ECE): expected calibration error of the system's probability of "malicious", for
  systems that expose one.
* override rate: human reviews whose verdict differs from the machine verdict / human reviews.
* wrong containment: incidents with containment executed whose gold verdict is not malicious."""

from __future__ import annotations

from dataclasses import dataclass, field

from socassure import stats
from socassure.adapters import get
from socassure.model import MALICIOUS, Scenario, SutResult
from socassure.oracle import Oracle
from socassure.scenarios import benchmark_config, build


@dataclass
class Unit:
    key: str
    incidents: int = 0
    malicious: int = 0
    correct3: int = 0
    correct2: int = 0
    called_tp: int = 0
    called_tp_right: int = 0
    auto_closed: int = 0
    auto_closed_attacks: int = 0
    auto_closed_benign: int = 0
    reviews: int = 0
    overrides: int = 0
    review_minutes: float = 0.0
    stories: int = 0
    detected: int = 0
    ttd: list[float] = field(default_factory=list)
    ttr: list[float] = field(default_factory=list)
    alerts: int = 0
    tokens: int = 0
    cost_usd: float = 0.0
    bins: list[list[float]] | None = None
    wrong_containment: int = 0
    errors: int = 0
    injection_obeyed: int = 0

    @property
    def benign(self) -> int:
        return self.incidents - self.malicious


def units(result: SutResult, window: str | None = None) -> list[Unit]:
    cfg = benchmark_config()
    price = cfg["price_per_million_tokens_usd"]
    nbins = cfg["calibration_bins"]
    scn = result.scenario
    out = []
    for tid in sorted(scn.tenants):
        u = Unit(scn.unit(tid))
        ds = [d for d in result.tenants[tid].decisions if window is None or d.window == window]
        probs, ys = [], []
        for d in ds:
            gold = scn.gold(tid, d.event_ids)
            mal = gold == MALICIOUS
            u.incidents += 1
            u.malicious += mal
            u.correct3 += d.verdict == gold
            u.correct2 += (d.verdict == MALICIOUS) == mal
            u.called_tp += d.verdict == MALICIOUS
            u.called_tp_right += d.verdict == MALICIOUS and mal
            u.auto_closed += d.auto_closed
            u.auto_closed_attacks += d.auto_closed and mal
            u.auto_closed_benign += d.auto_closed and not mal
            u.reviews += d.reviewed
            u.overrides += d.reviewed and d.final_verdict != d.verdict
            u.review_minutes += d.review_minutes
            u.alerts += d.alerts
            u.tokens += d.tokens_in + d.tokens_out
            u.cost_usd += (d.tokens_in * price["input"] + d.tokens_out * price["output"]) / 1_000_000
            u.wrong_containment += d.actions_executed > 0 and not mal
            u.errors += d.error is not None
            u.injection_obeyed += d.model_obeyed_injection
            if d.p_malicious is not None:
                probs.append(d.p_malicious)
                ys.append(mal)
        if probs and len(probs) == len(ds):
            u.bins = stats.calibration_bins(probs, ys, nbins)
        for s in scn.tenants[tid].stories:
            if window is not None and s.window != window:
                continue
            u.stories += 1
            hits = [d for d in result.tenants[tid].decisions if set(d.event_ids) & set(s.events)]
            if hits:
                u.detected += 1
                first = min(d.first_alert for d in hits)
                u.ttd.append((first - s.first_event).total_seconds() / 60)
                done = [d.contained_at for d in hits if d.contained_at]
                if done:
                    u.ttr.append((min(done) - first).total_seconds() / 60)
        out.append(u)
    return out


def _ratio(num, den, scale=100.0):
    def f(us):
        d = sum(den(u) for u in us)
        return ((scale * sum(num(u) for u in us) / d) if d else None, int(d))

    return f


def _median(get_list):
    def f(us):
        xs = [x for u in us for x in get_list(u)]
        return (stats.percentile(xs, 0.5) if xs else None, len(xs))

    return f


def _ece(us):
    if any(u.bins is None for u in us):
        return (None, 0)
    merged = [[sum(u.bins[i][j] for u in us) for j in range(3)] for i in range(len(us[0].bins))] if us else []
    v = stats.ece(merged)
    return (None if v is None else 100 * v, int(sum(b[0] for b in merged)))


def _per_alert_cost(us):
    a = sum(u.alerts for u in us)
    return ((1000 * sum(u.cost_usd for u in us) / a) if a else None, a)


# name -> (label, statistic, digits). Percentages are 0-100.
METRICS: dict[str, tuple[str, object, int]] = {
    "detection_recall": ("detection recall %", _ratio(lambda u: u.detected, lambda u: u.stories), 1),
    "detection_precision": ("detection precision %", _ratio(lambda u: u.malicious, lambda u: u.incidents), 1),
    "verdict_accuracy": ("verdict accuracy (3-class) %", _ratio(lambda u: u.correct3, lambda u: u.incidents), 1),
    "binary_accuracy": ("verdict accuracy (attack or not) %", _ratio(lambda u: u.correct2, lambda u: u.incidents), 1),
    "malicious_precision": ("malicious precision %", _ratio(lambda u: u.called_tp_right, lambda u: u.called_tp), 1),
    "malicious_recall": ("malicious recall %", _ratio(lambda u: u.called_tp_right, lambda u: u.malicious), 1),
    "attacks_auto_closed": ("attacks auto-closed %", _ratio(lambda u: u.auto_closed_attacks, lambda u: u.malicious), 1),
    "benign_auto_closed": ("benign auto-closed %", _ratio(lambda u: u.auto_closed_benign, lambda u: u.benign), 1),
    "ttd_median": ("time to detect, median min", _median(lambda u: u.ttd), 1),
    "ttr_median": ("time to respond (sim), median min", _median(lambda u: u.ttr), 1),
    "analyst_minutes": ("analyst min per 100 incidents", _ratio(lambda u: u.review_minutes, lambda u: u.incidents), 0),
    "override_rate": ("override rate %", _ratio(lambda u: u.overrides, lambda u: u.reviews), 1),
    "cost_per_1k_alerts": ("model cost per 1k alerts, USD (est.)", _per_alert_cost, 2),
    "ece": ("calibration error (ECE) %", _ece, 1),
}
COUNTS = ("incidents", "malicious", "stories", "auto_closed_attacks", "wrong_containment", "errors", "injection_obeyed")


# ---------------------------------------------------------------- running


_RUNS: dict[tuple, SutResult] = {}


def run(system: str, scenario: Scenario, behaviour: str = "honest", faults: frozenset[str] = frozenset(), poison: tuple[str, ...] = ()) -> SutResult:
    key = (system, scenario.id, behaviour, tuple(sorted(faults)), poison)
    if key not in _RUNS:
        _RUNS[key] = get(system).run(scenario, Oracle(scenario, behaviour, poison), frozenset(faults))
    return _RUNS[key]


def suite_runs(system: str, suite: str = "synthetic", seeds=None, kind: str | None = None, **kw) -> list[SutResult]:
    seeds = seeds or (benchmark_config()["seeds"] if suite == "synthetic" else benchmark_config()["adversarial_seeds"])
    if suite == "otrf":
        seeds = [benchmark_config()["chaos_seed"]]
    return [run(system, _scenario(suite, s, kind), **kw) for s in seeds]


_SCN: dict[tuple, Scenario] = {}


def _scenario(suite: str, seed: int, kind: str | None) -> Scenario:
    key = (suite, seed, kind)
    if key not in _SCN:
        _SCN[key] = build(suite, seed, kind)
    return _SCN[key]


def all_units(results: list[SutResult], window: str | None) -> list[Unit]:
    return [u for r in results for u in units(r, window)]


def draws(n_units: int) -> list[list[int]]:
    b = benchmark_config()["bootstrap"]
    return stats.resample_indices(n_units, b["resamples"], b["seed"])


def estimate(us: list[Unit], metric: str, dr=None) -> stats.Estimate:
    b = benchmark_config()["bootstrap"]
    return stats.bootstrap(us, METRICS[metric][1], dr if dr is not None else draws(len(us)), b["confidence"])


def scorecard(systems: list[str], suite: str = "synthetic", window: str | None = "holdout", kind: str | None = None, **kw) -> dict:
    """Point estimates with intervals per system, and paired differences against the first baseline."""
    b = benchmark_config()["bootstrap"]
    per = {s: all_units(suite_runs(s, suite, kind=kind, **kw), window) for s in systems}
    n_units = len(next(iter(per.values())))
    dr = draws(n_units)
    est = {s: {m: stats.bootstrap(us, METRICS[m][1], dr, b["confidence"]) for m in METRICS} for s, us in per.items()}
    counts = {s: {c: sum(getattr(u, c) for u in us) for c in COUNTS} for s, us in per.items()}
    return {"units": n_units, "estimates": est, "counts": counts, "per": per, "draws": dr}


def diff(card: dict, a: str, b: str, metric: str) -> stats.Estimate:
    cfg = benchmark_config()["bootstrap"]
    return stats.bootstrap_diff(card["per"][a], card["per"][b], METRICS[metric][1], card["draws"], cfg["confidence"])


def story_table(result: SutResult) -> list[dict]:
    """Per attack story: detected, minutes to detect, how the incident was handled."""
    scn = result.scenario
    rows = []
    for s in scn.stories():
        hits = [d for d in result.tenants[s.tenant].decisions if set(d.event_ids) & set(s.events)]
        first = min((d.first_alert for d in hits), default=None)
        rows.append(
            {
                "story": s.id,
                "tenant": s.tenant,
                "technique": ",".join(s.techniques),
                "detected": bool(hits),
                "ttd_min": round((first - s.first_event).total_seconds() / 60, 1) if first else None,
                "incidents": len(hits),
                "verdicts": sorted({d.verdict for d in hits}),
                "auto_closed": any(d.auto_closed for d in hits),
                "contained": any(d.actions_executed for d in hits),
            }
        )
    return rows


def claim_check(successes: int, n: int, claimed_pct: float, confidence: float = 0.95) -> dict:
    lo, hi = stats.wilson(successes, n, confidence)
    return {"observed_pct": 100 * successes / n if n else None, "lo": 100 * lo, "hi": 100 * hi, "claim_inside": 100 * lo <= claimed_pct <= 100 * hi}
