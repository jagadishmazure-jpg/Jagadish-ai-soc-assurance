"""Naive baselines that see exactly the same alerts as the system under test.

Both baselines reuse the detection and incident-correlation layer of azure-ai-soc (its analytics rules,
product alerts and grouping), so the comparison isolates what AI triage, investigation and response add
on top of the same detections. Neither uses a language model.

* `always-escalate`: every incident goes to a human. Nothing is auto-closed, so no attack can be closed
  by mistake; the price is analyst time. Tier 3 when any alert is High severity, otherwise tier 2.
* `severity-rules`: a common rules-only triage under load. Incidents with a High severity alert are
  escalated to tier 3 as suspected attacks; everything else is closed automatically.

Containment is done by the analyst by hand after a confirmed attack; its time is the end of the review."""

from __future__ import annotations

from datetime import timedelta

from socassure.adapters.base import check_faults
from socassure.model import MALICIOUS, Decision, Scenario, SutResult, TenantOutcome
from socassure.oracle import Ask, Oracle
from socassure.scenarios import benchmark_config, window_of


def incidents_for(scenario: Scenario, tid: str):
    """The system under test's alert stream and incident grouping for one tenant."""
    from aisoc import synth
    from aisoc.detections import all_alerts
    from aisoc.store import TenantStore
    from aisoc.tenants import get
    from aisoc.triage import build_incidents

    tables = {k: [dict(r) for r in v] for k, v in scenario.tenants[tid].tables.items()}
    store = TenantStore(get(tid), tables, synth.T0 + timedelta(days=synth.DAYS))
    return build_incidents(store, all_alerts(store))


class _Baseline:
    name = "baseline"
    description = ""
    supported_faults: frozenset[str] = frozenset()

    def triage(self, inc) -> tuple[str, int]:  # (machine verdict, tier: 1 = auto-close)
        raise NotImplementedError

    def run(self, scenario: Scenario, oracle: Oracle, faults: frozenset[str] = frozenset()) -> SutResult:
        check_faults(self, frozenset(faults))
        settle = timedelta(minutes=benchmark_config()["settle_minutes"])
        out = {}
        for tid in sorted(scenario.tenants):
            outcome = TenantOutcome(tid)
            for inc in incidents_for(scenario, tid):
                verdict, tier = self.triage(inc)
                minutes, final, contained = 0, verdict, None
                if tier > 1:
                    a = oracle.answer(
                        Ask(
                            tid,
                            inc.id,
                            tuple(inc.event_ids),
                            "approval",
                            tier,
                            verdict,
                            tuple(inc.sources),
                            window_of(inc.start),
                            verdict == MALICIOUS,
                        )
                    )
                    minutes, final = a.minutes, a.verdict
                    if a.approve:
                        contained = inc.end + settle + timedelta(minutes=a.minutes)
                outcome.decisions.append(
                    Decision(
                        tid,
                        inc.id,
                        tuple(inc.event_ids),
                        inc.start,
                        len(inc.alerts) + inc.duplicates,
                        window_of(inc.start),
                        verdict,
                        None,
                        tier,
                        tier == 1,
                        tier > 1,
                        minutes,
                        final,
                        actions_executed=1 if contained else 0,
                        contained_at=contained,
                    )
                )
            out[tid] = outcome
        return SutResult(self.name, scenario, out)


def _severity(inc) -> str:
    order = ["Informational", "Low", "Medium", "High"]
    return max((a.severity for a in inc.alerts), key=lambda s: order.index(s) if s in order else 0)


class AlwaysEscalate(_Baseline):
    name = "always-escalate"
    description = "same detections; every incident is reviewed by a human; no AI"

    def triage(self, inc) -> tuple[str, int]:
        return MALICIOUS, 3 if _severity(inc) == "High" else 2


class SeverityRules(_Baseline):
    name = "severity-rules"
    description = "same detections; incidents with a High severity alert escalated, the rest auto-closed; no AI"

    def triage(self, inc) -> tuple[str, int]:
        if _severity(inc) == "High":
            return MALICIOUS, 3
        return "false_positive", 1
