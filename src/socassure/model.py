"""Vendor-neutral data types shared by scenarios, adapters and metrics.

A `Scenario` is telemetry shaped like Microsoft Sentinel and Defender XDR tables, one set per tenant,
plus ground truth that only the harness reads. An adapter turns a scenario into a `SutResult`: one
`Decision` per incident the system raised, the audit records it wrote, and any errors. Metrics compare
decisions with the ground truth; nothing a system under test returns is trusted as a label."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime

MALICIOUS = "true_positive"
VERDICTS = ("true_positive", "benign_positive", "false_positive")


@dataclass(frozen=True)
class Story:
    """One attack in a scenario: the events that belong to it and when it started."""

    id: str
    tenant: str
    kind: str
    first_event: datetime
    events: tuple[str, ...]
    window: str  # "train" or "holdout"
    techniques: tuple[str, ...] = ()


@dataclass
class TenantData:
    tenant: str
    tables: dict[str, list[dict]]
    labels: dict[str, str]  # event id -> story id, benign kind, or "noise" (harness only)
    stories: list[Story]
    benign_kinds: dict[str, str]  # benign label -> the verdict an expert would give

    def label(self, event_id: str) -> str:
        return self.labels.get(event_id, "noise")


@dataclass
class Scenario:
    id: str
    suite: str
    seed: int
    tenants: dict[str, TenantData]
    notes: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)  # perturbation details (harness only)

    def gold(self, tenant: str, event_ids) -> str:
        """Expert verdict for a set of events: any attack event makes it malicious; else the benign kind decides."""
        td = self.tenants[tenant]
        story_ids = {s.id for s in td.stories}
        labs = [td.label(e) for e in event_ids]
        if any(lab in story_ids for lab in labs):
            return MALICIOUS
        kinds = {td.benign_kinds[lab] for lab in labs if lab in td.benign_kinds}
        return "benign_positive" if "benign_positive" in kinds else "false_positive"

    def story_of(self, tenant: str, event_ids) -> str | None:
        td = self.tenants[tenant]
        story_ids = {s.id for s in td.stories}
        return next((td.label(e) for e in event_ids if td.label(e) in story_ids), None)

    def stories(self) -> list[Story]:
        return [s for t in sorted(self.tenants) for s in self.tenants[t].stories]

    def unit(self, tenant: str) -> str:
        """Bootstrap cluster key: incidents in one tenant of one seeded scenario are not independent."""
        return f"{self.suite}:{self.seed}:{tenant}"

    def copy(self, scenario_id: str, suite: str | None = None) -> Scenario:
        return Scenario(scenario_id, suite or self.suite, self.seed, copy.deepcopy(self.tenants), list(self.notes), copy.deepcopy(self.meta))


@dataclass
class Decision:
    """What a system did with one incident, in neutral terms."""

    tenant: str
    incident_id: str
    event_ids: tuple[str, ...]
    first_alert: datetime
    alerts: int
    window: str
    verdict: str  # machine verdict before any human review
    p_malicious: float | None
    tier: int
    auto_closed: bool
    reviewed: bool
    review_minutes: float
    final_verdict: str  # after human review, if any
    actions_planned: int = 0
    actions_executed: int = 0
    actions_live: int = 0
    contained_at: datetime | None = None
    tokens_in: int = 0
    tokens_out: int = 0
    narrative_fallback: bool = False
    injection_flagged: bool = False
    model_obeyed_injection: bool = False
    error: str | None = None


@dataclass
class TenantOutcome:
    tenant: str
    decisions: list[Decision] = field(default_factory=list)
    audit: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    artefacts: str = ""  # prompts, narratives and notes, for leakage searches
    extras: dict = field(default_factory=dict)


@dataclass
class SutResult:
    system: str
    scenario: Scenario
    tenants: dict[str, TenantOutcome]
    notes: list[str] = field(default_factory=list)

    def decisions(self, window: str | None = None) -> list[Decision]:
        out = [d for t in sorted(self.tenants) for d in self.tenants[t].decisions]
        return [d for d in out if window is None or d.window == window]
