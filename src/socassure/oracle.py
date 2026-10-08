"""The simulated analyst and approvers that answer a system's human-in-the-loop requests.

A system under test asks people to review incidents and approve containment. Offline, the harness answers
from its own ground truth, so a system can never mark its own homework. Behaviours:

* `honest`: the analyst's verdict is the gold verdict; approvers approve containment only for real attacks.
* `rubber_stamp`: approval fatigue. Verdicts stay honest, but every containment request is approved,
  including plans for incidents that are not attacks.
* `poisoned`: an insider corrupts the feedback loop. In the training window, reviews of incidents raised
  by the `poison_sources` detectors are answered "benign_positive" even when they are attacks. Approvals
  stay honest.

Minutes per review come from config/benchmark.yaml and are the same for every system."""

from __future__ import annotations

from dataclasses import dataclass, field

from socassure.model import MALICIOUS, Scenario
from socassure.scenarios import benchmark_config

BEHAVIOURS = ("honest", "rubber_stamp", "poisoned")


@dataclass(frozen=True)
class Ask:
    tenant: str
    incident_id: str
    event_ids: tuple[str, ...]
    kind: str  # "approval" or "qa"
    tier: int
    machine_verdict: str
    sources: tuple[str, ...]
    window: str
    has_actions: bool


@dataclass(frozen=True)
class Answer:
    analyst: str
    verdict: str
    approve: bool
    minutes: int
    poisoned: bool = False


@dataclass
class Oracle:
    scenario: Scenario
    behaviour: str = "honest"
    poison_sources: tuple[str, ...] = ()
    log: list[tuple[Ask, Answer]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.behaviour not in BEHAVIOURS:
            raise ValueError(f"unknown behaviour {self.behaviour!r}")

    def minutes(self, ask: Ask) -> int:
        m = benchmark_config()["analyst_minutes"]
        return m["qa"] if ask.kind == "qa" else m["tier3"] if ask.tier == 3 else m["tier2"]

    def answer(self, ask: Ask) -> Answer:
        gold = self.scenario.gold(ask.tenant, ask.event_ids)
        verdict, poisoned = gold, False
        if self.behaviour == "poisoned" and ask.window == "train" and set(ask.sources) & set(self.poison_sources):
            verdict, poisoned = "benign_positive", gold == MALICIOUS
        approve = ask.has_actions and (verdict == MALICIOUS or self.behaviour == "rubber_stamp")
        analyst = "analyst.tier3" if ask.tier == 3 else "analyst.tier2"
        a = Answer(analyst, verdict, approve, self.minutes(ask), poisoned)
        self.log.append((ask, a))
        return a

    def confirmed(self, tenant: str, event_ids) -> str:
        """The outcome recorded for a past incident: what the analysts said, poisoned or not."""
        for ask, ans in reversed(self.log):
            if ask.tenant == tenant and set(ask.event_ids) == set(event_ids):
                return ans.verdict
        return self.scenario.gold(tenant, event_ids)
