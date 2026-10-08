"""The contract between the harness and any AI SOC.

A system under test receives a `Scenario` (tables per tenant, no labels) and an `Oracle` that plays the
humans, and returns a `SutResult`. Faults are named so that every adapter can say which ones it
supports; an adapter that cannot inject a fault must raise `UnsupportedFault`, never ignore it."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from socassure.model import Scenario, SutResult
from socassure.oracle import Oracle

FAULTS = {
    "llm_outage": "every call to the language model fails",
    "tool_outage": "every investigation tool call fails",
    "hallucinating_model": "the model cites evidence that does not exist and flips the verdict",
    "gullible_model": "the model obeys instructions it finds outside quoted data",
    "guardrails_off": "input screening, redaction and quoting are switched off",
    "stale_threat_feed": "every threat-intelligence indicator has expired",
}


class UnsupportedFault(NotImplementedError):
    pass


@runtime_checkable
class SystemUnderTest(Protocol):
    name: str
    description: str
    supported_faults: frozenset[str]

    def run(self, scenario: Scenario, oracle: Oracle, faults: frozenset[str] = frozenset()) -> SutResult: ...


def check_faults(sut: SystemUnderTest, faults: frozenset[str]) -> None:
    unknown = set(faults) - set(FAULTS)
    if unknown:
        raise KeyError(f"unknown fault(s) {sorted(unknown)}")
    missing = set(faults) - set(sut.supported_faults)
    if missing:
        raise UnsupportedFault(f"{sut.name} cannot inject {sorted(missing)}")
