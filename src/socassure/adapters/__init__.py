"""Adapters: the only code that knows how a particular system under test works.

Every adapter implements `SystemUnderTest.run(scenario, oracle, faults) -> SutResult` (see base.py).
`get(name)` returns a configured adapter by name."""

from __future__ import annotations

from socassure.adapters.base import FAULTS, SystemUnderTest


def get(name: str, **kwargs) -> SystemUnderTest:
    if name == "azure-ai-soc":
        from socassure.adapters.azure_ai_soc import AzureAiSoc

        return AzureAiSoc(**kwargs)
    if name == "azure-ai-soc-static":
        from socassure.adapters.azure_ai_soc import AzureAiSoc

        return AzureAiSoc(mode="baseline", **kwargs)
    if name == "always-escalate":
        from socassure.adapters.baselines import AlwaysEscalate

        return AlwaysEscalate()
    if name == "severity-rules":
        from socassure.adapters.baselines import SeverityRules

        return SeverityRules()
    if name == "third-party":
        from socassure.adapters.third_party import ThirdPartyStub

        return ThirdPartyStub(**kwargs)
    if name == "recorded":
        from socassure.adapters.recorded import RecordedDecisions

        return RecordedDecisions(**kwargs)
    raise KeyError(f"unknown system {name!r}; known: {SYSTEMS}")


SYSTEMS = ("azure-ai-soc", "azure-ai-soc-static", "always-escalate", "severity-rules", "third-party", "recorded")

__all__ = ["FAULTS", "SYSTEMS", "SystemUnderTest", "get"]
