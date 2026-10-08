"""Adapters: fidelity to the system under test, baselines, the recorded round trip and the third-party contract."""

from collections import Counter

import pytest

from socassure import benchmark, scenarios
from socassure.adapters import SYSTEMS, get
from socassure.adapters import recorded as rec
from socassure.adapters.base import FAULTS, UnsupportedFault


def test_adapter_reproduces_the_sut_published_holdout_numbers():
    """azure-ai-soc publishes, for its own seed: 40 holdout incidents, 100% 3-class accuracy, tiers 28/10/2,
    15 human reviews; and for its no-learning baseline 77.5% accuracy and 30 reviews."""
    s = scenarios.synthetic(1337)
    r = benchmark.run("azure-ai-soc", s)
    ds = r.decisions("holdout")
    assert len(ds) == 40
    assert sum(d.verdict == s.gold(d.tenant, d.event_ids) for d in ds) == 40
    assert Counter(d.tier for d in ds) == {1: 28, 2: 10, 3: 2}
    assert sum(d.reviewed for d in ds) == 15
    b = benchmark.run("azure-ai-soc-static", s).decisions("holdout")
    assert sum(d.verdict == s.gold(d.tenant, d.event_ids) for d in b) == 31
    assert sum(d.reviewed for d in b) == 30


def test_baselines_share_the_detection_layer():
    s = scenarios.synthetic(101)
    n = {name: len(benchmark.run(name, s).decisions()) for name in ("azure-ai-soc", "always-escalate", "severity-rules")}
    assert len(set(n.values())) == 1


def test_always_escalate_never_auto_closes_and_severity_rules_does():
    s = scenarios.synthetic(101)
    assert not any(d.auto_closed for d in benchmark.run("always-escalate", s).decisions())
    assert any(d.auto_closed for d in benchmark.run("severity-rules", s).decisions())


def test_recorded_round_trip_scores_identically(tmp_path):
    s = scenarios.synthetic(101)
    r = benchmark.run("azure-ai-soc", s)
    path = rec.export(r, tmp_path / "d.jsonl")
    again = get("recorded", path=path, product="replayed").run(s)
    a = benchmark.units(r, "holdout")
    b = benchmark.units(again, "holdout")
    for m in ("verdict_accuracy", "attacks_auto_closed", "benign_auto_closed", "ttr_median"):
        assert benchmark.METRICS[m][1](a) == benchmark.METRICS[m][1](b), m


def test_recorded_rejects_faults_and_unknown_tenants(tmp_path):
    p = tmp_path / "x.jsonl"
    p.write_text('{"tenant": "nobody", "incident_id": "X", "event_ids": [], "first_alert": "2000-01-01T00:00:00"}\n')
    with pytest.raises(ValueError):
        get("recorded", path=p).run(scenarios.synthetic(101))
    with pytest.raises(NotImplementedError):
        get("recorded", path=p).run(scenarios.synthetic(101), None, frozenset({"llm_outage"}))


def test_third_party_stub_documents_the_contract():
    stub = get("third-party")
    with pytest.raises(NotImplementedError) as e:
        stub.run(scenarios.synthetic(101), None)
    assert "export" in str(e.value).lower() or "adapter" in str(e.value).lower()


def test_unknown_system_and_unsupported_fault():
    with pytest.raises(KeyError):
        get("nope")
    with pytest.raises(UnsupportedFault):
        benchmark.run("always-escalate", scenarios.synthetic(101), faults=frozenset({"llm_outage"}))
    assert "recorded" in SYSTEMS and "llm_outage" in FAULTS


def test_faults_do_not_leak_between_runs():
    s = scenarios.synthetic(102)
    clean_before = len([d for d in benchmark.run("azure-ai-soc", s).decisions() if d.error])
    benchmark.run("azure-ai-soc", s, faults=frozenset({"llm_outage"}))
    fresh = get("azure-ai-soc").run(s, benchmark.Oracle(s), frozenset())
    assert clean_before == 0 and not [d for d in fresh.decisions() if d.error]
