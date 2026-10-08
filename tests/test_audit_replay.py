"""Decision-audit replay: independent verification, reconstruction, rules, explanations and reports."""

import copy
import csv
import io

import pytest
from aisoc.audit import AuditLog

from socassure import audit_replay, benchmark, scenarios
from socassure.cli import rel


@pytest.fixture(scope="module")
def chains():
    r = benchmark.run("azure-ai-soc", scenarios.synthetic(101))
    return {t: o.audit for t, o in r.tenants.items()}


def _sut_verify(tenant, records):
    return AuditLog(tenant, copy.deepcopy(records)).verify()[0]


def test_independent_verify_agrees_with_the_sut_on_real_and_tampered_chains(chains):
    for tenant, recs in chains.items():
        assert audit_replay.verify(recs)[0] is True is _sut_verify(tenant, recs)
        bad = copy.deepcopy(recs)
        bad[5]["data"]["note"] = "edited"
        assert audit_replay.verify(bad)[0] is False is _sut_verify(tenant, bad)
        assert audit_replay.verify(recs[:4] + recs[5:])[0] is False is _sut_verify(tenant, recs[:4] + recs[5:])


def test_every_incident_is_rebuilt(chains):
    r = benchmark.run("azure-ai-soc", scenarios.synthetic(101))
    for tenant, recs in chains.items():
        trails = audit_replay.reconstruct(recs)
        assert {t.incident for t in trails} == {d.incident_id for d in r.tenants[tenant].decisions}


def test_no_critical_or_high_flags_on_honest_runs(chains):
    for recs in chains.values():
        sev = audit_replay.replay(recs).by_severity()
        assert sev["critical"] == 0 and sev["high"] == 0


def test_known_gaps_are_flagged_on_every_escalated_incident(chains):
    rep = audit_replay.replay(chains["brightwater"])
    escalated = [t for t in rep.trails if (t.tier or 0) > 1]
    assert escalated and all({"AUD-09", "AUD-10"} <= {f.rule for f in t.flags} for t in escalated)


def test_rubber_stamp_by_an_agent_identity_is_critical(chains):
    recs = copy.deepcopy(chains["pinecrest"])
    i = next(n for n, x in enumerate(recs) if x["event"] == "approval.decided")
    recs[i]["actor"] = "agent:response"
    recs[i]["data"]["approver"] = "agent:response"
    rep = audit_replay.replay(recs)
    assert not rep.valid  # the edit breaks the chain ...
    rules = {f.rule for t in rep.trails for f in t.flags}
    assert "AUD-04" in rules  # ... and the decision itself is flagged


def test_missing_approval_is_flagged(chains):
    recs = [x for x in chains["orchidvalley"] if x["event"] != "approval.decided"]
    rep = audit_replay.replay(recs)
    assert "AUD-02" in {f.rule for t in rep.trails for f in t.flags}


def test_explanations_use_only_audit_facts_and_relative_times(chains):
    rep = audit_replay.replay(chains["brightwater"])
    t = next(t for t in rep.trails if t.executions)
    text = audit_replay.explain(t, rel)
    assert t.incident in text and "dry-run" in text and "approved by" in text
    assert " D" in text and "T" not in text.split("approval requested")[1][:8]


def test_relative_time_format():
    assert rel(scenarios.epoch().isoformat()) == "D0 00:00"
    assert rel(None) == ""


def test_reports_in_three_formats(chains, tmp_path):
    reps = [audit_replay.replay(chains[t]) for t in sorted(chains)]
    paths = audit_replay.write_reports(reps, tmp_path, rel)
    assert [p.suffix for p in paths] == [".md", ".html", ".csv"]
    rows = list(csv.DictReader(io.StringIO(paths[2].read_text())))
    assert len(rows) == sum(len(r.trails) for r in reps)
    assert set(rows[0]) == set(audit_replay.CSV_FIELDS)
    assert "<table>" in paths[1].read_text() and "# Decision audit report" in paths[0].read_text()
