"""Data residency: flow checks, deployment types, the SUT's IaC and this repository's Azure Policy parameters."""

import copy

from socassure import residency


def _shipped():
    return residency.load_deployment("azure-ai-soc-as-shipped")


def test_shipped_layout_fails_the_canadian_tenant_and_unpinned_model_types():
    checks = residency.check(_shipped())
    bad = {(c.tenant, c.flow, c.result) for c in checks if c.result != "pass"}
    assert ("orchidvalley", "F1", "violation") in bad
    assert ("orchidvalley", "F6", "violation") in bad  # cross-border analyst access
    assert {(t, "F3", "unknown") for t in ("brightwater", "orchidvalley", "pinecrest")} <= bad
    assert not [c for c in checks if c.tenant != "orchidvalley" and c.result == "violation"]


def test_proposed_layout_passes_every_check():
    s = residency.summary(residency.check(residency.load_deployment("proposed")))
    assert s["violation"] == 0 and s["unknown"] == 0 and s["pass"] == 24


def test_global_deployment_type_is_a_violation_for_geography_bound_data():
    d = copy.deepcopy(residency.load_deployment("proposed"))
    d["tenants"]["pinecrest"]["model"]["deployment_type"] = "GlobalStandard"
    c = next(c for c in residency.check(d) if c.tenant == "pinecrest" and c.flow == "F3")
    assert c.result == "violation" and "global" in c.reason


def test_data_zone_needs_tenant_consent_and_a_matching_zone():
    d = copy.deepcopy(residency.load_deployment("proposed"))
    d["tenants"]["orchidvalley"]["model"] = {"region": "eastus2", "deployment_type": "DataZoneStandard"}
    c = next(c for c in residency.check(d) if c.tenant == "orchidvalley" and c.flow == "F3")
    assert c.result == "violation"
    d["tenants"]["pinecrest"]["model"] = {"region": "westeurope", "deployment_type": "DataZoneStandard"}
    c = next(c for c in residency.check(d) if c.tenant == "pinecrest" and c.flow == "F3")
    assert c.result == "violation" and "europe" in c.reason


def test_unknown_region_fails_closed():
    d = copy.deepcopy(residency.load_deployment("proposed"))
    d["tenants"]["brightwater"]["audit"] = "marsnorth"
    c = next(c for c in residency.check(d) if c.tenant == "brightwater" and c.flow == "F5")
    assert c.result == "unknown"


def test_unrestricted_data_classes_pass_anywhere():
    for c in residency.check(_shipped()):
        if c.data_class in {"threat_intel", "aggregate_metrics"}:
            assert c.result == "pass"


def test_policy_deployment_types_cover_the_learn_page_families():
    types = residency.policy()["deployment_types"]
    assert types["GlobalStandard"] == "global" and types["DataZoneStandard"] == "data_zone" and types["Standard"] == "geography"


def test_sut_iac_cannot_place_the_canadian_tenant():
    rows = {t: r for t, _, r in residency.sut_iac_findings()}
    assert rows["orchidvalley"] == "cannot be deployed in its geography"
    assert rows["brightwater"] == "deployable in geography"


def test_this_repository_policy_parameters_enforce_the_policy():
    rows = residency.iac_consistency()
    assert len(rows) == 6 and all(ok for _, _, ok, _ in rows)


def test_terraform_and_bicep_parameters_agree():
    for t in residency.policy()["tenants"]:
        assert residency.tfvars(t) == residency.bicep_params(t)
