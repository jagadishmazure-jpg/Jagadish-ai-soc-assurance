"""Residency policy stacks and workflow structure, checked offline (no Terraform or Bicep binaries needed)."""

import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WF = ROOT / ".github/workflows"
TF = ROOT / "infra/terraform"
BICEP = ROOT / "infra/bicep"
SHA_PIN = re.compile(r"uses:\s*[\w./-]+@[0-9a-f]{40}\b")
SKU_ALIAS = "Microsoft.CognitiveServices/accounts/deployments/sku.name"


def tf_text() -> str:
    return "\n".join(p.read_text() for p in sorted(TF.glob("*.tf")))


def wf(name):
    return yaml.safe_load((WF / name).read_text())


def test_both_stacks_define_the_same_four_rules():
    tf, bi = tf_text(), (BICEP / "main.bicep").read_text()
    for target in ("Microsoft.CognitiveServices/accounts", "Microsoft.OperationalInsights/workspaces", SKU_ALIAS):
        assert target in tf and target in bi, target
    assert len(re.findall(r"^    (locations|ai_accounts|model_deployment_types|log_analytics) = \{", tf, re.M)) == 4
    assert len(re.findall(r"key: '(locations|ai-accounts|model-deployment-types|log-analytics)'", bi)) == 4


def test_both_stacks_reject_global_deployment_types():
    assert '!startswith(t, "Global")' in tf_text()
    assert "startsWith(t, 'Global')" in (BICEP / "main.bicep").read_text()
    for p in TF.glob("envs/*.tfvars"):
        assert "Global" not in p.read_text(), p.name


def test_effect_defaults_to_deny_and_every_tenant_denies():
    assert re.search(r'variable "policy_effect"[\s\S]*?default\s*=\s*"Deny"', tf_text())
    assert "param policyEffect string = 'Deny'" in (BICEP / "main.bicep").read_text()
    for p in BICEP.glob("params/*.json"):
        assert json.loads(p.read_text())["parameters"]["policyEffect"]["value"] == "Deny"


def test_stacks_create_only_policy_resources():
    kinds = set(re.findall(r'^resource "([a-z_]+)"', tf_text(), re.M))
    assert kinds == {"azurerm_policy_definition", "azurerm_policy_set_definition", "azurerm_subscription_policy_assignment"}
    bi = set(re.findall(r"^resource \w+ '([^@]+)@", (BICEP / "main.bicep").read_text(), re.M))
    assert bi == {
        "Microsoft.Authorization/policyDefinitions",
        "Microsoft.Authorization/policySetDefinitions",
        "Microsoft.Authorization/policyAssignments",
    }


def test_every_tenant_has_tfvars_backend_and_bicep_params():
    for t in ("brightwater", "orchidvalley", "pinecrest"):
        assert (TF / f"envs/{t}.tfvars").exists() and (TF / f"envs/{t}.backend.hcl").exists()
        assert (BICEP / f"params/{t}.parameters.json").exists()


def test_terraform_tests_cover_the_key_paths():
    t = (TF / "tests/plan.tftest.hcl").read_text()
    for run in ("orchidvalley_canada_only", "global_deployment_types_rejected", "audit_mode_not_enforced_when_disabled"):
        assert f'run "{run}"' in t
    assert 'mock_provider "azurerm"' in t


def test_checkov_has_no_skips():
    assert "skip-check" not in (ROOT / ".checkov.yaml").read_text()


# ---------------------------------------------------------------- workflows


@pytest.mark.parametrize("name", sorted(p.name for p in WF.glob("*.yml")))
def test_workflow_hardening(name):
    d = wf(name)
    assert d["permissions"] == {"contents": "read"}, "top-level permissions must be read-only"
    text = (WF / name).read_text()
    for line in text.splitlines():
        if "uses:" in line and not line.strip().startswith("#"):
            assert SHA_PIN.search(line), f"{name}: action not pinned to a commit SHA: {line.strip()}"
    assert "client-secret" not in text and "AZURE_CLIENT_SECRET" not in text


def test_ci_runs_tests_gate_and_drift_checks():
    text = (WF / "ci.yml").read_text()
    for step in (
        "scripts/fetch_sut.sh",
        "pytest -q",
        "socassure gate",
        "socassure audit-replay",
        "render_docs.py --check",
        "gitleaks",
        "sbom-action",
        "bicep build",
    ):
        assert step in text, step


def test_infra_runs_fmt_validate_test_tflint_checkov():
    text = (WF / "infra.yml").read_text()
    for step in ("fmt -check", "validate", 'terraform -chdir="$STACK" test', "tflint", "checkov"):
        assert step in text, step


def test_deploy_is_gated_manual_and_uses_oidc():
    d = wf("deploy.yml")
    assert set(d[True]) == {"workflow_dispatch"}  # yaml reads the key `on` as True
    job = d["jobs"]["assign"]
    assert "vars.DEPLOY_ENABLED == 'true'" in job["if"]
    assert job["permissions"]["id-token"] == "write"
    assert any("azure/login" in s.get("uses", "") for s in job["steps"])


def test_teardown_needs_gate_and_confirmation():
    job = wf("teardown.yml")["jobs"]["teardown"]
    assert "vars.DEPLOY_ENABLED == 'true'" in job["if"] and "inputs.confirm == inputs.tenant" in job["if"]


def test_codeql_scans_python_and_actions():
    text = (WF / "codeql.yml").read_text()
    assert "python" in text and "actions" in text and "security-events: write" in text


def test_dependabot_covers_every_ecosystem():
    d = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text())
    assert {u["package-ecosystem"] for u in d["updates"]} >= {"pip", "github-actions", "terraform"}


def test_deploy_script_has_every_subcommand():
    text = (ROOT / ".github/scripts/deploy.sh").read_text()
    for fn in ("assign()", "smoke()", "destroy()"):
        assert fn in text


def test_sut_is_pinned_to_a_full_commit():
    cfg = yaml.safe_load((ROOT / "config/sut.yaml").read_text())["azure-ai-soc"]
    assert re.fullmatch(r"[0-9a-f]{40}", cfg["commit"])
