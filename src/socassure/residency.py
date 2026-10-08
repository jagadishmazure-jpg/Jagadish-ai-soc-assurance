"""Data residency: check every data flow and model endpoint against each tenant's residency policy.

The policy (config/residency/policy.yaml) gives each tenant a home geography and each data class a scope.
A deployment description (config/residency/deployments/*.yaml) says where each flow lands for each tenant.
`check(deployment)` resolves every flow to the geography where its data is processed and compares:

* a region resolves to its geography;
* a model endpoint resolves through its deployment type: `global` types may process anywhere, so they
  fail any geography-bound data class; `data_zone` types process within the region's data zone, which is
  allowed only when the tenant allows data zones and the zone sits inside its geography; `geography`
  types (Standard, regional provisioned) stay in the region's geography;
* an unset deployment type or an unknown region is `unknown`, which counts as a failure (fail closed);
* human access (analysts) is checked like a flow: viewing data from another country is cross-border access.

`sut_iac_findings()` reads the system under test's own Terraform and Bicep to see which regions it can be
deployed to, and `iac_consistency()` checks this repository's Azure Policy parameters against the policy."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import cache
from pathlib import Path

import yaml

from socassure import CONFIG, ROOT

RES = CONFIG / "residency"


@cache
def policy() -> dict:
    return yaml.safe_load((RES / "policy.yaml").read_text())


def deployments() -> dict[str, Path]:
    return {p.stem: p for p in sorted((RES / "deployments").glob("*.yaml"))}


def load_deployment(name: str) -> dict:
    return yaml.safe_load(deployments()[name].read_text())


def geography_of(region: str) -> str | None:
    for g, spec in policy()["geographies"].items():
        if region in spec["regions"]:
            return g
    return None


@dataclass(frozen=True)
class FlowCheck:
    tenant: str
    flow: str
    name: str
    data_class: str
    lands: str
    processed_in: str
    allowed: str
    result: str  # pass | violation | unknown
    reason: str


def _resolve(where, pol: dict) -> tuple[str, str]:
    """(processed-in description, resolved geography or 'global' / 'unknown')."""
    if isinstance(where, dict):  # model endpoint
        region, dtype = where.get("region"), where.get("deployment_type")
        scope = pol["deployment_types"].get(dtype)
        geo = geography_of(region) if region else None
        if scope is None:
            return f"{region} ({dtype or 'type not set'})", "unknown"
        if scope == "global":
            return f"{region} {dtype}: any Azure region", "global"
        if scope == "data_zone":
            zone = pol["geographies"].get(geo, {}).get("data_zone") if geo else None
            if not zone:
                return f"{region} {dtype}: no data zone for this region", "unknown"
            return f"{region} {dtype}: {zone} data zone", f"zone:{zone}"
        return f"{region} {dtype}: {geo}", geo or "unknown"
    if where == "global":
        return "global service", "global"
    if where in pol["geographies"]:
        return where, where
    geo = geography_of(str(where))
    return f"{where} ({geo or 'unknown region'})", geo or "unknown"


def check(deployment: dict) -> list[FlowCheck]:
    pol = policy()
    out = []
    for tid, t in sorted(pol["tenants"].items()):
        dep = deployment["tenants"][tid]
        for f in pol["flows"]:
            dc = pol["data_classes"][f["data_class"]]
            where = dep.get(f["where"])
            text, geo = _resolve(where, pol)
            if dc["scope"] == "anywhere":
                res, why, allowed = "pass", "data class may be processed anywhere", "anywhere"
            else:
                allowed = t["geography"] + (" (data zone allowed)" if t.get("allow_data_zone") else "")
                if geo == "unknown":
                    res, why = "unknown", "processing location cannot be established; treated as a failure"
                elif geo == "global":
                    res, why = "violation", "global processing for a geography-bound data class"
                elif geo.startswith("zone:"):
                    zone_geo = pol["data_zones"].get(geo.split(":", 1)[1])
                    if not t.get("allow_data_zone"):
                        res, why = "violation", "tenant does not allow data-zone processing"
                    elif zone_geo != t["geography"]:
                        res, why = "violation", f"data zone spans {zone_geo}, tenant requires {t['geography']}"
                    else:
                        res, why = "pass", "data zone inside the tenant geography"
                elif geo == t["geography"]:
                    res, why = "pass", "inside the tenant geography"
                else:
                    res, why = "violation", f"{geo} is outside {t['geography']}" + (" (cross-border access)" if f["where"] == "analysts" else "")
            if isinstance(where, dict) and where.get("verified") is False and res == "pass":
                why += "; model availability unverified"
            out.append(FlowCheck(tid, f["id"], f["name"], f["data_class"], str(f["where"]), text, allowed, res, why))
    return out


def summary(checks: list[FlowCheck]) -> dict[str, int]:
    return {k: sum(1 for c in checks if c.result == k) for k in ("pass", "violation", "unknown")}


# ---------------------------------------------------------------- IaC


def sut_iac_findings(sut_root: Path | None = None) -> list[tuple[str, str, str]]:
    """(tenant, regions the SUT's Terraform accepts in the tenant's geography, verdict)."""
    root = sut_root or ROOT / ".sut" / "azure-ai-soc"
    tf = (root / "infra/terraform/variables.tf").read_text()
    m = re.search(r'variable "location"[\s\S]*?contains\(\[([^\]]*)\]', tf)
    regions = re.findall(r'"([a-z0-9]+)"', m.group(1)) if m else []
    bicep = (root / "infra/bicep/main.bicep").read_text()
    default = re.search(r"param location string = '([a-z0-9]+)'", bicep)
    out = [("all", f"Terraform accepts {', '.join(regions)}; Bicep default {default.group(1) if default else '?'}", "info")]
    for tid, t in sorted(policy()["tenants"].items()):
        ok = [r for r in regions if geography_of(r) == t["geography"]]
        out.append((tid, ", ".join(ok) or "none", "deployable in geography" if ok else "cannot be deployed in its geography"))
    return out


def tfvars(tenant: str) -> dict:
    text = (ROOT / "infra/terraform/envs" / f"{tenant}.tfvars").read_text()
    out = {}
    for key in ("allowed_locations", "allowed_model_deployment_types"):
        m = re.search(rf"{key}\s*=\s*\[([^\]]*)\]", text)
        out[key] = re.findall(r'"([^"]+)"', m.group(1)) if m else []
    m = re.search(r'policy_effect\s*=\s*"(\w+)"', text)
    out["policy_effect"] = m.group(1) if m else None
    return out


def bicep_params(tenant: str) -> dict:
    p = json.loads((ROOT / "infra/bicep/params" / f"{tenant}.parameters.json").read_text())["parameters"]
    return {
        "allowed_locations": p["allowedLocations"]["value"],
        "allowed_model_deployment_types": p["allowedModelDeploymentTypes"]["value"],
        "policy_effect": p["policyEffect"]["value"],
    }


def iac_consistency() -> list[tuple[str, str, bool, str]]:
    """(tenant, stack, consistent, detail): the Azure Policy parameters must enforce the residency policy."""
    pol = policy()
    out = []
    for tid, t in sorted(pol["tenants"].items()):
        geo = pol["geographies"][t["geography"]]
        allowed_types = {
            k for k, v in pol["deployment_types"].items() if v == "geography" or (v == "data_zone" and t.get("allow_data_zone") and geo["data_zone"])
        }
        for stack, vals in (("terraform", tfvars(tid)), ("bicep", bicep_params(tid))):
            problems = []
            outside = [r for r in vals["allowed_locations"] if geography_of(r) != t["geography"]]
            if outside:
                problems.append(f"regions outside {t['geography']}: {outside}")
            extra = sorted(set(vals["allowed_model_deployment_types"]) - allowed_types)
            if extra:
                problems.append(f"deployment types beyond the policy: {extra}")
            if vals["policy_effect"] != "Deny":
                problems.append(f"effect {vals['policy_effect']} (Deny required)")
            out.append(
                (
                    tid,
                    stack,
                    not problems,
                    "; ".join(problems) or f"{len(vals['allowed_locations'])} regions, types {sorted(vals['allowed_model_deployment_types'])}",
                )
            )
    return out
