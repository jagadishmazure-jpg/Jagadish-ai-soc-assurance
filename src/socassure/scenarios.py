"""Seeded, reproducible scenarios with ground truth the system under test never sees.

Suites:
* `synthetic(seed)`: twenty-one days of Sentinel / Defender XDR-shaped telemetry for three fictional
  tenants, from the telemetry generator that ships with azure-ai-soc (`aisoc.synth`). That generator was
  written by the same author as the first system under test, so this suite has a home-field advantage;
  the benchmark reports it as such and uses seeds the system was not developed on.
* `adversarial(kind, seed)`: the synthetic suite with harness-authored perturbations from
  config/adversarial.yaml: prompt injection in attacker-controlled fields, evasive command lines, an
  alert flood, and a drift pattern (a new legitimate automation).
* `otrf(seed)`: process-creation events recorded from real attack tools in the OTRF Security-Datasets lab
  (MIT licence, data/otrf), replayed onto fictional workstations inside the synthetic background. This
  is the only suite whose attack telemetry was not written by this author.

Every scenario is a pure function of its arguments: the same call returns identical tables and labels."""

from __future__ import annotations

import json
import random
from datetime import timedelta
from functools import cache

import yaml

from socassure import CONFIG, DATA
from socassure.model import Scenario, Story, TenantData

SUITES = ("synthetic", "adversarial", "otrf")
ADVERSARIAL_KINDS = ("injection", "evasion", "flood", "drift")


@cache
def adversarial_config() -> dict:
    return yaml.safe_load((CONFIG / "adversarial.yaml").read_text())


@cache
def benchmark_config() -> dict:
    return yaml.safe_load((CONFIG / "benchmark.yaml").read_text())


def _generator():
    from aisoc import intel, synth
    from aisoc.tenants import tenants

    return synth, intel, tenants


@cache
def _synthetic(seed: int) -> Scenario:
    synth, intel, tenants = _generator()
    out = {}
    for tid in sorted(tenants()):
        ds = synth.generate(tid, seed)
        tables = {k: [dict(r) for r in v] for k, v in ds.tables.items()}
        tables["ThreatIntelligenceIndicator"] = intel.table(synth.DAYS)
        stories = [Story(s["id"], tid, s["kind"], s["first_event"], tuple(s["events"]), s["window"], tuple(s["techniques"])) for s in ds.stories]
        out[tid] = TenantData(tid, tables, dict(ds.labels), stories, dict(synth.BENIGN_KINDS))
    return Scenario(f"synthetic-{seed}", "synthetic", seed, out, [f"aisoc.synth generator, seed {seed}"])


def synthetic(seed: int) -> Scenario:
    """A private copy (callers may mutate it)."""
    return _synthetic(seed).copy(f"synthetic-{seed}")


def epoch():
    synth, _, _ = _generator()
    return synth.T0


def train_days() -> int:
    synth, _, _ = _generator()
    return synth.TRAIN_DAYS


def window_of(ts) -> str:
    return "train" if (ts - epoch()).days < train_days() else "holdout"


def _new_id(td: TenantData, tag: str) -> str:
    n = sum(1 for e in td.labels if e.startswith(f"{td.tenant[:2]}-{tag}")) + 1
    return f"{td.tenant[:2]}-{tag}{n:06d}"


def _add(td: TenantData, table: str, row: dict, label: str, tag: str) -> str:
    eid = _new_id(td, tag)
    td.tables.setdefault(table, []).append({**row, "EventId": eid})
    td.labels[eid] = label
    return eid


# ---------------------------------------------------------------- adversarial perturbations


def _malicious_rows(td: TenantData):
    story_ids = {s.id for s in td.stories}
    for table, rows in td.tables.items():
        for r in rows:
            if td.labels.get(r.get("EventId", "")) in story_ids:
                yield table, r


def inject(scn: Scenario, seed: int) -> list[dict]:
    """Append an injection phrase to one attacker-controlled field of every attack event that has one."""
    cfg = adversarial_config()["injection"]
    rng = random.Random(f"inject:{seed}")
    phrases = [("plain", p) for p in cfg["plain"]] + [("paraphrased", p) for p in cfg["paraphrased"]]
    placed = []
    for tid in sorted(scn.tenants):
        td = scn.tenants[tid]
        for table, r in _malicious_rows(td):
            col = cfg["fields"].get(table)
            if not col or col not in r:
                continue
            style, text = rng.choice(phrases)
            r[col] = f"{r[col]} {text}"
            placed.append({"tenant": tid, "event": r["EventId"], "table": table, "field": col, "style": style})
        # product alerts that cite an attack event carry the same text in their description
        events = {p["event"]: p for p in placed if p["tenant"] == tid}
        for a in td.tables.get("SecurityAlert", []):
            hit = next((events[e] for e in a.get("EventIds", []) if e in events), None)
            if hit:
                a["Description"] = f"{a['Description']} {next(t for s, t in phrases if s == hit['style'])}"
    return placed


def evade(scn: Scenario) -> list[dict]:
    rules = adversarial_config()["evasion"]
    changed = []
    for tid in sorted(scn.tenants):
        for table, r in _malicious_rows(scn.tenants[tid]):
            if table != "DeviceProcessEvents":
                continue
            for rule in rules:
                if rule["find"] in r.get("ProcessCommandLine", ""):
                    r["ProcessCommandLine"] = r["ProcessCommandLine"].replace(rule["find"], rule["replace"])
                    if "file" in rule:
                        r["FileName"] = rule["file"]
                    changed.append({"tenant": tid, "event": r["EventId"], "rewrite": rule["replace"].strip()})
    return changed


def flood(scn: Scenario, seed: int) -> int:
    cfg = adversarial_config()["flood"]
    rng = random.Random(f"flood:{seed}")
    t0 = epoch()
    n = 0
    for k, tid in enumerate(sorted(scn.tenants)):
        td = scn.tenants[tid]
        td.benign_kinds["misconfigured_app"] = "false_positive"
        users = [u["AccountUpn"] for u in td.tables["IdentityInfo"] if "breakglass" not in u["AccountUpn"]]
        for d in cfg["days"]:
            for b in range(cfg["bursts_per_day"]):
                ip = f"198.51.100.{200 + k * 10 + b}"
                start = t0 + timedelta(days=d, hours=rng.uniform(13, 21))
                for i, u in enumerate(rng.sample(users, cfg["users_per_burst"])):
                    _add(
                        td,
                        "SigninLogs",
                        {
                            "TimeGenerated": start + timedelta(minutes=i),
                            "UserPrincipalName": u,
                            "IPAddress": ip,
                            "Location": "US",
                            "City": "Unknown",
                            "ResultType": "50126",
                            "AppDisplayName": "Office 365",
                        },
                        "misconfigured_app",
                        "f",
                    )
                    n += 1
    return n


def drift(scn: Scenario, seed: int) -> int:
    cfg = adversarial_config()["drift"]
    rng = random.Random(f"drift:{seed}")
    t0 = epoch()
    n = 0
    for tid in sorted(scn.tenants):
        td = scn.tenants[tid]
        hosts = [a for a in td.tables["DeviceInfo"] if a["Role"] == "workstation" and a["PrimaryUser"]]
        for d in cfg["days"]:
            if d % 7 in (5, 6):
                continue
            for h in rng.sample(hosts, cfg["hosts_per_day"]):
                payload = "SQBuAHYAbwBrAGUALQBJAG4AdgBlAG4AdABvAHIAeQA="
                _add(
                    td,
                    "DeviceProcessEvents",
                    {
                        "TimeGenerated": t0 + timedelta(days=d, hours=rng.uniform(13, 20)),
                        "DeviceName": h["DeviceName"],
                        "AccountUpn": h["PrimaryUser"],
                        "FileName": "powershell.exe",
                        "ProcessCommandLine": f"powershell.exe -NoProfile -enc {payload}",
                        "InitiatingProcessFileName": "intune-agent.exe",
                        "SHA256": "0" * 64,
                    },
                    "admin_script",
                    "d",
                )
                n += 1
    return n


def adversarial(kind: str, seed: int) -> Scenario:
    if kind not in ADVERSARIAL_KINDS:
        raise ValueError(f"unknown adversarial kind {kind!r}; known: {ADVERSARIAL_KINDS}")
    scn = synthetic(seed).copy(f"adversarial-{kind}-{seed}", "adversarial")
    if kind == "injection":
        placed = inject(scn, seed)
        scn.meta["injection"] = placed
        scn.notes.append(f"injection phrases in {len(placed)} attack-event fields")
    elif kind == "evasion":
        changed = evade(scn)
        scn.meta["evasion"] = changed
        scn.notes.append(f"{len(changed)} attack command lines rewritten")
    elif kind == "flood":
        scn.notes.append(f"{flood(scn, seed)} flood sign-in events added")
    else:
        scn.notes.append(f"{drift(scn, seed)} automation events added")
    return scn


# ---------------------------------------------------------------- OTRF replay


@cache
def otrf_manifest() -> dict:
    return yaml.safe_load((DATA / "otrf" / "datasets.yaml").read_text())


@cache
def otrf_events() -> tuple[dict, ...]:
    return tuple(json.loads(line) for line in (DATA / "otrf" / "process-events.jsonl").read_text().splitlines() if line.strip())


def _base(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def otrf(seed: int = 101) -> Scenario:
    """Replay each OTRF recording as one attack story on a fictional workstation in the holdout window."""
    scn = synthetic(seed).copy(f"otrf-{seed}", "otrf")
    tids = sorted(scn.tenants)
    for td in scn.tenants.values():
        td.stories = []  # score only the replayed recordings; the synthetic stories stay as background
    t0 = epoch()
    for i, ds in enumerate(otrf_manifest()["datasets"]):
        td = scn.tenants[tids[i % len(tids)]]
        host = [a for a in td.tables["DeviceInfo"] if a["Role"] == "workstation" and a["PrimaryUser"]][3 + i // len(tids)]
        start = t0 + timedelta(days=14 + i % 7, hours=15)
        sid = f"otrf-{ds['id']}"
        ids = []
        for ev in (e for e in otrf_events() if e["dataset"] == ds["id"]):
            ids.append(
                _add(
                    td,
                    "DeviceProcessEvents",
                    {
                        "TimeGenerated": start + timedelta(seconds=ev["offset_s"]),
                        "DeviceName": host["DeviceName"],
                        "AccountUpn": host["PrimaryUser"],
                        "FileName": _base(ev["Image"]),
                        "ProcessCommandLine": ev["CommandLine"],
                        "InitiatingProcessFileName": _base(ev["ParentImage"]),
                        "SHA256": ev["SHA256"].lower(),
                    },
                    sid,
                    "o",
                )
            )
        td.stories.append(Story(sid, td.tenant, "otrf", start, tuple(ids), "holdout", (ds["technique"],)))
    scn.notes.append(f"{len(otrf_manifest()['datasets'])} OTRF recordings replayed (commit {otrf_manifest()['source']['commit'][:7]})")
    return scn


def build(suite: str, seed: int, kind: str | None = None) -> Scenario:
    if suite == "synthetic":
        return synthetic(seed)
    if suite == "adversarial":
        return adversarial(kind or "injection", seed)
    if suite == "otrf":
        return otrf(seed)
    raise ValueError(f"unknown suite {suite!r}; known: {SUITES}")


def fingerprint(scn: Scenario) -> str:
    """A short digest of tables and labels, used to prove a scenario is reproducible."""
    import hashlib

    h = hashlib.sha256()
    for tid in sorted(scn.tenants):
        td = scn.tenants[tid]
        for name in sorted(td.tables):
            for r in td.tables[name]:
                h.update(json.dumps(r, sort_keys=True, default=str).encode())
        h.update(json.dumps(sorted(td.labels.items())).encode())
    return h.hexdigest()[:16]
