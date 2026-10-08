"""Decision audit: verify an AI SOC's audit chain, rebuild every decision from it, explain it and flag gaps.

Input is a hash-chained audit log as JSON lines, one record per line, in the format azure-ai-soc writes
(`seq`, `tenant`, `at`, `actor`, `event`, `data`, `prev`, `hash`, where `hash` is the SHA-256 of the
canonical JSON of the other fields and `prev` is the previous record's hash). The verifier is written
from that description, independently of the system's own `verify`, so an auditor does not have to trust
the code that produced the log; a test checks that the two agree.

For each incident the replay rebuilds: the triage inputs and score, the routing decision and its reasons,
the investigation's tool calls, the containment plan and its digest, the approval request, each
approval, the analyst's review and every execution record. Rules then flag decisions that lack evidence
or approval, approvals that came from a non-human identity or arrived late, executions that do not
match the approved plan, and systemic gaps in what the log records."""

from __future__ import annotations

import csv
import hashlib
import html
import io
import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

GENESIS = "0" * 64
APPROVAL_TTL_MIN = 60
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
RULES = {
    "AUD-01": ("critical", "audit chain integrity: a record was edited, removed, re-ordered or moved between tenants"),
    "AUD-02": ("critical", "containment executed without enough valid approvals for the executed plan"),
    "AUD-03": ("critical", "containment executed for a plan digest that was never planned for this incident"),
    "AUD-04": ("critical", "approval recorded from a non-human identity"),
    "AUD-05": ("high", "containment executed in a live mode (not dry-run)"),
    "AUD-06": ("high", "malicious verdict escalated with no evidence gathered (no successful tool call)"),
    "AUD-07": ("high", "incident closed with no recorded triage inputs"),
    "AUD-08": ("medium", "approval decided after the approval time-to-live"),
    "AUD-09": ("medium", "model output and guardrail results for an escalated incident are not in the audit chain"),
    "AUD-10": ("low", "tool calls carry no incident id; attributed to an incident by position in the chain"),
    "AUD-11": ("info", "analyst overrode the machine verdict"),
}


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def load_chain(path: Path) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def save_chain(records: list[dict], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(canonical(r) + "\n" for r in records))
    return path


def verify(records: list[dict], tenant: str | None = None) -> tuple[bool, list[str]]:
    """Recompute every hash and link. Returns (valid, problems); the first problem is the first break."""
    problems = []
    prev = GENESIS
    tenant = tenant or (records[0]["tenant"] if records else None)
    for i, rec in enumerate(records, 1):
        body = {k: v for k, v in rec.items() if k != "hash"}
        if rec.get("seq") != i:
            problems.append(f"record {i}: sequence number {rec.get('seq')}")
        if rec.get("prev") != prev:
            problems.append(f"record {i}: previous-hash link broken")
        if hashlib.sha256(canonical(body).encode()).hexdigest() != rec.get("hash"):
            problems.append(f"record {i}: content does not match its hash")
        if rec.get("tenant") != tenant:
            problems.append(f"record {i}: tenant {rec.get('tenant')} inside the {tenant} chain")
        prev = rec.get("hash")
    return (not problems), problems


@dataclass
class Flag:
    rule: str
    detail: str

    @property
    def severity(self) -> str:
        return RULES[self.rule][0]


@dataclass
class Trail:
    tenant: str
    incident: str
    triage: dict | None = None
    route: dict | None = None
    tool_calls: list[dict] = field(default_factory=list)
    denied_calls: int = 0
    auto_closed: dict | None = None
    qa: dict | None = None
    plans: list[dict] = field(default_factory=list)
    approval_requested: dict | None = None
    approvals: list[dict] = field(default_factory=list)
    review: dict | None = None
    executions: list[dict] = field(default_factory=list)
    skipped: dict | None = None
    narrative_recorded: bool = False
    flags: list[Flag] = field(default_factory=list)

    @property
    def tier(self) -> int | None:
        return self.route["tier"] if self.route else None

    @property
    def outcome(self) -> str:
        if self.executions:
            return "contained (" + ", ".join(sorted({e["mode"] for e in self.executions})) + ")"
        if self.auto_closed:
            return "auto-closed"
        if self.skipped:
            return "containment not approved"
        if self.review:
            return "reviewed, no containment"
        return "open"


def _t(s: str | None) -> datetime | None:
    return datetime.fromisoformat(s) if s else None


def reconstruct(records: list[dict]) -> list[Trail]:
    trails: dict[str, Trail] = {}
    order: list[str] = []
    current: str | None = None

    def trail(inc: str, tenant: str) -> Trail:
        if inc not in trails:
            trails[inc] = Trail(tenant, inc)
            order.append(inc)
        return trails[inc]

    for r in records:
        d = r.get("data") or {}
        inc = d.get("incident")
        ev = r["event"]
        if ev in ("tool.call", "tool.denied"):
            if current:
                t = trails[current]
                if ev == "tool.call":
                    t.tool_calls.append({"actor": r["actor"], "tool": d.get("tool"), "rows": d.get("rows", 0), "args": d.get("args", {})})
                else:
                    t.denied_calls += 1
            continue
        if not inc:
            continue
        t = trail(inc, r["tenant"])
        current = inc
        if ev == "triage.scored":
            t.triage = {"verdict": d.get("verdict"), "p": d.get("p"), "features": d.get("features", {}), "at": r["at"], "actor": r["actor"]}
        elif ev == "case.routed":
            t.route = {"tier": d.get("tier"), "reasons": d.get("reasons", []), "actor": r["actor"]}
        elif ev == "case.auto_closed":
            t.auto_closed = {"verdict": d.get("verdict"), "confidence": d.get("confidence"), "qa_sampled": d.get("qa_sampled"), "at": r["at"]}
        elif ev == "case.qa_reviewed":
            t.qa = {"analyst": r["actor"], "verdict": d.get("verdict"), "agrees": d.get("agrees"), "at": r["at"]}
        elif ev == "containment.planned":
            t.plans.append({"digest": d.get("digest"), "actions": [list(a) for a in d.get("actions", [])], "denied": d.get("denied", [])})
        elif ev == "approval.requested":
            t.approval_requested = {"digest": d.get("digest"), "at": r["at"], "tier": d.get("tier")}
        elif ev == "approval.decided":
            t.approvals.append({"approver": r["actor"], "digest": d.get("digest"), "approved": d.get("approved"), "at": r["at"]})
        elif ev == "case.reviewed":
            t.review = {
                "analyst": r["actor"],
                "verdict": d.get("verdict"),
                "ai_verdict": d.get("ai_verdict"),
                "override": d.get("override"),
                "at": r["at"],
            }
        elif ev == "containment.executed":
            t.executions.append({k: d.get(k) for k in ("digest", "action", "target", "mode", "status")} | {"actor": r["actor"], "at": r["at"]})
        elif ev == "containment.skipped":
            t.skipped = {"digest": d.get("digest"), "reason": d.get("reason")}
        elif ev in ("narrative.written", "guardrail.result", "model.output"):
            t.narrative_recorded = True
    return [trails[i] for i in order]


def apply_rules(trails: list[Trail]) -> None:
    for t in trails:
        planned = {p["digest"]: p for p in t.plans}
        if t.executions:
            for digest in sorted({e["digest"] for e in t.executions}):
                if digest not in planned:
                    t.flags.append(Flag("AUD-03", f"executed digest {digest} not among planned {sorted(planned)}"))
                    continue
                need = max((a[2] for a in planned[digest]["actions"]), default=1)
                ok = {a["approver"] for a in t.approvals if a["approved"] and a["digest"] == digest and not _machine(a["approver"])}
                if len(ok) < need:
                    t.flags.append(Flag("AUD-02", f"digest {digest} needs {need} approver(s), chain shows {len(ok)}"))
            live = [e for e in t.executions if e["mode"] != "dry-run"]
            if live:
                t.flags.append(Flag("AUD-05", f"{len(live)} live action(s)"))
        for a in t.approvals:
            if _machine(a["approver"]):
                t.flags.append(Flag("AUD-04", f"approval by {a['approver']}"))
            if t.approval_requested and a["at"] and t.approval_requested["at"]:
                late = (_t(a["at"]) - _t(t.approval_requested["at"])).total_seconds() / 60
                if late > APPROVAL_TTL_MIN:
                    t.flags.append(Flag("AUD-08", f"{a['approver']} decided {late:.0f} min after the request"))
        if t.triage and t.triage["verdict"] == "true_positive" and (t.tier or 0) > 1 and not t.tool_calls:
            t.flags.append(Flag("AUD-06", "no successful tool call between routing and the containment plan"))
        if t.auto_closed and not t.triage:
            t.flags.append(Flag("AUD-07", "case.auto_closed with no triage.scored record"))
        if (t.tier or 0) > 1 and not t.narrative_recorded:
            t.flags.append(Flag("AUD-09", "no narrative, model output or guardrail record"))
        if t.tool_calls:
            t.flags.append(Flag("AUD-10", f"{len(t.tool_calls)} tool call(s) attributed by position"))
        if t.review and t.review.get("override"):
            t.flags.append(Flag("AUD-11", f"{t.review['analyst']}: {t.review['ai_verdict']} -> {t.review['verdict']}"))


def _machine(actor: str) -> bool:
    return actor.startswith(("agent:", "svc:"))


def explain(t: Trail, rel=lambda s: s) -> str:
    """A plain-language account of one decision, built only from the audit records."""
    parts = []
    if t.triage:
        top = sorted(((k, v) for k, v in t.triage["features"].items() if v and k != "prior"), key=lambda kv: -abs(kv[1]))[:4]
        feats = ", ".join(f"{k} {v:g}" for k, v in top) or "no extra signals"
        parts.append(f"triage scored p(malicious)={t.triage['p']} -> {t.triage['verdict']} (prior {t.triage['features'].get('prior', '?')}; {feats})")
    else:
        parts.append("no triage record")
    if t.route:
        parts.append(f"routed to tier {t.route['tier']} ({'; '.join(t.route['reasons'])})")
    if t.auto_closed:
        parts.append(f"auto-closed at confidence {t.auto_closed['confidence']}" + (" and sampled for QA" if t.auto_closed["qa_sampled"] else ""))
    if t.qa:
        parts.append(f"QA by {t.qa['analyst']}: {t.qa['verdict']} ({'agrees' if t.qa['agrees'] else 'disagrees'})")
    if t.tool_calls:
        parts.append(f"{len(t.tool_calls)} read-only tool calls returned {sum(c['rows'] for c in t.tool_calls)} rows")
    for p in t.plans:
        dual = sum(1 for a in p["actions"] if a[2] > 1)
        parts.append(f"plan {p['digest']}: {len(p['actions'])} action(s)" + (f", {dual} need two approvers" if dual else ""))
    if t.approval_requested:
        parts.append(f"approval requested {rel(t.approval_requested['at'])}")
    for a in t.approvals:
        parts.append(f"{'approved' if a['approved'] else 'rejected'} by {a['approver']} {rel(a['at'])}")
    if t.review:
        parts.append(f"{t.review['analyst']} recorded {t.review['verdict']}" + (" (override)" if t.review["override"] else ""))
    if t.executions:
        parts.append(f"{len(t.executions)} action(s) executed ({', '.join(sorted({e['mode'] for e in t.executions}))})")
    if t.skipped:
        parts.append(f"containment skipped: {t.skipped['reason']}")
    return f"{t.incident}: " + "; ".join(parts) + "."


@dataclass
class Report:
    tenant: str
    records: int
    valid: bool
    problems: list[str]
    trails: list[Trail]
    events: Counter

    def flags(self) -> Counter:
        return Counter(f.rule for t in self.trails for f in t.flags)

    def by_severity(self) -> dict[str, int]:
        c = Counter(f.severity for t in self.trails for f in t.flags)
        if not self.valid:
            c["critical"] += 1
        return {s: c.get(s, 0) for s in SEVERITY_ORDER}


def replay(records: list[dict]) -> Report:
    ok, problems = verify(records)
    trails = reconstruct(records)
    apply_rules(trails)
    tenant = records[0]["tenant"] if records else ""
    return Report(tenant, len(records), ok, problems, trails, Counter(r["event"] for r in records))


# ---------------------------------------------------------------- reports


CSV_FIELDS = ("tenant", "incident", "tier", "triage_verdict", "p_malicious", "tool_calls", "plan_digest", "actions_planned", "approvals",
              "analyst_verdict", "override", "outcome", "flags", "explanation")  # fmt: skip


def rows(reports: list[Report], rel=lambda s: s) -> list[dict]:
    out = []
    for rep in reports:
        for t in rep.trails:
            out.append(
                {
                    "tenant": t.tenant,
                    "incident": t.incident,
                    "tier": t.tier,
                    "triage_verdict": t.triage["verdict"] if t.triage else "",
                    "p_malicious": t.triage["p"] if t.triage else "",
                    "tool_calls": len(t.tool_calls),
                    "plan_digest": t.plans[-1]["digest"] if t.plans else "",
                    "actions_planned": len(t.plans[-1]["actions"]) if t.plans else 0,
                    "approvals": sum(1 for a in t.approvals if a["approved"]),
                    "analyst_verdict": t.review["verdict"] if t.review else (t.qa["verdict"] if t.qa else ""),
                    "override": bool(t.review and t.review.get("override")),
                    "outcome": t.outcome,
                    "flags": " ".join(sorted({f.rule for f in t.flags})),
                    "explanation": explain(t, rel),
                }
            )
    return out


def to_csv(reports: list[Report], rel=lambda s: s) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, lineterminator="\n")
    w.writeheader()
    w.writerows(rows(reports, rel))
    return buf.getvalue()


def summary_lines(reports: list[Report]) -> list[str]:
    lines = []
    for rep in reports:
        sev = rep.by_severity()
        lines.append(
            f"{rep.tenant}: {rep.records} records, chain {'verified' if rep.valid else 'BROKEN'}, {len(rep.trails)} decisions rebuilt; "
            f"flags critical {sev['critical']}, high {sev['high']}, medium {sev['medium']}, low {sev['low']}, info {sev['info']}"
        )
    return lines


def to_markdown(reports: list[Report], rel=lambda s: s, examples: int = 3) -> str:
    out = ["# Decision audit report", "", "## Summary", ""]
    out += [f"- {line}" for line in summary_lines(reports)]
    out += ["", "## Flags by rule", "", "| Rule | Severity | Meaning | Count |", "|---|---|---|---|"]
    total = Counter()
    for rep in reports:
        total.update(rep.flags())
        if not rep.valid:
            total["AUD-01"] += 1
    for rule, (sev, meaning) in RULES.items():
        out.append(f"| {rule} | {sev} | {meaning} | {total.get(rule, 0)} |")
    out += ["", "## Example decisions", ""]
    for rep in reports:
        shown = [t for t in rep.trails if t.executions][:examples] + [t for t in rep.trails if t.auto_closed][:1]
        for t in shown:
            out.append(f"- **{rep.tenant}** {explain(t, rel)}")
    for rep in reports:
        if rep.problems:
            out += ["", f"## Integrity problems in {rep.tenant}", ""] + [f"- {p}" for p in rep.problems[:10]]
    return "\n".join(out) + "\n"


def to_html(reports: list[Report], rel=lambda s: s) -> str:
    rs = rows(reports, rel)
    head = "".join(f"<th>{html.escape(k)}</th>" for k in CSV_FIELDS)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(str(r[k]))}</td>" for k in CSV_FIELDS) + "</tr>" for r in rs)
    summ = "".join(f"<li>{html.escape(line)}</li>" for line in summary_lines(reports))
    rules = "".join(f"<tr><td>{k}</td><td>{s}</td><td>{html.escape(m)}</td></tr>" for k, (s, m) in RULES.items())
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>Decision audit report</title>"
        "<style>body{font-family:sans-serif;margin:2em}table{border-collapse:collapse;font-size:12px}"
        "td,th{border:1px solid #ccc;padding:3px 6px;vertical-align:top}</style></head><body>"
        f"<h1>Decision audit report</h1><ul>{summ}</ul><h2>Rules</h2><table><tr><th>Rule</th><th>Severity</th><th>Meaning</th></tr>{rules}</table>"
        f"<h2>Decisions</h2><table><tr>{head}</tr>{body}</table></body></html>\n"
    )


def write_reports(reports: list[Report], folder: Path, rel=lambda s: s) -> list[Path]:
    folder.mkdir(parents=True, exist_ok=True)
    paths = [folder / "audit-report.md", folder / "audit-report.html", folder / "audit-decisions.csv"]
    paths[0].write_text(to_markdown(reports, rel))
    paths[1].write_text(to_html(reports, rel))
    paths[2].write_text(to_csv(reports, rel))
    return paths
