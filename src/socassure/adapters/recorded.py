"""Score decisions exported from any product, without running it.

Input: a JSONL file with one object per incident and these keys (unknown ones are ignored):
`tenant`, `incident_id`, `event_ids` (list), `first_alert` (ISO time), `verdict`, `p_malicious` (or null),
`auto_closed` (bool), `reviewed` (bool), `review_minutes`, `final_verdict`, `contained_at` (ISO time or
null), `tokens_in`, `tokens_out`. The scenario that was replayed supplies the ground truth.

`export(result, path)` writes the same format from any `SutResult`, which is how the tests prove the
round trip; a vendor POC would produce the file from the product's incident export instead."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from socassure.model import Decision, Scenario, SutResult, TenantOutcome
from socassure.oracle import Oracle
from socassure.scenarios import window_of

FIELDS = (
    "tenant",
    "incident_id",
    "event_ids",
    "first_alert",
    "alerts",
    "verdict",
    "p_malicious",
    "tier",
    "auto_closed",
    "reviewed",
    "review_minutes",
    "final_verdict",
    "actions_executed",
    "contained_at",
    "tokens_in",
    "tokens_out",
)


def export(result: SutResult, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for d in result.decisions():
            row = {k: getattr(d, k) for k in FIELDS}
            row["event_ids"] = list(d.event_ids)
            for k in ("first_alert", "contained_at"):
                row[k] = row[k].isoformat() if row[k] else None
            f.write(json.dumps(row, sort_keys=True) + "\n")
    return path


class RecordedDecisions:
    name = "recorded"
    description = "decisions exported from a product run (JSONL), scored against the replayed scenario"
    supported_faults: frozenset[str] = frozenset()

    def __init__(self, path: str | Path, product: str = "recorded") -> None:
        self.path = Path(path)
        self.name = product

    def run(self, scenario: Scenario, oracle: Oracle | None = None, faults: frozenset[str] = frozenset()) -> SutResult:
        if faults:
            raise NotImplementedError("a recording cannot be re-run with faults")
        out: dict[str, TenantOutcome] = {t: TenantOutcome(t) for t in scenario.tenants}
        for line in self.path.read_text().splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            if r["tenant"] not in out:
                raise ValueError(f"tenant {r['tenant']!r} is not in scenario {scenario.id}")
            first = datetime.fromisoformat(r["first_alert"])
            contained = datetime.fromisoformat(r["contained_at"]) if r.get("contained_at") else None
            out[r["tenant"]].decisions.append(
                Decision(
                    r["tenant"],
                    r["incident_id"],
                    tuple(r["event_ids"]),
                    first,
                    int(r.get("alerts", 1)),
                    window_of(first),
                    r["verdict"],
                    r.get("p_malicious"),
                    int(r.get("tier", 0)),
                    bool(r["auto_closed"]),
                    bool(r.get("reviewed", False)),
                    float(r.get("review_minutes", 0)),
                    r.get("final_verdict") or r["verdict"],
                    actions_executed=int(r.get("actions_executed", 0)),
                    contained_at=contained,
                    tokens_in=int(r.get("tokens_in", 0)),
                    tokens_out=int(r.get("tokens_out", 0)),
                )
            )
        return SutResult(self.name, scenario, out, [f"recorded from {self.path.name}"])
