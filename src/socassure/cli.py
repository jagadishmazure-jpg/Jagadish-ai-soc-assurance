"""socassure: command-line entry point. Every command is offline and deterministic.

socassure suites                       scenario suites and what is in them
socassure bench [--suite S] [--kind K] systems side by side, with 95% intervals
socassure compare [--a X --b Y]        paired differences between two systems
socassure otrf                         replay of public attack recordings, per dataset
socassure adversarial                  injection, evasion, flood and drift suites
socassure evasion                      which detections each command-line rewrite defeats
socassure claim --k K --n N --claimed P   check a vendor's headline number
socassure fmea                         failure modes ranked by risk, expected vs observed
socassure chaos [--experiment NAME]    run the fault-injection experiments
socassure residency [--deployment D]   data flows and model endpoints against the residency policy
socassure iac                          the Azure Policy parameters against the residency policy
socassure validate [--agent A]         model-risk validation against acceptance criteria
socassure drift                        population stability of the triage score
socassure challenger                   champion vs challenger vs rules
socassure audit-replay [--out DIR]     verify chains, rebuild and explain decisions, write reports
socassure scorecard [--product P]      weighted product scorecard
socassure export --system S --seed N --out F   decisions as JSONL (the recorded-adapter format)
socassure gate                         release gate for this repository's own claims
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from socassure import OUT, audit_replay, benchmark, claims, failures, modelrisk, residency, scenarios, scorecard

SUT = "azure-ai-soc"
DEFAULT_SYSTEMS = [SUT, "always-escalate", "severity-rules"]


def table(rows: list[list], header: list[str]) -> str:
    cells = [[str(c) for c in header]] + [[("" if c is None else str(c)) for c in r] for r in rows]
    widths = [max(len(r[i]) for r in cells) for i in range(len(header))]
    line = lambda r: "  ".join(c.ljust(w) for c, w in zip(r, widths, strict=True)).rstrip()  # noqa: E731
    return "\n".join([line(cells[0]), "  ".join("-" * w for w in widths)] + [line(r) for r in cells[1:]])


def rel(ts) -> str:
    """Scenario time as day and clock relative to the synthetic epoch (D14 09:05), never a calendar date."""
    if not ts:
        return ""
    t = datetime.fromisoformat(ts) if isinstance(ts, str) else ts
    d = t - scenarios.epoch()
    return f"D{d.days} {t:%H:%M}"


# ---------------------------------------------------------------- benchmark


def cmd_suites(a) -> int:
    cfg = scenarios.benchmark_config()
    rows = []
    for seed in cfg["seeds"][:1]:
        s = scenarios.synthetic(seed)
        rows.append(
            [
                "synthetic",
                f"{len(cfg['seeds'])} seeds ({cfg['seeds'][0]}-{cfg['seeds'][-1]})",
                len(s.tenants),
                len(s.stories()),
                "azure-ai-soc generator, seeds the SUT never used",
            ]
        )
    for kind in scenarios.ADVERSARIAL_KINDS:
        s = scenarios.adversarial(kind, cfg["adversarial_seeds"][0])
        rows.append([f"adversarial/{kind}", f"{len(cfg['adversarial_seeds'])} seeds", len(s.tenants), len(s.stories()), "; ".join(s.notes)])
    o = scenarios.otrf()
    rows.append(["otrf", "1 placement seed", len(o.tenants), len(o.stories()), "; ".join(o.notes)])
    print(table(rows, ["suite", "runs", "tenants", "attack stories / run", "notes"]))
    return 0


def _bench(systems, suite, kind, window) -> None:
    card = benchmark.scorecard(systems, suite, window, kind)
    print(f"suite {suite}{'/' + kind if kind else ''}, window {window or 'all'}, {card['units']} tenant-runs; 95% cluster-bootstrap intervals")
    rows = []
    for m, (label, _, digits) in benchmark.METRICS.items():
        rows.append([label] + [card["estimates"][s][m].fmt(digits) for s in systems])
    for c in benchmark.COUNTS:
        rows.append([c.replace("_", " ")] + [card["counts"][s][c] for s in systems])
    print(table(rows, ["metric", *systems]))


def cmd_bench(a) -> int:
    systems = a.systems.split(",") if a.systems else DEFAULT_SYSTEMS
    _bench(systems, a.suite, a.kind, None if a.window == "all" else a.window)
    return 0


def cmd_compare(a) -> int:
    card = benchmark.scorecard([a.a, a.b])
    print(f"{a.a} minus {a.b}, holdout window, {card['units']} paired tenant-runs; 95% paired bootstrap intervals")
    rows = []
    for m, (label, _, digits) in benchmark.METRICS.items():
        d = benchmark.diff(card, a.a, a.b, m)
        excl = "" if d.value is None or d.lo is None else ("yes" if d.lo > 0 or d.hi < 0 else "no")
        rows.append([label, card["estimates"][a.a][m].fmt(digits), card["estimates"][a.b][m].fmt(digits), d.fmt(digits), excl])
    print(table(rows, ["metric", a.a, a.b, "difference", "interval excludes 0"]))
    return 0


def cmd_otrf(a) -> int:
    r = benchmark.suite_runs(SUT, "otrf")[0]
    man = {d["id"]: d for d in scenarios.otrf_manifest()["datasets"]}
    rows = []
    for x in benchmark.story_table(r):
        ds = man[x["story"].removeprefix("otrf-")]
        rows.append([ds["id"], ds["technique"], ds.get("sut_rule_expected") or "-", "yes" if x["detected"] else "no",
                     ",".join(x["verdicts"]) or "-", "yes" if x["auto_closed"] else "no", "yes" if x["contained"] else "no"])  # fmt: skip
    print(f"OTRF Security-Datasets replay (MIT licence, commit {scenarios.otrf_manifest()['source']['commit'][:12]}); system {SUT}")
    print(table(rows, ["dataset", "technique", "SUT rule expected", "detected", "verdict", "auto-closed", "contained"]))
    k = sum(1 for x in rows if x[3] == "yes")
    c = claims.check(k, len(rows), 0)
    print(f"detected {k}/{len(rows)} = {c['observed_pct']:.1f}% (95% Wilson {c['lo']:.1f}-{c['hi']:.1f}%)")
    return 0


def cmd_adversarial(a) -> int:
    metrics = (
        "detection_recall",
        "malicious_recall",
        "attacks_auto_closed",
        "benign_auto_closed",
        "verdict_accuracy",
        "binary_accuracy",
        "analyst_minutes",
    )
    rows = []
    for kind in scenarios.ADVERSARIAL_KINDS:
        card = benchmark.scorecard([SUT], "adversarial", "holdout", kind)
        e, c = card["estimates"][SUT], card["counts"][SUT]
        rows.append([kind, c["incidents"]] + [e[m].fmt(benchmark.METRICS[m][2]) for m in metrics])
    base = benchmark.scorecard([SUT], "synthetic", "holdout", seeds=scenarios.benchmark_config()["adversarial_seeds"])
    e, c = base["estimates"][SUT], base["counts"][SUT]
    rows.insert(0, ["none (same seeds)", c["incidents"]] + [e[m].fmt(benchmark.METRICS[m][2]) for m in metrics])
    print(f"system {SUT}, holdout window, {len(scenarios.benchmark_config()['adversarial_seeds'])} seeds per suite")
    print(table(rows, ["perturbation", "incidents"] + [benchmark.METRICS[m][0] for m in metrics]))
    return 0


def cmd_evasion(a) -> int:
    rows = []
    for r in failures.evasion_report():
        lost = ", ".join(f"{k}" for k in sorted(r["lost"])) or "-"
        kept = ", ".join(f"{k}" for k in sorted(r["kept"])) or "-"
        rows.append([r["rewrite"], r["events"], lost, kept, r["uncited"]])
    print(
        f"attack command lines rewritten in {len(scenarios.benchmark_config()['adversarial_seeds'])} seeds; SUT alert sources citing the rewritten events"
    )
    print(table(rows, ["rewrite", "events", "detections lost", "detections still firing", "events no longer cited by any alert"]))
    return 0


def cmd_claim(a) -> int:
    c = claims.check(a.k, a.n, a.claimed)
    if c["observed_pct"] is None:
        print(f"claimed {a.claimed:g}%; observed 0/0: {c['verdict']}")
    else:
        print(
            f"claimed {a.claimed:g}%; observed {a.k}/{a.n} = {c['observed_pct']:.1f}% (95% Wilson interval {c['lo']:.1f}-{c['hi']:.1f}%): {c['verdict']}"
        )
    for m in (10, 5, 2):
        print(f"items needed for a +/-{m} point margin at {a.claimed:g}%: {claims.needed(m, a.claimed)}")
    print("ask the vendor:")
    for k, q in claims.QUESTIONS:
        print(f"  - {k}: {q}")
    return 0


# ---------------------------------------------------------------- failure modes


def cmd_fmea(a) -> int:
    agree = {fm: (exp, obs, ok) for fm, exp, obs, ok in failures.agreement()}
    rows = []
    for fm in failures.rpn_ranking():
        exp, obs, ok = agree[fm["id"]]
        rows.append([fm["id"], fm["name"], fm["severity"], fm["occurrence"], fm["detection"], fm["rpn"], exp, obs, "yes" if ok else "NO"])
    print("ranked by risk priority number (severity x occurrence x detection, 1-10 each); observed from the experiments")
    print(table(rows, ["id", "failure mode", "S", "O", "D", "RPN", "expected", "observed", "agrees"]))
    if a.detail:
        for fm in failures.catalogue():
            print(f"\n{fm['id']} {fm['name']}")
            for k in ("cause", "effect", "detection_method", "mitigation"):
                print(f"  {k.replace('_', ' ')}: {fm[k]}")
    return 0


def _print_result(r: failures.Result) -> None:
    print(f"{r.id} {r.name}: {'safe' if r.safe else 'FINDING'}")
    print(f"  injected: {r.injected}")
    for k, v in r.observations:
        print(f"  - {k}: {v}")
    if r.note:
        print(f"  note: {r.note}")


def cmd_chaos(a) -> int:
    names = [a.experiment] if a.experiment else [fm["experiment"] for fm in failures.catalogue()]
    for i, n in enumerate(names):
        if i:
            print()
        _print_result(failures.run_experiment(n))
    return 0


# ---------------------------------------------------------------- residency


def cmd_residency(a) -> int:
    names = [a.deployment] if a.deployment else list(residency.deployments())
    for i, name in enumerate(names):
        dep = residency.load_deployment(name)
        checks = residency.check(dep)
        s = residency.summary(checks)
        if i:
            print()
        print(f"{dep['name']}: {len(checks)} flow checks, {s['pass']} pass, {s['violation']} violation, {s['unknown']} unknown")
        shown = checks if a.all else [c for c in checks if c.result != "pass"]
        if shown:
            print(table([[c.tenant, c.flow, c.name, c.processed_in, c.allowed, c.result, c.reason] for c in shown],
                        ["tenant", "flow", "what", "processed in", "allowed", "result", "why"]))  # fmt: skip
    print()
    print("system under test infrastructure code (regions it can be deployed to, by tenant geography):")
    print(table([list(r) for r in residency.sut_iac_findings()], ["tenant", "regions", "result"]))
    return 0


def cmd_iac(a) -> int:
    rows = residency.iac_consistency()
    print(table([[t, s, "yes" if ok else "NO", d] for t, s, ok, d in rows], ["tenant", "stack", "enforces policy", "detail"]))
    return 0 if all(ok for _, _, ok, _ in rows) else 1


# ---------------------------------------------------------------- model risk


def cmd_validate(a) -> int:
    agents = [a.agent] if a.agent else list(modelrisk.inventory()["agents"])
    rows = []
    for ag in agents:
        for c in modelrisk.validate(ag):
            rows.append([ag, c.metric, c.suite, c.estimate.fmt(1), f"{c.op} {c.threshold:g}", f"{c.bound_used:.1f}" if c.bound_used is not None else "n/a", "pass" if c.passed else "FAIL"])  # fmt: skip
    print("criteria judged on the conservative end of the 95% interval (lower bound for >=, upper bound for <=)")
    print(table(rows, ["agent", "criterion", "suite", "estimate [95% CI]", "threshold", "bound used", "result"]))
    return 0


def cmd_drift(a) -> int:
    d = modelrisk.drift_report()
    cfg = scenarios.benchmark_config()["drift"]
    rows = [["reference", d["reference"]["n"], "", "", d["reference"]["incidents_per_scenario"], d["reference"]["binary_accuracy"]]]
    for k in ("comparison", "drifted"):
        rows.append([k, d[k]["n"], f"{d[k]['psi']:.3f}", d[k]["status"], d[k]["incidents_per_scenario"], d[k]["binary_accuracy"]])
    print(f"PSI of the triage agent's p(malicious), holdout window; watch >= {cfg['psi_watch']}, drift >= {cfg['psi_alert']}")
    print(table(rows, ["window", "scores", "PSI", "status", "incidents per run", "binary accuracy %"]))
    return 0


def cmd_challenger(a) -> int:
    c = modelrisk.challenger()
    rows = [
        [r["metric"], r["champion"].fmt(r["digits"]), r["challenger"].fmt(r["digits"]), r["rules"].fmt(r["digits"]), r["diff"].fmt(r["digits"])]
        for r in c["rows"]
    ]
    print(f"holdout window, {c['units']} tenant-runs; champion = feedback loop on, challenger = feedback loop off, rules = severity-rules")
    print(table(rows, ["metric", "champion", "challenger", "rules", "champion - challenger"]))
    return 0


# ---------------------------------------------------------------- audit


def cmd_audit_replay(a) -> int:
    r = benchmark.run(SUT, scenarios.synthetic(a.seed))
    reports = [audit_replay.replay(r.tenants[t].audit) for t in sorted(r.tenants)]
    print(f"audit chains from {SUT} on synthetic seed {a.seed}, verified independently of the SUT's own code")
    for line in audit_replay.summary_lines(reports):
        print(f"  {line}")
    total = sum((rep.flags() for rep in reports), start=__import__("collections").Counter())
    rows = [[k, sev, total.get(k, 0), meaning] for k, (sev, meaning) in audit_replay.RULES.items()]
    print(table(rows, ["rule", "severity", "count", "meaning"]))
    ex = next(t for rep in reports for t in rep.trails if t.executions)
    print("example explanation:")
    print(f"  {audit_replay.explain(ex, rel)}")
    if a.show == "md":
        print()
        print(audit_replay.to_markdown(reports, rel, examples=1).rstrip())
    elif a.show == "csv":
        print()
        print("\n".join(audit_replay.to_csv(reports, rel).splitlines()[: a.rows + 1]))
    if a.out:
        paths = audit_replay.write_reports(reports, Path(a.out), rel)
        print("wrote " + ", ".join(p.name for p in paths) + f" to {a.out}")
    return 0


# ---------------------------------------------------------------- scorecard


def cmd_scorecard(a) -> int:
    crit = scorecard.criteria()
    prods = [a.product] if a.product else list(scorecard.products())
    summary = []
    for name in prods:
        p = scorecard.products()[name]
        rows, total = scorecard.score(name)
        summary.append([p["product"], "not scored" if total is None else f"{total:.1f}", p["status"], p["public_docs"]])
        if total is not None and (a.product or len(prods) > 1):
            print(f"{p['product']}: {total:.1f} / 100")
            print(table([[r.criterion, r.weight, r.claimed, r.level, r.effective, "; ".join(r.reasons)] for r in rows],
                        ["criterion", "weight", "claimed", "evidence level", "effective", "capped because"]))  # fmt: skip
            print()
    print(f"weights sum to {sum(c['weight'] for c in crit['criteria'])}; scores 0-5; total = sum(weight x effective / 5)")
    print(table(summary, ["product", "score / 100", "status", "public docs"]))
    return 0


def cmd_export(a) -> int:
    from socassure.adapters import recorded

    r = benchmark.run(a.system, scenarios.build(a.suite, a.seed))
    p = recorded.export(r, Path(a.out))
    print(f"wrote {len(r.decisions())} decisions to {p}")
    return 0


# ---------------------------------------------------------------- gate


def gate_checks() -> list[tuple[str, bool, str]]:
    out = []
    agree = failures.agreement()
    bad = [fm for fm, _, _, ok in agree if not ok]
    out.append(
        (
            "FMEA: every experiment's outcome matches the documented expectation",
            not bad,
            f"{len(agree) - len(bad)}/{len(agree)} agree" + (f"; differ: {bad}" if bad else ""),
        )
    )
    card = benchmark.scorecard([SUT, "always-escalate"])
    e = card["estimates"][SUT]
    out.append(
        (
            "benchmark: no attack auto-closed on synthetic holdout (upper bound <= 1%)",
            e["attacks_auto_closed"].hi <= 1,
            e["attacks_auto_closed"].fmt(1),
        )
    )
    d = benchmark.diff(card, SUT, "always-escalate", "analyst_minutes")
    out.append(("benchmark: analyst minutes below always-escalate (interval excludes 0)", d.hi < 0, d.fmt(0)))
    reps = [audit_replay.replay(o.audit) for r in benchmark.suite_runs(SUT, "synthetic") for o in r.tenants.values()]
    crit = sum(rep.by_severity()["critical"] for rep in reps)
    out.append(
        ("audit: every chain verifies and no critical flag", all(rep.valid for rep in reps) and crit == 0, f"{len(reps)} chains, {crit} critical")
    )
    prop = residency.summary(residency.check(residency.load_deployment("proposed")))
    out.append(
        (
            "residency: proposed layout passes every flow check",
            prop["violation"] + prop["unknown"] == 0,
            f"{prop['pass']} pass, {prop['violation']} violation, {prop['unknown']} unknown",
        )
    )
    iac = residency.iac_consistency()
    out.append(
        (
            "residency: Terraform and Bicep policy parameters enforce the policy",
            all(ok for *_, ok, _ in iac),
            f"{sum(ok for *_, ok, _ in iac)}/{len(iac)}",
        )
    )
    probes = failures.run_experiment("containment_probes")
    out.append(("response: every unsafe containment attempt refused", probes.safe, f"{len(probes.observations)} probes"))
    real = [
        n for n, p in scorecard.products().items() if n != SUT and any((s or {}).get("score") is not None for s in (p.get("scores") or {}).values())
    ]
    out.append(("scorecard: no scores for real products in the repository", not real, ", ".join(real) or "none"))
    return out


def cmd_gate(a) -> int:
    checks = gate_checks()
    print(table([[n, "pass" if ok else "FAIL", d] for n, ok, d in checks], ["check", "result", "detail"]))
    ok = all(c[1] for c in checks)
    print(f"gate {'passed' if ok else 'FAILED'}: {sum(c[1] for c in checks)}/{len(checks)}")
    return 0 if ok else 1


# ---------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="socassure", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("suites").set_defaults(fn=cmd_suites)
    p = sub.add_parser("bench")
    p.add_argument("--suite", default="synthetic", choices=scenarios.SUITES)
    p.add_argument("--kind", choices=scenarios.ADVERSARIAL_KINDS)
    p.add_argument("--systems")
    p.add_argument("--window", default="holdout", choices=("holdout", "train", "all"))
    p.set_defaults(fn=cmd_bench)
    p = sub.add_parser("compare")
    p.add_argument("--a", default=SUT)
    p.add_argument("--b", default="always-escalate")
    p.set_defaults(fn=cmd_compare)
    sub.add_parser("otrf").set_defaults(fn=cmd_otrf)
    sub.add_parser("adversarial").set_defaults(fn=cmd_adversarial)
    sub.add_parser("evasion").set_defaults(fn=cmd_evasion)
    p = sub.add_parser("claim")
    p.add_argument("--k", type=int, required=True, help="successes observed")
    p.add_argument("--n", type=int, required=True, help="items observed")
    p.add_argument("--claimed", type=float, required=True, help="claimed percentage")
    p.set_defaults(fn=cmd_claim)
    p = sub.add_parser("fmea")
    p.add_argument("--detail", action="store_true", help="cause, effect, detection and mitigation per failure mode")
    p.set_defaults(fn=cmd_fmea)
    p = sub.add_parser("chaos")
    p.add_argument("--experiment", choices=sorted(failures.EXPERIMENTS))
    p.set_defaults(fn=cmd_chaos)
    p = sub.add_parser("residency")
    p.add_argument("--deployment", choices=sorted(residency.deployments()))
    p.add_argument("--all", action="store_true", help="show passing checks too")
    p.set_defaults(fn=cmd_residency)
    sub.add_parser("iac").set_defaults(fn=cmd_iac)
    p = sub.add_parser("validate")
    p.add_argument("--agent", choices=("triage", "investigation", "response"))
    p.set_defaults(fn=cmd_validate)
    sub.add_parser("drift").set_defaults(fn=cmd_drift)
    sub.add_parser("challenger").set_defaults(fn=cmd_challenger)
    p = sub.add_parser("audit-replay")
    p.add_argument("--seed", type=int, default=scenarios.benchmark_config()["chaos_seed"])
    p.add_argument("--out", help="folder for audit-report.md / .html / audit-decisions.csv")
    p.add_argument("--show", choices=("md", "csv"), help="also print the Markdown report or the first CSV rows")
    p.add_argument("--rows", type=int, default=4, help="CSV rows to print with --show csv")
    p.set_defaults(fn=cmd_audit_replay)
    p = sub.add_parser("scorecard")
    p.add_argument("--product")
    p.set_defaults(fn=cmd_scorecard)
    p = sub.add_parser("export")
    p.add_argument("--system", default=SUT)
    p.add_argument("--suite", default="synthetic", choices=scenarios.SUITES)
    p.add_argument("--seed", type=int, default=scenarios.benchmark_config()["chaos_seed"])
    p.add_argument("--out", default=str(OUT / "decisions.jsonl"))
    p.set_defaults(fn=cmd_export)
    sub.add_parser("gate").set_defaults(fn=cmd_gate)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
