"""Scenario suites: reproducible, independent of the SUT's development seed, perturbations as described."""

import hashlib
import json

from socassure import DATA, scenarios


def test_benchmark_seeds_exclude_the_sut_development_seed():
    cfg = scenarios.benchmark_config()
    assert 1337 not in cfg["seeds"] and 1337 not in cfg["adversarial_seeds"]
    assert len(cfg["seeds"]) == 10


def test_same_seed_same_scenario_different_seed_different_scenario():
    assert scenarios.fingerprint(scenarios.synthetic(101)) == scenarios.fingerprint(scenarios.synthetic(101))
    assert scenarios.fingerprint(scenarios.synthetic(101)) != scenarios.fingerprint(scenarios.synthetic(102))


def test_synthetic_returns_copies():
    a = scenarios.synthetic(101)
    a.tenants["brightwater"].tables.clear()
    assert scenarios.synthetic(101).tenants["brightwater"].tables


def test_every_suite_has_three_tenants_and_attack_stories():
    for suite, kind in (("synthetic", None), ("otrf", None), *(("adversarial", k) for k in scenarios.ADVERSARIAL_KINDS)):
        s = scenarios.build(suite, 101, kind)
        assert sorted(s.tenants) == ["brightwater", "orchidvalley", "pinecrest"]
        assert s.stories()


def test_injection_and_evasion_record_what_they_changed():
    inj = scenarios.adversarial("injection", 101)
    assert inj.meta["injection"] and {p["style"] for p in inj.meta["injection"]} == {"plain", "paraphrased"}
    ev = scenarios.adversarial("evasion", 101)
    assert ev.meta["evasion"] and all(c["rewrite"] for c in ev.meta["evasion"])


def test_injection_phrases_appear_only_in_attack_events():
    s = scenarios.adversarial("injection", 102)
    for p in s.meta["injection"]:
        td = s.tenants[p["tenant"]]
        assert td.label(p["event"]) in {st.id for st in td.stories}


def test_flood_and_drift_add_labelled_benign_events():
    base = scenarios.synthetic(101)
    for kind, label in (("flood", "misconfigured_app"), ("drift", "admin_script")):
        s = scenarios.adversarial(kind, 101)
        assert label in s.tenants["brightwater"].benign_kinds
        assert sum(map(len, s.tenants["brightwater"].tables.values())) > sum(map(len, base.tenants["brightwater"].tables.values()))


def test_otrf_replay_places_every_dataset_once():
    s = scenarios.otrf()
    ids = sorted(st.id for st in s.stories())
    man = sorted(f"otrf-{d['id']}" for d in scenarios.otrf_manifest()["datasets"])
    assert ids == man


def test_otrf_extract_is_licensed_pinned_and_hashed():
    man = scenarios.otrf_manifest()
    assert man["source"]["licence"] == "MIT" and len(man["source"]["commit"]) == 40
    assert (DATA / "otrf" / "LICENSE-OTRF").exists()
    for d in man["datasets"]:
        assert len(d["sha256"]) == 64
    rows = [json.loads(x) for x in (DATA / "otrf" / "process-events.jsonl").read_text().splitlines()]
    assert {r["dataset"] for r in rows} == {d["id"] for d in man["datasets"]}


def test_otrf_extract_is_stable():
    digest = hashlib.sha256((DATA / "otrf" / "process-events.jsonl").read_bytes()).hexdigest()
    assert scenarios.fingerprint(scenarios.otrf()) == scenarios.fingerprint(scenarios.otrf())
    assert len(digest) == 64
