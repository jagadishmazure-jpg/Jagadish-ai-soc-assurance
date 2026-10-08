"""Product scorecard and the vendor-claim checker."""

import pytest

from socassure import claims, scorecard


def test_weights_sum_to_100_and_scale_is_complete():
    c = scorecard.criteria()
    assert sum(x["weight"] for x in c["criteria"]) == 100
    assert sorted(c["scale"]) == [0, 1, 2, 3, 4, 5]
    assert max(c["evidence_levels"].values()) == 5 and c["evidence_levels"]["claimed"] == 1


def test_template_lists_every_criterion():
    import yaml

    t = yaml.safe_load((scorecard.SC / "template.yaml").read_text())
    assert set(t["scores"]) == {x["id"] for x in scorecard.criteria()["criteria"]}


def test_real_products_are_never_scored():
    for name, p in scorecard.products().items():
        if name == "azure-ai-soc":
            continue
        assert p["status"] == "to be filled from your own POC"
        assert p["public_docs"].startswith("https://")
        assert all(s["score"] is None for s in p["scores"].values())
        assert scorecard.score(name)[1] is None


def test_system_under_test_is_capped_by_its_own_results():
    rows, total = scorecard.score("azure-ai-soc")
    by = {r.criterion: r for r in rows}
    assert by["detection_quality"].effective < by["detection_quality"].claimed
    assert by["data_residency"].effective == 1
    assert all(r.effective <= r.claimed for r in rows)
    assert 0 < total < 100


def test_evidence_level_caps_a_claim(monkeypatch):
    prods = scorecard.products()
    fake = dict(prods["dropzone-ai"])
    fake["scores"] = {k: {"score": 5, "evidence_level": "claimed"} for k in fake["scores"]}
    monkeypatch.setattr(scorecard, "products", lambda: {**prods, "x": fake})
    rows, total = scorecard.score("x")
    assert all(r.effective == 1 for r in rows) and total == pytest.approx(20.0)


def test_claim_check_verdicts():
    assert claims.check(87, 100, 87)["consistent"]
    assert claims.check(70, 100, 87)["verdict"] == "claim is higher than the observation supports"
    assert claims.check(99, 100, 87)["verdict"] == "observation is better than the claim"
    assert claims.check(0, 0, 87)["verdict"].startswith("no data")


def test_sample_size_and_questions():
    assert claims.needed(5) == 385
    assert len(claims.QUESTIONS) >= 8 and any(k == "baseline" for k, _ in claims.QUESTIONS)
