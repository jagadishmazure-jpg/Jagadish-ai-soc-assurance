"""Checking a vendor's headline number before believing it.

`check(successes, n, claimed_pct)` puts a Wilson interval round the observed proportion and says whether
the claim is consistent with it; `needed(margin)` gives the sample size for a target margin. `QUESTIONS` is
the evidence checklist to send a vendor with any accuracy or time-saved claim."""

from __future__ import annotations

from socassure import stats

QUESTIONS = (
    ("definition", "What exactly is counted: alerts, incidents, verdicts, or analyst agreement? Which classes?"),
    ("denominator", "How many items, over what period, from how many customers? Was any data excluded?"),
    ("ground truth", "Who labelled the truth, independently of the system, and how were disagreements settled?"),
    ("selection", "Who chose the data? Was it from customers who agreed to a case study?"),
    ("baseline", "Compared with what: the same team without the product, a rules baseline, or nothing?"),
    ("errors", "How many attacks were auto-closed or missed? Accuracy alone hides the dangerous error."),
    ("interval", "What is the confidence interval, and how was it computed?"),
    ("reproduction", "Can we run the same measurement on our data during a POC, with exportable decisions?"),
    ("drift", "How is the figure monitored after go-live, and what happens when it drops?"),
)


def check(successes: int, n: int, claimed_pct: float, confidence: float = 0.95) -> dict:
    lo, hi = stats.wilson(successes, n, confidence)
    obs = 100 * successes / n if n else None
    inside = 100 * lo <= claimed_pct <= 100 * hi
    if n == 0:
        verdict = "no data: the claim cannot be checked"
    elif inside:
        verdict = "consistent with the observation"
    elif claimed_pct > 100 * hi:
        verdict = "claim is higher than the observation supports"
    else:
        verdict = "observation is better than the claim"
    return {"observed_pct": obs, "lo": 100 * lo, "hi": 100 * hi, "n": n, "claimed_pct": claimed_pct, "consistent": inside, "verdict": verdict}


def needed(margin_pct: float, expected_pct: float = 50.0, confidence: float = 0.95) -> int:
    return stats.sample_size_for(margin_pct / 100, expected_pct / 100, confidence)
