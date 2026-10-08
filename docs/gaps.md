# The gaps this repository closes

This repository started from a reading of a vendor whitepaper on AI-powered security operations,
[Conifers' guide to the AI-powered SOC](https://www.conifers.ai/blog/ai-powered-soc/). The guide is useful
as a map of the problem space and of one vendor's pitch. Its text is not quoted, copied or included here;
it is credited by link only. Its headline figures (an 87% figure and results attributed to a customer
deployment) are the vendor's own account, with no published method, denominator or interval.

What the guide does not give a buyer, and where this repository fills each gap:

| Gap | What a buyer needs | Where it is closed | Evidence command |
| --- | --- | --- | --- |
| Independent benchmarks | metrics with intervals, on data the vendor did not choose, against a baseline | [components/benchmark.md](components/benchmark.md) | `socassure bench`, `compare`, `otrf`, `adversarial` |
| Failure modes | ranked failure modes with experiments showing what actually happens | [components/failure-modes.md](components/failure-modes.md) | `socassure fmea`, `chaos` |
| Data residency | every data flow and model endpoint checked per customer, enforced by policy | [components/data-residency.md](components/data-residency.md) | `socassure residency`, `iac` |
| Model risk | inventory, criteria, validation, drift and challenger per agent | [components/model-risk.md](components/model-risk.md), [model-risk/](model-risk/README.md) | `socassure validate`, `drift`, `challenger` |
| Decision audit | independent verification and reconstruction of every decision, with an auditor report | [components/decision-audit.md](components/decision-audit.md) | `socassure audit-replay` |
| Product comparison | weighted criteria, evidence-capped scores, honest results, no invented vendor numbers | [components/product-scorecard.md](components/product-scorecard.md) | `socassure scorecard`, `claim` |

How to judge a vendor's headline number is in [vendor-claims.md](vendor-claims.md).
