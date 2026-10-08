# Adopt this

How to use the assurance layer on an AI SOC you are buying, building or running. Each step names the file
to change and the command that produces the evidence.

## 1. Run it as it is (15 minutes)

```bash
git clone https://github.com/jagadishmazure-jpg/Jagadish-ai-soc-assurance
cd Jagadish-ai-soc-assurance
python -m venv .venv && . .venv/bin/activate
scripts/fetch_sut.sh            # the portfolio SUT at its pinned commit
pip install -e ".[dev]"
pytest -q && socassure gate
socassure bench && socassure fmea && socassure residency && socassure scorecard
```

## 2. Point it at your product

Pick one of two routes:

* **Decision export (no code).** Export your product's incident decisions for a scenario you replayed into
  it, in the JSONL format documented in `src/socassure/adapters/recorded.py`, and score them:
  `get("recorded", path="decisions.jsonl", product="vendor-x")`. You get every benchmark metric with
  intervals, but no fault injection.
* **Adapter (code).** Implement `run(scenario, oracle, faults)` as described in
  `src/socassure/adapters/third_party.py`: load the scenario's tables into the product's test tenant, let
  it run, answer its human questions from the oracle, collect its decisions and audit records. Declare
  which faults you can inject; the rest raise `UnsupportedFault`.

## 3. Use your own data

* Replace or add suites in `src/socassure/scenarios.py`. The most valuable addition is your own labelled
  incidents from a past period: replay them and compare with what your analysts decided.
* Add public recordings with `scripts/vendor_otrf.py` (edit `data/otrf/datasets.yaml`; hashes are checked).

## 4. Set your own criteria before you look

* Analyst minutes and prices: `config/benchmark.yaml`.
* Acceptance criteria per agent: `config/model-risk.yaml`.
* FMEA ratings and expectations: `config/failure-modes.yaml`.
* Scorecard weights: `config/scorecard/criteria.yaml`.

Commit these before the POC starts so the decision cannot be tuned to the result.

## 5. Encode your residency rules

* Tenants, geographies and data classes: `config/residency/policy.yaml`.
* Describe each deployment in `config/residency/deployments/`; run `socassure residency`.
* Set allowed regions and deployment types per customer in `infra/terraform/envs/*.tfvars` and
  `infra/bicep/params/*.json`; `socassure iac` and the tests prove they match the policy.
* Assign with policy effect `Audit` first, read the compliance results, then switch to `Deny`. Enable the
  deploy workflow only after reading [components/data-residency.md](components/data-residency.md): set
  OIDC variables, GitHub Environments per customer with reviewers, and `DEPLOY_ENABLED=true`.

## 6. Audit what the product records

Map the product's audit export to the trail fields in `src/socassure/audit_replay.py` and run
`socassure audit-replay --out out/audit`. Hand the HTML and CSV to your auditors; sample rows per tier.

## 7. Score and decide

Copy `config/scorecard/template.yaml` to `config/scorecard/products/<product>.yaml`, fill it with evidence
levels and links to your POC evidence, and run `socassure scorecard`. A product with only claims cannot
score above 20.
