# Contributing

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
scripts/fetch_sut.sh
pip install -e ".[dev]"
```

## Before opening a pull request

```bash
ruff check . && ruff format --check .
pytest -q
socassure gate
python scripts/render_docs.py --check
terraform -chdir=infra/terraform init -backend=false && terraform -chdir=infra/terraform test
bicep build infra/bicep/main.bicep
```

If you change anything that affects output, run `python scripts/render_docs.py` to refresh the rendered
blocks, and update any hand-written sentence that quotes them.

## Rules

- Never invent a metric: numbers in docs come from rendered command output or from a run you can name.
- Never score a real product in `config/scorecard/products/`; leave its scores empty.
- Changing an FMEA expectation, a validation threshold or a scorecard weight is a reviewed change with a
  reason in the pull request.
- Never commit third-party documents. Paraphrase and attribute; run
  `python scripts/overlap_check.py <reference text>` on new prose and expect zero shared eight-word runs.
- Statements about Microsoft services link to Microsoft documentation; anything not checked is marked
  unverified.
- No dates, years or month names in markdown, and no placeholder words; component docs need all sixteen
  sections. `tests/test_repo_hygiene.py` checks these.
- Keep the honest labels: built, written but not run, planned. Never describe anything as deployed.
