# tests

Automated tests; all offline. `pytest -q`.

| File | What it does |
| --- | --- |
| `test_stats.py` | intervals, bootstrap determinism, PSI, ECE |
| `test_scenarios.py` | reproducibility, seed independence, perturbations, OTRF provenance |
| `test_adapters.py` | adapter fidelity to the SUT's published numbers, baselines, recorded round trip, fault isolation |
| `test_benchmark_modelrisk.py` | metric intervals, baseline comparison, validation, drift, challenger |
| `test_failures.py` | FMEA catalogue and every experiment against its expectation |
| `test_residency.py` | flow checks, deployment types, SUT IaC, policy parameters |
| `test_audit_replay.py` | agreement with the SUT's verifier, reconstruction, rules, reports |
| `test_scorecard_claims.py` | weights, no scores for real products, caps, claim checks |
| `test_iac_and_workflows.py` | policy stacks and workflow hardening |
| `test_cli.py` | every command runs; the gate passes |
| `test_render_docs.py` | doc renderer |
| `test_repo_hygiene.py` | READMEs, sections, dates, identifiers, links, honest test count |
