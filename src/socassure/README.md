# socassure

The assurance package. Entry point: `socassure` (cli.py).

| File | What it does |
| --- | --- |
| `__init__.py` | paths to the repository, configuration, data and output folders |
| `model.py` | neutral scenario and decision types |
| `scenarios.py` | synthetic, adversarial and OTRF suites; fingerprints |
| `oracle.py` | simulated analysts with honest, rubber-stamp and poisoned behaviours |
| `adapters/` | one adapter per system under test |
| `stats.py` | bootstrap, paired differences, Wilson interval, sample size, calibration, PSI |
| `benchmark.py` | metric definitions, runs, scorecards, paired differences |
| `failures.py` | FMEA catalogue and the twelve experiments; evasion report |
| `residency.py` | residency flow checks, SUT IaC reading, IaC consistency |
| `modelrisk.py` | validation, drift report, challenger |
| `audit_replay.py` | independent verification, reconstruction, rules, explanations, reports |
| `scorecard.py` | evidence-capped product scoring |
| `claims.py` | vendor-claim interval check and questions |
| `cli.py` | the `socassure` command |
