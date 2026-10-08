# config

Configuration for every component. Changing any file here changes rendered numbers; re-run `python scripts/render_docs.py`.

| File | What it does |
| --- | --- |
| `sut.yaml` | system under test: repository and the pinned commit CI checks out |
| `benchmark.yaml` | seeds, windows, bootstrap settings, analyst minutes, illustrative token prices, drift settings |
| `adversarial.yaml` | injection phrases (written for this repository), evasion rewrites, flood and drift parameters |
| `failure-modes.yaml` | FMEA: cause, effect, ratings, detection, mitigation, experiment and expected outcome |
| `model-risk.yaml` | agent inventory: purpose, model type, decision rights, risk tier, acceptance criteria |
| `residency/` | residency policy and deployment descriptions |
| `scorecard/` | scorecard criteria, template and product files |
