# Changelog

## Unreleased

- Independent benchmark: azure-ai-soc adapter (proved against the SUT's published numbers), two baselines,
  a recorded-decision adapter and a third-party stub; synthetic, adversarial and OTRF suites; cluster
  bootstrap intervals and paired differences.
- FMEA with twelve failure modes, each backed by a fault-injection experiment; evasion per-rule report.
- Data residency: policy model, flow checks, SUT IaC reading, Azure Policy initiative in Terraform and Bicep.
- Model risk: inventory, validation on the conservative bound, drift monitor, challenger; packs per agent.
- Decision-audit replay with eleven rules and HTML, Markdown and CSV reports.
- Product scorecard with evidence ladder and result caps; vendor-claim checker.
- CI: lint, tests, gate, doc drift, Bicep build, SBOM, gitleaks, CodeQL, Terraform checks; gated deploy.
