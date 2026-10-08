# workflows

GitHub Actions. All actions pinned to commit SHAs; top-level permissions read-only.

| File | What it does |
| --- | --- |
| `ci.yml` | lint, tests, gate, auditor reports, doc drift, Bicep build, SBOM, gitleaks |
| `infra.yml` | terraform fmt, validate, test, tflint, checkov; plan only with OIDC variables |
| `codeql.yml` | CodeQL for Python and workflow files |
| `deploy.yml` | manual, gated by DEPLOY_ENABLED: assign the residency initiative to one tenant |
| `teardown.yml` | manual, gated and confirmed: remove a tenant's initiative |
