# terraform

Residency initiative for one customer subscription. `terraform init -backend=false && terraform test` runs offline.

| File | What it does |
| --- | --- |
| `.tflint.hcl` | tflint configuration (recommended preset, azurerm ruleset) |
| `backend.tf` | remote state in Azure Storage with Entra ID auth (configured at init) |
| `envs/` | per-tenant variables and backend keys |
| `main.tf` | four policy definitions, the initiative and the subscription assignment |
| `outputs.tf` | initiative id, assignment id, rule names |
| `providers.tf` | azurerm provider |
| `tests/` | offline plan tests with a mocked provider |
| `variables.tf` | tenant, allowed regions, allowed deployment types (Global refused), effect |
| `versions.tf` | Terraform and provider versions |
