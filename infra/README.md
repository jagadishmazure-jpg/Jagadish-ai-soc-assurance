# infra

Azure Policy that enforces the data-residency policy, in Terraform and Bicep. Tested offline; never deployed.

| File | What it does |
| --- | --- |
| `terraform/` | policy definitions, initiative and subscription assignment; mocked-provider tests |
| `bicep/` | the same at subscription scope; per-tenant parameter files |
