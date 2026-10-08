# envs

Per-tenant inputs. Must agree with `config/residency/policy.yaml` and the Bicep parameters (`socassure iac`).

| File | What it does |
| --- | --- |
| `brightwater.tfvars` | US regions; geography and US data-zone deployment types |
| `brightwater.backend.hcl` | state key |
| `orchidvalley.tfvars` | Canadian regions; geography deployment types only |
| `orchidvalley.backend.hcl` | state key |
| `pinecrest.tfvars` | US regions; geography and US data-zone deployment types |
| `pinecrest.backend.hcl` | state key |
