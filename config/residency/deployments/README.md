# deployments

Deployment descriptions. Each gives, per tenant, the region (or geography) of every flow and the model endpoint's region and deployment type.

| File | What it does |
| --- | --- |
| `azure-ai-soc-as-shipped.yaml` | the SUT with its IaC defaults; model deployment type unset |
| `proposed.yaml` | a residency-aware layout: US data zone for US tenants, Canadian regions and Standard deployment for the Canadian tenant |
