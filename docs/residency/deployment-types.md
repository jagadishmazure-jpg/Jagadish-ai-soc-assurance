# Model deployment types and where prompts are processed

For models sold by Azure in Foundry (including Azure OpenAI models), the deployment type, not only the
resource's region, decides where prompts and completions are processed. This page summarises Microsoft's
documentation in this repository's own words and says how the residency checker uses it. Read the linked
pages for the authoritative text; they change.

Sources:

* Microsoft Learn, [Deployment types for Microsoft Foundry Models](https://learn.microsoft.com/en-us/azure/ai-foundry/foundry-models/concepts/deployment-types)
* Microsoft Learn, [Data, privacy, and security for Foundry Models sold by Azure](https://learn.microsoft.com/en-us/azure/ai-foundry/responsible-ai/openai/data-privacy)
* Microsoft Learn, [Azure Policy definition structure](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-basics)
* Microsoft Learn, [Microsoft Sentinel geographical availability and data residency](https://learn.microsoft.com/en-us/azure/sentinel/geographical-availability-data-residency)

## What the documentation says (paraphrased)

| Family | SKU names | Processing location per the Learn page | Checker treats it as |
| --- | --- | --- | --- |
| Global | `GlobalStandard`, `GlobalProvisionedManaged`, `GlobalBatch` | may be processed in any Azure region where the model is deployed | `global`: fails any geography-bound data class |
| Data zone | `DataZoneStandard`, `DataZoneProvisionedManaged`, `DataZoneBatch` | processed only within the Microsoft-defined data zone (US, EU or Asia Pacific) | `data_zone`: passes only if the tenant allows data zones and the zone sits inside its geography |
| Geography | `Standard`, `ProvisionedManaged` | processed within the customer-specified Azure geography, possibly across regions inside it | `geography`: passes if the region is in the tenant geography |
| Developer | `DeveloperTier` | for fine-tuned model evaluation; the page states no data-residency guarantee | `global` |

Other points from the same pages:

* For every type, data stored at rest stays in the designated geography; for Global and Data Zone types
  that includes the abuse-monitoring data store. Only the processing location changes.
* The EU data zone follows the EU Data Boundary and can include EFTA countries; Microsoft can add regions
  to a data zone without prior notice.
* Not every model is offered in every deployment type and region. Geography-based types tend to arrive
  last for new models.
* The Learn page gives an Azure Policy example that matches on
  `Microsoft.CognitiveServices/accounts/deployments/sku.name` with mode `All`; this repository's
  deployment-type rule uses the same alias with a `notIn` list of allowed types.

## What this repository has not verified

* **Unverified:** that any particular model (for example the SUT's default `gpt-5-mini`) is offered as a
  `Standard` deployment in `canadaeast` or `canadacentral`. The proposed layout assumes a Standard
  deployment in Canada exists for the chosen model; check the model availability tables before relying
  on it.
* **Unverified:** where human reviewers for abuse monitoring are located, and whether the modified
  abuse-monitoring option applies to a given customer. Read the abuse-monitoring section of the data
  privacy page.
* **Unverified:** the data location of Defender XDR and of Microsoft Sentinel features that process data
  outside the workspace region; the Sentinel page above lists them.
* **Unverified:** that the four policy rules behave as intended against a live subscription; they have
  been tested with mocked Terraform plans and `bicep build` only, and never assigned.

## How the residency checker uses this

`config/residency/policy.yaml` lists each SKU name with its processing scope. A model endpoint in a
deployment description is `{region, deployment_type}`; the checker resolves it to a geography, a data
zone or "any region", and compares it with the tenant's policy. An endpoint with no deployment type is
`unknown` and counts as a failure, because an unpinned deployment could be Global.
