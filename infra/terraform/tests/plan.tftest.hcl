# Offline plan tests: mocked provider, no Azure credentials, nothing created.
#   terraform init -backend=false && terraform test
mock_provider "azurerm" {
  mock_data "azurerm_subscription" {
    defaults = {
      id              = "/subscriptions/00000000-0000-0000-0000-000000000002"
      subscription_id = "00000000-0000-0000-0000-000000000002"
    }
  }
}

run "orchidvalley_canada_only" {
  command = plan
  variables {
    tenant_slug                    = "orchidvalley"
    allowed_locations              = ["canadacentral", "canadaeast"]
    allowed_model_deployment_types = ["Standard", "ProvisionedManaged"]
  }

  assert {
    condition     = length(azurerm_policy_definition.rule) == 4
    error_message = "Expected four residency rules."
  }
  assert {
    condition     = jsondecode(azurerm_subscription_policy_assignment.residency.parameters).allowedLocations.value == ["canadacentral", "canadaeast"]
    error_message = "Assignment must carry the tenant's regions."
  }
  assert {
    condition     = jsondecode(azurerm_subscription_policy_assignment.residency.parameters).effect.value == "Deny"
    error_message = "Default effect must be Deny."
  }
  assert {
    condition     = jsondecode(azurerm_policy_definition.rule["model_deployment_types"].policy_rule).if.allOf[1].field == "Microsoft.CognitiveServices/accounts/deployments/sku.name"
    error_message = "Deployment-type rule must test the deployment SKU name."
  }
  assert {
    condition     = jsondecode(azurerm_policy_definition.rule["log_analytics"].policy_rule).if.allOf[0].equals == "Microsoft.OperationalInsights/workspaces"
    error_message = "Log Analytics rule must target workspaces."
  }
  assert {
    condition     = azurerm_subscription_policy_assignment.residency.enforce
    error_message = "Assignment must be enforced."
  }
}

run "global_deployment_types_rejected" {
  command = plan
  variables {
    tenant_slug                    = "brightwater"
    allowed_locations              = ["eastus2"]
    allowed_model_deployment_types = ["DataZoneStandard", "GlobalStandard"]
  }
  expect_failures = [var.allowed_model_deployment_types]
}

run "audit_mode_not_enforced_when_disabled" {
  command = plan
  variables {
    tenant_slug                    = "pinecrest"
    allowed_locations              = ["eastus2"]
    allowed_model_deployment_types = ["DataZoneStandard"]
    policy_effect                  = "Disabled"
  }
  assert {
    condition     = !azurerm_subscription_policy_assignment.residency.enforce
    error_message = "Disabled effect must not enforce."
  }
}
