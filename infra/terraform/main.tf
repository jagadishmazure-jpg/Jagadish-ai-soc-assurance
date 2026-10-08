# Data-residency guardrails as Azure Policy, scoped to one customer subscription.
#   1. resources only in allowed regions (global-only resource types excepted)
#   2. Foundry / Azure OpenAI accounts only in allowed regions
#   3. model deployments only with allowed deployment types (no Global*)
#   4. Log Analytics workspaces (Sentinel) only in allowed regions
# Grouped in one initiative and assigned to the subscription. Nothing else is created.

data "azurerm_subscription" "current" {}

locals {
  prefix = "soc-residency-${var.tenant_slug}"
  effect_parameter = {
    effect = {
      type          = "String"
      allowedValues = ["Audit", "Deny", "Disabled"]
      defaultValue  = "Deny"
      metadata      = { displayName = "Effect" }
    }
  }
  locations_parameter = {
    allowedLocations = {
      type     = "Array"
      metadata = { displayName = "Allowed locations", strongType = "location" }
    }
  }
  rules = {
    locations = {
      display = "Resources only in the tenant's allowed regions"
      rule = {
        "if" = {
          allOf = [
            { field = "location", notIn = "[parameters('allowedLocations')]" },
            { field = "location", notEquals = "global" },
            { field = "type", notEquals = "Microsoft.AzureActiveDirectory/b2cDirectories" },
          ]
        }
        "then" = { effect = "[parameters('effect')]" }
      }
      parameters = merge(local.effect_parameter, local.locations_parameter)
    }
    ai_accounts = {
      display = "Foundry and Azure OpenAI accounts only in allowed regions"
      rule = {
        "if" = {
          allOf = [
            { field = "type", equals = "Microsoft.CognitiveServices/accounts" },
            { field = "location", notIn = "[parameters('allowedLocations')]" },
          ]
        }
        "then" = { effect = "[parameters('effect')]" }
      }
      parameters = merge(local.effect_parameter, local.locations_parameter)
    }
    model_deployment_types = {
      display = "Model deployments only with allowed deployment types"
      rule = {
        "if" = {
          allOf = [
            { field = "type", equals = "Microsoft.CognitiveServices/accounts/deployments" },
            { field = "Microsoft.CognitiveServices/accounts/deployments/sku.name", notIn = "[parameters('allowedDeploymentTypes')]" },
          ]
        }
        "then" = { effect = "[parameters('effect')]" }
      }
      parameters = merge(local.effect_parameter, {
        allowedDeploymentTypes = {
          type     = "Array"
          metadata = { displayName = "Allowed model deployment types" }
        }
      })
    }
    log_analytics = {
      display = "Log Analytics workspaces only in allowed regions"
      rule = {
        "if" = {
          allOf = [
            { field = "type", equals = "Microsoft.OperationalInsights/workspaces" },
            { field = "location", notIn = "[parameters('allowedLocations')]" },
          ]
        }
        "then" = { effect = "[parameters('effect')]" }
      }
      parameters = merge(local.effect_parameter, local.locations_parameter)
    }
  }
}

resource "azurerm_policy_definition" "rule" {
  for_each     = local.rules
  name         = "${local.prefix}-${replace(each.key, "_", "-")}"
  policy_type  = "Custom"
  mode         = each.key == "model_deployment_types" ? "All" : "Indexed"
  display_name = "SOC residency (${var.tenant_slug}): ${each.value.display}"
  metadata     = jsonencode({ category = "SOC data residency", source = "Jagadish-ai-soc-assurance" })
  policy_rule  = jsonencode(each.value.rule)
  parameters   = jsonencode(each.value.parameters)
}

resource "azurerm_policy_set_definition" "residency" {
  name         = local.prefix
  policy_type  = "Custom"
  display_name = "SOC data residency (${var.tenant_slug})"
  metadata     = jsonencode({ category = "SOC data residency" })
  parameters = jsonencode({
    effect                 = local.effect_parameter.effect
    allowedLocations       = local.locations_parameter.allowedLocations
    allowedDeploymentTypes = { type = "Array", metadata = { displayName = "Allowed model deployment types" } }
  })

  dynamic "policy_definition_reference" {
    for_each = azurerm_policy_definition.rule
    content {
      policy_definition_id = policy_definition_reference.value.id
      reference_id         = policy_definition_reference.key
      parameter_values = jsonencode(merge(
        { effect = { value = "[parameters('effect')]" } },
        policy_definition_reference.key == "model_deployment_types"
        ? { allowedDeploymentTypes = { value = "[parameters('allowedDeploymentTypes')]" } }
        : { allowedLocations = { value = "[parameters('allowedLocations')]" } },
      ))
    }
  }
}

resource "azurerm_subscription_policy_assignment" "residency" {
  name                 = local.prefix
  display_name         = "SOC data residency (${var.tenant_slug})"
  subscription_id      = data.azurerm_subscription.current.id
  policy_definition_id = azurerm_policy_set_definition.residency.id
  enforce              = var.policy_effect != "Disabled"
  parameters = jsonencode({
    effect                 = { value = var.policy_effect }
    allowedLocations       = { value = var.allowed_locations }
    allowedDeploymentTypes = { value = var.allowed_model_deployment_types }
  })
  non_compliance_message {
    content = "Blocked by SOC data residency for ${var.tenant_slug}: allowed regions ${join(", ", var.allowed_locations)}; allowed model deployment types ${join(", ", var.allowed_model_deployment_types)}."
  }
}
