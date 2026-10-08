output "initiative_id" {
  description = "Policy set (initiative) definition id."
  value       = azurerm_policy_set_definition.residency.id
}

output "assignment_id" {
  description = "Subscription policy assignment id."
  value       = azurerm_subscription_policy_assignment.residency.id
}

output "rules" {
  description = "Policy definition names in the initiative."
  value       = sort([for d in azurerm_policy_definition.rule : d.name])
}
