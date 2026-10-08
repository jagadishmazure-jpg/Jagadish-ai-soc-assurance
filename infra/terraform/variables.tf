variable "tenant_slug" {
  description = "Customer tenant this subscription belongs to (one subscription per customer)."
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9]{2,15}$", var.tenant_slug))
    error_message = "tenant_slug must be 3-16 lowercase letters or digits."
  }
}

variable "allowed_locations" {
  description = "Azure regions resources may be created in. Must sit inside the tenant's home geography (config/residency/policy.yaml)."
  type        = list(string)
  validation {
    condition     = length(var.allowed_locations) > 0
    error_message = "At least one region is required."
  }
}

variable "allowed_model_deployment_types" {
  description = "Model deployment SKU names allowed (Standard, DataZoneStandard, ...). Global types process data in any Azure region."
  type        = list(string)
  validation {
    condition     = alltrue([for t in var.allowed_model_deployment_types : !startswith(t, "Global") && t != "DeveloperTier"])
    error_message = "Global deployment types (and DeveloperTier) process data outside the geography and are never allowed by this stack."
  }
}

variable "policy_effect" {
  description = "Effect for every rule in the initiative. Audit first to see impact, then Deny."
  type        = string
  default     = "Deny"
  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.policy_effect)
    error_message = "policy_effect must be Audit, Deny or Disabled."
  }
}
