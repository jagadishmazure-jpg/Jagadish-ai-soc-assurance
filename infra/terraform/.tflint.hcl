plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

plugin "azurerm" {
  enabled = true
  version = "0.32.0"
  source  = "github.com/terraform-linters/tflint-ruleset-azurerm"
}

# The stack holds only policy definitions and one assignment, created by deploy.yml and removed by
# teardown.yml; prevent_destroy would only block the teardown workflow.
rule "azurerm_resources_missing_prevent_destroy" {
  enabled = false
}
