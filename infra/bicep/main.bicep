// Data-residency guardrails as Azure Policy for one customer subscription (same rules as
// infra/terraform): resources, Foundry / Azure OpenAI accounts and Log Analytics workspaces only in
// allowed regions; model deployments only with allowed deployment types (never Global*).
targetScope = 'subscription'

@description('Customer tenant this subscription belongs to.')
@minLength(3)
@maxLength(16)
param tenantSlug string

@description('Azure regions inside the tenant geography (config/residency/policy.yaml).')
@minLength(1)
param allowedLocations array

@description('Allowed model deployment SKU names. Global types are rejected by the check below.')
@minLength(1)
param allowedModelDeploymentTypes array

@description('Effect for every rule. Audit first to see impact, then Deny.')
@allowed([
  'Audit'
  'Deny'
  'Disabled'
])
param policyEffect string = 'Deny'

var globalTypes = filter(allowedModelDeploymentTypes, t => startsWith(t, 'Global') || t == 'DeveloperTier')
// Fails the deployment if a Global deployment type was passed in.
var noGlobalTypes = empty(globalTypes) ? true : fail('Global deployment types process data outside the geography: ${join(globalTypes, ', ')}')

var prefix = 'soc-residency-${tenantSlug}'
var effectParam = {
  type: 'String'
  allowedValues: [
    'Audit'
    'Deny'
    'Disabled'
  ]
  defaultValue: 'Deny'
  metadata: {
    displayName: 'Effect'
  }
}
var locationsParam = {
  type: 'Array'
  metadata: {
    displayName: 'Allowed locations'
    strongType: 'location'
  }
}
var typesParam = {
  type: 'Array'
  metadata: {
    displayName: 'Allowed model deployment types'
  }
}
var thenEffect = {
  effect: '[parameters(\'effect\')]'
}

var rules = [
  {
    key: 'locations'
    display: 'Resources only in the tenant\'s allowed regions'
    mode: 'Indexed'
    usesTypes: false
    rule: {
      if: {
        allOf: [
          {
            field: 'location'
            notIn: '[parameters(\'allowedLocations\')]'
          }
          {
            field: 'location'
            notEquals: 'global'
          }
          {
            field: 'type'
            notEquals: 'Microsoft.AzureActiveDirectory/b2cDirectories'
          }
        ]
      }
      then: thenEffect
    }
  }
  {
    key: 'ai-accounts'
    display: 'Foundry and Azure OpenAI accounts only in allowed regions'
    mode: 'Indexed'
    usesTypes: false
    rule: {
      if: {
        allOf: [
          {
            field: 'type'
            equals: 'Microsoft.CognitiveServices/accounts'
          }
          {
            field: 'location'
            notIn: '[parameters(\'allowedLocations\')]'
          }
        ]
      }
      then: thenEffect
    }
  }
  {
    key: 'model-deployment-types'
    display: 'Model deployments only with allowed deployment types'
    mode: 'All'
    usesTypes: true
    rule: {
      if: {
        allOf: [
          {
            field: 'type'
            equals: 'Microsoft.CognitiveServices/accounts/deployments'
          }
          {
            field: 'Microsoft.CognitiveServices/accounts/deployments/sku.name'
            notIn: '[parameters(\'allowedDeploymentTypes\')]'
          }
        ]
      }
      then: thenEffect
    }
  }
  {
    key: 'log-analytics'
    display: 'Log Analytics workspaces only in allowed regions'
    mode: 'Indexed'
    usesTypes: false
    rule: {
      if: {
        allOf: [
          {
            field: 'type'
            equals: 'Microsoft.OperationalInsights/workspaces'
          }
          {
            field: 'location'
            notIn: '[parameters(\'allowedLocations\')]'
          }
        ]
      }
      then: thenEffect
    }
  }
]

resource definitions 'Microsoft.Authorization/policyDefinitions@2025-03-01' = [
  for r in rules: {
    name: '${prefix}-${r.key}'
    properties: {
      policyType: 'Custom'
      mode: r.mode
      displayName: 'SOC residency (${tenantSlug}): ${r.display}'
      metadata: {
        category: 'SOC data residency'
        source: 'Jagadish-ai-soc-assurance'
      }
      parameters: r.usesTypes
        ? {
            effect: effectParam
            allowedDeploymentTypes: typesParam
          }
        : {
            effect: effectParam
            allowedLocations: locationsParam
          }
      policyRule: r.rule
    }
  }
]

resource initiative 'Microsoft.Authorization/policySetDefinitions@2025-03-01' = {
  name: prefix
  properties: {
    policyType: 'Custom'
    displayName: 'SOC data residency (${tenantSlug})'
    metadata: {
      category: 'SOC data residency'
    }
    parameters: {
      effect: effectParam
      allowedLocations: locationsParam
      allowedDeploymentTypes: typesParam
    }
    policyDefinitions: [
      for (r, i) in rules: {
        policyDefinitionId: definitions[i].id
        policyDefinitionReferenceId: r.key
        parameters: r.usesTypes
          ? {
              effect: {
                value: '[parameters(\'effect\')]'
              }
              allowedDeploymentTypes: {
                value: '[parameters(\'allowedDeploymentTypes\')]'
              }
            }
          : {
              effect: {
                value: '[parameters(\'effect\')]'
              }
              allowedLocations: {
                value: '[parameters(\'allowedLocations\')]'
              }
            }
      }
    ]
  }
}

resource assignment 'Microsoft.Authorization/policyAssignments@2025-03-01' = if (noGlobalTypes) {
  name: prefix
  properties: {
    displayName: 'SOC data residency (${tenantSlug})'
    policyDefinitionId: initiative.id
    enforcementMode: policyEffect == 'Disabled' ? 'DoNotEnforce' : 'Default'
    parameters: {
      effect: {
        value: policyEffect
      }
      allowedLocations: {
        value: allowedLocations
      }
      allowedDeploymentTypes: {
        value: allowedModelDeploymentTypes
      }
    }
    nonComplianceMessages: [
      {
        message: 'Blocked by SOC data residency for ${tenantSlug}: allowed regions ${join(allowedLocations, ', ')}; allowed model deployment types ${join(allowedModelDeploymentTypes, ', ')}.'
      }
    ]
  }
}

output initiativeId string = initiative.id
output assignmentName string = prefix
