@description('Azure region for the Logic App and the Sentinel API connection.')
param location string

@description('Logic App workflow name. Sentinel shows this name as the playbook.')
param playbookName string

@description('Full resource id of the WAF policy the playbook may update.')
param wafPolicyResourceId string

@description('ApplicationGateway or FrontDoor. This selects the custom-rule shape and the ARM API version.')
@allowed([
  'ApplicationGateway'
  'FrontDoor'
])
param wafProvider string

@description('Customer IPv4 addresses or /8, /16, /24, and /32 prefixes the playbook must not block.')
param protectedIpRanges array

@description('Maximum addresses stored on the block custom rule.')
@minValue(1)
@maxValue(500)
param maximumBlockEntries int

@description('When false, the playbook comments Would block IP and does not PUT the policy. This is the safe default.')
param autoBlockEnabled bool

@description('When true, built-in and customer protected ranges are not applied. Invalid IPs are still rejected.')
param overrideProtectedRanges bool

param blockRuleName string

@minValue(1)
@maxValue(100)
param blockRulePriority int

@description('ARM api-version used to read and write the selected policy type.')
param armApiVersion string

@description('Workspace resource id for playbook runtime logs.')
param logAnalyticsWorkspaceId string

param tags object

var connectionName = 'azuresentinel-${playbookName}'
var sentinelResponderRoleId = 'ab8e14d6-4a74-4a29-9ba8-549422addade'
var policyIdParts = split(wafPolicyResourceId, '/')
var policySubscriptionId = policyIdParts[2]
var policyResourceGroup = policyIdParts[4]
var policyName = last(policyIdParts)

resource sentinelConnection 'Microsoft.Web/connections@2016-06-01' = {
  name: connectionName
  location: location
  kind: 'V1'
  tags: tags
  properties: {
    displayName: connectionName
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
    }
    customParameterValues: {}
    // Alternative plus ManagedServiceIdentity on the workflow is the managed-identity
    // Sentinel connection. No user OAuth secret is stored.
    parameterValueType: 'Alternative'
  }
}

resource playbook 'Microsoft.Logic/workflows@2019-05-01' = {
  name: playbookName
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    state: 'Enabled'
    definition: loadJsonContent('../../playbooks/block-malicious-ip/workflow.json')
    parameters: {
      '$connections': {
        value: {
          azuresentinel: {
            connectionId: sentinelConnection.id
            connectionName: sentinelConnection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
            connectionProperties: {
              authentication: {
                type: 'ManagedServiceIdentity'
              }
            }
          }
        }
      }
      wafPolicyResourceId: {
        value: wafPolicyResourceId
      }
      wafProvider: {
        value: wafProvider
      }
      protectedIpRanges: {
        value: protectedIpRanges
      }
      maximumBlockEntries: {
        value: maximumBlockEntries
      }
      autoBlockEnabled: {
        value: autoBlockEnabled
      }
      overrideProtectedRanges: {
        value: overrideProtectedRanges
      }
      blockRuleName: {
        value: blockRuleName
      }
      blockRulePriority: {
        value: blockRulePriority
      }
      armApiVersion: {
        value: armApiVersion
      }
    }
  }
}

resource playbookDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'diag-playbook-runtime'
  scope: playbook
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      {
        category: 'WorkflowRuntime'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

resource sentinelResponder 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, playbook.id, sentinelResponderRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', sentinelResponderRoleId)
    principalId: playbook.identity.principalId
    principalType: 'ServicePrincipal'
    description: 'Lets the playbook comment on Sentinel incidents in this resource group.'
  }
}

module policyRole 'role-waf-policy.bicep' = {
  name: 'waf-policy-role'
  scope: resourceGroup(policySubscriptionId, policyResourceGroup)
  params: {
    policyName: policyName
    principalId: playbook.identity.principalId
    wafProvider: wafProvider
  }
}

output playbookName string = playbook.name
output playbookResourceId string = playbook.id
output principalId string = playbook.identity.principalId
