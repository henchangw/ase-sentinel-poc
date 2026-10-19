targetScope = 'resourceGroup'

@description('WAF policy name in the resource group this module is scoped to.')
param policyName string

@description('Object id of the function system-assigned managed identity.')
param principalId string

@description('Selects the policy resource type. ApplicationGateway or FrontDoor.')
@allowed([
  'ApplicationGateway'
  'FrontDoor'
])
param wafProvider string

var networkContributorRoleId = '4d97b98b-1d4f-4787-a291-c67834d212e7'

resource applicationGatewayPolicy 'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies@2024-05-01' existing = if (wafProvider == 'ApplicationGateway') {
  name: policyName
}

resource frontDoorPolicy 'Microsoft.Network/frontDoorWebApplicationFirewallPolicies@2024-02-01' existing = if (wafProvider == 'FrontDoor') {
  name: policyName
}

resource applicationGatewayPolicyWriter 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (wafProvider == 'ApplicationGateway') {
  name: guid(applicationGatewayPolicy.id, principalId, networkContributorRoleId)
  scope: applicationGatewayPolicy
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', networkContributorRoleId)
    principalId: principalId
    principalType: 'ServicePrincipal'
    description: 'Lets the ASE POC function update this Application Gateway WAF policy only.'
  }
}

resource frontDoorPolicyWriter 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (wafProvider == 'FrontDoor') {
  name: guid(frontDoorPolicy.id, principalId, networkContributorRoleId)
  scope: frontDoorPolicy
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', networkContributorRoleId)
    principalId: principalId
    principalType: 'ServicePrincipal'
    description: 'Lets the ASE POC function update this Front Door WAF policy only.'
  }
}
