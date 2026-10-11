targetScope = 'resourceGroup'

@description('Object id of the Azure Security Insights service principal in this tenant.')
param principalId string

var automationContributorRoleId = 'f4c81013-99ee-4d62-a7ee-b3f1f648599a'

resource automationContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, principalId, automationContributorRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', automationContributorRoleId)
    principalId: principalId
    principalType: 'ServicePrincipal'
    description: 'Lets Microsoft Sentinel automation rules run playbooks in this resource group.'
  }
}
