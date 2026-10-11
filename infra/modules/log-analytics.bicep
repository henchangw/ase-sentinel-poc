@description('Azure region for the Log Analytics workspace.')
param location string

@description('Workspace name. Must be unique in the tenant.')
param workspaceName string

@description('Hot retention in days. 30 is enough for this POC.')
@minValue(30)
@maxValue(730)
param retentionInDays int = 30

@description('Daily ingestion cap in GB. -1 means no cap. A cap can drop WAF events before Sentinel sees them.')
param dailyQuotaGb int = -1

param tags object

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: retentionInDays
    workspaceCapping: {
      dailyQuotaGb: dailyQuotaGb
    }
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

output workspaceName string = workspace.name
output workspaceResourceId string = workspace.id
output workspaceGuid string = workspace.properties.customerId
