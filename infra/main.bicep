targetScope = 'resourceGroup'

@description('Region for every regional resource in this POC. Use a region that offers Application Gateway WAF_v2 when the test WAF is deployed.')
param location string = resourceGroup().location

@description('Short name prefix. Use 3 to 24 lowercase letters, numbers, and hyphens. The deploy script enforces that pattern.')
@minLength(3)
@maxLength(24)
param namePrefix string = 'ase-sentinel-poc'

@description('Optional explicit workspace name. Empty uses a name that is unique inside the tenant.')
param workspaceName string = ''

@description('Which WAF product the detection query and the playbook update. This POC deploys a test WAF only for ApplicationGateway.')
@allowed([
  'ApplicationGateway'
  'FrontDoor'
])
param wafProvider string = 'ApplicationGateway'

@description('Deploy the Application Gateway test rig, its WAF policy, and Dedicated diagnostics. Must be false for Front Door. This repository does not create Front Door.')
param deployTestWaf bool = true

@description('Name of a WAF policy already in this resource group. Required when the test WAF is not deployed and existingWafPolicyResourceId is empty.')
param existingWafPolicyName string = ''

@description('Full resource id of an existing WAF policy. Use this when the policy is not in the deployment resource group. Ignored when the test WAF is deployed.')
param existingWafPolicyResourceId string = ''

@description('Front Door diagnostic shape used by the analytics rule. This repository does not configure Front Door diagnostics. ResourceSpecific is only valid after ASE confirms that table exists.')
@allowed([
  'AzureDiagnostics'
  'ResourceSpecific'
])
param frontDoorLogDestination string = 'AzureDiagnostics'

@description('Prevention is the mode Microsoft documents as enforcing WAF actions. Detection logs a custom block rule and does not enforce it.')
@allowed([
  'Prevention'
  'Detection'
])
param wafMode string = 'Prevention'

@description('Safe default. False records Would block IP on the incident and does not change the WAF policy. True PUTs the block rule. The deploy script requires a second confirmation switch.')
param autoBlockEnabled bool = false

@description('Skips built-in and customer protected-range filters in the KQL and the playbook. Invalid addresses are still rejected. Default false.')
param overrideProtectedRanges bool = false

@description('Extra IPv4 addresses or /8, /16, /24, and /32 prefixes that must not be blocked. Built-in private, loopback, link-local, metadata, and CGNAT ranges are always protected unless overrideProtectedRanges is true.')
param protectedIpRanges array = []

@description('Distinct simulated-probe events from one public IP before an incident is opened.')
@minValue(1)
@maxValue(100)
param detectionThreshold int = 3

@description('Analytics rule schedule in minutes. Minimum is 5.')
@minValue(5)
@maxValue(60)
param queryFrequencyMinutes int = 5

@description('Observation window in minutes. This is the analytics rule lookback. Must be greater than or equal to queryFrequencyMinutes.')
@minValue(5)
@maxValue(1440)
param queryLookbackMinutes int = 30

@description('Maximum IPs stored on the block custom rule.')
@minValue(1)
@maxValue(500)
param maximumBlockEntries int = 100

@description('Query-string marker used by the test rig and the analytics rule.')
param probeMarker string = 'ase-poc-probe'

@description('Custom rule that matches the simulated probe. Deployed on the test WAF only.')
param probeRuleName string = 'PocSimulatedProbe'

@description('Probe rule priority. Must differ from blockRulePriority.')
@minValue(1)
@maxValue(100)
param probeRulePriority int = 50

@description('Custom rule name reserved for the playbook. The analytics rule ignores it.')
param blockRuleName string = 'SentinelAutoBlock'

@description('Block rule priority. 1 runs first. Must differ from probeRulePriority.')
@minValue(1)
@maxValue(100)
param blockRulePriority int = 10

@description('WAF_v2 minimum capacity. Each unit is billed hourly. Used only when the test WAF is deployed.')
@minValue(1)
@maxValue(10)
param appGatewayMinCapacity int = 1

@description('WAF_v2 maximum capacity. Azure requires at least 2.')
@minValue(2)
@maxValue(10)
param appGatewayMaxCapacity int = 2

param vnetAddressPrefix string = '10.40.0.0/16'
param appGatewaySubnetPrefix string = '10.40.0.0/24'

@minValue(30)
@maxValue(730)
param retentionInDays int = 30

@description('Log Analytics daily cap in GB. -1 disables the cap so a demo burst is not dropped.')
param dailyQuotaGb int = -1

param enableAnalyticsRule bool = true

param tags object = {
  Customer: 'ASE'
  Purpose: 'SentinelWafBlockPoc'
  Environment: 'poc'
  ManagedBy: 'bicep'
}

var resolvedWorkspaceName = empty(workspaceName) ? 'log-${namePrefix}-${uniqueString(resourceGroup().id)}' : workspaceName
var deployApplicationGateway = deployTestWaf && wafProvider == 'ApplicationGateway'
var deployedPolicyName = 'wafpol-${namePrefix}'
var wafPolicyName = deployApplicationGateway ? deployedPolicyName : existingWafPolicyName
var wafPolicyResourceId = deployApplicationGateway
  ? resourceId('Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies', deployedPolicyName)
  : (!empty(existingWafPolicyResourceId)
      ? existingWafPolicyResourceId
      : (wafProvider == 'FrontDoor'
          ? resourceId('Microsoft.Network/frontDoorWebApplicationFirewallPolicies', existingWafPolicyName)
          : resourceId('Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies', existingWafPolicyName)))
var armApiVersion = wafProvider == 'FrontDoor' ? '2024-02-01' : '2024-05-01'
var builtInProtectedRanges = [
  '0.0.0.0/8'
  '10.0.0.0/8'
  '127.0.0.0/8'
  '169.254.0.0/16'
  '169.254.169.254/32'
  '172.16.0.0/12'
  '192.168.0.0/16'
  '100.64.0.0/10'
]
var watchlistRanges = concat(builtInProtectedRanges, protectedIpRanges)
var watchlistLines = [for range in watchlistRanges: '${range},POC protected range']
var allowlistCsv = join(concat(['IPAddress,Note'], watchlistLines), '\n')

module logAnalytics 'modules/log-analytics.bicep' = {
  name: 'log-analytics'
  params: {
    location: location
    workspaceName: resolvedWorkspaceName
    retentionInDays: retentionInDays
    dailyQuotaGb: dailyQuotaGb
    tags: tags
  }
}

module waf 'modules/waf.bicep' = {
  name: 'waf'
  params: {
    location: location
    enabled: deployApplicationGateway
    policyName: deployedPolicyName
    appGatewayName: 'agw-${namePrefix}'
    publicIpName: 'pip-${namePrefix}'
    vnetName: 'vnet-${namePrefix}'
    vnetAddressPrefix: vnetAddressPrefix
    appGatewaySubnetPrefix: appGatewaySubnetPrefix
    wafMode: wafMode
    minCapacity: appGatewayMinCapacity
    maxCapacity: appGatewayMaxCapacity
    probeRuleName: probeRuleName
    probeRulePriority: probeRulePriority
    probeMarker: probeMarker
    logAnalyticsWorkspaceId: logAnalytics.outputs.workspaceResourceId
    tags: tags
  }
}

module playbook 'modules/playbook.bicep' = {
  name: 'playbook'
  dependsOn: [
    waf
  ]
  params: {
    location: location
    playbookName: 'playbook-${namePrefix}-block-malicious-ip'
    wafPolicyResourceId: wafPolicyResourceId
    wafProvider: wafProvider
    protectedIpRanges: protectedIpRanges
    maximumBlockEntries: maximumBlockEntries
    autoBlockEnabled: autoBlockEnabled
    overrideProtectedRanges: overrideProtectedRanges
    blockRuleName: blockRuleName
    blockRulePriority: blockRulePriority
    armApiVersion: armApiVersion
    logAnalyticsWorkspaceId: logAnalytics.outputs.workspaceResourceId
    tags: tags
  }
}

module sentinel 'modules/sentinel.bicep' = {
  name: 'sentinel'
  params: {
    location: location
    workspaceName: logAnalytics.outputs.workspaceName
    watchlistAlias: 'AseWafIpAllowlist'
    allowlistCsv: allowlistCsv
    wafProvider: wafProvider
    frontDoorLogDestination: frontDoorLogDestination
    blockRuleName: blockRuleName
    probeRuleName: probeRuleName
    probeMarker: probeMarker
    detectionThreshold: detectionThreshold
    queryFrequencyMinutes: queryFrequencyMinutes
    queryLookbackMinutes: queryLookbackMinutes
    overrideProtectedRanges: overrideProtectedRanges
    enableAnalyticsRule: enableAnalyticsRule
    tags: tags
  }
}

output workspaceName string = logAnalytics.outputs.workspaceName
output workspaceResourceId string = logAnalytics.outputs.workspaceResourceId
output workspaceGuid string = logAnalytics.outputs.workspaceGuid
output wafProvider string = wafProvider
output wafPolicyName string = wafPolicyName
output wafPolicyId string = wafPolicyResourceId
output appGatewayName string = waf.outputs.appGatewayName
output publicIpAddress string = waf.outputs.publicIpAddress
output playbookName string = playbook.outputs.playbookName
output playbookResourceId string = playbook.outputs.playbookResourceId
output playbookPrincipalId string = playbook.outputs.principalId
output analyticsRuleId string = sentinel.outputs.analyticsRuleId
output watchlistAlias string = sentinel.outputs.watchlistAlias
output detectionQueryKind string = sentinel.outputs.detectionQueryKind
output autoBlockEnabled bool = autoBlockEnabled
output blockRuleName string = blockRuleName
output probeRuleName string = probeRuleName
output probeMarker string = probeMarker
output frontDoorLogDestination string = frontDoorLogDestination
