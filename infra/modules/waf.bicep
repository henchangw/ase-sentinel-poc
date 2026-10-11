@description('Azure region. Application Gateway, the WAF policy, and the public IP must share it.')
param location string

@description('Create the VNet, public IP, WAF policy, and Application Gateway. When false, nothing in this module is deployed.')
param enabled bool

@description('WAF policy name. Also used as the id of an existing policy when enabled is false.')
param policyName string

@description('Application Gateway name.')
param appGatewayName string

@description('Public IP name.')
param publicIpName string

@description('Virtual network name.')
param vnetName string

param vnetAddressPrefix string
param appGatewaySubnetPrefix string

@description('Prevention blocks matching requests and logs Action=Blocked. Detection logs Action=Detected and does not enforce managed rules.')
@allowed([
  'Prevention'
  'Detection'
])
param wafMode string

@description('Minimum WAF_v2 capacity units. This is the main hourly cost of the POC.')
@minValue(1)
@maxValue(10)
param minCapacity int

@description('Maximum WAF_v2 capacity units. The platform minimum is 2.')
@minValue(2)
@maxValue(10)
param maxCapacity int

@description('Custom rule that blocks the deterministic POC probe and writes RuleId on AGWFirewallLogs.')
param probeRuleName string

@description('Priority of the probe rule. The playbook block rule must use a different priority.')
@minValue(1)
@maxValue(100)
param probeRulePriority int

@description('Query-string marker the probe rule matches. The test script sends this value.')
param probeMarker string

@description('Log Analytics workspace resource id. The diagnostic setting uses Dedicated, which writes AGWFirewallLogs.')
param logAnalyticsWorkspaceId string

param tags object

var backendProbeAddress = '192.0.2.10'

resource wafPolicy 'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies@2024-05-01' = if (enabled) {
  name: policyName
  location: location
  tags: tags
  properties: {
    policySettings: {
      state: 'Enabled'
      mode: wafMode
      requestBodyCheck: true
      maxRequestBodySizeInKb: 128
      fileUploadLimitInMb: 100
    }
    // SentinelAutoBlock is created by the playbook on the first opted-in block.
    // An IPMatch rule with an empty match list is invalid, so none is seeded here.
    // The probe rule is a Contains match with a non-empty value. Its action is Block.
    // Microsoft documents that Detection mode logs a custom block rule and does not enforce it.
    customRules: [
      {
        name: probeRuleName
        priority: probeRulePriority
        ruleType: 'MatchRule'
        action: 'Block'
        state: 'Enabled'
        matchConditions: [
          {
            matchVariables: [
              {
                variableName: 'QueryString'
              }
            ]
            operator: 'Contains'
            matchValues: [
              probeMarker
            ]
          }
        ]
      }
    ]
    managedRules: {
      managedRuleSets: [
        {
          ruleSetType: 'OWASP'
          ruleSetVersion: '3.2'
        }
      ]
    }
  }
}

resource publicIp 'Microsoft.Network/publicIPAddresses@2024-05-01' = if (enabled) {
  name: publicIpName
  location: location
  tags: tags
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
    idleTimeoutInMinutes: 4
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = if (enabled) {
  name: vnetName
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [
        vnetAddressPrefix
      ]
    }
    subnets: [
      {
        name: 'snet-appgw'
        properties: {
          addressPrefix: appGatewaySubnetPrefix
        }
      }
    ]
  }
}

resource appGateway 'Microsoft.Network/applicationGateways@2024-05-01' = if (enabled) {
  name: appGatewayName
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'WAF_v2'
      tier: 'WAF_v2'
    }
    autoscaleConfiguration: {
      minCapacity: minCapacity
      maxCapacity: maxCapacity
    }
    gatewayIPConfigurations: [
      {
        name: 'gatewayIpConfig'
        properties: {
          subnet: {
            id: '${vnet.id}/subnets/snet-appgw'
          }
        }
      }
    ]
    frontendIPConfigurations: [
      {
        name: 'frontendPublic'
        properties: {
          publicIPAddress: {
            id: publicIp.id
          }
        }
      }
    ]
    frontendPorts: [
      {
        name: 'port80'
        properties: {
          port: 80
        }
      }
    ]
    backendAddressPools: [
      {
        name: 'backendDummy'
        properties: {
          backendAddresses: [
            {
              ipAddress: backendProbeAddress
            }
          ]
        }
      }
    ]
    backendHttpSettingsCollection: [
      {
        name: 'httpSettings'
        properties: {
          port: 80
          protocol: 'Http'
          cookieBasedAffinity: 'Disabled'
          pickHostNameFromBackendAddress: false
          requestTimeout: 20
        }
      }
    ]
    httpListeners: [
      {
        name: 'httpListener'
        properties: {
          frontendIPConfiguration: {
            id: resourceId('Microsoft.Network/applicationGateways/frontendIPConfigurations', appGatewayName, 'frontendPublic')
          }
          frontendPort: {
            id: resourceId('Microsoft.Network/applicationGateways/frontendPorts', appGatewayName, 'port80')
          }
          protocol: 'Http'
        }
      }
    ]
    requestRoutingRules: [
      {
        name: 'httpRule'
        properties: {
          ruleType: 'Basic'
          priority: 100
          httpListener: {
            id: resourceId('Microsoft.Network/applicationGateways/httpListeners', appGatewayName, 'httpListener')
          }
          backendAddressPool: {
            id: resourceId('Microsoft.Network/applicationGateways/backendAddressPools', appGatewayName, 'backendDummy')
          }
          backendHttpSettings: {
            id: resourceId('Microsoft.Network/applicationGateways/backendHttpSettingsCollection', appGatewayName, 'httpSettings')
          }
        }
      }
    ]
    firewallPolicy: {
      id: wafPolicy.id
    }
    enableHttp2: true
  }
}

resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (enabled) {
  name: 'diag-waf-to-sentinel'
  scope: appGateway
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    // Dedicated writes AGWFirewallLogs and AGWAccessLogs. AzureDiagnostics is not used.
    logAnalyticsDestinationType: 'Dedicated'
    logs: [
      {
        category: 'ApplicationGatewayFirewallLog'
        enabled: true
      }
      {
        category: 'ApplicationGatewayAccessLog'
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

output policyName string = policyName
output policyId string = resourceId('Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies', policyName)
output publicIpAddress string = publicIp.?properties.?ipAddress ?? ''
output appGatewayName string = appGateway.?name ?? ''
