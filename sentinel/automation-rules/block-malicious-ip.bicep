targetScope = 'resourceGroup'

@description('Log Analytics workspace that hosts Microsoft Sentinel.')
param workspaceName string

@description('Full resource id of the ASE POC simulated-probe analytics rule.')
param analyticsRuleId string

@description('Full resource id of the block-IP Logic App.')
param playbookResourceId string

@description('When false, the rule is deployed but does not run the playbook.')
param enabled bool = true

// Created in its own deployment because Sentinel rejects a RunPlaybook action
// until the Azure Security Insights service principal has Microsoft Sentinel
// Automation Contributor on the resource group that contains the playbook.
resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource automationRule 'Microsoft.SecurityInsights/automationRules@2024-01-01-preview' = {
  name: guid('ase-waf-block-playbook', workspace.id)
  scope: workspace
  properties: {
    displayName: 'ASE POC - run block playbook for simulated WAF probe'
    order: 100
    triggeringLogic: {
      isEnabled: enabled
      triggersOn: 'Incidents'
      triggersWhen: 'Created'
      conditions: [
        {
          conditionType: 'Property'
          conditionProperties: {
            propertyName: 'IncidentRelatedAnalyticRuleIds'
            operator: 'Contains'
            propertyValues: [
              analyticsRuleId
            ]
          }
        }
      ]
    }
    actions: [
      {
        order: 1
        actionType: 'ModifyProperties'
        actionConfiguration: {
          status: 'Active'
          labels: [
            {
              labelName: 'poc-simulated-probe'
            }
          ]
        }
      }
      {
        order: 2
        actionType: 'RunPlaybook'
        actionConfiguration: {
          logicAppResourceId: playbookResourceId
          tenantId: tenant().tenantId
        }
      }
    ]
  }
}

output automationRuleName string = automationRule.name
output automationRuleId string = automationRule.id
