# Deploys the ASE WAF -> Sentinel -> dry-run block proof of concept.
# Requires Azure CLI, a subscription, and rights to create the resource group,
# role assignments, and Microsoft Sentinel. This script does not register resource providers.
#requires -Version 7.0
[CmdletBinding()]
param(
    [string] $SubscriptionId,
    [string] $ResourceGroupName = 'rg-ase-sentinel-poc',
    [string] $Location = 'eastus',
    [ValidatePattern('^[a-z0-9-]{3,24}$')]
    [string] $NamePrefix = 'ase-sentinel-poc',
    [ValidateSet('ApplicationGateway', 'FrontDoor')]
    [string] $WafProvider = 'ApplicationGateway',
    [bool] $DeployTestWaf = $true,
    [string] $ExistingWafPolicyName = '',
    [string] $ExistingWafPolicyResourceId = '',
    [ValidateSet('AzureDiagnostics', 'ResourceSpecific')]
    [string] $FrontDoorLogDestination = 'AzureDiagnostics',
    [ValidateSet('Prevention', 'Detection')]
    [string] $WafMode = 'Prevention',
    [bool] $AutoBlockEnabled = $false,
    [switch] $ConfirmAutoBlock,
    [bool] $OverrideProtectedRanges = $false,
    [switch] $ConfirmOverrideProtectedRanges,
    [string[]] $ProtectedIpRanges = @(),
    [ValidateRange(1, 500)]
    [int] $MaximumBlockEntries = 100,
    [ValidateRange(1, 100)]
    [int] $DetectionThreshold = 3,
    [ValidateRange(5, 60)]
    [int] $QueryFrequencyMinutes = 5,
    [ValidateRange(5, 1440)]
    [int] $QueryLookbackMinutes = 30,
    [ValidatePattern('^[A-Za-z0-9-]{3,40}$')]
    [string] $ProbeMarker = 'ase-poc-probe',
    [ValidatePattern('^[A-Za-z][A-Za-z0-9]{2,39}$')]
    [string] $ProbeRuleName = 'PocSimulatedProbe',
    [ValidateRange(1, 100)]
    [int] $ProbeRulePriority = 50,
    [ValidatePattern('^[A-Za-z][A-Za-z0-9]{2,39}$')]
    [string] $BlockRuleName = 'SentinelAutoBlock',
    [ValidateRange(1, 100)]
    [int] $BlockRulePriority = 10,
    [ValidateRange(1, 10)]
    [int] $AppGatewayMinCapacity = 1,
    [ValidateRange(2, 10)]
    [int] $AppGatewayMaxCapacity = 2,
    [switch] $AutomationRuleOnly,
    [switch] $WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}

if ($WhatIf -and $AutomationRuleOnly) {
    throw 'Use either -WhatIf or -AutomationRuleOnly, not both.'
}
if ($QueryFrequencyMinutes -gt $QueryLookbackMinutes) {
    throw "QueryFrequencyMinutes ($QueryFrequencyMinutes) must be less than or equal to QueryLookbackMinutes ($QueryLookbackMinutes)."
}
if ($AppGatewayMinCapacity -gt $AppGatewayMaxCapacity) {
    throw "AppGatewayMinCapacity ($AppGatewayMinCapacity) must be less than or equal to AppGatewayMaxCapacity ($AppGatewayMaxCapacity)."
}
if ($ProbeRulePriority -eq $BlockRulePriority) {
    throw 'ProbeRulePriority and BlockRulePriority must be different. The block rule is created later on the same policy.'
}
if ($WafProvider -eq 'FrontDoor' -and $DeployTestWaf) {
    throw 'This repository deploys a test WAF only for Application Gateway. For Front Door, pass -DeployTestWaf $false and an existing policy name or resource id. Front Door itself and its diagnostic settings are not created here.'
}
if ($DeployTestWaf -and -not [string]::IsNullOrWhiteSpace($ExistingWafPolicyName)) {
    throw 'DeployTestWaf creates the WAF policy. Do not also pass -ExistingWafPolicyName.'
}
if ($DeployTestWaf -and -not [string]::IsNullOrWhiteSpace($ExistingWafPolicyResourceId)) {
    throw 'DeployTestWaf creates the WAF policy. Do not also pass -ExistingWafPolicyResourceId.'
}
if (-not $DeployTestWaf -and [string]::IsNullOrWhiteSpace($ExistingWafPolicyName) -and [string]::IsNullOrWhiteSpace($ExistingWafPolicyResourceId)) {
    throw 'Without the test WAF, pass -ExistingWafPolicyName (same resource group) or -ExistingWafPolicyResourceId.'
}
if ($AutoBlockEnabled -and -not $ConfirmAutoBlock) {
    throw 'Refusing to enable blocking. autoBlockEnabled writes the WAF policy. Re-run with -AutoBlockEnabled $true -ConfirmAutoBlock after you intend that write.'
}
if ($OverrideProtectedRanges -and -not $ConfirmOverrideProtectedRanges) {
    throw 'Refusing to skip protected ranges. Re-run with -OverrideProtectedRanges $true -ConfirmOverrideProtectedRanges only when that exception is intended. Invalid IPs are still rejected.'
}
if ($WafProvider -eq 'FrontDoor' -and $FrontDoorLogDestination -eq 'ResourceSpecific') {
    Write-Warning 'ResourceSpecific selects AzureFrontDoorWebApplicationFirewallLog. This repository does not create that diagnostic setting. Use it only after ASE confirms the table exists. The default AzureDiagnostics query is the one Microsoft documents.'
}
if ($WafMode -eq 'Detection') {
    Write-Warning 'Detection mode logs an Application Gateway custom block rule and does not enforce it. The analytics rule accepts Action Blocked or Detected. A Prevention-mode test is what produces HTTP 403.'
}
if ($AutoBlockEnabled) {
    Write-Warning 'autoBlockEnabled is true. The next matching incident will PUT the WAF policy. Dry-run is no longer the behavior of this deployment.'
}

$rangePattern = '^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:/(?:8|16|24|32))?$'
foreach ($entry in $ProtectedIpRanges) {
    if ($entry -notmatch $rangePattern) {
        throw "Protected range '$entry' is not an IPv4 address or a /8, /16, /24, or /32 prefix. The playbook fails closed on other prefixes. 172.16.0.0/12 and 100.64.0.0/10 are already built in."
    }
}
if (-not [string]::IsNullOrWhiteSpace($ExistingWafPolicyResourceId)) {
    $agwType = 'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies'
    $fdType = 'Microsoft.Network/frontDoorWebApplicationFirewallPolicies'
    $expectedType = if ($WafProvider -eq 'FrontDoor') { $fdType } else { $agwType }
    if ($ExistingWafPolicyResourceId -notmatch "^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/$([regex]::Escape($expectedType))/[^/]+$") {
        throw "ExistingWafPolicyResourceId must be a resource id for $expectedType."
    }
}

function ConvertTo-BicepArray {
    param([string[]] $Values)
    if ($null -eq $Values -or $Values.Count -eq 0) {
        return '[]'
    }
    $quoted = foreach ($value in $Values) {
        '"' + $value + '"'
    }
    return '[' + ($quoted -join ',') + ']'
}

function Invoke-AzCli {
    param(
        [Parameter(Mandatory)]
        [string[]] $Arguments
    )
    Write-Host "az $($Arguments -join ' ')"
    & az @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI failed with exit code $LASTEXITCODE."
    }
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI (az) is not installed or not on PATH.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$infra = Join-Path $repoRoot 'infra'
$rangesJson = ConvertTo-BicepArray -Values $ProtectedIpRanges

if ($SubscriptionId) {
    Invoke-AzCli @('account', 'set', '--subscription', $SubscriptionId)
}
Invoke-AzCli @('account', 'show', '--output', 'none')

if (-not $AutomationRuleOnly) {
    if ($DeployTestWaf) {
        Write-Warning 'The test Application Gateway uses WAF_v2 and bills hourly until the resource group is deleted.'
    }
    Invoke-AzCli @(
        'group', 'create',
        '--name', $ResourceGroupName,
        '--location', $Location,
        '--tags', 'Customer=ASE', 'Purpose=SentinelWafBlockPoc', 'Environment=poc', 'ManagedBy=bicep'
    )

    $mainArgs = @(
        'deployment', 'group', $(if ($WhatIf) { 'what-if' } else { 'create' }),
        '--name', 'ase-sentinel-poc-main',
        '--resource-group', $ResourceGroupName,
        '--template-file', (Join-Path $infra 'main.bicep'),
        '--parameters',
        "location=$Location",
        "namePrefix=$NamePrefix",
        "wafProvider=$WafProvider",
        "deployTestWaf=$($DeployTestWaf.ToString().ToLowerInvariant())",
        "existingWafPolicyName=$ExistingWafPolicyName",
        "existingWafPolicyResourceId=$ExistingWafPolicyResourceId",
        "frontDoorLogDestination=$FrontDoorLogDestination",
        "wafMode=$WafMode",
        "autoBlockEnabled=$($AutoBlockEnabled.ToString().ToLowerInvariant())",
        "overrideProtectedRanges=$($OverrideProtectedRanges.ToString().ToLowerInvariant())",
        "protectedIpRanges=$rangesJson",
        "maximumBlockEntries=$MaximumBlockEntries",
        "detectionThreshold=$DetectionThreshold",
        "queryFrequencyMinutes=$QueryFrequencyMinutes",
        "queryLookbackMinutes=$QueryLookbackMinutes",
        "probeMarker=$ProbeMarker",
        "probeRuleName=$ProbeRuleName",
        "probeRulePriority=$ProbeRulePriority",
        "blockRuleName=$BlockRuleName",
        "blockRulePriority=$BlockRulePriority",
        "appGatewayMinCapacity=$AppGatewayMinCapacity",
        "appGatewayMaxCapacity=$AppGatewayMaxCapacity"
    )
    if (-not $WhatIf) {
        Write-Host 'Main deployment started. Application Gateway WAF_v2 often takes 20 to 40 minutes.'
    }
    Invoke-AzCli $mainArgs
}

if ($WhatIf) {
    Write-Host 'What-if complete. No automation rule was deployed. Nothing was blocked.'
    return
}

function Get-SentinelAutomationPrincipalId {
    # display-name is a prefix match and also returns Content As Code and Management.
    $raw = az ad sp list --display-name 'Azure Security Insights' --query "[?displayName=='Azure Security Insights'].id" --output tsv 2>$null
    if ($LASTEXITCODE -ne 0) {
        return $null
    }
    $lines = @($raw -split "\r?\n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($lines.Count -eq 0) {
        return $null
    }
    return $lines[0]
}

$principalId = Get-SentinelAutomationPrincipalId
if (-not $principalId) {
    Write-Warning 'Could not find the Azure Security Insights service principal. The workspace, analytics rule, and playbook are deployed. The automation rule was not created. After Sentinel is available in the tenant, re-run this script with -AutomationRuleOnly.'
}
else {
    Write-Host "Azure Security Insights object id: $principalId"
    Invoke-AzCli @(
        'deployment', 'group', 'create',
        '--name', 'ase-sentinel-poc-automation-role',
        '--resource-group', $ResourceGroupName,
        '--template-file', (Join-Path $infra 'role-sentinel-automation.bicep'),
        '--parameters', "principalId=$principalId"
    )
    Write-Host 'Waiting 30 seconds for the role assignment to replicate before creating the automation rule.'
    Start-Sleep -Seconds 30
    $deployment = az deployment group show --name 'ase-sentinel-poc-main' --resource-group $ResourceGroupName --query 'properties.outputs' --output json
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not read outputs from deployment ase-sentinel-poc-main.'
    }
    $outputs = $deployment | ConvertFrom-Json
    Invoke-AzCli @(
        'deployment', 'group', 'create',
        '--name', 'ase-sentinel-poc-automation-rule',
        '--resource-group', $ResourceGroupName,
        '--template-file', (Join-Path $repoRoot 'sentinel\automation-rules\block-malicious-ip.bicep'),
        '--parameters',
        "workspaceName=$($outputs.workspaceName.value)",
        "analyticsRuleId=$($outputs.analyticsRuleId.value)",
        "playbookResourceId=$($outputs.playbookResourceId.value)",
        'enabled=true'
    )
}

$shownRaw = az deployment group show --name 'ase-sentinel-poc-main' --resource-group $ResourceGroupName --query 'properties.outputs' --output json
if ($LASTEXITCODE -ne 0) {
    throw 'Could not read outputs from deployment ase-sentinel-poc-main.'
}
$shown = $shownRaw | ConvertFrom-Json
Write-Host ''
Write-Host "Resource group:      $ResourceGroupName"
Write-Host "Workspace:           $($shown.workspaceName.value)"
Write-Host "Workspace id:        $($shown.workspaceResourceId.value)"
Write-Host "WAF provider:        $($shown.wafProvider.value)"
Write-Host "WAF policy:          $($shown.wafPolicyName.value)"
Write-Host "WAF policy id:       $($shown.wafPolicyId.value)"
Write-Host "Playbook:            $($shown.playbookName.value)"
Write-Host "autoBlockEnabled:    $($shown.autoBlockEnabled.value)"
Write-Host "Detection query:     $($shown.detectionQueryKind.value)"
Write-Host "Analytics rule id:   $($shown.analyticsRuleId.value)"
Write-Host "Probe marker:        $($shown.probeMarker.value)"
if ($shown.publicIpAddress.value) {
    Write-Host "Application Gateway: http://$($shown.publicIpAddress.value)/"
    Write-Host "Test:                ./scripts/test.ps1 -Target http://$($shown.publicIpAddress.value)/ -Count $DetectionThreshold"
}
else {
    Write-Host 'No test Application Gateway was deployed. This repository does not send Front Door traffic and does not configure Front Door diagnostics.'
}
Write-Host ''
if ($shown.autoBlockEnabled.value -eq $true) {
    Write-Host 'Blocking is enabled. A matching incident can change the WAF policy.'
}
else {
    Write-Host 'Dry-run is active. A matching incident records "Would block IP: <address>" and does not change the WAF policy.'
    Write-Host 'To opt in later, redeploy with -AutoBlockEnabled $true -ConfirmAutoBlock and the same resource group and name prefix.'
}
Write-Host 'Cleanup: ./scripts/cleanup.ps1 -ResourceGroupName' $ResourceGroupName
Write-Host 'Incident latency is usually 10 to 15 minutes: ingestion plus the analytics schedule.'
Write-Host 'The procedure is in docs/testing.md.'
