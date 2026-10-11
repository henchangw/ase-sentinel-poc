# Sends the deterministic POC probe to a WAF endpoint.
# The request is a normal GET with the configured query-string marker.
#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $Target,
    [ValidateRange(1, 20)]
    [int] $Count = 5,
    [ValidatePattern('^[A-Za-z0-9-]{3,40}$')]
    [string] $ProbeMarker = 'ase-poc-probe',
    [ValidateSet('ApplicationGateway', 'FrontDoor')]
    [string] $WafProvider = 'ApplicationGateway',
    [ValidateSet('AzureDiagnostics', 'ResourceSpecific')]
    [string] $FrontDoorLogDestination = 'AzureDiagnostics',
    [string] $WorkspaceId,
    [ValidateRange(0, 3600)]
    [int] $WaitSeconds = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}

if ($WaitSeconds -gt 0 -and [string]::IsNullOrWhiteSpace($WorkspaceId)) {
    throw 'WaitSeconds requires -WorkspaceId. Leave WaitSeconds at 0 to send traffic without querying Log Analytics.'
}

$trimmed = $Target.TrimEnd('/')
$uri = if ($trimmed.Contains('?')) { "$trimmed&${ProbeMarker}=1" } else { "$trimmed/?${ProbeMarker}=1" }
Write-Host "Sending $Count GET request(s) to $uri"
Write-Host 'This is the POC marker only. It is not an exploit payload.'

$statuses = @()
for ($i = 1; $i -le $Count; $i++) {
    $response = Invoke-WebRequest -Uri $uri -Method GET -MaximumRedirection 0 -SkipHttpErrorCheck
    $statuses += [int] $response.StatusCode
    Write-Host ("{0}/{1} HTTP {2}" -f $i, $Count, $response.StatusCode)
}

$blocked = @($statuses | Where-Object { $_ -eq 403 }).Count
$gatewayError = @($statuses | Where-Object { $_ -eq 502 }).Count
Write-Host ''
if ($blocked -eq $Count) {
    Write-Host 'Every request returned 403. That is the expected Prevention-mode result for the Application Gateway probe rule.'
}
elseif ($gatewayError -gt 0) {
    Write-Host 'At least one request returned 502. The probe rule did not block it, and the POC backend is the documentation address 192.0.2.10.'
}
else {
    Write-Host 'Review the status codes above. Prevention mode on the test gateway is expected to return 403 for this marker.'
}
Write-Host 'HTTP 403 does not by itself prove the Sentinel incident. Wait for ingestion and the analytics schedule, usually 10 to 15 minutes.'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$queryName = if ($WafProvider -eq 'FrontDoor') {
    if ($FrontDoorLogDestination -eq 'ResourceSpecific') { 'verify-front-door-resource-specific.kql' } else { 'verify-front-door-azurediagnostics.kql' }
}
else {
    'verify-application-gateway.kql'
}
$queryPath = Join-Path $repoRoot "sentinel\queries\$queryName"
Write-Host "Verification query: $queryPath"

if ($WaitSeconds -gt 0) {
    Write-Host "Waiting $WaitSeconds seconds before querying workspace $WorkspaceId."
    Start-Sleep -Seconds $WaitSeconds
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        throw 'Azure CLI (az) is required for the workspace query.'
    }
    $query = Get-Content -Path $queryPath -Raw
    & az monitor log-analytics query --workspace $WorkspaceId --analytics-query $query --output table
    if ($LASTEXITCODE -ne 0) {
        throw "Log Analytics query failed with exit code $LASTEXITCODE. Run the verification file in the Sentinel Logs blade after ingestion catches up."
    }
}
