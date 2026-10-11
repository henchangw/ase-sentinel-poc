# Deletes the POC resource group. This is destructive and irreversible.
# A WAF policy that lives in a different resource group is not deleted.
#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $ResourceGroupName,
    [switch] $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}

Write-Host "This deletes resource group '$ResourceGroupName' and everything in it:"
Write-Host '  Log Analytics workspace, Microsoft Sentinel, the playbook, role assignments created here,'
Write-Host '  and the test Application Gateway, public IP, VNet, and WAF policy if this POC created them.'
Write-Host 'A WAF policy in another resource group is not deleted. Addresses added to that policy are also not removed.'
Write-Host 'Export the Sentinel incident and the Logic App run first if that evidence must be kept.'

if (-not $Force) {
    $typed = Read-Host "Type the resource group name to delete"
    if ($typed -cne $ResourceGroupName) {
        throw "The name did not match '$ResourceGroupName'. Nothing was deleted."
    }
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI (az) is not installed or not on PATH.'
}

Write-Host "az group delete --name $ResourceGroupName --yes --no-wait"
az group delete --name $ResourceGroupName --yes --no-wait
if ($LASTEXITCODE -ne 0) {
    throw "Azure CLI failed with exit code $LASTEXITCODE. Nothing further was changed by this script."
}
Write-Host "Delete requested. Azure continues in the background. Check with: az group exists --name $ResourceGroupName"
