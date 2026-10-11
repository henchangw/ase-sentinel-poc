# Deployment

Use `scripts/deploy.ps1`. It creates the resource group, deploys `infra/main.bicep`, assigns the Sentinel automation role, and then deploys the automation rule. `infra/parameters/main.bicepparam` is the safe default set for review. A deployment that uses only that file does not create the automation rule, so Sentinel will not call the playbook.

## Default test rig

```powershell
./scripts/deploy.ps1 -ResourceGroupName rg-ase-sentinel-poc -Location eastus
```

What-if, main template only:

```powershell
./scripts/deploy.ps1 -ResourceGroupName rg-ase-sentinel-poc -Location eastus -WhatIf
```

The script prints a warning that WAF_v2 bills hourly. Application Gateway deployments often take 20 to 40 minutes.

Outputs include the workspace name, workspace resource id, policy id, playbook name, `autoBlockEnabled`, the detection query kind, the analytics rule id, and the public IP when the test rig was created.

## Parameters the script enforces

- `QueryFrequencyMinutes` <= `QueryLookbackMinutes`
- Application Gateway min capacity <= max capacity, and max capacity >= 2
- `ProbeRulePriority` != `BlockRulePriority`
- `FrontDoor` requires `-DeployTestWaf $false` and either `-ExistingWafPolicyName` or `-ExistingWafPolicyResourceId`
- The test rig rejects an existing policy name or id at the same time, so a deploy cannot silently ignore one
- An existing resource id must be the ARM type for the selected provider
- `-AutoBlockEnabled $true` requires `-ConfirmAutoBlock`
- `-OverrideProtectedRanges $true` requires `-ConfirmOverrideProtectedRanges`
- Each `ProtectedIpRanges` entry matches an IPv4 address or `/8`, `/16`, `/24`, `/32`
- `NamePrefix` is 3 to 24 characters of lowercase letters, digits, and hyphens
- `ProbeMarker` is 3 to 40 letters, digits, and hyphens, so it cannot break the KQL string it is substituted into

Customer ranges are passed as a JSON array string. A one-element array stays an array.

## Existing Application Gateway policy

Only do this with a disposable policy. The playbook receives Network Contributor on that policy. Opt-in mode PUTs the policy.

```powershell
./scripts/deploy.ps1 `
  -ResourceGroupName rg-ase-sentinel-poc `
  -DeployTestWaf $false `
  -WafProvider ApplicationGateway `
  -ExistingWafPolicyName wafpol-disposable
```

This path does **not** add `PocSimulatedProbe` and does **not** create a diagnostic setting. Create an equivalent custom rule yourself if you want the same marker, and point that gateway's `ApplicationGatewayFirewallLog` at the workspace this deployment creates. If the policy is in another resource group, pass `-ExistingWafPolicyResourceId` instead of the name. The identity that runs the script needs `Microsoft.Authorization/roleAssignments/write` on that policy.

Until those logs arrive, the analytics rule has nothing to match. That is expected. This repository does not attach diagnostics to a gateway it did not create.

## Front Door

```powershell
./scripts/deploy.ps1 `
  -ResourceGroupName rg-ase-sentinel-poc `
  -WafProvider FrontDoor `
  -DeployTestWaf $false `
  -ExistingWafPolicyResourceId /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/frontDoorWebApplicationFirewallPolicies/<policy> `
  -FrontDoorLogDestination AzureDiagnostics
```

What this does not do:

- Create a Front Door profile, endpoint, origin, or WAF policy
- Enable Front Door diagnostic logs
- Send test traffic at a Front Door hostname
- Prove that `AzureFrontDoorWebApplicationFirewallLog` exists

`AzureDiagnostics` is the query Microsoft documents (`Category == "FrontDoorWebApplicationFirewallLog"`, with `column_ifexists` for `clientIP_s`, `action_s`, `ruleName_s`, `requestUri_s`, and `host_s`). Use `-FrontDoorLogDestination ResourceSpecific` only after ASE confirms `AzureFrontDoorWebApplicationFirewallLog` in the chosen workspace. The script warns when that option is selected.

The playbook still dry-runs unless you also pass `-AutoBlockEnabled $true -ConfirmAutoBlock`.

## Automation rule phase

Sentinel returns an error if an automation rule uses `RunPlaybook` before the **Azure Security Insights** service principal has **Microsoft Sentinel Automation Contributor** on the playbook's resource group.

The script:

1. Resolves that principal with `az ad sp list --display-name "Azure Security Insights"`.
2. Deploys `infra/role-sentinel-automation.bicep`.
3. Waits 30 seconds.
4. Deploys `sentinel/automation-rules/block-malicious-ip.bicep` using the workspace name, analytics rule id, and playbook id from the main deployment outputs.

If the principal cannot be found, the script leaves the analytics rule and the playbook in place and tells you to re-run:

```powershell
./scripts/deploy.ps1 -ResourceGroupName rg-ase-sentinel-poc -AutomationRuleOnly
```

`-AutomationRuleOnly` still needs a successful `ase-sentinel-poc-main` deployment in that resource group. It does not combine with `-WhatIf`.

If the second deployment fails on replication, wait and run `-AutomationRuleOnly` again. The rule name is stable, so the retry updates the same rule.

## Turning blocking on later

Redeploy with the same resource group and name prefix:

```powershell
./scripts/deploy.ps1 `
  -ResourceGroupName rg-ase-sentinel-poc `
  -NamePrefix ase-sentinel-poc `
  -AutoBlockEnabled $true `
  -ConfirmAutoBlock
```

Bicep updates the Logic App parameter. Previous incidents are not replayed. Resubmitting the Logic App run after this change uses the new parameter and will PUT. Read [security-considerations.md](security-considerations.md) before you do that against any policy you need to keep.

## Destroy

```powershell
./scripts/cleanup.ps1 -ResourceGroupName rg-ase-sentinel-poc
```

Type the resource group name when prompted. `-Force` skips the prompt and is still a full group delete.

If opt-in mode wrote a policy outside this resource group, `cleanup.ps1` does not remove those addresses. Remove them with the procedure in the README first.
