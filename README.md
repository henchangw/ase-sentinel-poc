# ASE Sentinel WAF block POC

Proof of concept for this path:

`WAF request -> diagnostic log -> Log Analytics -> Sentinel analytics rule -> incident -> automation rule -> Logic App -> block decision`

The detection is a **simulated probe**, a normal HTTP GET that carries the query-string marker `ase-poc-probe`. It does not identify a malicious actor. The playbook's safe default is dry-run: it records `Would block IP: <address>` on the Sentinel incident and does not change the WAF.

This is a reference implementation, not a production deployment. Nothing in this repository was deployed to an Azure subscription as part of authoring it. Bicep was compiled locally. See [Known limitations](#known-limitations).

## What the POC demonstrates

1. An Application Gateway WAF test rig writes firewall logs to Log Analytics.
2. Microsoft Sentinel is enabled on that workspace.
3. A scheduled analytics rule matches the simulated probe and opens an incident with the source IP as an entity.
4. An automation rule starts a Logic App playbook.
5. The playbook validates the IP, refuses protected ranges, and in the default configuration only records what it would block.
6. Opt-in mode adds the IP to one WAF custom rule and writes the result back on the incident.

Application Gateway is the **test rig**, because ASE has not confirmed which WAF product is in production. Front Door is a substitutable query and policy shape. This repository does not create Front Door and does not turn on Front Door diagnostics.

## Architecture

```
test.ps1
    |
    |  GET /?ase-poc-probe=1
    v
+-------------------------------------------+
| Application Gateway WAF_v2 (POC test rig) |
| policy mode Prevention                    |
| custom rule PocSimulatedProbe (priority 50)|
|   QueryString contains ase-poc-probe      |
|   action Block                            |
+-------------------------------------------+
    |  diagnostic setting on the gateway
    |  logAnalyticsDestinationType = Dedicated
    |  category ApplicationGatewayFirewallLog
    v
+-------------------------------------------+
| Log Analytics                             |
| table AGWFirewallLogs                     |
| (this table is guaranteed by that setting)|
+-------------------------------------------+
    v
+-------------------------------------------+
| Microsoft Sentinel                        |
| analytics rule: ASE POC - simulated WAF   |
|   probe                                   |
| incident grouped by IP entity             |
+-------------------------------------------+
    |  automation rule, incident Created
    v
+-------------------------------------------+
| Logic App playbook, system-assigned MI    |
| 1. read IP entities                       |
| 2. validate IPv4                          |
| 3. reject loopback, RFC1918, link-local,  |
|    169.254.169.254, CGNAT, protectedIpRanges|
| 4. read the WAF policy                    |
| 5. dry-run comment, or PUT if opted in    |
+-------------------------------------------+
    |
    v
custom rule SentinelAutoBlock (priority 10)
RemoteAddr IPMatch, action Block
created only on the first opted-in block

Front Door path (not deployed):
  existing Front Door WAF policy
  -> logs ASE already sends to a workspace
  -> AzureDiagnostics category FrontDoorWebApplicationFirewallLog
     (or AzureFrontDoorWebApplicationFirewallLog only if ASE confirms it)
  -> same Sentinel incident and playbook
  -> PUT uses Front Door customRules.rules and matchValue
```

| Piece | Role |
| --- | --- |
| `infra/main.bicep` | Resource group contents: workspace, Sentinel, test WAF, playbook, RBAC |
| `sentinel/analytics-rules/` | KQL per WAF product and log schema |
| `sentinel/automation-rules/` | Second deployment. Sentinel rejects `RunPlaybook` until Azure Security Insights can run playbooks |
| `playbooks/block-malicious-ip/` | Logic App definition |
| `scripts/deploy.ps1` | Supported deploy path, including the automation-rule phase |
| `scripts/test.ps1` | Sends the probe marker |
| `scripts/cleanup.ps1` | Deletes the resource group after the name is confirmed |

More detail is in [docs/architecture.md](docs/architecture.md).

## Prerequisites

- Azure CLI 2.89 or newer, with Bicep (this tree was compiled with Bicep 0.47.16).
- PowerShell 7.
- A subscription where you can create a resource group, role assignments, and Microsoft Sentinel.
- Resource providers already registered: `Microsoft.OperationalInsights`, `Microsoft.OperationsManagement`, `Microsoft.SecurityInsights`, `Microsoft.Network`, `Microsoft.Logic`, `Microsoft.Web`, `Microsoft.Insights`. This script does not register them.
- Rights to assign **Microsoft Sentinel Automation Contributor** to the **Azure Security Insights** service principal on the POC resource group. The script looks that principal up by display name. If the lookup fails, re-run with `-AutomationRuleOnly` after Sentinel is available in the tenant.
- A region that offers Application Gateway WAF_v2 when you deploy the test rig. `eastus` is the script default.
- For Front Door, an existing WAF policy resource id and a workspace that already receives that policy's logs. This repo will not create those logs.

WAF_v2 bills per gateway-hour until the resource group is deleted. The default autoscale is min 1, max 2.

## Deployment

Supported command:

```powershell
./scripts/deploy.ps1 -ResourceGroupName rg-ase-sentinel-poc -Location eastus
```

Defaults that matter:

| Parameter | Default | Effect |
| --- | --- | --- |
| `autoBlockEnabled` | `false` | Dry-run. No WAF write |
| `wafProvider` | `ApplicationGateway` | Test rig plus `AGWFirewallLogs` query |
| `deployTestWaf` | `true` | Create the gateway, policy, and Dedicated diagnostics |
| `wafMode` | `Prevention` | Mode Microsoft documents as enforcing WAF actions |
| `detectionThreshold` | `3` | Matching events per IP in the observation window |
| `queryFrequencyMinutes` | `5` | Sentinel minimum schedule |
| `queryLookbackMinutes` | `30` | Observation window |
| `protectedIpRanges` | empty | Customer ranges, in addition to the built-in ranges |
| `maximumBlockEntries` | `100` | Cap on the block custom rule |
| `overrideProtectedRanges` | `false` | Do not skip protected ranges |

Preview without writes:

```powershell
./scripts/deploy.ps1 -WhatIf
```

`-WhatIf` stops after the main what-if. It does not create the automation rule.

`infra/parameters/main.bicepparam` repeats the safe defaults for an engineer who wants to read them. Deploying that file alone does **not** create the automation rule. Use `scripts/deploy.ps1`.

The script deploys in two phases:

1. `infra/main.bicep` creates the workspace, Sentinel, the test WAF, the playbook, Sentinel Responder on the resource group, and Network Contributor on the WAF policy only.
2. After the Azure Security Insights principal has **Microsoft Sentinel Automation Contributor** (`f4c81013-99ee-4d62-a7ee-b3f1f648599a`) on the resource group, `sentinel/automation-rules/block-malicious-ip.bicep` creates the automation rule. The script waits 30 seconds. If that is not long enough, the rule deployment fails and you re-run `-AutomationRuleOnly`.

Step-by-step notes, including an existing policy, are in [docs/deployment.md](docs/deployment.md).

## Test procedure

Full checklist: [docs/testing.md](docs/testing.md).

```powershell
./scripts/test.ps1 -Target http://<public-ip>/ -Count 5
```

`-Count` must be at least `detectionThreshold` (default 3). The script sends only `GET /?ase-poc-probe=1`.

Then, in the Sentinel workspace:

1. Run `sentinel/queries/verify-application-gateway.kql`.
2. Wait for the analytics rule. End-to-end latency is usually 10 to 15 minutes.
3. Open the incident. The label is `poc-simulated-probe`.
4. Open the playbook comment. In the default deployment it contains `Would block IP: <address>` and the policy is unchanged.

Optional log check from the script, after you have the workspace customer id (a GUID):

```powershell
./scripts/test.ps1 -Target http://<public-ip>/ -Count 5 -WorkspaceId <workspace-guid> -WaitSeconds 180
```

Three minutes is often too short for ingestion. A miss on that query is not a failed WAF block. Re-run the KQL file later.

## Expected Sentinel incident

- Rule name: **ASE POC - simulated WAF probe**
- Severity: Medium
- Title shape: `ASE POC simulated WAF probe from <ip>`
- The description says this is a simulated probe, not an identified attacker.
- Entity: IP / Address = the client IP
- Custom details: event count, rule ids, messages, request URIs, hosts, WAF actions, first seen, last seen, probe marker
- Grouped by IP for 12 hours. A repeat does not open a second incident. Closed incidents are not reopened.
- The automation rule sets status Active and label `poc-simulated-probe`, then starts the playbook.

The analytics rule does not use an ATT&CK tactic. A probe marker is not an exploit technique.

## Expected automation flow

```
Incident created
  -> automation rule (only this analytics rule)
  -> playbook trigger /incident-creation
  -> Entities - Get IPs
  -> reject empty, non-IPv4, and protected addresses
  -> GET the WAF policy (read)
  -> skip addresses already on SentinelAutoBlock
  -> skip the write when the list would pass maximumBlockEntries
  -> if autoBlockEnabled is not exactly true: comment and stop
  -> if autoBlockEnabled is true: PUT the one custom rule, then comment
```

Failure comments are written on the incident when entity lookup, the policy read, the custom-rule shape, or the PUT fails. A failed PUT comment says not to assume the address was blocked.

## How dry-run works

`autoBlockEnabled` defaults to `false` in Bicep, in `infra/parameters/main.bicepparam`, in the Logic App parameter default, and in `scripts/deploy.ps1`.

When the value is not the boolean `true`:

- The playbook still validates the IP and reads the policy.
- If the address is already on the block rule, the comment says so and does not say "Would block".
- Otherwise the incident comment contains the exact text `Would block IP: <address>` (one line per new address, separated by `<br>`).
- There is no PUT on that path. The WAF policy and any network configuration are unchanged.

A customer range the playbook cannot evaluate (`/12`, `/10`, a bad token, and anything other than a single IPv4 or `/8`, `/16`, `/24`, `/32`) stops the run before any "Would block" line. That failure is closed: an unparsed allow range must not be treated as public.

## How actual blocking is enabled

Blocking is a second, explicit deploy. The script refuses `-AutoBlockEnabled $true` unless `-ConfirmAutoBlock` is also present.

```powershell
./scripts/deploy.ps1 `
  -ResourceGroupName rg-ase-sentinel-poc `
  -NamePrefix ase-sentinel-poc `
  -AutoBlockEnabled $true `
  -ConfirmAutoBlock
```

Use the same resource group and name prefix so Bicep updates the existing Logic App parameter. This does not rewrite the previous incident. Either wait for a new incident or resubmit the Logic App run after you have confirmed the new parameter. A resubmit uses the current definition and will PUT.

On success the comment contains `Blocked IP: <address>`, the rule name, the policy id, the list size, rejected addresses, and the Logic App run name. The rule is:

- Application Gateway: custom rule array, `matchVariables.variableName = RemoteAddr`, `matchValues`, `negationCondition = false`, action Block, state Enabled
- Front Door: `customRules.rules`, `matchVariable = RemoteAddr`, `matchValue`, `negateCondition = false`, `enabledState = Enabled`, action Block, and the sku echoed from the GET

Other custom rules, including `PocSimulatedProbe`, are copied onto the PUT. The Application Gateway PUT does not send `applicationGateways`, `httpListeners`, `pathBasedRules`, or `provisioningState`.

The block rule is priority 10, so after a real block that client may stop hitting the priority 50 probe rule. The analytics rule ignores `SentinelAutoBlock`, which avoids a feedback incident. It also means a blocked client will not keep generating probe incidents.

## How to remove a blocked IP

There is no automatic expiry and no unblock playbook. Dry-run mode has nothing to remove.

The evidence of why an address was added is the Sentinel incident comment plus the alert custom details, not a field on the WAF rule. Export the incident and the Logic App run before you delete the resource group if you need to keep that record.

Application Gateway, remove the whole POC block list (the probe rule is a different name and remains):

```powershell
az network application-gateway waf-policy custom-rule delete `
  --resource-group <rg> `
  --policy-name <policy> `
  --name SentinelAutoBlock
```

To remove one address, GET the policy and PUT it back without that address. Keep every other custom rule and the managed rules.

```powershell
az rest --method get --uri "<policy-resource-id>?api-version=2024-05-01"
```

Edit `properties.customRules` so `SentinelAutoBlock.matchConditions[0].matchValues` no longer contains the address. PUT `location`, `tags`, `properties.policySettings`, `properties.customRules`, and `properties.managedRules`. Do not PUT an empty `matchValues` array. If the list would be empty, delete the rule instead.

Front Door uses api-version `2024-02-01`. The list is `properties.customRules.rules`, and the addresses are `matchConditions[0].matchValue`. Echo `sku` as well. Delete the single rule with the Front Door WAF CLI or portal for your SKU if you want the whole list gone. Confirm the command against the policy type ASE actually uses. This repository does not invent a Front Door CLI command beyond the ARM shape above.

Built-in ranges that are never sent to the block list unless `overrideProtectedRanges` is true:

| Range | Why |
| --- | --- |
| `0.0.0.0/8` | "This" network |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | RFC1918 |
| `127.0.0.0/8` | Loopback |
| `169.254.0.0/16` and `169.254.169.254/32` | Link-local, including the Azure metadata address |
| `100.64.0.0/10` | Shared address space / CGNAT |

The analytics rule hard-codes those ranges and also loads watchlist `AseWafIpAllowlist`, which contains the same built-ins plus `protectedIpRanges`. Editing the watchlist cannot drop the built-ins. `overrideProtectedRanges` skips both filters in the KQL and the playbook. Invalid IPs are still rejected. The deploy script requires `-ConfirmOverrideProtectedRanges` before it will set that switch. Leave it false.

Customer `protectedIpRanges` accept only a single IPv4 or `/8`, `/16`, `/24`, `/32`, because that is what the Logic App expression can compare without a regex. `/12` and `/10` stay hard-coded so they are not forced through that matcher.

## Cleanup / destroy

```powershell
./scripts/cleanup.ps1 -ResourceGroupName rg-ase-sentinel-poc
```

The script prints what will be deleted and continues only if you type the resource group name. `-Force` skips the prompt. The delete is `az group delete --yes --no-wait`.

That deletes the workspace, Sentinel, the playbook, the test gateway, and a WAF policy that lives **in that resource group**. A policy in another resource group is not deleted, and addresses the playbook added there are not removed. Remove those first if you opted in against an existing policy.

## Known limitations

- Syntax-checked with `az bicep build` and PowerShell parsing. Not deployed, and the KQL was not executed against a live workspace.
- The test gateway is HTTP/80, with dummy backend `192.0.2.10`, no TLS, no NSG, and no availability zones. Those are POC shortcuts. See [docs/production-hardening.md](docs/production-hardening.md).
- WAF_v2 cost starts when the gateway exists and stops when the resource group delete finishes.
- Microsoft documents that an Application Gateway custom block rule is logged and **not** enforced while the policy is in Detection mode. The default here is Prevention so the probe returns 403 and the log action can be `Blocked`. The query also accepts `Detected` so a Detection-mode log can still open an incident. If a live workspace shows a different `Action` value, change the query after you see that value. Do not add action names that have not been observed.
- Front Door log rows use `Block` and `Log`, not `Blocked`. The Front Door queries in this repo follow that. They are not deployed against a Front Door diagnostic setting this repo creates.
- `AzureFrontDoorWebApplicationFirewallLog` is optional and unconfirmed. The default Front Door query uses `AzureDiagnostics` and `Category == "FrontDoorWebApplicationFirewallLog"`, which is the schema Microsoft documents.
- The playbook's customer-range matcher is exact IP, `/8`, `/16`, `/24`, and `/32` only.
- Network Contributor on the policy is wider than "edit one custom rule". A custom role was not invented here.
- The PUT does not use `If-Match`. A concurrent policy edit can be overwritten. The PUT is not retried.
- No automatic unblock, no expiry, and no analyst approval gate inside Sentinel. Approval is "do not set `autoBlockEnabled`".
- After a real block, that IP can stop producing probe logs.
- The 30 second wait for the automation-rule role can be too short.
- The Azure Security Insights lookup depends on the display name `Azure Security Insights`.

## Questions to Confirm with ASE

This repository does not answer these. The Application Gateway resources are a disposable test rig so an engineer can run the workflow before ASE confirms production. They are not a guess about the production design.

1. Is the existing WAF Azure Application Gateway WAF or Azure Front Door WAF?
2. What architecture was implemented at the other ASE site?
3. Is there an existing Microsoft support case for the previous "Sentinel / Block-IP / Azure WAF" investigation?
4. Which WAF logs are currently enabled?
5. Which Log Analytics workspace / Sentinel workspace is intended?
6. What is the desired blocking target?
7. Should automatic blocking be fully automatic or analyst-approved?
8. What IP allowlist / protected ranges must never be blocked?
9. What retention / rollback policy should apply to blocked addresses?

## Layout

```
/
├── README.md
├── docs/
│   ├── architecture.md
│   ├── deployment.md
│   ├── testing.md
│   ├── security-considerations.md
│   └── production-hardening.md
├── infra/
│   ├── main.bicep
│   ├── parameters/main.bicepparam
│   ├── role-sentinel-automation.bicep
│   └── modules/
├── sentinel/
│   ├── analytics-rules/
│   ├── automation-rules/
│   └── queries/
├── playbooks/block-malicious-ip/
├── scripts/
│   ├── deploy.ps1
│   ├── test.ps1
│   └── cleanup.ps1
└── .gitignore
```
