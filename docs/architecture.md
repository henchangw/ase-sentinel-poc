# Architecture

The POC is one resource group. An engineer can delete that group and redeploy it. Sentinel content that must exist before an automation rule can call a playbook is a second deployment in the same group. See [deployment.md](deployment.md).

## Test rig versus the customer's WAF

`wafProvider` is `ApplicationGateway` or `FrontDoor`.

| | Application Gateway (default) | Front Door |
| --- | --- | --- |
| Created by this repo | Yes, when `deployTestWaf` is true | No |
| Policy type | `Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies` | `Microsoft.Network/frontDoorWebApplicationFirewallPolicies` |
| ARM api-version used by the playbook | `2024-05-01` | `2024-02-01` |
| Diagnostics configured here | Dedicated, category `ApplicationGatewayFirewallLog` | Not configured. ASE must already send logs |
| Table the analytics rule queries | `AGWFirewallLogs` | Default: `AzureDiagnostics`. Optional: `AzureFrontDoorWebApplicationFirewallLog` |
| Why that table is safe to name | `logAnalyticsDestinationType = Dedicated` on that category writes `AGWFirewallLogs`. Without Dedicated, the same category lands in `AzureDiagnostics` | Microsoft’s Front Door WAF samples use `AzureDiagnostics` and category `FrontDoorWebApplicationFirewallLog`. This repo does not create a resource-specific setting, so it does not claim `AzureFrontDoorWebApplicationFirewallLog` unless `frontDoorLogDestination` is set to `ResourceSpecific` |
| Action values the query accepts | `Blocked`, `Detected` | `Block`, `Log` |
| Block-rule JSON | `customRules[]`, `matchVariables[].variableName`, `matchValues`, `state` | `customRules.rules[]`, `matchVariable`, `matchValue`, `enabledState`, plus `sku` echoed from GET |

The KQL files are selected at deploy time in `infra/modules/sentinel.bicep`. Replacing the WAF product is a parameter and a policy resource id, not a rewrite of the incident path. The playbook branches on `wafProvider` and will not PUT when that value is anything else.

The Sentinel module waits for the test-rig module, which creates the Dedicated diagnostic setting, before the analytics rule that names `AGWFirewallLogs` is saved.

`deployTestWaf` is ignored unless the provider is Application Gateway. The deploy script rejects `FrontDoor` combined with the test rig so the two are not half-configured.

## Request path on the test rig

`scripts/test.ps1` sends `GET /?ase-poc-probe=1` to the gateway public IP on port 80.

The WAF policy is OWASP 3.2 plus one custom rule, `PocSimulatedProbe`, priority 50, match variable QueryString, operator Contains, value `ase-poc-probe`, action Block. No empty IPMatch rule is deployed. `SentinelAutoBlock` does not exist until the first opted-in playbook run.

The backend pool is `192.0.2.10`, a documentation address. In Prevention mode the probe rule is expected to answer 403 before that backend matters. Microsoft’s custom-rule documentation says Detection mode logs a custom block rule and does not enforce it, so a Detection-mode gateway is expected to pass the request and then fail at the dummy backend.

The gateway diagnostic setting enables `ApplicationGatewayFirewallLog` and `ApplicationGatewayAccessLog` with destination type Dedicated. Firewall rows are the detection source. Access logs are there so an operator can see the request if the firewall row is missing. The analytics rule does not read the access log.

## Detection

The scheduled rule is named **ASE POC - simulated WAF probe**. Its resource name is `guid('ase-waf-malicious-source-ip', workspace.id)` so a redeploy updates the same rule.

The query keeps a row when all of the following are true:

- The row is in the observation window (`queryLookbackMinutes`, also applied as the rule period).
- Application Gateway: `Action` is `Blocked` or `Detected`. Front Door: `Action` is `Block` or `Log`.
- The rule name is not `SentinelAutoBlock`.
- The rule name is `PocSimulatedProbe`, or the request URI contains `ase-poc-probe`.
- The client value is a non-empty IPv4 address.
- Unless `overrideProtectedRanges` is true: the address is not private, not inside the built-in ranges, and not inside watchlist `AseWafIpAllowlist`.

The summary is one row per client IP. Projected string columns are `ClientIp`, `EventCountText`, `RuleIdList`, `MessageList`, `RequestUriList`, `HostnameList`, `ActionList`, `FirstSeenText`, `LastSeenText`, and `ProbeMarkerText`. Sentinel custom details have to be strings. The IP entity mapping uses `ClientIp`.

The alert title is `ASE POC simulated WAF probe from {{ClientIp}}`. The description uses three placeholders, which is the Sentinel maximum: the event count, the client IP, and the action list. Rule ids, requests, hosts, and timestamps stay on the custom details.

Threshold and the observation window are parameters. The rule trigger is `GreaterThan 0` because the KQL already applies the threshold. Frequency cannot be below 5 minutes.

Incidents group on the IP entity for 12 hours. That lookback is separate from the observation window. The rule does not close incidents.

Tokens in the KQL files are replaced by Bicep `replace()` for the threshold, window, block rule name, probe rule name, probe marker, watchlist alias, and the override flag. The override flag is substituted as the bare KQL booleans `true` or `false`.

## Playbook

Consumption Logic App, system-assigned managed identity, definition in `playbooks/block-malicious-ip/workflow.json`.

The Sentinel connection uses `parameterValueType: Alternative` and `ManagedServiceIdentity`. Bicep warns BCP187 on `kind` and BCP037 on `parameterValueType`. Those properties are required for this connection and are kept.

Trigger path: `/incident-creation`. IP extraction: Sentinel action `Entities - Get IPs` with `triggerBody().object.properties.relatedEntities`.

Validation, in order:

1. If any `protectedIpRanges` entry is not a single IPv4 or `/8`, `/16`, `/24`, `/32`, comment and stop. No "Would block" line.
2. Reject empty values, anything containing `:`, `/`, a space, or a comma, and any value that is not four canonical decimal octets in `0..255`. A non-numeric octet fails inside a scope; that failure appends `invalid IPv4` instead of failing the run.
3. Unless override is true, reject `0.0.0.0/8`, `10.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16` (this includes `169.254.169.254`), `172.16.0.0/12`, `192.168.0.0/16`, and `100.64.0.0/10`. The `/12` and `/10` checks are octet comparisons, not the customer prefix matcher.
4. Unless override is true, reject an address contained in `protectedIpRanges`.
5. GET the policy. A failed GET comments and does not guess a block line.
6. Read existing match values from `matchValues` (Application Gateway) or `matchValue` (Front Door). `union` drops duplicates.
7. If nothing new remains, comment that the address is already listed.
8. If the merged list would exceed `maximumBlockEntries`, comment and do not write a partial list.
9. If `autoBlockEnabled` is not the boolean `true`, comment `Would block IP: <address>` and terminate. The PUT actions are not on this branch.
10. If it is `true`, PUT only the matching provider body, then comment `Blocked IP: <address>`. A failed PUT comments that the address must not be assumed blocked. The PUT retry policy is none.

The foreach runs at concurrency 1. Customer-range comparison uses a Filter action, not a nested foreach, so the loop does not share a match flag across parallel iterations.

## Identity and RBAC

| Principal | Role | Scope |
| --- | --- | --- |
| Playbook managed identity | Microsoft Sentinel Responder `3e150937-b8fe-4cfb-8069-0eaf05ecd056` | POC resource group, so it can comment on incidents in the workspace in that group |
| Playbook managed identity | Network Contributor `4d97b98b-1d4f-4787-a291-c67834d212e7` | The one WAF policy resource |
| Azure Security Insights service principal | Microsoft Sentinel Automation Contributor `f4c81013-99ee-4d62-a7ee-b3f1f648599a` | POC resource group, so the automation rule can start the playbook |

No secrets, connection strings, or user OAuth tokens are stored. The automation-rule role assignment name is `guid(resourceGroup, principalId, roleId)`. The automation rule name is `guid('ase-waf-block-playbook', workspace.id)`.

Network Contributor can change more than the custom-rule list. That gap is recorded in [security-considerations.md](security-considerations.md) and [production-hardening.md](production-hardening.md). A custom role definition was not added, because its exact action set should be confirmed against the policy type ASE uses.

## What is out of scope

- Production ASE WAF, Front Door, or an existing workspace. The questions in the README stay open.
- Microsoft Sentinel Content Hub solution for WAF. Those workbooks often assume `AzureDiagnostics`.
- Private Link, TLS, a real backend, zones, an NSG, and customer-managed keys.
- Automatic expiry, unblock, or an approval action inside the automation rule.
- IPv6. Addresses containing `:` are rejected.
