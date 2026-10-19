# Sentinel WAF auto-block

Azure Function App project for the ASE Sentinel block-IP playbook. The runtime is Python. The decision engine is the `sentinel_waf_block` package in this directory. `scripts/deploy.ps1` publishes this package to the Function App and points `playbooks/block-malicious-ip/thin-workflow.json` at `POST /api/SentinelWafAutoBlock`. `workflow.json` remains the expression reference and is not the deployed definition.

## Architecture

```
Sentinel incident
  -> automation rule, triggersWhen Created only
  -> thin Logic App
  -> POST /api/SentinelWafAutoBlock
  -> Engine
  -> ARM GET, then PUT only when enforcement is on
  -> one incident comment
```

`function_app.py` parses JSON and returns the structured result. `sentinel_waf_block` owns validation and the WAF write. It does not import Azure Functions types.

Incidents group by the IP entity for 12 hours, and a closed incident is not reopened. Removing an address from the WAF rule while that incident is still open does not run this workload again. There is no timer and no incident-update trigger.

## Payload

`POST /api/SentinelWafAutoBlock`

```json
{
  "incidentArmId": "/subscriptions/<subscription>/resourceGroups/<group>/providers/Microsoft.OperationalInsights/workspaces/<workspace>/providers/Microsoft.SecurityInsights/incidents/<id>",
  "incidentNumber": 11,
  "incidentTitle": "ASE POC simulated WAF probe from 203.0.113.5",
  "ipEntities": ["203.0.113.5"]
}
```

`ipEntities` is an array of strings. The function does not read `autoBlockEnabled` from this body. Enforcement comes only from configuration.

The response is the structured result: `status`, `changed`, `candidate_addresses`, `new_addresses`, `rejected_addresses`, `unenforced_addresses`, `existing_count`, `resulting_count`, `reason`. The function also writes one incident comment. The Logic App should not write a second copy.

## Managed Identity

Azure execution uses `DefaultAzureCredential`, which selects the Function App managed identity. Local development can use the normal Azure CLI developer login. The package does not store client secrets, passwords, or bearer tokens.

## RBAC

| Role | Scope |
| --- | --- |
| Microsoft Sentinel Responder | Resource group that contains the Sentinel workspace |
| Network Contributor | The one WAF policy |

Network Contributor can change more than the custom-rule list. This package does not define a custom role.

## Dry-run and enforcement

The deployed app setting `AUTO_BLOCK_ENABLED` defaults to the JSON boolean `true`. Only that JSON boolean sends a PUT. The string `"true"`, the number `1`, and a missing value are dry-run. `config.example.json` matches the deployed default. A local run that points that file at a real policy will PUT.

Dry-run still validates, reads the policy when an enforceable address exists, and comments `Would block IP: <address>` for each new address. It does not change the policy.

Enforcement rebuilds custom rule `SentinelAutoBlock` and comments `Blocked IP: <address>`. A failed or unfinished PUT is `waf-put-failed`. The comment says `Do not assume` the address was blocked. A comment failure after a successful PUT is `blocked-comment-failed` with `changed: true`, and the PUT is not repeated.

There is no automatic expiry. Rollback is an operator action. The workload never deletes a block entry.

## Configuration

Copy `config.example.json` and set `SENTINEL_WAF_CONFIG` to that file path. Booleans in the file must be JSON booleans.

Environment variables are the alternative. `AUTO_BLOCK_ENABLED`, `OVERRIDE_PROTECTED_RANGES`, `MAXIMUM_BLOCK_ENTRIES`, `BLOCK_RULE_PRIORITY`, and `PROTECTED_IP_RANGES` are parsed with `json.loads`. `true` enables enforcement. The JSON string `"true"` does not. `WAF_POLICY_RESOURCE_ID`, `WAF_PROVIDER`, `BLOCK_RULE_NAME`, and `ARM_API_VERSION` are plain strings.

| Setting | Default |
| --- | --- |
| `wafPolicyResourceId` | required ARM id of the one policy |
| `wafProvider` | `ApplicationGateway` or `FrontDoor` |
| `protectedIpRanges` | `[]` |
| `maximumBlockEntries` | `100` |
| `autoBlockEnabled` | `true` in `config.example.json` and in the deployed app. A missing setting stays `false` |
| `overrideProtectedRanges` | `false` |
| `blockRuleName` | `SentinelAutoBlock` |
| `blockRulePriority` | `10` |
| `armApiVersion` | `2024-05-01` for Application Gateway, `2024-02-01` for Front Door |

`maximumBlockEntries` is the product cap. Application Gateway also has a platform cap of 600 addresses per IPMatch condition on the OWASP 3.2 policy used by this POC. This package does not raise the configured cap to 600.

## Local testing

From `function-app/`:

```powershell
python -m pip install -e ".[dev]"
python -m pytest
```

The tests mock ARM and Sentinel. They do not need a subscription or a network connection.

## Deployment

`scripts/deploy.ps1` creates a Linux Function App on Flex Consumption `FC1`, Python 3.11, system-assigned managed identity, and the role assignments above. Flex rejects the Oryx build settings, so the script packs manylinux wheels for Python 3.11 into the zip. `FC1` is used because this subscription's `eastus` quota is 0 for Y1, Basic, Standard, Premium v3, and Elastic Premium. Flex bills for executions. `AuthLevel.FUNCTION` is set in `function_app.py`. The thin Logic App calls `POST /api/SentinelWafAutoBlock` with the incident fields. `host.json` allows five minutes. The Logic App HTTP action stops at two minutes. The ARM PUT timeout inside the function is 120 seconds. The PUT is not retried and does not send `If-Match`.

App settings carry the configuration. Boolean and numeric settings are JSON tokens (`true`, `false`, `100`), because the loader uses `json.loads` and does not treat the string `"true"` as enforcement. Host storage uses `AzureWebJobsStorage__credential=managedidentity`. The function key stays in the Logic App secure parameter. Neither a storage key nor the function key is written to the repository.

## Prefix allow-list

Built-in networks always apply unless `overrideProtectedRanges` is JSON `true`:

- IPv4: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16` (includes `169.254.169.254`), `172.16.0.0/12`, `192.168.0.0/16`
- IPv6: `::/128`, `::1/128`, `fe80::/10`, `fc00::/7`

Customer `protectedIpRanges` accept an IPv4 host or `/8`, `/16`, `/24`, `/32`, and an IPv6 host or `/16`, `/32`, `/48`, `/64`, `/80`, `/96`, `/112`, `/128`. Other prefix lengths fail closed before any `Would block IP:` line, including `/12`, `/10`, `/7`, and `/40`. A single address matches that host only.

Incident values are single hosts. Empty text, whitespace, commas, slashes, and zone ids are rejected and are not repaired. IPv4-mapped IPv6 is rejected and is not converted. Compressed or uppercase incident IPv6 is stored as eight lowercase groups. The block list stores that observed host, not its `/64`.

## Application Gateway and IPv6

Azure Application Gateway does not support IPv6 as an IP block source. Custom-rule IPMatch on `RemoteAddr` is IPv4-only. A validated IPv6 address is returned in `unenforced_addresses`. It is not added to `matchValues`, it is not counted toward `maximumBlockEntries`, and the comment does not say `Would block IP:` or `Blocked IP:` for it. When the incident has no enforceable IPv4 address, the workload does not GET the policy. A mixed incident updates IPv4 only and still records the IPv6 sentence.

Front Door writes the canonical IPv6 address in `matchValue` and counts it toward capacity.

`overrideProtectedRanges` does not change this. Application Gateway still cannot block an IPv6 source.

## Opaque match values and PUT bodies

Values already stored on the named rule are copied in order as exact strings. They are not lowercased or expanded. A compressed IPv6 value already on a Front Door rule is not the same entry as the expanded form, so the expanded candidate is appended.

An IPv6 value already stored on an Application Gateway rule is copied back unchanged. It still counts toward `maximumBlockEntries`. The following PUT can fail because that provider cannot use IPv6 as a block source. The failure is reported. The stored value is not deleted to make the PUT succeed.

Application Gateway PUT sends `location`, `tags`, `properties.policySettings`, `properties.customRules`, and `properties.managedRules`. It does not send `sku`, `id`, `etag`, or read-only links. The match condition uses the ARM spelling `negationConditon`. API `2024-05-01` rejects `negationCondition`.

Front Door PUT also sends `sku` and writes `properties.customRules.rules`. Its match condition uses `negateCondition` and `matchValue`.

The named rule is rebuilt and placed first. Every other custom rule object is copied through. If `policySettings` or `managedRules` is missing, the workload does not PUT.

## `overrideProtectedRanges`

JSON `true` skips built-in and customer membership checks. These addresses can then be written to the WAF rule: loopback, RFC1918, link-local, CGNAT, the Azure metadata address, and customer ranges. Invalid addresses and IPv4-mapped IPv6 are still rejected. A malformed `protectedIpRanges` entry still fails closed. Application Gateway still does not gain IPv6 enforcement.

## Rollback

There is no automatic expiry and no automatic deletion. An operator removes the address from `SentinelAutoBlock`, or deletes that rule when it would otherwise be left empty. Do not PUT an empty `matchValues` or `matchValue` array.

## Known limits

- The automation rule runs only when the incident is created.
- Two incidents can PUT the same policy at the same time. This contract does not send `If-Match`, so one write can overwrite the other.
- Network Contributor is wider than editing one custom rule.
- The watchlist `AseWafIpAllowlist` is not read here. Built-ins are hard-coded, and customer ranges come only from `protectedIpRanges`.
