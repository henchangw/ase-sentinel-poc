# Security considerations

This POC can change a WAF policy only after two choices: the deploy command sets `autoBlockEnabled` to true, and the script is also given `-ConfirmAutoBlock`. The Logic App parameter defaults to false, so a definition that is created without that parameter still dry-runs.

## Identity

The playbook uses a system-assigned managed identity. The Sentinel API connection is `ManagedServiceIdentity` with `parameterValueType` Alternative. There is no user token and no secret in source.

The identity can comment on Sentinel incidents in the POC resource group (Sentinel Responder) and can write the single WAF policy (Network Contributor). It is not a subscription Owner and it is not a contributor on the resource group.

Network Contributor is broader than updating one custom rule. A holder of that identity can change other properties of that policy, including managed rules, if the workflow is edited later. The workflow in this repo PUTs `policySettings`, `customRules`, and `managedRules` echoed from the GET, plus the block rule. It does not grant itself more roles.

The Azure Security Insights service principal is granted Microsoft Sentinel Automation Contributor on the POC resource group so an automation rule can start the playbook. That is the role Microsoft requires for `RunPlaybook`. It is not granted on other resource groups by this template.

## What cannot be blocked by default

The analytics rule and the playbook both refuse, unless `overrideProtectedRanges` is explicitly set:

- `0.0.0.0/8`
- RFC1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Loopback `127.0.0.0/8`
- Link-local `169.254.0.0/16`, which includes the instance metadata address `169.254.169.254`
- `100.64.0.0/10`

The rule also applies watchlist `AseWafIpAllowlist`. The playbook applies `protectedIpRanges` passed into the workflow. Built-in ranges are hard-coded in the KQL, not only stored in the watchlist, so a watchlist edit cannot remove them.

`overrideProtectedRanges` skips those filters in both places. The deploy script will not set it without `-ConfirmOverrideProtectedRanges`. Empty and non-IPv4 values are still rejected. IPv6 is rejected.

Customer ranges the playbook cannot parse fail the run before any block decision, including the dry-run sentence. The deploy script rejects those ranges first. The playbook check remains so a later parameter edit cannot silently ignore a prefix such as `/12`.

## Dry-run and opt-in

The PUT actions exist only on the branch where `autoBlockEnabled` is the boolean `true`. The string `"true"` does not take that branch. Dry-run still GETs the policy so it can avoid saying "Would block" for an address that is already listed. GET does not modify the policy.

Duplicates are removed with `union` before a write. A second incident for an address already on the rule does not PUT. If the merged list would exceed `maximumBlockEntries`, nothing is written.

The automation rule does not contain an approval action. Leaving `autoBlockEnabled` false is the approval gate. Turning it on means the next matching incident is written without an analyst click. That is a product decision ASE still has to make. The README question list leaves it open.

## Evidence

Each terminal path comments on the incident: incident number, title, decision, rejected addresses, policy id, and the Logic App run name. Alert custom details carry the request, rule, action, and timestamps from the WAF row. Playbook runtime logs go to the same workspace.

The WAF rule itself does not store a reason. If the incident is closed and deleted, or the resource group is deleted, that comment is gone. Export it before cleanup when the record has to be kept. Workspace retention defaults to 30 days.

A failed PUT tells the operator not to assume the address was blocked. The PUT is not retried, because a timeout after a successful write must not be followed by a second write from the same action. The operator reads the policy before resubmitting.

## Integrity of the policy write

The PUT replaces the custom-rule collection with "every existing rule except the block rule, plus the new block rule". A bug in provider selection could send the wrong JSON shape. The intended result is an ARM validation error and the failure comment. Do not point `wafProvider` at a policy of the other type to find out. The deploy script checks the resource-id type when a full id is supplied.

There is no `If-Match` etag. Two writers can lose an update. This matters if an operator edits the same policy while a playbook run is in flight.

The block rule uses action Block. On Application Gateway that action is enforced in Prevention mode. In Detection mode Microsoft documents that the custom rule is logged and not enforced. Opting in while the policy is in Detection mode can still write the IP onto the rule. It should not be described as blocking traffic until the policy mode enforces it.

## Test rig exposure

The test gateway has a public IPv4 address and an HTTP listener. The backend is not a real application. The listener is still on the internet and the gateway is billed. Delete the resource group when the test is finished.

No customer data and no production WAF is required to run the default path. Attaching the playbook to an existing policy is a separate, explicit parameter set and should be a disposable policy until ASE names the real target.

## Secrets

Source, parameter files, and scripts do not contain keys, passwords, or connection strings. `.gitignore` excludes local ARM build output. Do not add a service principal secret to make the deploy script non-interactive. Use the Azure CLI login you already have.
