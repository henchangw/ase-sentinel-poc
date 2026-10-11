# Block malicious IP playbook

Logic App definition: `workflow.json`. Bicep passes parameters from `infra/modules/playbook.bicep`. The parameter default for `autoBlockEnabled` is `false`.

The playbook is started by the Sentinel incident trigger. It reads IP entities, rejects values that are not a canonical IPv4 address, rejects the built-in protected ranges and `protectedIpRanges`, reads the WAF policy, and then either comments `Would block IP: <address>` or, only when `autoBlockEnabled` is the boolean `true`, PUTs custom rule `SentinelAutoBlock`.

Application Gateway and Front Door use different custom-rule JSON. A provider value other than `ApplicationGateway` or `FrontDoor` does not PUT. A prefix in `protectedIpRanges` other than `/8`, `/16`, `/24`, or `/32` stops the run before any would-block line.

The system-assigned identity needs Microsoft Sentinel Responder on the workspace resource group and Network Contributor on the one WAF policy. Both assignments are in the Bicep modules.

Empty arrays in the workflow use `json('[]')`. `createArray()` with no arguments is rejected by the Logic Apps runtime, including on the first dry-run when `SentinelAutoBlock` does not exist yet.

The Application Gateway match condition uses the ARM property `negationConditon`. That spelling is what API version `2024-05-01` accepts. `negationCondition` makes the policy PUT return InvalidJson. Front Door uses `negateCondition`.
