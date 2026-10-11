# Block malicious IP playbook

Logic App definition: `workflow.json`. Bicep passes parameters from `infra/modules/playbook.bicep`. The parameter default for `autoBlockEnabled` is `false`.

The playbook is started by the Sentinel incident trigger. It reads IP entities, rejects values that are not a canonical IPv4 address, rejects the built-in protected ranges and `protectedIpRanges`, reads the WAF policy, and then either comments `Would block IP: <address>` or, only when `autoBlockEnabled` is the boolean `true`, PUTs custom rule `SentinelAutoBlock`.

Application Gateway and Front Door use different custom-rule JSON. A provider value other than `ApplicationGateway` or `FrontDoor` does not PUT. A prefix in `protectedIpRanges` other than `/8`, `/16`, `/24`, or `/32` stops the run before any would-block line.

The system-assigned identity needs Microsoft Sentinel Responder on the workspace resource group and Network Contributor on the one WAF policy. Both assignments are in the Bicep modules.
