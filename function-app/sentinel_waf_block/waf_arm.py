"""Read a WAF GET document and build the provider PUT body.

Only the named block rule is rebuilt. Every other custom rule object is copied
through. Existing match values are opaque strings.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from sentinel_waf_block.models import APPLICATION_GATEWAY, FRONT_DOOR, Config


@dataclass(frozen=True)
class PolicyView:
    location: str
    tags: dict[str, Any]
    sku: dict[str, Any] | None
    policy_settings: dict[str, Any]
    managed_rules: dict[str, Any]
    existing_values: tuple[str, ...]
    other_rules: tuple[dict[str, Any], ...]


class PolicyShapeError(Exception):
    """The GET document does not match the selected provider."""


def read_policy(document: object, provider: str, rule_name: str) -> PolicyView:
    if not isinstance(document, dict):
        raise PolicyShapeError("WAF document is not an object")
    location = document.get("location")
    if not isinstance(location, str) or location == "":
        raise PolicyShapeError("WAF location is missing")
    tags = document.get("tags", {})
    if tags is None:
        tags = {}
    if not isinstance(tags, dict):
        raise PolicyShapeError("WAF tags are not an object")
    properties = document.get("properties")
    if not isinstance(properties, dict):
        raise PolicyShapeError("WAF properties are missing")
    policy_settings = properties.get("policySettings")
    managed_rules = properties.get("managedRules")
    if not isinstance(policy_settings, dict) or not isinstance(managed_rules, dict):
        raise PolicyShapeError("policySettings or managedRules is missing")
    sku = document.get("sku")
    if provider == FRONT_DOOR:
        if not isinstance(sku, dict):
            raise PolicyShapeError("Front Door sku is missing")
    elif sku is not None and not isinstance(sku, dict):
        raise PolicyShapeError("WAF sku is not an object")
    rules, values = _rules_and_values(properties, provider, rule_name)
    return PolicyView(
        location=location,
        tags=copy.deepcopy(tags),
        sku=copy.deepcopy(sku) if isinstance(sku, dict) else None,
        policy_settings=copy.deepcopy(policy_settings),
        managed_rules=copy.deepcopy(managed_rules),
        existing_values=tuple(values),
        other_rules=tuple(rules),
    )


def build_put_body(view: PolicyView, merged: list[str], config: Config) -> dict[str, Any]:
    rule = _block_rule(config, merged)
    custom_rules: list[dict[str, Any]] = [rule, *view.other_rules]
    properties: dict[str, Any] = {
        "policySettings": copy.deepcopy(view.policy_settings),
        "managedRules": copy.deepcopy(view.managed_rules),
    }
    body: dict[str, Any] = {
        "location": view.location,
        "tags": copy.deepcopy(view.tags) if view.tags else {},
    }
    if config.waf_provider == FRONT_DOOR:
        body["sku"] = copy.deepcopy(view.sku)
        properties["customRules"] = {"rules": custom_rules}
    elif config.waf_provider == APPLICATION_GATEWAY:
        properties["customRules"] = custom_rules
    else:
        raise PolicyShapeError("unsupported provider")
    body["properties"] = properties
    return body


def _rules_and_values(
    properties: dict[str, Any],
    provider: str,
    rule_name: str,
) -> tuple[list[dict[str, Any]], list[str]]:
    custom = properties.get("customRules", None)
    if provider == APPLICATION_GATEWAY:
        if not isinstance(custom, list):
            raise PolicyShapeError("Application Gateway customRules must be an array")
        rules = custom
        value_key = "matchValues"
    elif provider == FRONT_DOOR:
        if not isinstance(custom, dict) or not isinstance(custom.get("rules"), list):
            raise PolicyShapeError("Front Door customRules.rules must be an array")
        rules = custom["rules"]
        value_key = "matchValue"
    else:
        raise PolicyShapeError("unsupported provider")
    existing: list[str] | None = None
    others: list[dict[str, Any]] = []
    for rule in rules:
        if not isinstance(rule, dict):
            raise PolicyShapeError("a custom rule is not an object")
        if existing is None and rule.get("name") == rule_name:
            existing = _match_values(rule, value_key)
            continue
        others.append(copy.deepcopy(rule))
    return others, existing or []


def _match_values(rule: dict[str, Any], value_key: str) -> list[str]:
    conditions = rule.get("matchConditions", [])
    if conditions is None:
        raise PolicyShapeError("matchConditions is null")
    if not isinstance(conditions, list):
        raise PolicyShapeError("matchConditions is not an array")
    if not conditions:
        return []
    first = conditions[0]
    if not isinstance(first, dict):
        raise PolicyShapeError("match condition is not an object")
    if value_key not in first or first[value_key] is None:
        return []
    values = first[value_key]
    if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
        raise PolicyShapeError(f"{value_key} must be an array of strings")
    return list(values)


def _block_rule(config: Config, merged: list[str]) -> dict[str, Any]:
    if config.waf_provider == APPLICATION_GATEWAY:
        # API 2024-05-01 rejects the corrected spelling negationCondition.
        return {
            "name": config.block_rule_name,
            "priority": config.block_rule_priority,
            "ruleType": "MatchRule",
            "action": "Block",
            "state": "Enabled",
            "matchConditions": [
                {
                    "matchVariables": [{"variableName": "RemoteAddr"}],
                    "operator": "IPMatch",
                    "negationConditon": False,
                    "matchValues": list(merged),
                    "transforms": [],
                }
            ],
        }
    return {
        "name": config.block_rule_name,
        "enabledState": "Enabled",
        "priority": config.block_rule_priority,
        "ruleType": "MatchRule",
        "action": "Block",
        "matchConditions": [
            {
                "matchVariable": "RemoteAddr",
                "operator": "IPMatch",
                "negateCondition": False,
                "matchValue": list(merged),
            }
        ],
    }
