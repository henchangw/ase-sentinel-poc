import traceback

import pytest

from sentinel_waf_block.azure_clients import ArmWafClient
from sentinel_waf_block.engine import AuthenticationError, WafGetError, WafPutError


class _Token:
    def __init__(self, token: str) -> None:
        self.token = token


class _Credential:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error

    def get_token(self, scope: str) -> _Token:
        if self.error:
            raise self.error
        return _Token("super-secret-token")


class _Response:
    def __init__(self, status: int, payload: object | None = None) -> None:
        self.status_code = status
        self._payload = payload

    def json(self) -> object:
        return self._payload


class _Session:
    def __init__(self, response: _Response | None = None, error: Exception | None = None) -> None:
        self.response = response or _Response(200, {"ok": True})
        self.error = error
        self.calls: list[dict[str, object]] = []

    def request(self, method: str, url: str, params: dict | None = None, json: object = None, headers: dict | None = None, timeout: float | None = None) -> _Response:
        self.calls.append({"method": method, "url": url, "headers": headers or {}, "json": json, "timeout": timeout})
        if self.error:
            raise self.error
        return self.response


def test_get_and_put_do_not_leak_the_token_on_failure() -> None:
    session = _Session(response=_Response(403, {"error": "no"}))
    client = ArmWafClient(credential=_Credential(), session=session)
    with pytest.raises(WafGetError) as got:
        client.get_policy("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies/waf", "2024-05-01")
    assert "super-secret-token" not in str(got.value)
    assert session.calls[0]["headers"]["Authorization"] == "Bearer super-secret-token"

    class _ReadTimeout(Exception):
        def __str__(self) -> str:
            return "Authorization: Bearer super-secret-token"

    session = _Session(error=_ReadTimeout())
    client = ArmWafClient(credential=_Credential(), session=session)
    with pytest.raises(WafPutError) as put:
        client.put_policy("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies/waf", "2024-05-01", {"location": "eastus"})
    rendered = "".join(traceback.format_exception(put.value))
    assert "super-secret-token" not in rendered
    assert "timed out" in str(put.value)


def test_credential_failure_does_not_keep_the_token_in_the_chain() -> None:
    client = ArmWafClient(credential=_Credential(error=RuntimeError("Bearer super-secret-token")), session=_Session())
    with pytest.raises(AuthenticationError) as got:
        client.get_policy("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies/waf", "2024-05-01")
    rendered = "".join(traceback.format_exception(got.value))
    assert "super-secret-token" not in rendered


def test_accepted_put_is_not_success() -> None:
    client = ArmWafClient(credential=_Credential(), session=_Session(response=_Response(202, {})))
    with pytest.raises(WafPutError, match="did not finish"):
        client.put_policy("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/frontDoorWebApplicationFirewallPolicies/waf", "2024-02-01", {"sku": {}})
