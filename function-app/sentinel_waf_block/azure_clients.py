"""ARM and Sentinel clients.

Tokens stay in the Authorization header. Exceptions and logs receive only a
status or a generic failure name, never the header value or response body.
"""

from __future__ import annotations

import uuid

from sentinel_waf_block.engine import AuthenticationError, CommentError, WafGetError, WafPutError

_ARM = "https://management.azure.com"
_SCOPE = "https://management.azure.com/.default"
_COMMENT_API = "2024-01-01-preview"


class ArmWafClient:
    def __init__(self, credential: object | None = None, session: object | None = None) -> None:
        self._credential = credential
        self._session = session

    def get_policy(self, resource_id: str, api_version: str) -> object:
        response = self._request("GET", resource_id, api_version, None, WafGetError)
        if response.status_code != 200:
            raise WafGetError(f"GET failed with HTTP {response.status_code}")
        try:
            return response.json()
        except ValueError as exc:
            raise WafGetError("GET returned non-JSON") from exc

    def put_policy(
        self,
        resource_id: str,
        api_version: str,
        body: object,
        timeout_seconds: float = 120,
    ) -> None:
        response = self._request("PUT", resource_id, api_version, body, WafPutError, timeout_seconds)
        if response.status_code == 202:
            raise WafPutError("PUT was accepted but did not finish; read the policy before retrying")
        if response.status_code not in {200, 201}:
            raise WafPutError(f"PUT failed with HTTP {response.status_code}")

    def _request(
        self,
        method: str,
        resource_id: str,
        api_version: str,
        body: object,
        error_type: type[Exception],
        timeout_seconds: float = 120,
    ) -> object:
        session = self._session_or_default()
        try:
            token = self._credential_or_default().get_token(_SCOPE).token
        except Exception as exc:
            raise AuthenticationError("authentication failed") from _redacted(exc)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        try:
            return session.request(
                method,
                _ARM + resource_id,
                params={"api-version": api_version},
                json=body,
                headers=headers,
                timeout=timeout_seconds,
            )
        except Exception as exc:
            if "Timeout" in type(exc).__name__:
                raise error_type(f"{method} timed out") from None
            raise error_type(f"{method} failed") from None

    def _credential_or_default(self) -> object:
        if self._credential is None:
            from azure.identity import DefaultAzureCredential

            self._credential = DefaultAzureCredential()
        return self._credential

    def _session_or_default(self) -> object:
        if self._session is None:
            import requests

            self._session = requests.Session()
        return self._session


class SentinelCommentClient:
    def __init__(self, credential: object | None = None, session: object | None = None) -> None:
        self._inner = ArmWafClient(credential=credential, session=session)

    def write_comment(self, incident_arm_id: str, message: str) -> None:
        comment_id = str(uuid.uuid4())
        path = f"{incident_arm_id}/comments/{comment_id}"
        response = self._inner._request("PUT", path, _COMMENT_API, {"properties": {"message": message}}, CommentError)
        if getattr(response, "status_code", 0) not in {200, 201}:
            raise CommentError(f"comment failed with HTTP {getattr(response, 'status_code', 0)}")


def _redacted(exc: Exception) -> Exception:
    """Drop the original exception text so a token in it cannot reach logs."""

    return AuthenticationError(type(exc).__name__)
