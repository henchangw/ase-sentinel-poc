"""Thin HTTP adapter. Business rules live in sentinel_waf_block."""

from __future__ import annotations

import json
import logging

import azure.functions as func

from sentinel_waf_block.azure_clients import ArmWafClient, SentinelCommentClient
from sentinel_waf_block.config import ConfigError, config_from_env
from sentinel_waf_block.engine import Engine
from sentinel_waf_block.models import STATUS_INTERNAL, STATUS_VALIDATION, InputError, incident_from_payload

log = logging.getLogger("sentinel_waf_block.function")
app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)


@app.route(route="SentinelWafAutoBlock", methods=["POST"])
def sentinel_waf_auto_block(req: func.HttpRequest) -> func.HttpResponse:
    try:
        payload = req.get_json()
    except ValueError:
        return _response(
            {"status": STATUS_VALIDATION, "changed": False, "reason": "request body is not JSON"},
            400,
        )
    try:
        incident = incident_from_payload(payload)
        config = config_from_env()
    except InputError as exc:
        return _response({"status": STATUS_VALIDATION, "changed": False, "reason": str(exc)}, 400)
    except ConfigError as exc:
        return _response(
            {"status": STATUS_VALIDATION, "changed": False, "reason": "configuration: " + str(exc)},
            500,
        )
    try:
        result = Engine(ArmWafClient(), SentinelCommentClient()).execute(incident, config)
    except Exception:
        log.warning("unhandled failure during execution")
        return _response({"status": STATUS_INTERNAL, "changed": False, "reason": "internal error"}, 500)
    return _response(result.to_dict(), 200)


def _response(body: dict[str, object], status: int) -> func.HttpResponse:
    return func.HttpResponse(json.dumps(body), status_code=status, mimetype="application/json")
