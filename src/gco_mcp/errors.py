from __future__ import annotations

from enum import Enum
from typing import Any, Mapping

from gco.runtime import Decision

from gco_mcp.extension import EXTENSION_ID


MISSING_REQUIRED_CLIENT_CAPABILITY = -32021
INVALID_PARAMS = -32602


class GcoMcpError(str, Enum):
    MISSING_CAPABILITY = "gco_missing_capability"
    MISSING_GCO = "gco_missing"
    OVERSIZE_GCO = "gco_oversize"
    MALFORMED_GCO = "gco_malformed"


def error_code_value(error_code: Any) -> str | None:
    if error_code is None:
        return None
    if isinstance(error_code, Enum):
        return error_code.name.lower()
    if isinstance(error_code, type):
        return str(error_code.__name__)
    return str(error_code)


def missing_required_capability_error() -> dict[str, Any]:
    return {
        "code": MISSING_REQUIRED_CLIENT_CAPABILITY,
        "message": "Missing required client capability",
        "data": {
            "requiredCapabilities": {
                "extensions": {
                    EXTENSION_ID: {"version": "1"},
                },
            },
        },
    }


def invalid_params_error(message: str, *, code: GcoMcpError = GcoMcpError.MALFORMED_GCO) -> dict[str, Any]:
    return {
        "code": INVALID_PARAMS,
        "message": message,
        "data": {"error_code": code.value},
    }


def decision_to_tool_error(decision: Decision) -> dict[str, Any]:
    return {
        "isError": True,
        "content": [
            {
                "type": "text",
                "text": decision.reason or "GCO authorization denied",
            }
        ],
        "structuredContent": {
            "error_code": error_code_value(decision.error_code) or "gco_denied",
            "reason": decision.reason,
        },
    }


def mcp_error_for_decision(decision: Decision) -> dict[str, Any]:
    code = decision.error_code
    if code is GcoMcpError.MISSING_CAPABILITY:
        return missing_required_capability_error()
    if code in {GcoMcpError.MISSING_GCO, GcoMcpError.OVERSIZE_GCO, GcoMcpError.MALFORMED_GCO}:
        return invalid_params_error(decision.reason or code.value, code=code)
    return decision_to_tool_error(decision)


def denial_decision(error_code: Any, reason: str) -> Decision:
    return Decision(allowed=False, reason=reason, error_code=error_code)


def is_tool_error(payload: Mapping[str, Any]) -> bool:
    return payload.get("isError") is True
