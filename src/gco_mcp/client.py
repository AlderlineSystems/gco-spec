from __future__ import annotations

from typing import Any, Mapping

from gco.derivation import DelegationRequest
from gco.models import GCO
from gco.runtime import Decision, GovernanceRuntime

from gco_mcp.errors import denial_decision
from gco_mcp.wire import GcoWireCodec, WireError


class GovernedClientBoundary:
    """E1 boundary: authorize, derive, and attach before MCP ``tools/call``."""

    def __init__(self, runtime: GovernanceRuntime, codec: GcoWireCodec | None = None) -> None:
        self.runtime = runtime
        self.codec = codec or GcoWireCodec()

    def prepare_tool_call(
        self,
        parent: GCO,
        *,
        tool_uri: str,
        requested_scope: str | None,
        delegation: DelegationRequest,
        base_meta: Mapping[str, Any] | None = None,
    ) -> tuple[Decision, dict[str, Any] | None]:
        authorized = self.runtime.authorize_tool_call(parent, tool_uri, requested_scope)
        if not authorized.allowed:
            return authorized, None
        derived = self.runtime.derive_for_subcall(parent, delegation)
        if not derived.allowed:
            return derived, None
        if derived.child is None:
            return denial_decision("gco_missing_child", "GCO derivation did not return a child"), None
        try:
            return derived, self.codec.attach(base_meta, derived.child)
        except WireError as exc:
            return denial_decision(exc.error_code, str(exc)), None
