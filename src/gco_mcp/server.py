from __future__ import annotations

from typing import Any, Mapping

from gco.derivation import DelegationRequest
from gco.models import GCO
from gco.runtime import Decision, GovernanceRuntime

from gco_mcp.errors import GcoMcpError, denial_decision
from gco_mcp.extension import EXTENSION_ID, peer_supports_gco
from gco_mcp.wire import GcoWireCodec, WireError


CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"


class GovernedServerBoundary:
    """E2 boundary: verify incoming GCO before executing an MCP tool."""

    def __init__(self, runtime: GovernanceRuntime, codec: GcoWireCodec | None = None, *, require: bool = True) -> None:
        self.runtime = runtime
        self.codec = codec or GcoWireCodec()
        self.require = require

    def authorize_incoming(
        self,
        meta: Mapping[str, Any] | None,
        *,
        tool_uri: str,
        requested_scope: str | None = None,
    ) -> Decision:
        if not self._client_advertised_gco(meta):
            if self.require:
                return denial_decision(GcoMcpError.MISSING_CAPABILITY, f"{EXTENSION_ID} client capability is required")
            return Decision(allowed=True)
        try:
            wire = self.codec.extract(meta)
        except WireError as exc:
            if self.require:
                return denial_decision(exc.error_code, str(exc))
            return Decision(allowed=True)
        if wire.parent is not None:
            subcall = self.runtime.authorize_subcall(wire.parent, wire.gco)
            if not subcall.allowed:
                return subcall
        return self.runtime.authorize_tool_call(wire.gco, tool_uri, requested_scope)

    def _client_advertised_gco(self, meta: Mapping[str, Any] | None) -> bool:
        if meta is None:
            return False
        capabilities = meta.get(CLIENT_CAPABILITIES)
        return isinstance(capabilities, Mapping) and peer_supports_gco(capabilities)


class GovernedFanout:
    """E3 boundary: derive and attach before a governed server fans out."""

    def __init__(self, runtime: GovernanceRuntime, codec: GcoWireCodec | None = None) -> None:
        self.runtime = runtime
        self.codec = codec or GcoWireCodec()

    def prepare_subcall(
        self,
        current: GCO,
        *,
        tool_uri: str,
        requested_scope: str | None,
        delegation: DelegationRequest,
        base_meta: Mapping[str, Any] | None = None,
        attach_parent: bool = False,
    ) -> tuple[Decision, dict[str, Any] | None]:
        authorized = self.runtime.authorize_tool_call(current, tool_uri, requested_scope)
        if not authorized.allowed:
            return authorized, None
        derived = self.runtime.derive_for_subcall(current, delegation)
        if not derived.allowed:
            return derived, None
        if derived.child is None:
            return denial_decision("gco_missing_child", "GCO derivation did not return a child"), None
        try:
            parent = current if attach_parent else None
            return derived, self.codec.attach(base_meta, derived.child, parent=parent)
        except WireError as exc:
            return denial_decision(exc.error_code, str(exc)), None
