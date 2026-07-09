from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from gco.derivation import DelegationRequest
from gco.models import AccessMode, AttestationFormat, AttestationModel, GCO, StatePermission, TaintPolicy, ToolAuthority
from gco.runtime import Decision, GovernanceRuntime
from gco.trust import TrustBundle
from gco.validator import DerivationError, canonical_gco_hash
from gco_mcp import (
    EXTENSION_ID,
    META_GCO,
    META_HANDLE,
    META_PARENT_GCO,
    GcoExtensionSettings,
    GcoMcpError,
    GcoWireCodec,
    GovernedClientBoundary,
    GovernedFanout,
    GovernedServerBoundary,
    WireError,
    client_extensions_block,
    decision_to_tool_error,
    invalid_params_error,
    is_tool_error,
    mcp_error_for_decision,
    missing_required_capability_error,
    peer_supports_gco,
    server_extensions_block,
)

NOW = datetime(2099, 1, 1, 11, 0, tzinfo=timezone.utc)
A_TOOL = "mcp://analytics/tools/query"
B_TOOL = "mcp://warehouse/tools/fetch"
SPIFFE_ID = "spiffe://example.org/ns/default/sa/model-alpha"


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(private_key, kid: str) -> dict[str, Any]:
    payload = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    payload.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return payload


def _bundle(private_key, *, kid: str = "mcp") -> TrustBundle:
    return TrustBundle.from_mapping({"example.org": {"jwks": {"keys": [_jwk(private_key, kid)]}}})


def _attestation(gco: GCO, private_key, *, kid: str = "mcp") -> AttestationModel:
    token = jwt.encode(
        {
            "sub": gco.model_identity,
            "gco_hash": canonical_gco_hash(gco),
            "exp": int((NOW + timedelta(hours=1)).timestamp()),
        },
        private_key,
        algorithm="RS256",
        headers={"kid": kid},
    )
    return AttestationModel(format=AttestationFormat.JWT_SVID, value=token)


def _sign(gco: GCO, private_key, *, kid: str = "mcp") -> GCO:
    return gco.model_copy(update={"attestation": _attestation(gco, private_key, kid=kid)})


class SigningAuthority:
    def __init__(self, private_key, *, kid: str = "mcp") -> None:
        self.private_key = private_key
        self.kid = kid

    def issue(self, identity: str, gco_data: dict[str, Any]) -> AttestationModel:
        gco = GCO.model_validate({**gco_data, "model_identity": identity, "attestation": None})
        return _attestation(gco, self.private_key, kid=self.kid)


def _root(private_key) -> GCO:
    gco = GCO(
        gco_version="1.0.0",
        trace_id=uuid4(),
        span_id=uuid4(),
        parent_span_id=None,
        policy_id="policy-alpha",
        model_identity=SPIFFE_ID,
        intervention_version="intervention-v1",
        tool_authority=[
            ToolAuthority(tool_uri=A_TOOL, scope="read:metrics", max_depth=3),
            ToolAuthority(tool_uri=B_TOOL, scope="read:table write:table", max_depth=3),
        ],
        state_access_permissions=[
            StatePermission(namespace="memory", access_mode=AccessMode.READ, taint_policy=TaintPolicy.CLEAN),
        ],
        expires_at=NOW + timedelta(hours=2),
        lineage=[],
        attestation=None,
    )
    return _sign(gco, private_key)


def _runtime(private_key) -> GovernanceRuntime:
    return GovernanceRuntime(
        _bundle(private_key),
        attestation_authority=SigningAuthority(private_key),
        now=lambda: NOW,
    )


def _meta() -> dict[str, Any]:
    return {
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": client_extensions_block(),
        },
        "traceparent": "00-11111111111111111111111111111111-2222222222222222-01",
    }


def _delegation(tool_uri: str, scope: str, *, depth: int = 1, expiry: datetime | None = None) -> DelegationRequest:
    return DelegationRequest(
        tool_authority=[ToolAuthority(tool_uri=tool_uri, scope=scope, max_depth=depth)],
        state_access_permissions=[],
        requested_expiry=expiry or NOW + timedelta(minutes=30),
    )


def _host_to_a_delegation() -> DelegationRequest:
    return DelegationRequest(
        tool_authority=[
            ToolAuthority(tool_uri=A_TOOL, scope="read:metrics", max_depth=2),
            ToolAuthority(tool_uri=B_TOOL, scope="read:table", max_depth=2),
        ],
        state_access_permissions=[],
        requested_expiry=NOW + timedelta(minutes=45),
    )


def test_codec_round_trip_with_parent_and_handle():
    key = _key()
    root = _root(key)
    runtime = _runtime(key)
    child = runtime.derive_for_subcall(root, _host_to_a_delegation()).child
    assert child is not None
    codec = GcoWireCodec()

    meta = codec.attach({"existing": True}, child, parent=root)
    meta[META_HANDLE] = "opaque-handle"
    wire = codec.extract(meta)

    assert meta["existing"] is True
    assert META_GCO in meta
    assert META_PARENT_GCO in meta
    assert wire.gco == child
    assert wire.parent == root
    assert wire.handle == "opaque-handle"
    assert codec.extension_capability()["maxGcoBytes"] == 65_536


def test_codec_rejects_missing_malformed_oversize_and_bad_handle():
    key = _key()
    root = _root(key)
    codec = GcoWireCodec(GcoExtensionSettings(max_gco_bytes=10))

    with pytest.raises(WireError) as missing:
        codec.extract(None)
    with pytest.raises(WireError) as malformed:
        GcoWireCodec().extract({META_GCO: {"not": "a gco"}})
    with pytest.raises(WireError) as non_json:
        GcoWireCodec().extract({META_GCO: {"bad": object()}})
    with pytest.raises(WireError) as oversize:
        codec.attach({}, root)
    with pytest.raises(WireError) as bad_handle:
        GcoWireCodec().extract({META_GCO: root.model_dump(mode="json"), META_HANDLE: ""})

    assert missing.value.error_code is GcoMcpError.MISSING_GCO
    assert malformed.value.error_code is GcoMcpError.MALFORMED_GCO
    assert non_json.value.error_code is GcoMcpError.MALFORMED_GCO
    assert oversize.value.error_code is GcoMcpError.OVERSIZE_GCO
    assert bad_handle.value.error_code is GcoMcpError.MALFORMED_GCO


def test_capability_negotiation_helpers():
    settings = GcoExtensionSettings(require_gco=False, max_gco_bytes=123, handle_support=True)

    client_block = client_extensions_block(settings)
    server_block = server_extensions_block(settings)

    assert client_block == server_block
    assert client_block[EXTENSION_ID]["requireGco"] is False
    assert client_block[EXTENSION_ID]["maxGcoBytes"] == 123
    assert client_block[EXTENSION_ID]["handleSupport"] is True
    assert peer_supports_gco({"extensions": client_block}) is True
    assert peer_supports_gco(client_block) is True
    assert peer_supports_gco({"extensions": {}}) is False
    assert peer_supports_gco(None) is False


def test_e1_client_boundary_allow_and_deny_paths():
    key = _key()
    root = _root(key)
    runtime = _runtime(key)
    client = GovernedClientBoundary(runtime)

    decision, meta = client.prepare_tool_call(
        root,
        tool_uri=A_TOOL,
        requested_scope="read:metrics",
        delegation=_host_to_a_delegation(),
        base_meta=_meta(),
    )
    denied, denied_meta = client.prepare_tool_call(
        root,
        tool_uri=A_TOOL,
        requested_scope="write:metrics",
        delegation=_host_to_a_delegation(),
        base_meta=_meta(),
    )
    widened, widened_meta = client.prepare_tool_call(
        root,
        tool_uri=A_TOOL,
        requested_scope="read:metrics",
        delegation=_delegation(A_TOOL, "read:metrics admin"),
        base_meta=_meta(),
    )

    assert decision.allowed is True
    assert meta is not None and META_GCO in meta
    assert denied.allowed is False
    assert denied.error_code is DerivationError.TOOL_AUTHORITY_EXPANDED
    assert denied_meta is None
    assert widened.allowed is False
    assert widened.error_code is DerivationError.TOOL_AUTHORITY_EXPANDED
    assert widened_meta is None


def test_client_boundary_denies_missing_child_and_attach_failure(monkeypatch):
    key = _key()
    root = _root(key)
    runtime = _runtime(key)

    monkeypatch.setattr(runtime, "derive_for_subcall", lambda parent, request: Decision(allowed=True))
    missing_child, missing_meta = GovernedClientBoundary(runtime).prepare_tool_call(
        root,
        tool_uri=A_TOOL,
        requested_scope="read:metrics",
        delegation=_host_to_a_delegation(),
        base_meta=_meta(),
    )

    codec = GcoWireCodec(GcoExtensionSettings(max_gco_bytes=10))
    attach_denied, attach_meta = GovernedClientBoundary(_runtime(key), codec).prepare_tool_call(
        root,
        tool_uri=A_TOOL,
        requested_scope="read:metrics",
        delegation=_host_to_a_delegation(),
        base_meta=_meta(),
    )

    assert missing_child.allowed is False
    assert missing_child.error_code == "gco_missing_child"
    assert missing_meta is None
    assert attach_denied.allowed is False
    assert attach_denied.error_code is GcoMcpError.OVERSIZE_GCO
    assert attach_meta is None


def test_e2_server_boundary_allow_deny_optional_and_parent_validation_paths():
    key = _key()
    root = _root(key)
    runtime = _runtime(key)
    codec = GcoWireCodec()
    child = runtime.derive_for_subcall(root, _host_to_a_delegation()).child
    assert child is not None
    server = GovernedServerBoundary(runtime, codec)

    allowed = server.authorize_incoming(codec.attach(_meta(), child, parent=root), tool_uri=A_TOOL, requested_scope="read:metrics")
    bad_scope = server.authorize_incoming(codec.attach(_meta(), child), tool_uri=A_TOOL, requested_scope="write:metrics")
    missing_cap = server.authorize_incoming({}, tool_uri=A_TOOL)
    malformed = server.authorize_incoming({"io.modelcontextprotocol/clientCapabilities": {"extensions": client_extensions_block()}}, tool_uri=A_TOOL)
    tampered_parent_meta = codec.attach(_meta(), child, parent=root.model_copy(update={"policy_id": "policy-beta"}))
    parent_denied = server.authorize_incoming(tampered_parent_meta, tool_uri=A_TOOL, requested_scope="read:metrics")
    optional_missing_cap = GovernedServerBoundary(runtime, codec, require=False).authorize_incoming({}, tool_uri=A_TOOL)
    optional_malformed = GovernedServerBoundary(runtime, codec, require=False).authorize_incoming(
        {"io.modelcontextprotocol/clientCapabilities": {"extensions": client_extensions_block()}},
        tool_uri=A_TOOL,
    )
    none_meta = server.authorize_incoming(None, tool_uri=A_TOOL)

    assert allowed.allowed is True
    assert bad_scope.allowed is False
    assert missing_cap.error_code is GcoMcpError.MISSING_CAPABILITY
    assert malformed.error_code is GcoMcpError.MISSING_GCO
    assert parent_denied.allowed is False
    assert none_meta.error_code is GcoMcpError.MISSING_CAPABILITY
    assert optional_missing_cap.allowed is True
    assert optional_malformed.allowed is True


def test_e2_tampered_meta_denied_by_attestation():
    key = _key()
    root = _root(key)
    runtime = _runtime(key)
    child = runtime.derive_for_subcall(root, _host_to_a_delegation()).child
    assert child is not None
    meta = GcoWireCodec().attach(_meta(), child)
    tampered = dict(meta[META_GCO])
    tampered["policy_id"] = "policy-beta"
    meta[META_GCO] = tampered

    decision = GovernedServerBoundary(runtime).authorize_incoming(meta, tool_uri=A_TOOL, requested_scope="read:metrics")

    assert decision.allowed is False
    assert str(decision.error_code.value) == "gco_digest_mismatch"


def test_e3_fanout_allow_deny_attach_parent_and_missing_child(monkeypatch):
    key = _key()
    root = _root(key)
    runtime = _runtime(key)
    g1 = runtime.derive_for_subcall(root, _host_to_a_delegation()).child
    assert g1 is not None
    fanout = GovernedFanout(runtime)

    allowed, meta = fanout.prepare_subcall(
        g1,
        tool_uri=B_TOOL,
        requested_scope="read:table",
        delegation=_delegation(B_TOOL, "read:table"),
        base_meta=_meta(),
        attach_parent=True,
    )
    denied, denied_meta = fanout.prepare_subcall(
        g1,
        tool_uri=B_TOOL,
        requested_scope="write:table",
        delegation=_delegation(B_TOOL, "read:table"),
        base_meta=_meta(),
    )
    widened, widened_meta = fanout.prepare_subcall(
        g1,
        tool_uri=B_TOOL,
        requested_scope="read:table",
        delegation=_delegation(B_TOOL, "read:table write:table"),
        base_meta=_meta(),
    )

    monkeypatch.setattr(runtime, "derive_for_subcall", lambda parent, request: Decision(allowed=True))
    missing_child, missing_meta = fanout.prepare_subcall(
        g1,
        tool_uri=B_TOOL,
        requested_scope="read:table",
        delegation=_delegation(B_TOOL, "read:table"),
        base_meta=_meta(),
    )
    attach_denied, attach_meta = GovernedFanout(_runtime(key), GcoWireCodec(GcoExtensionSettings(max_gco_bytes=10))).prepare_subcall(
        g1,
        tool_uri=B_TOOL,
        requested_scope="read:table",
        delegation=_delegation(B_TOOL, "read:table"),
        base_meta=_meta(),
    )

    assert allowed.allowed is True
    assert meta is not None and META_PARENT_GCO in meta
    assert denied.allowed is False
    assert denied_meta is None
    assert widened.allowed is False
    assert widened.error_code is DerivationError.TOOL_AUTHORITY_EXPANDED
    assert widened_meta is None
    assert missing_child.allowed is False
    assert missing_child.error_code == "gco_missing_child"
    assert missing_meta is None
    assert attach_denied.error_code is GcoMcpError.OVERSIZE_GCO
    assert attach_meta is None


def test_design_end_to_end_host_to_a_to_b_tightens_each_hop():
    key = _key()
    root = _root(key)
    runtime = _runtime(key)
    codec = GcoWireCodec()

    host_decision, host_meta = GovernedClientBoundary(runtime, codec).prepare_tool_call(
        root,
        tool_uri=A_TOOL,
        requested_scope="read:metrics",
        delegation=_host_to_a_delegation(),
        base_meta=_meta(),
    )
    assert host_decision.allowed is True
    assert host_decision.child is not None
    assert host_meta is not None
    assert host_decision.child.lineage == [canonical_gco_hash(root)]

    a_decision = GovernedServerBoundary(runtime, codec).authorize_incoming(
        host_meta,
        tool_uri=A_TOOL,
        requested_scope="read:metrics",
    )
    assert a_decision.allowed is True

    fanout_decision, fanout_meta = GovernedFanout(runtime, codec).prepare_subcall(
        host_decision.child,
        tool_uri=B_TOOL,
        requested_scope="read:table",
        delegation=_delegation(B_TOOL, "read:table", depth=1),
        base_meta=_meta(),
    )
    assert fanout_decision.allowed is True
    assert fanout_decision.child is not None
    assert fanout_decision.child.lineage == [canonical_gco_hash(root), canonical_gco_hash(host_decision.child)]

    b_decision = GovernedServerBoundary(runtime, codec).authorize_incoming(
        fanout_meta,
        tool_uri=B_TOOL,
        requested_scope="read:table",
    )
    assert b_decision.allowed is True


def test_error_mapping_shapes():
    missing = mcp_error_for_decision(Decision(False, "missing", GcoMcpError.MISSING_CAPABILITY))
    malformed = mcp_error_for_decision(Decision(False, "bad", GcoMcpError.MALFORMED_GCO))
    tool = mcp_error_for_decision(Decision(False, "denied", DerivationError.TOOL_AUTHORITY_EXPANDED))
    none_code = decision_to_tool_error(Decision(False, None, None))
    class_error = decision_to_tool_error(Decision(False, "class", RuntimeError))
    string_error = decision_to_tool_error(Decision(False, "string", "custom_code"))
    direct_missing = missing_required_capability_error()
    direct_invalid = invalid_params_error("oversize", code=GcoMcpError.OVERSIZE_GCO)

    assert missing["code"] == -32021
    assert missing == direct_missing
    assert malformed["code"] == -32602
    assert direct_invalid["data"]["error_code"] == "gco_oversize"
    assert tool["isError"] is True
    assert tool["structuredContent"]["error_code"] == "tool_authority_expanded"
    assert none_code["structuredContent"]["error_code"] == "gco_denied"
    assert class_error["structuredContent"]["error_code"] == "RuntimeError"
    assert string_error["structuredContent"]["error_code"] == "custom_code"
    assert is_tool_error(tool) is True
    assert is_tool_error({"isError": False}) is False
