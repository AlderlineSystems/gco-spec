"""Adversarial audit for the P0 GCO MCP adapter boundary.

Oracle: governed boundaries fail closed for missing capability, tampered
_meta, oversize payloads, and widening fan-out requests. Run:
python audit_mcp_boundary.py
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from gco.derivation import DelegationRequest
from gco.models import AttestationFormat, AttestationModel, GCO, ToolAuthority
from gco.runtime import GovernanceRuntime
from gco.trust import TrustBundle
from gco.validator import DerivationError, canonical_gco_hash
from gco_mcp import META_GCO, GcoExtensionSettings, GcoMcpError, GcoWireCodec, GovernedFanout, GovernedServerBoundary, client_extensions_block

NOW = datetime(2099, 1, 1, 11, 0, tzinfo=timezone.utc)
SPIFFE_ID = "spiffe://example.org/ns/default/sa/model-alpha"
A_TOOL = "mcp://analytics/tools/query"
B_TOOL = "mcp://warehouse/tools/fetch"


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


KEY = _key()


def _jwk(private_key, kid: str) -> dict[str, Any]:
    payload = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    payload.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return payload


def _attestation(gco: GCO) -> AttestationModel:
    token = jwt.encode(
        {
            "sub": gco.model_identity,
            "gco_hash": canonical_gco_hash(gco),
            "exp": int((NOW + timedelta(hours=1)).timestamp()),
        },
        KEY,
        algorithm="RS256",
        headers={"kid": "mcp"},
    )
    return AttestationModel(format=AttestationFormat.JWT_SVID, value=token)


class Authority:
    def issue(self, identity: str, gco_data: dict[str, Any]) -> AttestationModel:
        gco = GCO.model_validate({**gco_data, "model_identity": identity, "attestation": None})
        return _attestation(gco)


def _sign(gco: GCO) -> GCO:
    return gco.model_copy(update={"attestation": _attestation(gco)})


def _root() -> GCO:
    return _sign(
        GCO(
            gco_version="1.0.0",
            trace_id=uuid4(),
            span_id=uuid4(),
            parent_span_id=None,
            policy_id="p",
            model_identity=SPIFFE_ID,
            intervention_version="iv",
            tool_authority=[
                ToolAuthority(tool_uri=A_TOOL, scope="read:metrics", max_depth=3),
                ToolAuthority(tool_uri=B_TOOL, scope="read:table", max_depth=3),
            ],
            state_access_permissions=[],
            expires_at=NOW + timedelta(hours=2),
            lineage=[],
            attestation=None,
        )
    )


def _runtime() -> GovernanceRuntime:
    bundle = TrustBundle.from_mapping({"example.org": {"jwks": {"keys": [_jwk(KEY, "mcp")]}}})
    return GovernanceRuntime(bundle, attestation_authority=Authority(), now=lambda: NOW)


def _meta() -> dict[str, Any]:
    return {"io.modelcontextprotocol/clientCapabilities": {"extensions": client_extensions_block()}}


def _request(*, tool_uri: str, scope: str, max_depth: int = 1) -> DelegationRequest:
    return DelegationRequest(
        tool_authority=[ToolAuthority(tool_uri=tool_uri, scope=scope, max_depth=max_depth)],
        state_access_permissions=[],
        requested_expiry=NOW + timedelta(minutes=30),
    )


def main() -> None:
    runtime = _runtime()
    root = _root()
    codec = GcoWireCodec()
    child = runtime.derive_for_subcall(
        root,
        DelegationRequest(
            tool_authority=[
                ToolAuthority(tool_uri=A_TOOL, scope="read:metrics", max_depth=2),
                ToolAuthority(tool_uri=B_TOOL, scope="read:table", max_depth=2),
            ],
            state_access_permissions=[],
            requested_expiry=NOW + timedelta(minutes=30),
        ),
    ).child
    assert child is not None

    cases: list[tuple[str, bool]] = []
    server = GovernedServerBoundary(runtime, codec)
    cases.append(("missing capability denied", server.authorize_incoming({}, tool_uri=A_TOOL).error_code is GcoMcpError.MISSING_CAPABILITY))

    meta = codec.attach(_meta(), child)
    tampered = dict(meta[META_GCO])
    tampered["policy_id"] = "p2"
    meta[META_GCO] = tampered
    cases.append(("tampered meta denied", server.authorize_incoming(meta, tool_uri=A_TOOL).allowed is False))

    oversize_server = GovernedServerBoundary(runtime, GcoWireCodec(GcoExtensionSettings(max_gco_bytes=10)))
    cases.append(("oversize meta denied", oversize_server.authorize_incoming(codec.attach(_meta(), child), tool_uri=A_TOOL).error_code is GcoMcpError.OVERSIZE_GCO))

    widening, widened_meta = GovernedFanout(runtime).prepare_subcall(
        child,
        tool_uri=B_TOOL,
        requested_scope="read:table",
        delegation=_request(tool_uri=B_TOOL, scope="read:table write:table", max_depth=9),
        base_meta=_meta(),
    )
    cases.append(("widening fanout denied", widening.error_code is DerivationError.TOOL_AUTHORITY_EXPANDED and widened_meta is None))

    failed = [name for name, ok in cases if not ok]
    for name, ok in cases:
        print(f"{name}: {'PASS' if ok else 'FAIL'}")
    print("RESULT:", "PASS" if not failed else "**FAIL**")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
