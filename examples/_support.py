from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from gco.derivation import DelegationRequest  # noqa: E402
from gco.models import AccessMode, AttestationFormat, AttestationModel, GCO, StatePermission, ToolAuthority  # noqa: E402
from gco.trust import TrustBundle  # noqa: E402
from gco.validator import canonical_gco_hash  # noqa: E402


NOW = datetime(2099, 1, 1, 12, 0, tzinfo=timezone.utc)
SPIFFE_ID = "spiffe://example.org/ns/default/sa/model-alpha"
TOOL_URI = "https://tools.example/search"


def make_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def trust_bundle_for(private_key, *, kid: str = "example-key") -> TrustBundle:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return TrustBundle.from_mapping({"example.org": {"jwks": {"keys": [jwk]}}})


def sign(gco: GCO, private_key, *, kid: str = "example-key") -> GCO:
    payload = {
        "sub": gco.model_identity,
        "gco_hash": canonical_gco_hash(gco),
        "exp": int((NOW + timedelta(hours=1)).timestamp()),
    }
    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})
    return gco.model_copy(update={"attestation": AttestationModel(format=AttestationFormat.JWT_SVID, value=token)})


class SigningAuthority:
    def __init__(self, private_key, *, kid: str = "example-key") -> None:
        self.private_key = private_key
        self.kid = kid

    def issue(self, identity: str, gco_data: dict) -> AttestationModel:
        unsigned = GCO.model_validate({**gco_data, "attestation": None})
        signed = sign(unsigned.model_copy(update={"model_identity": identity}), self.private_key, kid=self.kid)
        if signed.attestation is None:
            raise RuntimeError("signing failed")
        return signed.attestation


def root_gco() -> GCO:
    return GCO(
        gco_version="1.0",
        trace_id=uuid4(),
        span_id=uuid4(),
        parent_span_id=None,
        policy_id="policy:demo",
        model_identity=SPIFFE_ID,
        intervention_version="demo-v1",
        tool_authority=[ToolAuthority(tool_uri=TOOL_URI, scope="read summarize", max_depth=2)],
        state_access_permissions=[StatePermission(namespace="memory", access_mode=AccessMode.READ)],
        expires_at=NOW + timedelta(minutes=30),
        lineage=[],
        attestation=None,
    )


def valid_delegation_request() -> DelegationRequest:
    return DelegationRequest(
        tool_authority=[ToolAuthority(tool_uri=TOOL_URI, scope="read", max_depth=1)],
        state_access_permissions=[StatePermission(namespace="memory", access_mode=AccessMode.READ)],
        requested_expiry=NOW + timedelta(minutes=10),
    )
