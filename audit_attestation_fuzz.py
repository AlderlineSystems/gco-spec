"""Fuzz attestation verification.

Oracle: forged, malformed, expired, wrong-digest, or unsupported attestations
must never verify and must never raise uncaught exceptions.
Run: python audit_attestation_fuzz.py
"""
from __future__ import annotations

import base64
import json
import random
from datetime import datetime, timedelta, timezone
from uuid import UUID

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from gco.attestation import AttestationVerifier
from gco.models import AccessMode, AttestationFormat, AttestationModel, GCO, StatePermission, TaintPolicy, ToolAuthority
from gco.trust import TrustBundle
from gco.validator import canonical_gco_hash

NOW = datetime(2099, 1, 1, 12, 0, tzinfo=timezone.utc)
SPIFFE_ID = "spiffe://example.org/ns/default/sa/model-alpha"


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


TRUSTED_KEY = _key()
FORGERY_KEY = _key()


def _jwk(private_key, kid: str) -> dict:
    payload = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    payload.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return payload


BUNDLE = TrustBundle.from_mapping({"example.org": {"jwks": {"keys": [_jwk(TRUSTED_KEY, "trusted")]}}})
VERIFIER = AttestationVerifier(BUNDLE)


def gco() -> GCO:
    return GCO(
        gco_version="1.0.0",
        trace_id=UUID("11111111-1111-4111-8111-111111111111"),
        span_id=UUID("22222222-2222-4222-8222-222222222222"),
        parent_span_id=None,
        policy_id="policy-alpha",
        model_identity=SPIFFE_ID,
        intervention_version="iv",
        tool_authority=[ToolAuthority(tool_uri="https://tools.example/search", scope="read", max_depth=1)],
        state_access_permissions=[StatePermission(namespace="ns", access_mode=AccessMode.READ, taint_policy=TaintPolicy.CLEAN)],
        expires_at=NOW + timedelta(days=1),
        lineage=[],
        attestation=None,
    )


def _claims(subject: GCO, *, digest: str | None = None, exp: datetime | None = None, sub: str = SPIFFE_ID) -> dict:
    return {
        "sub": sub,
        "gco_hash": digest or canonical_gco_hash(subject),
        "exp": int((exp or NOW + timedelta(hours=1)).timestamp()),
    }


def _random_token(rng: random.Random) -> str:
    chunks = []
    for _ in range(rng.randint(1, 4)):
        raw = rng.randbytes(rng.randint(0, 32))
        chunks.append(base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="))
    return ".".join(chunks)


def forged_attestation(subject: GCO, rng: random.Random) -> AttestationModel:
    choice = rng.randrange(7)
    if choice == 0:
        return AttestationModel(format=AttestationFormat.JWT_SVID, value=_random_token(rng))
    if choice == 1:
        token = jwt.encode(_claims(subject), FORGERY_KEY, algorithm="RS256", headers={"kid": "forged"})
        return AttestationModel(format=AttestationFormat.JWT_SVID, value=token)
    if choice == 2:
        token = jwt.encode(_claims(subject, digest="0" * 64), TRUSTED_KEY, algorithm="RS256", headers={"kid": "trusted"})
        return AttestationModel(format=AttestationFormat.JWT_SVID, value=token)
    if choice == 3:
        token = jwt.encode(
            _claims(subject, exp=NOW - timedelta(seconds=1)),
            TRUSTED_KEY,
            algorithm="RS256",
            headers={"kid": "trusted"},
        )
        return AttestationModel(format=AttestationFormat.JWT_SVID, value=token)
    if choice == 4:
        token = jwt.encode(
            _claims(subject, sub="spiffe://example.org/ns/default/sa/other"),
            TRUSTED_KEY,
            algorithm="RS256",
            headers={"kid": "trusted"},
        )
        return AttestationModel(format=AttestationFormat.JWT_SVID, value=token)
    if choice == 5:
        token = jwt.encode(_claims(subject), TRUSTED_KEY, algorithm="RS256", headers={"kid": "trusted"})
        head, payload, sig = token.split(".")
        return AttestationModel(format=AttestationFormat.JWT_SVID, value=f"{head}.{payload}.{sig[:-2]}xx")
    return AttestationModel(format=rng.choice([AttestationFormat.RAW_JWS, AttestationFormat.TPM_QUOTE]), value=_random_token(rng))


def main() -> None:
    rng = random.Random(424242)
    iterations = 20000
    verified_forgeries = 0
    uncaught = 0
    examples: list[str] = []
    subject = gco()

    for _ in range(iterations):
        try:
            result = VERIFIER.verify(forged_attestation(subject, rng), subject, now=NOW)
            if result.verified:
                verified_forgeries += 1
                if len(examples) < 3:
                    examples.append("forgery verified")
        except Exception as exc:  # noqa: BLE001
            uncaught += 1
            if len(examples) < 3:
                examples.append(f"UNCAUGHT {type(exc).__name__}: {exc}")

    print(f"iterations:            {iterations}")
    print(f"forgeries verified:    {verified_forgeries}")
    print(f"uncaught exceptions:   {uncaught}")
    for example in examples:
        print("  example:", example)
    print("RESULT:", "PASS" if verified_forgeries == 0 and uncaught == 0 else "**FAIL**")


if __name__ == "__main__":
    main()
