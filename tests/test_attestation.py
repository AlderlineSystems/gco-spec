from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import gco.attestation as attestation_module
from conftest import BASE_TIME
from gco.attestation import AttestationError, AttestationVerifier, InMemoryReplayCache
from gco.models import AttestationFormat, AttestationModel, GCO
from gco.trust import TrustBundle
from gco.validator import canonical_gco_hash


SPIFFE_ID = "spiffe://example.org/ns/default/sa/model-alpha"
VERIFY_TIME = datetime(2099, 1, 1, 11, 0, tzinfo=timezone.utc)


def _rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _dsa_key():
    return dsa.generate_private_key(key_size=2048)


def _ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def _jwk(private_key, kid: str) -> dict:
    payload = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    payload["kid"] = kid
    payload["alg"] = "RS256"
    payload["use"] = "sig"
    return payload


def _with_identity(gco: GCO) -> GCO:
    return gco.model_copy(update={"model_identity": SPIFFE_ID})


def _claims(
    gco: GCO,
    *,
    sub: str = SPIFFE_ID,
    exp: datetime | None = None,
    digest: str | None = None,
    aud=None,
    jti: str | None = None,
) -> dict:
    claims = {
        "sub": sub,
        "gco_hash": digest or canonical_gco_hash(gco),
        "exp": int((exp or VERIFY_TIME + timedelta(hours=1)).timestamp()),
    }
    if aud is not None:
        claims["aud"] = aud
    if jti is not None:
        claims["jti"] = jti
    return claims


def _jwt_attestation(gco: GCO, key, *, kid: str = "jwt-key", claims: dict | None = None) -> AttestationModel:
    token = jwt.encode(
        claims or _claims(gco),
        key,
        algorithm="RS256",
        headers={"kid": kid},
    )
    return AttestationModel(format=AttestationFormat.JWT_SVID, value=token)


def _trust_bundle_for_jwt(key, *, kid: str = "jwt-key") -> TrustBundle:
    return TrustBundle.from_mapping({"example.org": {"jwks": {"keys": [_jwk(key, kid)]}}})


def _verify(attestation: AttestationModel, gco: GCO, bundle: TrustBundle):
    return AttestationVerifier(bundle).verify(attestation, gco, now=VERIFY_TIME)


def _b64_json(payload: dict | list) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unsigned_token(header: dict, payload: dict | list) -> str:
    return f"{_b64_json(header)}.{_b64_json(payload)}."


def _token_with_corrupted_signature(token: str) -> str:
    head, payload, signature = token.split(".")
    replacement = "A" if signature[0] != "A" else "B"
    return f"{head}.{payload}.{replacement}{signature[1:]}"


def test_jwt_svid_happy_path(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    attestation = _jwt_attestation(gco, key)

    result = _verify(attestation, gco, _trust_bundle_for_jwt(key))

    assert result.verified is True
    assert result.error_code is None


def test_jwt_svid_tampered_gco_returns_digest_mismatch(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    attestation = _jwt_attestation(gco, key)
    tampered = gco.model_copy(update={"policy_id": "policy-beta"})

    result = _verify(attestation, tampered, _trust_bundle_for_jwt(key))

    assert result.verified is False
    assert result.error_code is AttestationError.GCO_DIGEST_MISMATCH


def test_jwt_svid_wrong_key_id_returns_untrusted_key(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    signer = _rsa_key()
    trusted = _rsa_key()
    attestation = _jwt_attestation(gco, signer, kid="unknown")

    result = _verify(attestation, gco, _trust_bundle_for_jwt(trusted, kid="trusted"))

    assert result.verified is False
    assert result.error_code is AttestationError.UNTRUSTED_KEY


def test_jwt_svid_unknown_trust_domain_returns_untrusted_key(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    attestation = _jwt_attestation(gco, key, claims=_claims(gco, sub="spiffe://missing.example/workload"))

    result = _verify(attestation, gco, _trust_bundle_for_jwt(key))

    assert result.verified is False
    assert result.error_code is AttestationError.UNTRUSTED_KEY


def test_jwt_svid_non_spiffe_subject_returns_untrusted_key(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    attestation = _jwt_attestation(gco, key, claims=_claims(gco, sub="not-spiffe"))

    result = _verify(attestation, gco, _trust_bundle_for_jwt(key))

    assert result.verified is False
    assert result.error_code is AttestationError.UNTRUSTED_KEY


def test_jwt_svid_missing_kid_returns_untrusted_key(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    token = jwt.encode(_claims(gco), key, algorithm="RS256")

    result = _verify(AttestationModel(format=AttestationFormat.JWT_SVID, value=token), gco, _trust_bundle_for_jwt(key))

    assert result.verified is False
    assert result.error_code is AttestationError.UNTRUSTED_KEY


def test_jwt_svid_bad_signature_returns_unverified_signature(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    attestation = _jwt_attestation(gco, key)
    corrupted = _token_with_corrupted_signature(attestation.value)

    result = _verify(
        AttestationModel(format=AttestationFormat.JWT_SVID, value=corrupted),
        gco,
        _trust_bundle_for_jwt(key),
    )

    assert result.verified is False
    assert result.error_code is AttestationError.UNVERIFIED_SIGNATURE


def test_jwt_svid_unsafe_algorithm_returns_malformed(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    token = _unsigned_token({"alg": "none", "kid": "jwt-key", "typ": "JWT"}, _claims(gco))

    result = _verify(AttestationModel(format=AttestationFormat.JWT_SVID, value=token), gco, _trust_bundle_for_jwt(_rsa_key()))

    assert result.verified is False
    assert result.error_code is AttestationError.MALFORMED_ATTESTATION


def test_decode_non_object_payload_is_malformed(monkeypatch):
    key = _rsa_key()
    monkeypatch.setattr(attestation_module.jwt, "decode", lambda *args, **kwargs: ["not", "object"])

    result = attestation_module._decode_with_key("token", key.public_key(), {"alg": "RS256"})

    assert result.verified is False
    assert result.error_code is AttestationError.MALFORMED_ATTESTATION


def test_decode_generic_exception_is_malformed(monkeypatch):
    key = _rsa_key()

    def raise_decode_error(*args, **kwargs):
        raise RuntimeError("decode failed")

    monkeypatch.setattr(attestation_module.jwt, "decode", raise_decode_error)

    result = attestation_module._decode_with_key("token", key.public_key(), {"alg": "RS256"})

    assert result.verified is False
    assert result.error_code is AttestationError.MALFORMED_ATTESTATION
    assert result.message == "JWS payload is malformed"


def test_jwt_svid_decode_failure_after_key_selection_returns_malformed(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    token = jwt.encode(_claims(gco), "x" * 32, algorithm="HS256", headers={"kid": "jwt-key"})

    result = _verify(AttestationModel(format=AttestationFormat.JWT_SVID, value=token), gco, _trust_bundle_for_jwt(key))

    assert result.verified is False
    assert result.error_code is AttestationError.MALFORMED_ATTESTATION


def test_jwt_svid_identity_mismatch(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    attestation = _jwt_attestation(gco, key, claims=_claims(gco, sub="spiffe://example.org/other"))

    result = _verify(attestation, gco, _trust_bundle_for_jwt(key))

    assert result.verified is False
    assert result.error_code is AttestationError.SPIFFE_ID_MISMATCH


def test_jwt_svid_expired(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    attestation = _jwt_attestation(gco, key, claims=_claims(gco, exp=VERIFY_TIME - timedelta(seconds=1)))

    result = _verify(attestation, gco, _trust_bundle_for_jwt(key))

    assert result.verified is False
    assert result.error_code is AttestationError.EXPIRED_ATTESTATION


def test_jwt_svid_nbf_uses_injected_time(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    claims = _claims(gco)
    claims["nbf"] = int((VERIFY_TIME - timedelta(seconds=1)).timestamp())
    attestation = _jwt_attestation(gco, key, claims=claims)

    result = _verify(attestation, gco, _trust_bundle_for_jwt(key))

    assert result.verified is True


def test_jwt_svid_future_nbf_rejected_by_injected_time(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    claims = _claims(gco)
    claims["nbf"] = int((VERIFY_TIME + timedelta(seconds=1)).timestamp())
    attestation = _jwt_attestation(gco, key, claims=claims)

    result = _verify(attestation, gco, _trust_bundle_for_jwt(key))

    assert result.verified is False
    assert result.error_code is AttestationError.MALFORMED_ATTESTATION


def test_jwt_svid_iat_uses_injected_time(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    claims = _claims(gco)
    claims["iat"] = int((VERIFY_TIME - timedelta(seconds=1)).timestamp())
    attestation = _jwt_attestation(gco, key, claims=claims)

    result = _verify(attestation, gco, _trust_bundle_for_jwt(key))

    assert result.verified is True


def test_jwt_svid_future_iat_rejected_by_injected_time(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    claims = _claims(gco)
    claims["iat"] = int((VERIFY_TIME + timedelta(seconds=1)).timestamp())
    attestation = _jwt_attestation(gco, key, claims=claims)

    result = _verify(attestation, gco, _trust_bundle_for_jwt(key))

    assert result.verified is False
    assert result.error_code is AttestationError.MALFORMED_ATTESTATION


@pytest.mark.parametrize("claim", ["nbf", "iat"])
def test_jwt_svid_malformed_time_claim_rejected(claim, valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    claims = _claims(gco)
    claims[claim] = "not-a-timestamp"
    attestation = _jwt_attestation(gco, key, claims=claims)

    result = _verify(attestation, gco, _trust_bundle_for_jwt(key))

    assert result.verified is False
    assert result.error_code is AttestationError.MALFORMED_ATTESTATION


@pytest.mark.parametrize("claim", ["exp", "nbf", "iat"])
def test_jwt_svid_out_of_range_time_claim_rejected(claim, valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    claims = _claims(gco)
    claims[claim] = 10**100
    attestation = _jwt_attestation(gco, key, claims=claims)

    result = _verify(attestation, gco, _trust_bundle_for_jwt(key))

    assert result.verified is False
    assert result.error_code is AttestationError.MALFORMED_ATTESTATION


def test_non_finite_numeric_date_is_rejected():
    assert attestation_module._numeric_date(float("inf")) is None


def test_jwt_svid_missing_exp_is_malformed(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    claims = _claims(gco)
    claims.pop("exp")
    attestation = _jwt_attestation(gco, key, claims=claims)

    result = _verify(attestation, gco, _trust_bundle_for_jwt(key))

    assert result.verified is False
    assert result.error_code is AttestationError.MALFORMED_ATTESTATION


def test_jwt_svid_audience_is_ignored_without_expected_audience(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    attestation = _jwt_attestation(gco, key, claims=_claims(gco, aud="https://other.example/receiver"))

    result = _verify(attestation, gco, _trust_bundle_for_jwt(key))

    assert result.verified is True


def test_jwt_svid_expected_audience_accepts_string_or_list(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    bundle = _trust_bundle_for_jwt(key)
    string_aud = _jwt_attestation(gco, key, claims=_claims(gco, aud="https://api.example/receiver"))
    list_aud = _jwt_attestation(gco, key, claims=_claims(gco, aud=["https://other.example", "https://api.example/receiver"]))
    verifier = AttestationVerifier(bundle, expected_audience=("https://api.example/receiver",))

    assert verifier.verify(string_aud, gco, now=VERIFY_TIME).verified is True
    assert verifier.verify(list_aud, gco, now=VERIFY_TIME).verified is True


@pytest.mark.parametrize("aud", [None, "https://other.example/receiver", [], [123]])
def test_jwt_svid_expected_audience_rejects_missing_wrong_or_malformed_audience(aud, valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    attestation = _jwt_attestation(gco, key, claims=_claims(gco, aud=aud))
    verifier = AttestationVerifier(_trust_bundle_for_jwt(key), expected_audience="https://api.example/receiver")

    result = verifier.verify(attestation, gco, now=VERIFY_TIME)

    assert result.verified is False
    assert result.error_code is AttestationError.AUDIENCE_MISMATCH


def test_jwt_svid_uses_trust_bundle_expected_audience(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    jwk = _jwk(key, "jwt-key")
    bundle = TrustBundle.from_mapping(
        {
            "expected_audience": "https://api.example/receiver",
            "trust_domains": {"example.org": {"jwks": {"keys": [jwk]}}},
        }
    )
    attestation = _jwt_attestation(gco, key, claims=_claims(gco, aud="https://api.example/receiver"))

    assert AttestationVerifier(bundle).verify(attestation, gco, now=VERIFY_TIME).verified is True


def test_jwt_svid_verifier_expected_audience_overrides_trust_bundle(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    jwk = _jwk(key, "jwt-key")
    bundle = TrustBundle.from_mapping(
        {
            "expected_audience": "https://bundle.example/receiver",
            "trust_domains": {"example.org": {"jwks": {"keys": [jwk]}}},
        }
    )
    attestation = _jwt_attestation(gco, key, claims=_claims(gco, aud="https://verifier.example/receiver"))
    verifier = AttestationVerifier(bundle, expected_audience="https://verifier.example/receiver")

    assert verifier.verify(attestation, gco, now=VERIFY_TIME).verified is True


def test_jwt_svid_replay_cache_accepts_first_jti_and_rejects_reuse(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    attestation = _jwt_attestation(gco, key, claims=_claims(gco, jti="token-1"))
    verifier = AttestationVerifier(_trust_bundle_for_jwt(key), replay_cache=InMemoryReplayCache())

    first = verifier.verify(attestation, gco, now=VERIFY_TIME)
    second = verifier.verify(attestation, gco, now=VERIFY_TIME)

    assert first.verified is True
    assert second.verified is False
    assert second.error_code is AttestationError.REPLAY_DETECTED


def test_jwt_svid_missing_jti_rejected_when_replay_cache_enabled(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    attestation = _jwt_attestation(gco, key)
    verifier = AttestationVerifier(_trust_bundle_for_jwt(key), replay_cache=InMemoryReplayCache())

    result = verifier.verify(attestation, gco, now=VERIFY_TIME)

    assert result.verified is False
    assert result.error_code is AttestationError.JTI_MISSING


def test_in_memory_replay_cache_expires_entries_and_evicts_oldest():
    cache = InMemoryReplayCache(max_entries=1)
    expires = VERIFY_TIME + timedelta(seconds=10)

    assert cache.check_and_record("seen", expires, VERIFY_TIME) is True
    assert cache.check_and_record("seen", expires, VERIFY_TIME) is False
    assert cache.check_and_record("seen", expires, expires) is True
    assert cache.check_and_record("newer", expires + timedelta(seconds=1), VERIFY_TIME) is True
    assert cache.check_and_record("seen", expires, VERIFY_TIME) is True
    cache._entries.clear()
    cache._evict_oldest()


def test_in_memory_replay_cache_rejects_non_positive_max_entries():
    with pytest.raises(ValueError):
        InMemoryReplayCache(max_entries=0)


def test_verify_accepts_default_and_naive_injected_clocks(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    attestation = _jwt_attestation(gco, key)
    verifier = AttestationVerifier(_trust_bundle_for_jwt(key), now=lambda: VERIFY_TIME.replace(tzinfo=None))

    assert verifier.verify(attestation, gco).verified is True


@pytest.mark.parametrize("value", ["not-a-token", "a.b.c", ""])
def test_jwt_svid_malformed(value, valid_root_gco):
    gco = _with_identity(valid_root_gco)

    result = AttestationVerifier(_trust_bundle_for_jwt(_rsa_key())).verify(
        AttestationModel(format=AttestationFormat.JWT_SVID, value=value),
        gco,
        now=VERIFY_TIME,
    )

    assert result.verified is False
    assert result.error_code is AttestationError.MALFORMED_ATTESTATION


def test_tpm_quote_and_raw_jws_are_unsupported(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    verifier = AttestationVerifier(_trust_bundle_for_jwt(_rsa_key()))

    for fmt in (AttestationFormat.TPM_QUOTE, AttestationFormat.RAW_JWS):
        result = verifier.verify(AttestationModel(format=fmt, value="opaque"), gco, now=VERIFY_TIME)
        assert result.verified is False
        assert result.error_code is AttestationError.UNSUPPORTED_FORMAT


def test_missing_attestation_is_malformed(valid_root_gco):
    gco = _with_identity(valid_root_gco)

    result = AttestationVerifier(_trust_bundle_for_jwt(_rsa_key())).verify(None, gco, now=VERIFY_TIME)

    assert result.verified is False
    assert result.error_code is AttestationError.MALFORMED_ATTESTATION


def _cert(
    subject_cn: str,
    subject_key,
    issuer_cn: str,
    issuer_key,
    *,
    is_ca: bool,
    issuer_cert: x509.Certificate | None = None,
    spiffe_id: str | None = None,
) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = issuer_cert.subject if issuer_cert is not None else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(VERIFY_TIME - timedelta(days=1))
        .not_valid_after(VERIFY_TIME + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None if is_ca else None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
    )
    if is_ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        if spiffe_id is not None:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]),
                critical=False,
            )
    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())


def _chain(spiffe_id: str | None = SPIFFE_ID):
    root_key = _rsa_key()
    int_key = _rsa_key()
    leaf_key = _rsa_key()
    root = _cert("Root", root_key, "Root", root_key, is_ca=True)
    intermediate = _cert("Intermediate", int_key, "Root", root_key, is_ca=True, issuer_cert=root)
    leaf = _cert("Leaf", leaf_key, "Intermediate", int_key, is_ca=False, issuer_cert=intermediate, spiffe_id=spiffe_id)
    return root_key, root, int_key, intermediate, leaf_key, leaf


def _dsa_chain():
    root_key = _rsa_key()
    int_key = _rsa_key()
    leaf_key = _dsa_key()
    root = _cert("Root", root_key, "Root", root_key, is_ca=True)
    intermediate = _cert("Intermediate", int_key, "Root", root_key, is_ca=True, issuer_cert=root)
    leaf = _cert("Leaf", leaf_key, "Intermediate", int_key, is_ca=False, issuer_cert=intermediate, spiffe_id=SPIFFE_ID)
    return root, intermediate, leaf


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _x5c(cert: x509.Certificate) -> str:
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")


def _x509_attestation(gco: GCO, leaf_key, leaf: x509.Certificate, intermediate: x509.Certificate, *, claims: dict | None = None) -> AttestationModel:
    token = jwt.encode(
        claims or _claims(gco),
        leaf_key,
        algorithm="RS256",
        headers={"x5c": [_x5c(leaf), _x5c(intermediate)]},
    )
    return AttestationModel(format=AttestationFormat.X509_SVID, value=token)


def _trust_bundle_for_ca(root: x509.Certificate) -> TrustBundle:
    return TrustBundle.from_mapping({"example.org": {"ca_certs": [_pem(root)]}})


def test_x509_svid_happy_path(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    _, root, _, intermediate, leaf_key, leaf = _chain()
    attestation = _x509_attestation(gco, leaf_key, leaf, intermediate)

    result = _verify(attestation, gco, _trust_bundle_for_ca(root))

    assert result.verified is True


def test_x509_svid_untrusted_root(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    _, _, _, intermediate, leaf_key, leaf = _chain()
    _, other_root, *_ = _chain()
    attestation = _x509_attestation(gco, leaf_key, leaf, intermediate)

    result = _verify(attestation, gco, _trust_bundle_for_ca(other_root))

    assert result.verified is False
    assert result.error_code is AttestationError.UNTRUSTED_KEY


def test_x509_svid_malformed_token(valid_root_gco):
    gco = _with_identity(valid_root_gco)

    result = _verify(
        AttestationModel(format=AttestationFormat.X509_SVID, value="not-a-token"),
        gco,
        TrustBundle.from_mapping({}),
    )

    assert result.verified is False
    assert result.error_code is AttestationError.MALFORMED_ATTESTATION


def test_x509_svid_missing_x5c(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    token = jwt.encode(_claims(gco), key, algorithm="RS256")

    result = _verify(
        AttestationModel(format=AttestationFormat.X509_SVID, value=token),
        gco,
        TrustBundle.from_mapping({}),
    )

    assert result.verified is False
    assert result.error_code is AttestationError.MALFORMED_ATTESTATION


def test_x509_svid_no_ca_for_domain(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    _, _, _, intermediate, leaf_key, leaf = _chain()
    attestation = _x509_attestation(gco, leaf_key, leaf, intermediate)

    result = _verify(attestation, gco, TrustBundle.from_mapping({"example.org": {"jwks": {"keys": []}}}))

    assert result.verified is False
    assert result.error_code is AttestationError.UNTRUSTED_KEY


def test_x509_svid_missing_intermediate(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    _, root, _, intermediate, leaf_key, leaf = _chain()
    token = jwt.encode(_claims(gco), leaf_key, algorithm="RS256", headers={"x5c": [_x5c(leaf)]})

    result = _verify(AttestationModel(format=AttestationFormat.X509_SVID, value=token), gco, _trust_bundle_for_ca(root))

    assert result.verified is False
    assert result.error_code is AttestationError.UNTRUSTED_KEY
    assert intermediate is not None


@pytest.mark.parametrize("spiffe_id", [None, "spiffe://example.org/ns/default/sa/other"])
def test_x509_svid_san_failures(spiffe_id, valid_root_gco):
    gco = _with_identity(valid_root_gco)
    _, root, _, intermediate, leaf_key, leaf = _chain(spiffe_id)
    attestation = _x509_attestation(gco, leaf_key, leaf, intermediate)

    result = _verify(attestation, gco, _trust_bundle_for_ca(root))

    assert result.verified is False
    assert result.error_code is AttestationError.SPIFFE_ID_MISMATCH


def test_x509_svid_reuses_digest_and_expiry_bindings(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    _, root, _, intermediate, leaf_key, leaf = _chain()
    expired = _x509_attestation(gco, leaf_key, leaf, intermediate, claims=_claims(gco, exp=VERIFY_TIME - timedelta(seconds=1)))
    bad_digest = _x509_attestation(gco, leaf_key, leaf, intermediate, claims=_claims(gco, digest="f" * 64))

    expired_result = _verify(expired, gco, _trust_bundle_for_ca(root))
    digest_result = _verify(bad_digest, gco, _trust_bundle_for_ca(root))

    assert expired_result.error_code is AttestationError.EXPIRED_ATTESTATION
    assert digest_result.error_code is AttestationError.GCO_DIGEST_MISMATCH


def test_x509_svid_malformed_x5c(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    leaf_key = _rsa_key()
    token = jwt.encode(_claims(gco), leaf_key, algorithm="RS256", headers={"x5c": ["not-base64"]})

    result = _verify(AttestationModel(format=AttestationFormat.X509_SVID, value=token), gco, TrustBundle.from_mapping({}))

    assert result.verified is False
    assert result.error_code is AttestationError.MALFORMED_ATTESTATION


def test_x509_svid_non_string_x5c_entry_is_malformed(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    token = jwt.encode(_claims(gco), key, algorithm="RS256", headers={"x5c": [123]})

    result = _verify(AttestationModel(format=AttestationFormat.X509_SVID, value=token), gco, TrustBundle.from_mapping({}))

    assert result.verified is False
    assert result.error_code is AttestationError.MALFORMED_ATTESTATION


def test_x509_svid_unsupported_leaf_key(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    root, intermediate, leaf = _dsa_chain()
    token = jwt.encode(
        _claims(gco),
        _rsa_key(),
        algorithm="RS256",
        headers={"x5c": [_x5c(leaf), _x5c(intermediate)]},
    )

    result = _verify(AttestationModel(format=AttestationFormat.X509_SVID, value=token), gco, _trust_bundle_for_ca(root))

    assert result.verified is False
    assert result.error_code is AttestationError.UNTRUSTED_KEY


def test_x509_svid_generic_chain_error_maps_malformed(monkeypatch, valid_root_gco):
    gco = _with_identity(valid_root_gco)
    _, root, _, intermediate, leaf_key, leaf = _chain()
    attestation = _x509_attestation(gco, leaf_key, leaf, intermediate)

    class BrokenBuilder:
        def store(self, _store):
            return self

        def time(self, _now):
            return self

        def build_client_verifier(self):
            raise RuntimeError("builder failed")

    monkeypatch.setattr(attestation_module, "PolicyBuilder", BrokenBuilder)

    result = _verify(attestation, gco, _trust_bundle_for_ca(root))

    assert result.verified is False
    assert result.error_code is AttestationError.MALFORMED_ATTESTATION


def test_x509_svid_bad_signature_returns_unverified_signature(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    _, root, _, intermediate, leaf_key, leaf = _chain()
    attestation = _x509_attestation(gco, leaf_key, leaf, intermediate)
    corrupted = _token_with_corrupted_signature(attestation.value)

    result = _verify(AttestationModel(format=AttestationFormat.X509_SVID, value=corrupted), gco, _trust_bundle_for_ca(root))

    assert result.verified is False
    assert result.error_code is AttestationError.UNVERIFIED_SIGNATURE


def test_decode_with_key_ignores_attacker_controlled_header_alg_for_rsa_key():
    # The allowlist must be derived from the key TYPE, not the attacker-controlled
    # header 'alg' claim. Passing a header alg outside the RSA allowlist must be
    # rejected without ever calling jwt.decode with that untrusted algorithm name.
    key = _rsa_key()

    result = attestation_module._decode_with_key("a.b.c", key.public_key(), {"alg": "HS256"})

    assert result.verified is False
    assert result.error_code in (AttestationError.UNVERIFIED_SIGNATURE, AttestationError.MALFORMED_ATTESTATION)


def test_decode_with_key_rejects_alg_not_in_key_type_allowlist():
    key = _rsa_key()

    result = attestation_module._decode_with_key("token", key.public_key(), {"alg": "ES256"})

    assert result.verified is False
    assert result.error_code in (AttestationError.UNVERIFIED_SIGNATURE, AttestationError.MALFORMED_ATTESTATION)


def test_decode_with_key_allows_only_key_type_matched_algorithms(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    # A legitimate RS256 token must still verify when the allowlist is derived
    # from the RSA key type (regression guard for the alg-pinning fix).
    token = jwt.encode(_claims(gco), key, algorithm="RS256", headers={"kid": "jwt-key"})

    result = _verify(
        AttestationModel(format=AttestationFormat.JWT_SVID, value=token),
        gco,
        _trust_bundle_for_jwt(key),
    )

    assert result.verified is True


def test_decode_with_key_derives_allowlist_from_ec_key_type():
    key = _ec_key()
    jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "ec-key", "alg": "ES256", "use": "sig"})
    token = jwt.encode({"sub": "x", "gco_hash": "y", "exp": 9999999999}, key, algorithm="ES256", headers={"kid": "ec-key"})

    allowed = attestation_module._decode_with_key(token, key.public_key(), {"alg": "ES256"})
    denied = attestation_module._decode_with_key(token, key.public_key(), {"alg": "RS256"})

    assert isinstance(allowed, dict)
    assert isinstance(denied, attestation_module.VerificationResult)
    assert denied.verified is False


def test_decode_with_key_rejects_unsupported_key_type(monkeypatch):
    class BogusKey:
        pass

    result = attestation_module._decode_with_key("a.b.c", BogusKey(), {"alg": "RS256"})

    assert result.verified is False
    assert result.error_code is AttestationError.MALFORMED_ATTESTATION


def test_ec_jwk_is_loaded_and_verifies(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _ec_key()
    jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "ec-key", "alg": "ES256", "use": "sig"})
    token = jwt.encode(_claims(gco), key, algorithm="ES256", headers={"kid": "ec-key"})

    result = _verify(
        AttestationModel(format=AttestationFormat.JWT_SVID, value=token),
        gco,
        TrustBundle.from_mapping({"example.org": {"jwks": {"keys": [jwk]}}}),
    )

    assert result.verified is True


def test_decode_with_key_rejects_algorithm_not_allowed_for_key_type():
    rsa_result = attestation_module._decode_with_key("token", _rsa_key().public_key(), {"alg": "ES256"})
    ec_result = attestation_module._decode_with_key("token", _ec_key().public_key(), {"alg": "RS256"})
    hmac_result = attestation_module._decode_with_key("token", _rsa_key().public_key(), {"alg": "HS256"})

    for result in (rsa_result, ec_result, hmac_result):
        assert result.verified is False
        assert result.error_code is AttestationError.MALFORMED_ATTESTATION
        assert result.message == "JWS algorithm is not permitted for the trusted key type"


def test_decode_with_key_rejects_unsupported_key_type():
    result = attestation_module._decode_with_key("token", _dsa_key().public_key(), {"alg": "RS256"})

    assert result.verified is False
    assert result.error_code is AttestationError.UNTRUSTED_KEY


def test_jwt_svid_ps256_verifies_with_rsa_trust_anchor(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    key = _rsa_key()
    token = jwt.encode(_claims(gco), key, algorithm="PS256", headers={"kid": "jwt-key"})

    result = _verify(AttestationModel(format=AttestationFormat.JWT_SVID, value=token), gco, _trust_bundle_for_jwt(key))

    assert result.verified is True


def test_jwt_svid_header_alg_cannot_select_foreign_algorithm(valid_root_gco):
    gco = _with_identity(valid_root_gco)
    rsa_key = _rsa_key()
    ec_key = _ec_key()
    token = jwt.encode(_claims(gco), ec_key, algorithm="ES256", headers={"kid": "jwt-key"})

    result = _verify(AttestationModel(format=AttestationFormat.JWT_SVID, value=token), gco, _trust_bundle_for_jwt(rsa_key))

    assert result.verified is False
    assert result.error_code is AttestationError.MALFORMED_ATTESTATION
    assert result.message == "JWS algorithm is not permitted for the trusted key type"
