from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import jwt
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.verification import PolicyBuilder, VerificationError

from gco.models import AttestationFormat, AttestationModel, GCO
from gco.trust import TrustBundle, TrustDomainBundle, TrustedPublicKey
from gco.validator import canonical_gco_hash


class AttestationError(Enum):
    UNVERIFIED_SIGNATURE = "unverified_signature"
    UNTRUSTED_KEY = "untrusted_key"
    SPIFFE_ID_MISMATCH = "spiffe_id_mismatch"
    GCO_DIGEST_MISMATCH = "gco_digest_mismatch"
    EXPIRED_ATTESTATION = "expired_attestation"
    UNSUPPORTED_FORMAT = "unsupported_format"
    MALFORMED_ATTESTATION = "malformed_attestation"


@dataclass(frozen=True)
class VerificationResult:
    """Cryptographic attestation verification result."""

    verified: bool
    error_code: AttestationError | None = None
    message: str | None = None


class AttestationVerifier:
    """Verify GCO-bound JWT-SVID and X.509-SVID attestations."""

    def __init__(
        self,
        trust_bundle: TrustBundle,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._trust_bundle = trust_bundle
        self._now = now or (lambda: datetime.now(timezone.utc))

    def verify(
        self,
        attestation: AttestationModel | None,
        gco: GCO,
        *,
        now: Callable[[], datetime] | datetime | None = None,
    ) -> VerificationResult:
        check_time = _coerce_now(now, self._now)
        if attestation is None or not attestation.value:
            return _failure(AttestationError.MALFORMED_ATTESTATION, "attestation is missing")

        if attestation.format is AttestationFormat.JWT_SVID:
            return self._verify_jwt_svid(attestation.value, gco, check_time)
        if attestation.format is AttestationFormat.X509_SVID:
            return self._verify_x509_svid(attestation.value, gco, check_time)
        return _failure(AttestationError.UNSUPPORTED_FORMAT, "attestation format is not cryptographically verified")

    def _verify_jwt_svid(self, token: str, gco: GCO, now: datetime) -> VerificationResult:
        try:
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
        except Exception:  # noqa: BLE001
            return _failure(AttestationError.MALFORMED_ATTESTATION, "JWT-SVID is malformed")

        domain = _trust_domain(payload.get("sub"))
        domain_bundle = self._trust_bundle.get(domain) if domain is not None else None
        if domain_bundle is None:
            return _failure(AttestationError.UNTRUSTED_KEY, "no trust anchors for SPIFFE trust domain")

        key_result = _select_jwk(domain_bundle, header)
        if isinstance(key_result, VerificationResult):
            return key_result

        decoded = _decode_with_key(token, key_result, header)
        if isinstance(decoded, VerificationResult):
            return decoded

        return _verify_bindings(decoded, gco, now)

    def _verify_x509_svid(self, token: str, gco: GCO, now: datetime) -> VerificationResult:
        try:
            header = jwt.get_unverified_header(token)
        except Exception:  # noqa: BLE001
            return _failure(AttestationError.MALFORMED_ATTESTATION, "X.509-SVID JWS is malformed")

        chain_result = _validated_x509_chain(header, self._trust_bundle, now)
        if isinstance(chain_result, VerificationResult):
            return chain_result
        leaf = chain_result

        leaf_spiffe = _leaf_spiffe_id(leaf)
        if leaf_spiffe != gco.model_identity:
            return _failure(AttestationError.SPIFFE_ID_MISMATCH, "leaf SPIFFE URI SAN does not match GCO model identity")

        key = leaf.public_key()
        if not isinstance(key, (RSAPublicKey, EllipticCurvePublicKey)):
            return _failure(AttestationError.UNTRUSTED_KEY, "leaf key type is unsupported")

        decoded = _decode_with_key(token, key, header)
        if isinstance(decoded, VerificationResult):
            return decoded

        return _verify_bindings(decoded, gco, now, expected_sub=leaf_spiffe)


def _coerce_now(
    now: Callable[[], datetime] | datetime | None,
    default: Callable[[], datetime],
) -> datetime:
    value = now() if callable(now) else (now or default())
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _failure(error: AttestationError, message: str) -> VerificationResult:
    return VerificationResult(verified=False, error_code=error, message=message)


def _trust_domain(spiffe_id: Any) -> str | None:
    if not isinstance(spiffe_id, str) or not spiffe_id.startswith("spiffe://"):
        return None
    rest = spiffe_id.removeprefix("spiffe://")
    domain = rest.split("/", maxsplit=1)[0]
    return domain or None


def _select_jwk(domain_bundle: TrustDomainBundle, header: dict[str, Any]) -> TrustedPublicKey | VerificationResult:
    kid = header.get("kid")
    if not isinstance(kid, str):
        return _failure(AttestationError.UNTRUSTED_KEY, "JWS header does not identify a trusted key")
    key = domain_bundle.key(kid)
    if key is None:
        return _failure(AttestationError.UNTRUSTED_KEY, "JWS key id is not trusted")
    return key


RSA_ALGORITHMS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512")
EC_ALGORITHMS = ("ES256", "ES384", "ES512")


def _allowed_algorithms(key: TrustedPublicKey) -> tuple[str, ...] | None:
    if isinstance(key, RSAPublicKey):
        return RSA_ALGORITHMS
    if isinstance(key, EllipticCurvePublicKey):
        return EC_ALGORITHMS
    return None


def _decode_with_key(
    token: str,
    key: TrustedPublicKey,
    header: dict[str, Any],
) -> dict[str, Any] | VerificationResult:
    alg = header.get("alg")
    if not isinstance(alg, str) or alg.lower() == "none":
        return _failure(AttestationError.MALFORMED_ATTESTATION, "JWS algorithm is missing or unsafe")
    allowed = _allowed_algorithms(key)
    if allowed is None:
        return _failure(AttestationError.UNTRUSTED_KEY, "trusted key type is unsupported")
    if alg not in allowed:
        return _failure(AttestationError.MALFORMED_ATTESTATION, "JWS algorithm is not permitted for the trusted key type")
    try:
        payload = jwt.decode(
            token,
            key=key,
            algorithms=list(allowed),
            options={"verify_aud": False, "verify_exp": False},
        )
    except jwt.InvalidSignatureError:
        return _failure(AttestationError.UNVERIFIED_SIGNATURE, "JWS signature could not be verified")
    except Exception:  # noqa: BLE001
        return _failure(AttestationError.MALFORMED_ATTESTATION, "JWS payload is malformed")
    if not isinstance(payload, dict):
        return _failure(AttestationError.MALFORMED_ATTESTATION, "JWS payload is not a JSON object")
    return payload


def _verify_bindings(
    payload: dict[str, Any],
    gco: GCO,
    now: datetime,
    *,
    expected_sub: str | None = None,
) -> VerificationResult:
    subject = payload.get("sub")
    if subject != (expected_sub or gco.model_identity):
        return _failure(AttestationError.SPIFFE_ID_MISMATCH, "attestation subject does not match GCO model identity")
    if payload.get("gco_hash") != canonical_gco_hash(gco):
        return _failure(AttestationError.GCO_DIGEST_MISMATCH, "attestation digest does not bind this GCO")
    exp = payload.get("exp")
    if not isinstance(exp, int | float):
        return _failure(AttestationError.MALFORMED_ATTESTATION, "attestation exp claim is missing")
    if datetime.fromtimestamp(exp, timezone.utc) <= now:
        return _failure(AttestationError.EXPIRED_ATTESTATION, "attestation is expired")
    return VerificationResult(verified=True)


def _validated_x509_chain(
    header: dict[str, Any],
    trust_bundle: TrustBundle,
    now: datetime,
) -> x509.Certificate | VerificationResult:
    x5c = header.get("x5c")
    if not isinstance(x5c, list) or not x5c:
        return _failure(AttestationError.MALFORMED_ATTESTATION, "x5c header is missing")

    try:
        certs = tuple(_load_x5c_cert(cert) for cert in x5c)
    except Exception:  # noqa: BLE001
        return _failure(AttestationError.MALFORMED_ATTESTATION, "x5c certificate material is malformed")

    leaf = certs[0]
    leaf_spiffe = _leaf_spiffe_id(leaf)
    if leaf_spiffe is None:
        return _failure(AttestationError.SPIFFE_ID_MISMATCH, "leaf certificate has no SPIFFE URI SAN")
    domain = _trust_domain(leaf_spiffe)
    domain_bundle = trust_bundle.get(domain) if domain is not None else None
    if domain_bundle is None or domain_bundle.ca_store is None:
        return _failure(AttestationError.UNTRUSTED_KEY, "no CA trust anchors for SPIFFE trust domain")

    try:
        verifier = PolicyBuilder().store(domain_bundle.ca_store).time(now).build_client_verifier()
        verifier.verify(leaf, list(certs[1:]))
    except VerificationError:
        return _failure(AttestationError.UNTRUSTED_KEY, "X.509 chain does not validate to a trusted CA")
    except Exception:  # noqa: BLE001
        return _failure(AttestationError.MALFORMED_ATTESTATION, "X.509 chain is malformed")

    return leaf


def _load_x5c_cert(value: Any) -> x509.Certificate:
    if not isinstance(value, str):
        raise ValueError("x5c entry must be a base64 string")
    der = base64.b64decode(value, validate=True)
    return x509.load_der_x509_certificate(der)


def _leaf_spiffe_id(leaf: x509.Certificate) -> str | None:
    try:
        san = leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    except Exception:  # noqa: BLE001
        return None
    spiffe_uris = [uri for uri in uris if uri.startswith("spiffe://")]
    return spiffe_uris[0] if len(spiffe_uris) == 1 else None
