from __future__ import annotations

import base64
import math
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol

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
    AUDIENCE_MISMATCH = "audience_mismatch"
    JTI_MISSING = "jti_missing"
    REPLAY_DETECTED = "replay_detected"
    UNSUPPORTED_FORMAT = "unsupported_format"
    MALFORMED_ATTESTATION = "malformed_attestation"


@dataclass(frozen=True)
class VerificationResult:
    """Cryptographic attestation verification result."""

    verified: bool
    error_code: AttestationError | None = None
    message: str | None = None


class ReplayCache(Protocol):
    """Replay cache contract for atomically accepting a jti once until expiry.

    Horizontally scaled hosts should provide a shared or state-synchronized
    implementation, or use short attestation TTLs to bound cross-instance replay
    exposure when only per-instance caches are available.
    """

    def check_and_record(self, jti: str, expires_at: datetime, now: datetime) -> bool:
        """Return True only when ``jti`` was not already recorded and is now stored."""
        ...


class InMemoryReplayCache:
    """Bounded in-process replay cache.

    This protects only one Python process. Multi-instance deployments should
    provide a shared ``ReplayCache`` implementation with the same atomic
    check-and-record semantics, or keep attestation TTLs short enough to bound
    the cross-instance replay window.
    """

    def __init__(self, max_entries: int = 10000) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        self._max_entries = max_entries
        self._entries: dict[str, datetime] = {}
        self._lock = threading.Lock()

    def check_and_record(self, jti: str, expires_at: datetime, now: datetime) -> bool:
        with self._lock:
            self._evict_expired(now)
            if jti in self._entries:
                return False
            if len(self._entries) >= self._max_entries:
                self._evict_oldest()
            self._entries[jti] = expires_at
            return True

    def _evict_expired(self, now: datetime) -> None:
        for jti, expires_at in tuple(self._entries.items()):
            if expires_at <= now:
                del self._entries[jti]

    def _evict_oldest(self) -> None:
        if not self._entries:
            return
        oldest = min(self._entries, key=self._entries.__getitem__)
        del self._entries[oldest]


class AttestationVerifier:
    """Verify GCO-bound JWT-SVID and X.509-SVID attestations."""

    def __init__(
        self,
        trust_bundle: TrustBundle,
        now: Callable[[], datetime] | None = None,
        expected_audience: str | tuple[str, ...] | None = None,
        replay_cache: ReplayCache | None = None,
    ) -> None:
        self._trust_bundle = trust_bundle
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._expected_audience = _coerce_expected_audience(expected_audience) or trust_bundle.expected_audience
        self._replay_cache = replay_cache

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
            payload = jwt.decode(
                token,
                options={
                    "verify_signature": False,
                    "verify_aud": False,
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                },
            )
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

        return _verify_bindings(
            decoded,
            gco,
            now,
            expected_audience=self._expected_audience,
            replay_cache=self._replay_cache,
        )

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

        return _verify_bindings(
            decoded,
            gco,
            now,
            expected_sub=leaf_spiffe,
            expected_audience=self._expected_audience,
            replay_cache=self._replay_cache,
        )


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


def _coerce_expected_audience(value: str | tuple[str, ...] | None) -> tuple[str, ...] | None:
    if value is None:
        return None
    if isinstance(value, str):
        return (value,)
    return tuple(value)


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
            options={
                "verify_aud": False,
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
            },
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
    expected_audience: tuple[str, ...] | None = None,
    replay_cache: ReplayCache | None = None,
) -> VerificationResult:
    subject = payload.get("sub")
    if subject != (expected_sub or gco.model_identity):
        return _failure(AttestationError.SPIFFE_ID_MISMATCH, "attestation subject does not match GCO model identity")
    if payload.get("gco_hash") != canonical_gco_hash(gco):
        return _failure(AttestationError.GCO_DIGEST_MISMATCH, "attestation digest does not bind this GCO")
    if expected_audience is not None:
        audience_result = _verify_audience(payload.get("aud"), expected_audience)
        if audience_result is not None:
            return audience_result
    exp = payload.get("exp")
    if not isinstance(exp, int | float):
        return _failure(AttestationError.MALFORMED_ATTESTATION, "attestation exp claim is missing")
    exp_time = _numeric_date(exp)
    if exp_time is None:
        return _failure(AttestationError.MALFORMED_ATTESTATION, "attestation exp claim is malformed")
    if exp_time <= now:
        return _failure(AttestationError.EXPIRED_ATTESTATION, "attestation is expired")
    nbf = payload.get("nbf")
    if nbf is not None:
        if not isinstance(nbf, int | float):
            return _failure(AttestationError.MALFORMED_ATTESTATION, "attestation nbf claim is malformed")
        nbf_time = _numeric_date(nbf)
        if nbf_time is None:
            return _failure(AttestationError.MALFORMED_ATTESTATION, "attestation nbf claim is malformed")
        if nbf_time > now:
            return _failure(AttestationError.MALFORMED_ATTESTATION, "attestation is not yet valid")
    iat = payload.get("iat")
    if iat is not None:
        if not isinstance(iat, int | float):
            return _failure(AttestationError.MALFORMED_ATTESTATION, "attestation iat claim is malformed")
        iat_time = _numeric_date(iat)
        if iat_time is None:
            return _failure(AttestationError.MALFORMED_ATTESTATION, "attestation iat claim is malformed")
        if iat_time > now:
            return _failure(AttestationError.MALFORMED_ATTESTATION, "attestation was issued in the future")
    if replay_cache is not None:
        replay_result = _verify_replay(payload.get("jti"), exp_time, now, replay_cache)
        if replay_result is not None:
            return replay_result
    return VerificationResult(verified=True)


def _verify_audience(audience: Any, expected_audience: tuple[str, ...]) -> VerificationResult | None:
    if isinstance(audience, str):
        actual = (audience,)
    elif isinstance(audience, list) and all(isinstance(item, str) for item in audience):
        actual = tuple(audience)
    else:
        return _failure(AttestationError.AUDIENCE_MISMATCH, "attestation audience is missing or malformed")
    if set(actual).isdisjoint(expected_audience):
        return _failure(AttestationError.AUDIENCE_MISMATCH, "attestation audience does not match verifier audience")
    return None


def _verify_replay(jti: Any, exp_time: datetime, now: datetime, replay_cache: ReplayCache) -> VerificationResult | None:
    if not isinstance(jti, str) or not jti:
        return _failure(AttestationError.JTI_MISSING, "attestation jti claim is required when replay protection is enabled")
    if not replay_cache.check_and_record(jti, exp_time, now):
        return _failure(AttestationError.REPLAY_DETECTED, "attestation jti has already been seen")
    return None


def _numeric_date(value: int | float) -> datetime | None:
    if not math.isfinite(value):
        return None
    try:
        return datetime.fromtimestamp(value, timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


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
