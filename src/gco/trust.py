from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import jwt
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509.verification import Store


TrustedPublicKey = RSAPublicKey | EllipticCurvePublicKey


class TrustBundleError(Exception):
    """Raised when trust anchor material cannot be parsed safely."""


@dataclass(frozen=True)
class TrustDomainBundle:
    """Trusted JWS keys and X.509 CA anchors for one SPIFFE trust domain."""

    jwks: Mapping[str, TrustedPublicKey]
    ca_certs: tuple[x509.Certificate, ...]
    ca_store: Store | None

    def key(self, kid: str) -> TrustedPublicKey | None:
        return self.jwks.get(kid)


@dataclass(frozen=True)
class TrustBundle:
    """Offline trust configuration keyed by SPIFFE trust domain.

    ``expected_audience`` is optional verifier metadata; when present, the
    default verifier/runtime requires matching attestation ``aud`` claims.
    """

    domains: Mapping[str, TrustDomainBundle]
    expected_audience: tuple[str, ...] | None = None

    @classmethod
    def from_mapping(cls, config: Mapping[str, Any]) -> "TrustBundle":
        try:
            domains = config.get("trust_domains")
            if domains is None:
                domains = {key: value for key, value in config.items() if key != "expected_audience"}
        except AttributeError as exc:
            raise TrustBundleError("trust bundle config must be a mapping") from exc

        parsed: dict[str, TrustDomainBundle] = {}
        for domain, material in domains.items():
            if not isinstance(domain, str) or not isinstance(material, Mapping):
                raise TrustBundleError("trust domain entries must be mappings")
            parsed[domain] = _parse_domain(material)
        return cls(domains=parsed, expected_audience=_parse_expected_audience(config.get("expected_audience")))

    @classmethod
    def from_json_file(cls, path: str | Path) -> "TrustBundle":
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            raise TrustBundleError("trust bundle config file is malformed") from exc
        return cls.from_mapping(payload)

    def get(self, trust_domain: str) -> TrustDomainBundle | None:
        return self.domains.get(trust_domain)


def _parse_domain(material: Mapping[str, Any]) -> TrustDomainBundle:
    jwks = _parse_jwks(material.get("jwks") or material.get("jwk_set") or {"keys": []})
    ca_certs = _parse_ca_certs(material.get("ca_certs") or material.get("ca_certificates") or [])
    ca_store = Store(list(ca_certs)) if ca_certs else None
    return TrustDomainBundle(jwks=jwks, ca_certs=ca_certs, ca_store=ca_store)


def _parse_expected_audience(value: Any) -> tuple[str, ...] | None:
    if value is None:
        return None
    if isinstance(value, str):
        if not value:
            raise TrustBundleError("expected_audience must not be empty")
        return (value,)
    if isinstance(value, list) and value and all(isinstance(item, str) and item for item in value):
        return tuple(value)
    raise TrustBundleError("expected_audience must be a non-empty string or list of strings")


def _parse_jwks(jwks_material: Any) -> Mapping[str, TrustedPublicKey]:
    try:
        if isinstance(jwks_material, str):
            jwks_material = json.loads(jwks_material)
        keys = jwks_material.get("keys")
    except Exception as exc:  # noqa: BLE001
        raise TrustBundleError("JWK set is malformed") from exc

    if not isinstance(keys, list):
        raise TrustBundleError("JWK set is malformed")

    parsed: dict[str, TrustedPublicKey] = {}
    for index, jwk in enumerate(keys):
        try:
            kid = jwk.get("kid") or f"key-{index}"
            key = jwt.PyJWK.from_dict(jwk).key
        except Exception as exc:  # noqa: BLE001
            raise TrustBundleError("JWK material is malformed") from exc
        if not isinstance(key, (RSAPublicKey, EllipticCurvePublicKey)):
            raise TrustBundleError("JWK material must contain an RSA or EC public key")
        parsed[str(kid)] = key
    return parsed


def _parse_ca_certs(ca_material: Any) -> tuple[x509.Certificate, ...]:
    if not isinstance(ca_material, list):
        raise TrustBundleError("CA certificate material is malformed")

    certs: list[x509.Certificate] = []
    for item in ca_material:
        try:
            data = item.encode("ascii") if isinstance(item, str) else item
            certs.append(x509.load_pem_x509_certificate(data))
        except Exception as exc:  # noqa: BLE001
            raise TrustBundleError("CA certificate material is malformed") from exc
    return tuple(certs)
