from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from gco.trust import TrustBundle, TrustBundleError


def _private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(key, kid: str = "kid-1") -> dict:
    payload = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    payload["kid"] = kid
    payload["alg"] = "RS256"
    payload["use"] = "sig"
    return payload


def _ca_pem(key) -> str:
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def test_trust_bundle_loads_jwks_and_cas():
    key = _private_key()
    bundle = TrustBundle.from_mapping(
        {
            "example.org": {
                "jwks": {"keys": [_jwk(key)]},
                "ca_certs": [_ca_pem(key)],
            }
        }
    )

    domain = bundle.get("example.org")

    assert domain is not None
    assert domain.key("kid-1") is not None
    assert len(domain.ca_certs) == 1
    assert domain.ca_store is not None


def test_trust_bundle_loads_from_trust_domains_wrapper_and_file(tmp_path):
    key = _private_key()
    config = {
        "expected_audience": ["https://api.example/receiver"],
        "trust_domains": {"example.org": {"jwks": {"keys": [_jwk(key)]}}},
    }
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(config), encoding="utf-8")

    bundle = TrustBundle.from_json_file(path)

    assert bundle.get("example.org").key("kid-1") is not None
    assert bundle.expected_audience == ("https://api.example/receiver",)


def test_empty_and_unknown_domain_are_controlled_misses():
    bundle = TrustBundle.from_mapping({})

    assert bundle.get("missing.example") is None


def test_trust_bundle_flat_mapping_ignores_expected_audience_metadata():
    key = _private_key()
    bundle = TrustBundle.from_mapping(
        {
            "expected_audience": "https://api.example/receiver",
            "example.org": {"jwks": {"keys": [_jwk(key)]}},
        }
    )

    assert bundle.get("example.org").key("kid-1") is not None
    assert bundle.expected_audience == ("https://api.example/receiver",)


@pytest.mark.parametrize("expected_audience", ["", [], ["ok", ""], [123], {"aud": "x"}])
def test_trust_bundle_rejects_malformed_expected_audience(expected_audience):
    with pytest.raises(TrustBundleError):
        TrustBundle.from_mapping({"expected_audience": expected_audience})


def test_non_mapping_config_raises_trust_bundle_error():
    with pytest.raises(TrustBundleError):
        TrustBundle.from_mapping(None)  # type: ignore[arg-type]


def test_non_mapping_domain_entry_raises_trust_bundle_error():
    with pytest.raises(TrustBundleError):
        TrustBundle.from_mapping({"example.org": []})


def test_bad_config_file_raises_trust_bundle_error(tmp_path):
    path = tmp_path / "bundle.json"
    path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(TrustBundleError):
        TrustBundle.from_json_file(path)


def test_malformed_jwk_raises_trust_bundle_error():
    with pytest.raises(TrustBundleError):
        TrustBundle.from_mapping({"example.org": {"jwks": {"keys": [{"kty": "RSA", "n": "bad"}]}}})


def test_jwk_without_kid_gets_stable_fallback():
    key = _private_key()
    jwk = _jwk(key)
    jwk.pop("kid")
    bundle = TrustBundle.from_mapping({"example.org": {"jwks": {"keys": [jwk]}}})

    assert bundle.get("example.org").key("key-0") is not None


def test_jwk_set_without_keys_raises_trust_bundle_error():
    with pytest.raises(TrustBundleError):
        TrustBundle.from_mapping({"example.org": {"jwks": {"not_keys": []}}})


def test_symmetric_jwk_raises_trust_bundle_error():
    with pytest.raises(TrustBundleError):
        TrustBundle.from_mapping({"example.org": {"jwks": {"keys": [{"kty": "oct", "k": "MTIzNA"}]}}})


def test_malformed_jwk_json_raises_trust_bundle_error():
    with pytest.raises(TrustBundleError):
        TrustBundle.from_mapping({"example.org": {"jwks": "{not-json"}})


def test_malformed_pem_raises_trust_bundle_error():
    with pytest.raises(TrustBundleError):
        TrustBundle.from_mapping({"example.org": {"ca_certs": ["not a certificate"]}})


def test_ca_cert_bytes_and_bad_ca_container():
    key = _private_key()
    pem = _ca_pem(key).encode("ascii")
    bundle = TrustBundle.from_mapping({"example.org": {"ca_certs": [pem]}})

    assert len(bundle.get("example.org").ca_certs) == 1

    with pytest.raises(TrustBundleError):
        TrustBundle.from_mapping({"example.org": {"ca_certs": "not-a-list"}})
