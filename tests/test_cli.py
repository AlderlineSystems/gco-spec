from __future__ import annotations

import json
import sys
import tomllib
from datetime import timedelta
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from conftest import BASE_TIME, make_child_gco, make_root_gco
from gco import cli
from gco.attestation import VerificationResult
from gco.derivation import DelegationRequest
from gco.models import AccessMode, AttestationFormat, AttestationModel, GCO, StatePermission, ToolAuthority
from gco.validator import DerivationError, GCODerivationException, canonical_gco_hash


SPIFFE_ID = "spiffe://example.org/ns/default/sa/model-alpha"


@pytest.fixture
def cli_files(tmp_path: Path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kid = "gco-cli"
    parent = _with_identity(make_root_gco()).model_copy(update={"expires_at": BASE_TIME + timedelta(hours=1)})
    child = make_child_gco(parent)
    signed_parent = _sign(parent, key, kid=kid)
    signed_child = _sign(child, key, kid=kid)
    request = DelegationRequest(
        tool_authority=[ToolAuthority(tool_uri="https://tools.example/search", scope="read", max_depth=1)],
        state_access_permissions=[StatePermission(namespace="memory", access_mode=AccessMode.READ)],
        requested_expiry=BASE_TIME + timedelta(minutes=30),
    )

    paths = {
        "parent": _write_json(tmp_path / "parent.json", signed_parent.model_dump(mode="json")),
        "child": _write_json(tmp_path / "child.json", signed_child.model_dump(mode="json")),
        "request": _write_json(tmp_path / "request.json", request.model_dump(mode="json")),
        "bundle": _write_json(tmp_path / "bundle.json", _trust_bundle_json(key, kid=kid)),
        "key": tmp_path / "signing-key.pem",
        "bad_json": tmp_path / "bad.json",
    }
    paths["key"].write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    paths["bad_json"].write_text("{", encoding="utf-8")
    return paths


def test_console_script_is_registered():
    pyproject = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8"))

    assert pyproject["project"]["scripts"]["gco"] == "gco.cli:main"


def test_validate_allows_tightened_child(cli_files, capsys):
    status = cli.main(["--json", "validate", str(cli_files["child"]), "--parent", str(cli_files["parent"])])

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output == {"ok": True, "decision": "allow"}


def test_validate_denies_expanded_child(cli_files, tmp_path, capsys):
    child = GCO.model_validate(json.loads(cli_files["child"].read_text(encoding="utf-8")))
    expanded = child.model_copy(
        update={"tool_authority": [ToolAuthority(tool_uri="https://tools.example/search", scope="read write admin", max_depth=1)]}
    )
    expanded_path = _write_json(tmp_path / "expanded.json", expanded.model_dump(mode="json"))

    status = cli.main(["validate", str(expanded_path), "--parent", str(cli_files["parent"])])

    captured = capsys.readouterr()
    assert status == 1
    assert "deny: TOOL_AUTHORITY_EXPANDED" in captured.err


def test_validate_reports_malformed_json_as_json(cli_files, capsys):
    status = cli.main(["--json", "validate", str(cli_files["bad_json"]), "--parent", str(cli_files["parent"])])

    output = json.loads(capsys.readouterr().out)
    assert status == 1
    assert output["error_code"] == "JSON_MALFORMED"


def test_verify_reports_all_checks_on_success(cli_files, capsys):
    status = cli.main(["--json", "verify", str(cli_files["parent"]), "--trust-bundle", str(cli_files["bundle"])])

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["verified"] is True
    assert output["checks"] == {"digest": "pass", "expiry": "pass", "identity": "pass", "signature": "pass"}


def test_verify_reports_digest_failure(cli_files, tmp_path, capsys):
    gco = GCO.model_validate(json.loads(cli_files["parent"].read_text(encoding="utf-8")))
    tampered = gco.model_copy(update={"policy_id": "policy:tampered"})
    tampered_path = _write_json(tmp_path / "tampered.json", tampered.model_dump(mode="json"))

    status = cli.main(["--json", "verify", str(tampered_path), "--trust-bundle", str(cli_files["bundle"])])

    output = json.loads(capsys.readouterr().out)
    assert status == 1
    assert output["error_code"] == "GCO_DIGEST_MISMATCH"
    assert output["checks"]["digest"] == "fail"


def test_verify_reports_unknown_checks_for_unsupported_attestation_format(cli_files, tmp_path, capsys):
    gco = GCO.model_validate(json.loads(cli_files["parent"].read_text(encoding="utf-8")))
    unsupported = gco.model_copy(update={"attestation": AttestationModel(format=AttestationFormat.RAW_JWS, value="token")})
    unsupported_path = _write_json(tmp_path / "unsupported.json", unsupported.model_dump(mode="json"))

    status = cli.main(["--json", "verify", str(unsupported_path), "--trust-bundle", str(cli_files["bundle"])])

    output = json.loads(capsys.readouterr().out)
    assert status == 1
    assert output["error_code"] == "UNSUPPORTED_FORMAT"
    assert output["checks"] == {"digest": "unknown", "expiry": "unknown", "identity": "unknown", "signature": "unknown"}


def test_verify_denies_malformed_trust_bundle(cli_files, tmp_path, capsys):
    bad_bundle = _write_json(tmp_path / "bad-bundle.json", {"trust_domains": []})

    status = cli.main(["verify", str(cli_files["parent"]), "--trust-bundle", str(bad_bundle)])

    captured = capsys.readouterr()
    assert status == 1
    assert "TRUST_BUNDLE_MALFORMED" in captured.err


def test_inspect_outputs_human_authority_dump(cli_files, capsys):
    status = cli.main(["inspect", str(cli_files["parent"])])

    captured = capsys.readouterr()
    assert status == 0
    assert "identity: spiffe://example.org/ns/default/sa/model-alpha" in captured.out
    assert "tool authority:" in captured.out
    assert "attestation format: jwt-svid" in captured.out


def test_inspect_outputs_json(cli_files, capsys):
    status = cli.main(["--json", "inspect", str(cli_files["parent"])])

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["identity"]["model_identity"] == SPIFFE_ID
    assert output["ok"] is True


def test_inspect_denies_malformed_gco_json(cli_files, tmp_path, capsys):
    malformed = _write_json(tmp_path / "malformed-gco.json", {"gco_version": "1.0"})

    status = cli.main(["--json", "inspect", str(malformed)])

    output = json.loads(capsys.readouterr().out)
    assert status == 1
    assert output["error_code"] == "GCO_MALFORMED"


def test_derive_with_signing_key_outputs_verified_child(cli_files, capsys):
    status = cli.main(
        [
            "--json",
            "derive",
            str(cli_files["parent"]),
            "--request",
            str(cli_files["request"]),
            "--trust-bundle",
            str(cli_files["bundle"]),
            "--sign-key",
            str(cli_files["key"]),
        ]
    )

    output = json.loads(capsys.readouterr().out)
    child = GCO.model_validate(output["child"])
    assert status == 0
    assert output["preview_only"] is False
    assert child.parent_span_id == GCO.model_validate(json.loads(cli_files["parent"].read_text(encoding="utf-8"))).span_id


def test_derive_with_signing_key_denies_invalid_request(cli_files, tmp_path, capsys):
    invalid_request = DelegationRequest(
        tool_authority=[ToolAuthority(tool_uri="https://tools.example/search", scope="admin", max_depth=1)],
        requested_expiry=BASE_TIME + timedelta(minutes=30),
    )
    invalid_path = _write_json(tmp_path / "invalid-request.json", invalid_request.model_dump(mode="json"))

    status = cli.main(
        [
            "--json",
            "derive",
            str(cli_files["parent"]),
            "--request",
            str(invalid_path),
            "--trust-bundle",
            str(cli_files["bundle"]),
            "--sign-key",
            str(cli_files["key"]),
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert status == 1
    assert output["error_code"] == "TOOL_AUTHORITY_EXPANDED"


def test_derive_without_signing_key_outputs_preview_only_child(cli_files, capsys):
    status = cli.main(
        [
            "--json",
            "derive",
            str(cli_files["parent"]),
            "--request",
            str(cli_files["request"]),
            "--trust-bundle",
            str(cli_files["bundle"]),
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["preview_only"] is True
    assert output["warning"] == "unsigned derivation is preview-only"
    assert output["child"]["attestation"]["value"].startswith("preview-unsigned:")


def test_derive_without_signing_key_denies_invalid_request(cli_files, tmp_path, capsys):
    invalid_request = _write_json(
        tmp_path / "invalid-preview-request.json",
        {
            "tool_authority": [],
            "state_access_permissions": [
                {"namespace": "scratch", "access_mode": "read", "taint_policy": "clean"},
            ],
            "requested_expiry": (BASE_TIME + timedelta(minutes=30)).isoformat(),
        },
    )

    status = cli.main(
        [
            "--json",
            "derive",
            str(cli_files["parent"]),
            "--request",
            str(invalid_request),
            "--trust-bundle",
            str(cli_files["bundle"]),
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert status == 1
    assert output["error_code"] == "TAINT_DOWNGRADED"


def test_derive_denies_malformed_request(cli_files, tmp_path, capsys):
    malformed_request = _write_json(tmp_path / "malformed-request.json", {"requested_expiry": "not-a-date"})

    status = cli.main(
        [
            "--json",
            "derive",
            str(cli_files["parent"]),
            "--request",
            str(malformed_request),
            "--trust-bundle",
            str(cli_files["bundle"]),
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert status == 1
    assert output["error_code"] == "GCO_MALFORMED"


def test_derive_denies_unverified_parent(cli_files, tmp_path, capsys):
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong_bundle = _write_json(tmp_path / "wrong-bundle.json", _trust_bundle_json(wrong_key))

    status = cli.main(
        [
            "--json",
            "derive",
            str(cli_files["parent"]),
            "--request",
            str(cli_files["request"]),
            "--trust-bundle",
            str(wrong_bundle),
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert status == 1
    assert output["error_code"] == "UNVERIFIED_SIGNATURE"


def test_derive_rejects_malformed_sign_key(cli_files, tmp_path, capsys):
    bad_key = tmp_path / "bad-key.pem"
    bad_key.write_text("not a pem", encoding="utf-8")

    status = cli.main(
        [
            "--json",
            "derive",
            str(cli_files["parent"]),
            "--request",
            str(cli_files["request"]),
            "--trust-bundle",
            str(cli_files["bundle"]),
            "--sign-key",
            str(bad_key),
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert status == 1
    assert output["error_code"] == "SIGN_KEY_MALFORMED"


def test_schema_prints_path_and_content(capsys):
    status = cli.main(["--json", "schema"])

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["path"].endswith("schemas/gco_schema_v1.json")
    assert output["schema"]["$id"] == "https://alderlinesystems.com/schemas/gco_schema_v1.json"


def test_schema_path_falls_back_to_sys_prefix(tmp_path, monkeypatch):
    fake_module = tmp_path / "fake" / "src" / "gco" / "cli.py"
    fake_schema = tmp_path / "prefix" / "schemas" / "gco_schema_v1.json"
    fake_schema.parent.mkdir(parents=True)
    fake_schema.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(cli, "__file__", str(fake_module))
    monkeypatch.setattr(sys, "prefix", str(tmp_path / "prefix"))

    assert cli._schema_path() == fake_schema


def test_schema_path_missing_has_stable_error(tmp_path, monkeypatch):
    fake_module = tmp_path / "fake" / "src" / "gco" / "cli.py"
    monkeypatch.setattr(cli, "__file__", str(fake_module))
    monkeypatch.setattr(sys, "prefix", str(tmp_path / "prefix"))

    with pytest.raises(cli.CLIError) as exc_info:
        cli._schema_path()

    assert exc_info.value.code == "SCHEMA_NOT_FOUND"


def test_usage_error_has_stable_code(capsys):
    status = cli.main([])

    captured = capsys.readouterr()
    assert status == 2
    assert "USAGE_ERROR" in captured.err


def test_unexpected_cli_error_fails_closed(monkeypatch, capsys):
    class Parser:
        def parse_args(self, argv):
            raise RuntimeError("boom")

    monkeypatch.setattr(cli, "_build_parser", Parser)

    status = cli.main(["--json", "schema"])

    output = json.loads(capsys.readouterr().out)
    assert status == 1
    assert output == {"error_code": "GCO_CLI_ERROR", "message": "boom", "ok": False}


def test_helper_codes_cover_public_shapes():
    assert cli._code(cli.CLIError) == "CLIError"
    assert cli._code(None) == "UNKNOWN"
    assert cli._code("CUSTOM") == "CUSTOM"
    assert cli._exception_code(RuntimeError("boom")) == "GCO_MALFORMED"
    assert cli._exception_code(GCODerivationException(DerivationError.EXPIRED)) == "EXPIRED"
    assert cli._verification_checks(VerificationResult(verified=False)) == {
        "digest": "unknown",
        "expiry": "unknown",
        "identity": "unknown",
        "signature": "unknown",
    }


def test_format_inspection_handles_no_taint_or_attestation(valid_root_gco):
    gco = valid_root_gco.model_copy(update={"state_access_permissions": [], "attestation": None})
    payload = cli._inspection_payload(gco)

    formatted = cli._format_inspection(payload)
    assert payload["attestation_format"] is None
    assert "taint policy: none" in formatted


def _with_identity(gco: GCO) -> GCO:
    return gco.model_copy(update={"model_identity": SPIFFE_ID})


def _sign(gco: GCO, private_key, *, kid: str) -> GCO:
    payload = {
        "sub": gco.model_identity,
        "gco_hash": canonical_gco_hash(gco),
        "exp": int(gco.expires_at.timestamp()),
    }
    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})
    attestation = AttestationModel(format=AttestationFormat.JWT_SVID, value=token)
    return gco.model_copy(update={"attestation": attestation})


def _trust_bundle_json(private_key, *, kid: str = "gco-cli") -> dict:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return {"example.org": {"jwks": {"keys": [jwk]}}}


def _write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path
