from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError
from pydantic import ValidationError as PydanticValidationError

from gco.models import AttestationFormat, AttestationModel, GCO, TaintPolicy, ToolAuthority


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "gco_schema_v1.json"


def _schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def test_json_schema_accepts_pydantic_gco_example(valid_root_gco):
    schema = _schema()
    Draft202012Validator.check_schema(schema)
    data = valid_root_gco.model_dump(mode="json")

    Draft202012Validator(schema).validate(data)

    assert GCO.model_validate(data).model_dump(mode="json") == data


@pytest.mark.parametrize("format_value", [format.value for format in AttestationFormat])
def test_json_schema_accepts_supported_attestation_formats(valid_root_gco, format_value):
    data = valid_root_gco.model_dump(mode="json")
    data["attestation"]["format"] = format_value

    Draft202012Validator(_schema()).validate(data)

    assert GCO.model_validate(data).attestation.format.value == format_value


def test_json_schema_and_model_allow_default_taint_policy(valid_root_gco):
    data = valid_root_gco.model_dump(mode="json")
    del data["state_access_permissions"][0]["taint_policy"]

    Draft202012Validator(_schema()).validate(data)

    assert GCO.model_validate(data).state_access_permissions[0].taint_policy is TaintPolicy.CLEAN


def test_model_allows_attestation_without_issuer():
    attestation = AttestationModel(format=AttestationFormat.JWT_SVID, value="token", issuer=None)

    assert attestation.issuer is None


@pytest.mark.parametrize(
    ("tool_uri", "issuer"),
    [
        ("urn:tool:search", "spiffe://example.org/issuer/gco"),
        ("spiffe://example.org/tool/search", "urn:issuer:gco"),
    ],
)
def test_json_schema_uri_fields_match_model_uri_contract(valid_root_gco, tool_uri, issuer):
    data = valid_root_gco.model_dump(mode="json")
    data["tool_authority"][0]["tool_uri"] = tool_uri
    data["attestation"]["issuer"] = issuer

    Draft202012Validator(_schema()).validate(data)
    parsed = GCO.model_validate(data)

    assert str(parsed.tool_authority[0].tool_uri) == tool_uri
    assert str(parsed.attestation.issuer) == issuer


@pytest.mark.parametrize("tool_uri", ["tools.example/search", "://tools.example/search", "urn:", "urn:bad value"])
def test_model_rejects_malformed_tool_uri(tool_uri):
    with pytest.raises(PydanticValidationError):
        ToolAuthority(tool_uri=tool_uri, scope="read", max_depth=1)


@pytest.mark.parametrize("issuer", ["issuer.example/gco", "://issuer.example/gco", "urn:", "urn:bad value"])
def test_model_rejects_malformed_attestation_issuer(issuer):
    with pytest.raises(PydanticValidationError):
        AttestationModel(format=AttestationFormat.JWT_SVID, value="token", issuer=issuer)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("attestation", "format"), "unknown"),
        (("state_access_permissions", 0, "access_mode"), "admin"),
        (("state_access_permissions", 0, "taint_policy"), "public"),
    ],
)
def test_json_schema_rejects_unknown_enums(valid_root_gco, path, value):
    data = valid_root_gco.model_dump(mode="json")
    target = data
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value

    with pytest.raises(ValidationError):
        Draft202012Validator(_schema()).validate(data)


@pytest.mark.parametrize(
    "path",
    [
        ("tool_authority", 0),
        ("state_access_permissions", 0),
        ("attestation",),
    ],
)
def test_json_schema_rejects_nested_extra_fields(valid_root_gco, path):
    data = valid_root_gco.model_dump(mode="json")
    target = data
    for key in path:
        target = target[key]
    target["unexpected"] = "extra"

    with pytest.raises(ValidationError):
        Draft202012Validator(_schema()).validate(data)
