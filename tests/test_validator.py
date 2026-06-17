from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from gco.models import (
    AccessMode,
    AttestationFormat,
    AttestationModel,
    GCO,
    StatePermission,
    TaintPolicy,
    ToolAuthority,
)
from gco.validator import DerivationError, GCODerivationException, GCOValidator, canonical_gco_hash
from conftest import BASE_TIME, make_child_gco, make_root_gco


def _replace_tool(child: GCO, index: int, **updates) -> GCO:
    tools = list(child.tool_authority)
    tools[index] = tools[index].model_copy(update=updates)
    return child.model_copy(update={"tool_authority": tools})


def _replace_permission(child: GCO, namespace: str, **updates) -> GCO:
    permissions = [
        permission.model_copy(update=updates) if permission.namespace == namespace else permission
        for permission in child.state_access_permissions
    ]
    return child.model_copy(update={"state_access_permissions": permissions})


def test_valid_child_gco_passes(valid_root_gco, valid_child_gco):
    assert GCOValidator().validate(valid_root_gco, valid_child_gco(valid_root_gco)) is True


@pytest.mark.parametrize(
    ("error", "mutation"),
    [
        (DerivationError.VERSION_MISMATCH, lambda child: child.model_copy(update={"gco_version": "2.0.0"})),
        (
            DerivationError.TRACE_ID_CHANGED,
            lambda child: child.model_copy(update={"trace_id": UUID("44444444-4444-4444-8444-444444444444")}),
        ),
        (DerivationError.POLICY_ID_CHANGED, lambda child: child.model_copy(update={"policy_id": "changed"})),
        (
            DerivationError.MODEL_IDENTITY_CHANGED,
            lambda child: child.model_copy(update={"model_identity": "changed"}),
        ),
        (
            DerivationError.INTERVENTION_CHANGED,
            lambda child: child.model_copy(update={"intervention_version": "changed"}),
        ),
        (
            DerivationError.PARENT_LINKAGE_INVALID,
            lambda child: child.model_copy(
                update={"parent_span_id": UUID("55555555-5555-4555-8555-555555555555")}
            ),
        ),
        (DerivationError.LINEAGE_APPEND_FAILED, lambda child: child.model_copy(update={"lineage": []})),
        (
            DerivationError.LINEAGE_FLOODED,
            lambda child: child.model_copy(update={"lineage": ["0" * 64 for _ in range(129)]}),
        ),
        (DerivationError.MAX_DEPTH_INCREASED, lambda child: _replace_tool(child, 0, max_depth=2)),
        (
            DerivationError.TOOL_AUTHORITY_EXPANDED,
            lambda child: child.model_copy(
                update={
                    "tool_authority": [
                        *child.tool_authority,
                        ToolAuthority(tool_uri="https://tools.example/new", scope="read", max_depth=0),
                    ]
                }
            ),
        ),
        (
            DerivationError.STATE_PERMISSION_EXPANDED,
            lambda child: _replace_permission(child, "scratch", access_mode=AccessMode.WRITE),
        ),
        (
            DerivationError.TAINT_DOWNGRADED,
            lambda child: _replace_permission(child, "scratch", taint_policy=TaintPolicy.CLEAN),
        ),
        (
            DerivationError.EXPIRY_EXTENDED,
            lambda child: child.model_copy(update={"expires_at": child.expires_at + timedelta(seconds=1)}),
        ),
        (
            DerivationError.EXPIRED,
            lambda child: child.model_copy(update={"expires_at": datetime(2000, 1, 1, tzinfo=timezone.utc)}),
        ),
        (DerivationError.ATTESTATION_MISSING, lambda child: child.model_copy(update={"attestation": None})),
        (
            DerivationError.ATTESTATION_FORMAT_INVALID,
            lambda child: {
                **child.model_dump(mode="json"),
                "attestation": {"format": "raw", "value": "token"},
            },
        ),
        (
            DerivationError.CANONICAL_HASH_MISMATCH,
            lambda child: child.model_copy(update={"lineage": ["f" * 64]}),
        ),
    ],
)
def test_derivation_error_paths(valid_root_gco, invalid_gco_factory, error, mutation):
    child = invalid_gco_factory(valid_root_gco, mutation)
    validator = GCOValidator(now=lambda: BASE_TIME - timedelta(days=1))

    with pytest.raises(GCODerivationException) as exc_info:
        validator.validate(valid_root_gco, child)

    assert exc_info.value.error is error
    assert str(exc_info.value) == error.value


def test_lineage_prefix_mismatch_raises_append_failed(valid_child_gco):
    parent = make_root_gco(lineage=["prior"])
    child = valid_child_gco(parent).model_copy(update={"lineage": ["wrong", canonical_gco_hash(parent)]})

    with pytest.raises(GCODerivationException) as exc_info:
        GCOValidator().validate(parent, child)

    assert exc_info.value.error is DerivationError.LINEAGE_APPEND_FAILED


def test_parent_depth_zero_rejects_child_tool():
    parent = make_root_gco(
        tool_authority=[ToolAuthority(tool_uri="https://tools.example/search", scope="read", max_depth=0)]
    )
    child = make_child_gco(
        parent,
        tool_authority=[ToolAuthority(tool_uri="https://tools.example/search", scope="read", max_depth=0)],
    )

    with pytest.raises(GCODerivationException) as exc_info:
        GCOValidator().validate(parent, child)

    assert exc_info.value.error is DerivationError.MAX_DEPTH_INCREASED


def test_scope_expansion_rejected(valid_root_gco, valid_child_gco):
    child = _replace_tool(valid_child_gco(valid_root_gco), 0, scope="read admin")

    with pytest.raises(GCODerivationException) as exc_info:
        GCOValidator().validate(valid_root_gco, child)

    assert exc_info.value.error is DerivationError.TOOL_AUTHORITY_EXPANDED


def test_missing_state_namespace_rejected(valid_root_gco, valid_child_gco):
    child = valid_child_gco(valid_root_gco)
    permissions = [
        *child.state_access_permissions,
        StatePermission(namespace="new", access_mode=AccessMode.NONE),
    ]
    child = child.model_copy(update={"state_access_permissions": permissions})

    with pytest.raises(GCODerivationException) as exc_info:
        GCOValidator().validate(valid_root_gco, child)

    assert exc_info.value.error is DerivationError.STATE_PERMISSION_EXPANDED


def test_empty_attestation_value_is_missing(valid_root_gco, valid_child_gco):
    child = valid_child_gco(valid_root_gco).model_copy(
        update={"attestation": AttestationModel(format=AttestationFormat.JWT_SVID, value="")}
    )

    with pytest.raises(GCODerivationException) as exc_info:
        GCOValidator().validate(valid_root_gco, child)

    assert exc_info.value.error is DerivationError.ATTESTATION_MISSING


def test_validator_allows_omitted_delegations(valid_root_gco, valid_child_gco):
    child = valid_child_gco(valid_root_gco).model_copy(
        update={"tool_authority": [], "state_access_permissions": []}
    )

    assert GCOValidator().validate(valid_root_gco, child) is True


def test_root_validation_accepts_root_gco(valid_root_gco):
    assert GCOValidator(now=lambda: BASE_TIME - timedelta(days=1)).validate_root(valid_root_gco) is True


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        (lambda root: root.model_copy(update={"parent_span_id": UUID("66666666-6666-4666-8666-666666666666")}), DerivationError.PARENT_LINKAGE_INVALID),
        (lambda root: root.model_copy(update={"lineage": ["prior"]}), DerivationError.LINEAGE_APPEND_FAILED),
    ],
)
def test_root_validation_rejects_non_root_shape(valid_root_gco, mutation, error):
    with pytest.raises(GCODerivationException) as exc_info:
        GCOValidator(now=lambda: BASE_TIME - timedelta(days=1)).validate_root(mutation(valid_root_gco))

    assert exc_info.value.error is error


def test_unknown_access_rank_fails_closed(valid_root_gco, valid_child_gco):
    child = valid_child_gco(valid_root_gco)
    permissions = [
        StatePermission.model_construct(
            namespace="scratch",
            access_mode="admin",
            taint_policy=TaintPolicy.SANITIZED,
        )
    ]
    child = child.model_copy(update={"state_access_permissions": permissions})

    with pytest.raises(GCODerivationException) as exc_info:
        GCOValidator(now=lambda: BASE_TIME - timedelta(days=1)).validate(valid_root_gco, child)

    assert exc_info.value.error is DerivationError.STATE_PERMISSION_EXPANDED


def test_unknown_taint_rank_fails_closed(valid_root_gco, valid_child_gco):
    child = valid_child_gco(valid_root_gco)
    permissions = [
        StatePermission.model_construct(
            namespace="scratch",
            access_mode=AccessMode.READ,
            taint_policy="public",
        )
    ]
    child = child.model_copy(update={"state_access_permissions": permissions})

    with pytest.raises(GCODerivationException) as exc_info:
        GCOValidator(now=lambda: BASE_TIME - timedelta(days=1)).validate(valid_root_gco, child)

    assert exc_info.value.error is DerivationError.TAINT_DOWNGRADED


def test_canonical_hash_excludes_attestation(valid_root_gco):
    changed_attestation = valid_root_gco.model_copy(
        update={"attestation": AttestationModel(format=AttestationFormat.X509_SVID, value="x")}
    )

    assert canonical_gco_hash(valid_root_gco) == canonical_gco_hash(changed_attestation)


def test_validate_result_returns_error_code(valid_root_gco, valid_child_gco):
    child = valid_child_gco(valid_root_gco).model_copy(update={"gco_version": "2.0.0"})

    result = GCOValidator().validate_result(valid_root_gco, child)

    assert result.valid is False
    assert result.error_code is DerivationError.VERSION_MISMATCH
    assert result.message == DerivationError.VERSION_MISMATCH.value


def test_validate_result_returns_valid(valid_root_gco, valid_child_gco):
    assert GCOValidator().validate_result(valid_root_gco, valid_child_gco(valid_root_gco)).valid is True


@pytest.mark.parametrize(
    "mutate_child",
    [
        lambda child: {**child, "trace_id": "not-a-uuid"},
        lambda child: {**child, "tool_authority": {"tool_uri": "https://tools.example/search"}},
        lambda child: {
            **child,
            "tool_authority": [{**child["tool_authority"][0], "max_depth": None}],
        },
        lambda child: {key: value for key, value in child.items() if key != "expires_at"},
        lambda child: None,
    ],
)
def test_validate_result_returns_malformed_for_bad_raw_input(valid_root_gco, valid_child_gco, mutate_child):
    child = valid_child_gco(valid_root_gco).model_dump(mode="json")

    result = GCOValidator().validate_result(valid_root_gco.model_dump(mode="json"), mutate_child(child))

    assert result.valid is False
    assert result.error_code is DerivationError.GCO_MALFORMED
    assert result.message


def test_validate_result_preserves_attestation_format_error(valid_root_gco, valid_child_gco):
    child = valid_child_gco(valid_root_gco).model_dump(mode="json")
    child["attestation"]["format"] = "raw"

    result = GCOValidator().validate_result(valid_root_gco.model_dump(mode="json"), child)

    assert result.valid is False
    assert result.error_code is DerivationError.ATTESTATION_FORMAT_INVALID
    assert result.message == DerivationError.ATTESTATION_FORMAT_INVALID.value


def test_raw_payload_non_attestation_shape_error_remains_pydantic(valid_root_gco, valid_child_gco):
    child = valid_child_gco(valid_root_gco).model_dump(mode="json")
    child["tool_authority"] = {"tool_uri": "https://tools.example/search"}

    with pytest.raises(ValidationError):
        GCOValidator().validate(valid_root_gco, child)


def test_gco_rejects_non_utc_expiry(valid_root_gco):
    data = valid_root_gco.model_dump()
    data["expires_at"] = datetime(2031, 1, 1, 7, 0, tzinfo=timezone(timedelta(hours=-5)))

    with pytest.raises(ValidationError):
        GCO(**data)


def test_gco_rejects_extra_fields(valid_root_gco):
    data = valid_root_gco.model_dump()
    data["extra"] = "nope"

    with pytest.raises(ValidationError):
        GCO(**data)


def test_fixture_child_uses_base_time(valid_root_gco, valid_child_gco):
    assert valid_child_gco(valid_root_gco).expires_at == BASE_TIME
