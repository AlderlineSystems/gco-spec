from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from gco.derivation import DelegationRequest, GCODerivationRuntime
from gco.models import AccessMode, AttestationFormat, AttestationModel, StatePermission, TaintPolicy, ToolAuthority
from gco.validator import DerivationError, GCODerivationException, GCOValidator, IMMUTABLE_PARENT_FIELDS
from conftest import BASE_TIME, make_root_gco


class MockAttestationAuthority:
    def __init__(self) -> None:
        self.calls = []

    def issue(self, identity: str, gco_data: dict) -> AttestationModel:
        self.calls.append((identity, gco_data))
        return AttestationModel(format=AttestationFormat.JWT_SVID, value="issued-token")


class EmptyAttestationAuthority:
    def issue(self, identity: str, gco_data: dict) -> AttestationModel:
        return AttestationModel(format=AttestationFormat.JWT_SVID, value="")


def _request(
    *,
    tools: list[ToolAuthority] | None = None,
    permissions: list[StatePermission] | None = None,
    expiry_offset: timedelta = -timedelta(hours=1),
    identity: str | None = None,
) -> DelegationRequest:
    return DelegationRequest(
        tool_authority=[] if tools is None else tools,
        state_access_permissions=[] if permissions is None else permissions,
        requested_expiry=BASE_TIME + expiry_offset,
        attestation_identity=identity,
    )


def test_derive_round_trips_through_validator(valid_root_gco):
    authority = MockAttestationAuthority()
    runtime = GCODerivationRuntime(authority)
    request = _request(
        tools=[ToolAuthority(tool_uri="https://tools.example/search", scope="read", max_depth=99)],
        permissions=[
            StatePermission(namespace="memory", access_mode=AccessMode.READ, taint_policy=TaintPolicy.CLEAN)
        ],
    )

    child = runtime.derive(valid_root_gco, request)

    assert GCOValidator().validate(valid_root_gco, child) is True
    assert child.parent_span_id == valid_root_gco.span_id
    assert child.tool_authority[0].max_depth == 1
    assert child.expires_at == BASE_TIME - timedelta(hours=1)
    assert child.attestation.value == "issued-token"
    assert authority.calls[0][0] == valid_root_gco.model_identity
    assert "attestation" not in authority.calls[0][1]


def test_derive_copies_shared_immutable_parent_fields(valid_root_gco):
    child = GCODerivationRuntime(MockAttestationAuthority()).derive(valid_root_gco, _request())

    for field_name in IMMUTABLE_PARENT_FIELDS:
        assert getattr(child, field_name) == getattr(valid_root_gco, field_name)


def test_derive_clamps_expiry(valid_root_gco):
    authority = MockAttestationAuthority()
    runtime = GCODerivationRuntime(authority)

    child = runtime.derive(valid_root_gco, _request(expiry_offset=timedelta(days=1)))

    assert child.tool_authority == []
    assert child.state_access_permissions == []
    assert child.expires_at == valid_root_gco.expires_at
    assert authority.calls[0][0] == valid_root_gco.model_identity


def test_delegation_request_rejects_attestation_identity_override():
    with pytest.raises(ValidationError):
        _request(identity="delegate")


@pytest.mark.parametrize(
    ("delegation_request", "error"),
    [
        (
            _request(tools=[ToolAuthority(tool_uri="https://tools.example/missing", scope="read", max_depth=0)]),
            DerivationError.TOOL_AUTHORITY_EXPANDED,
        ),
        (
            _request(tools=[ToolAuthority(tool_uri="https://tools.example/search", scope="admin", max_depth=0)]),
            DerivationError.TOOL_AUTHORITY_EXPANDED,
        ),
        (
            _request(permissions=[StatePermission(namespace="missing", access_mode=AccessMode.READ)]),
            DerivationError.STATE_PERMISSION_EXPANDED,
        ),
        (
            _request(
                permissions=[
                    StatePermission(namespace="scratch", access_mode=AccessMode.WRITE, taint_policy=TaintPolicy.SANITIZED)
                ]
            ),
            DerivationError.STATE_PERMISSION_EXPANDED,
        ),
        (
            _request(
                permissions=[
                    StatePermission(namespace="scratch", access_mode=AccessMode.READ, taint_policy=TaintPolicy.CLEAN)
                ]
            ),
            DerivationError.TAINT_DOWNGRADED,
        ),
    ],
)
def test_impossible_requests_rejected(valid_root_gco, delegation_request, error):
    with pytest.raises(GCODerivationException) as exc_info:
        GCODerivationRuntime(MockAttestationAuthority()).derive(valid_root_gco, delegation_request)

    assert exc_info.value.error is error


def test_depth_exhaustion_rejected():
    parent = make_root_gco(
        tool_authority=[ToolAuthority(tool_uri="https://tools.example/search", scope="read", max_depth=0)]
    )

    with pytest.raises(GCODerivationException) as exc_info:
        GCODerivationRuntime(MockAttestationAuthority()).derive(
            parent,
            _request(tools=[ToolAuthority(tool_uri="https://tools.example/search", scope="read", max_depth=0)]),
        )

    assert exc_info.value.error is DerivationError.MAX_DEPTH_INCREASED


@pytest.mark.parametrize(
    ("requested_depth", "expected_depth"),
    [
        (0, 0),
        (1, 1),
        (99, 2),
    ],
)
def test_derive_caps_tool_depth_to_request_and_parent(requested_depth, expected_depth):
    parent = make_root_gco(
        tool_authority=[ToolAuthority(tool_uri="https://tools.example/search", scope="read write", max_depth=3)]
    )
    request = _request(
        tools=[ToolAuthority(tool_uri="https://tools.example/search", scope="read", max_depth=requested_depth)]
    )

    child = GCODerivationRuntime(MockAttestationAuthority()).derive(parent, request)

    assert child.tool_authority[0].max_depth == expected_depth
    assert GCOValidator().validate(parent, child) is True


def test_lineage_growth_to_128_and_rejection_at_129():
    runtime = GCODerivationRuntime(MockAttestationAuthority())
    parent_at_127 = make_root_gco(lineage=[f"{index:064x}" for index in range(127)])

    child = runtime.derive(parent_at_127, _request())

    assert len(child.lineage) == 128

    parent_at_128 = make_root_gco(lineage=[f"{index:064x}" for index in range(128)])
    with pytest.raises(GCODerivationException) as exc_info:
        runtime.derive(parent_at_128, _request())

    assert exc_info.value.error is DerivationError.LINEAGE_FLOODED


def test_expired_parent_cannot_mint_valid_child(valid_root_gco):
    authority = MockAttestationAuthority()
    expired_parent = valid_root_gco.model_copy(
        update={"expires_at": datetime(2000, 1, 1, tzinfo=timezone.utc)}
    )

    with pytest.raises(GCODerivationException) as exc_info:
        GCODerivationRuntime(authority).derive(expired_parent, _request())

    assert exc_info.value.error is DerivationError.EXPIRED
    assert authority.calls == []


def test_derive_validates_issued_attestation_before_returning(valid_root_gco):
    with pytest.raises(GCODerivationException) as exc_info:
        GCODerivationRuntime(EmptyAttestationAuthority()).derive(valid_root_gco, _request())

    assert exc_info.value.error is DerivationError.ATTESTATION_MISSING


def test_delegation_request_rejects_non_utc_expiry():
    with pytest.raises(ValidationError):
        DelegationRequest(requested_expiry=BASE_TIME.astimezone(timezone(timedelta(hours=2))))


def test_derive_rejects_duplicate_namespace_in_request(valid_root_gco):
    request = _request(
        permissions=[
            StatePermission(namespace="memory", access_mode=AccessMode.READ, taint_policy=TaintPolicy.CLEAN),
            StatePermission(namespace="memory", access_mode=AccessMode.NONE, taint_policy=TaintPolicy.CLEAN),
        ],
    )

    with pytest.raises(GCODerivationException) as exc_info:
        GCODerivationRuntime(MockAttestationAuthority()).derive(valid_root_gco, request)

    assert exc_info.value.error is DerivationError.STATE_PERMISSION_EXPANDED


def test_derive_rejects_duplicate_tool_uri_in_request(valid_root_gco):
    request = _request(
        tools=[
            ToolAuthority(tool_uri="https://tools.example/search", scope="read", max_depth=0),
            ToolAuthority(tool_uri="https://tools.example/search", scope="write", max_depth=0),
        ],
    )

    with pytest.raises(GCODerivationException) as exc_info:
        GCODerivationRuntime(MockAttestationAuthority()).derive(valid_root_gco, request)

    assert exc_info.value.error is DerivationError.TOOL_AUTHORITY_EXPANDED


def test_derive_rejects_duplicate_namespace_in_parent(valid_root_gco):
    parent_permissions = [
        *valid_root_gco.state_access_permissions,
        StatePermission(namespace="memory", access_mode=AccessMode.NONE),
    ]
    parent = valid_root_gco.model_copy(update={"state_access_permissions": parent_permissions})
    request = _request(permissions=[StatePermission(namespace="memory", access_mode=AccessMode.READ)])

    with pytest.raises(GCODerivationException) as exc_info:
        GCODerivationRuntime(MockAttestationAuthority()).derive(parent, request)

    assert exc_info.value.error is DerivationError.STATE_PERMISSION_EXPANDED


def test_derive_rejects_read_from_append_parent():
    parent = make_root_gco(
        state_access_permissions=[StatePermission(namespace="log", access_mode=AccessMode.APPEND)]
    )
    request = _request(permissions=[StatePermission(namespace="log", access_mode=AccessMode.READ)])

    with pytest.raises(GCODerivationException) as exc_info:
        GCODerivationRuntime(MockAttestationAuthority()).derive(parent, request)

    assert exc_info.value.error is DerivationError.STATE_PERMISSION_EXPANDED


def test_derive_rejects_duplicate_tool_uri_in_parent(valid_root_gco):
    parent_tools = [
        *valid_root_gco.tool_authority,
        ToolAuthority(tool_uri="https://tools.example/search", scope="read write", max_depth=2),
    ]
    parent = valid_root_gco.model_copy(update={"tool_authority": parent_tools})
    request = _request(tools=[ToolAuthority(tool_uri="https://tools.example/search", scope="read", max_depth=1)])

    with pytest.raises(GCODerivationException) as exc_info:
        GCODerivationRuntime(MockAttestationAuthority()).derive(parent, request)

    assert exc_info.value.error is DerivationError.TOOL_AUTHORITY_EXPANDED
