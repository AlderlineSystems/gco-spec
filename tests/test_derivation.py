from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from gco.derivation import DelegationRequest, GCODerivationRuntime
from gco.models import AccessMode, AttestationFormat, AttestationModel, StatePermission, TaintPolicy, ToolAuthority
from gco.validator import DerivationError, GCODerivationException, GCOValidator
from conftest import BASE_TIME, make_root_gco


class MockAttestationAuthority:
    def __init__(self) -> None:
        self.calls = []

    def issue(self, identity: str, gco_data: dict) -> AttestationModel:
        self.calls.append((identity, gco_data))
        return AttestationModel(format=AttestationFormat.JWT_SVID, value="issued-token")


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
    assert authority.calls[0][0] == "model-alpha"
    assert "attestation" not in authority.calls[0][1]


def test_derive_uses_explicit_identity_and_clamps_expiry(valid_root_gco):
    authority = MockAttestationAuthority()
    runtime = GCODerivationRuntime(authority)

    child = runtime.derive(valid_root_gco, _request(expiry_offset=timedelta(days=1), identity="delegate"))

    assert child.tool_authority == []
    assert child.state_access_permissions == []
    assert child.expires_at == valid_root_gco.expires_at
    assert authority.calls[0][0] == "delegate"


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
    expired_parent = valid_root_gco.model_copy(
        update={"expires_at": datetime(2000, 1, 1, tzinfo=timezone.utc)}
    )

    with pytest.raises(GCODerivationException) as exc_info:
        GCODerivationRuntime(MockAttestationAuthority()).derive(expired_parent, _request())

    assert exc_info.value.error is DerivationError.EXPIRED


def test_delegation_request_rejects_non_utc_expiry():
    with pytest.raises(ValidationError):
        DelegationRequest(requested_expiry=BASE_TIME.astimezone(timezone(timedelta(hours=2))))
