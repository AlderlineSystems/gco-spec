from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import pytest

from gco.models import (
    AccessMode,
    AttestationFormat,
    AttestationModel,
    GCO,
    StatePermission,
    TaintPolicy,
    ToolAuthority,
)
from gco.validator import canonical_gco_hash


BASE_TIME = datetime(2099, 1, 1, 12, 0, tzinfo=timezone.utc)


def make_attestation(value: str = "test-token") -> AttestationModel:
    return AttestationModel(
        format=AttestationFormat.JWT_SVID,
        value=value,
        issuer="https://issuer.example/gco",
    )


def make_root_gco(
    *,
    lineage: list[str] | None = None,
    tool_authority: list[ToolAuthority] | None = None,
    state_access_permissions: list[StatePermission] | None = None,
) -> GCO:
    return GCO(
        gco_version="1.0.0-draft",
        trace_id=UUID("11111111-1111-4111-8111-111111111111"),
        span_id=UUID("22222222-2222-4222-8222-222222222222"),
        parent_span_id=None,
        policy_id="policy-alpha",
        model_identity="spiffe://example.org/model/model-alpha",
        intervention_version="intervention-v1",
        tool_authority=tool_authority
        if tool_authority is not None
        else [
            ToolAuthority(tool_uri="https://tools.example/search", scope="read write", max_depth=2),
            ToolAuthority(tool_uri="https://tools.example/calc", scope="read", max_depth=1),
        ],
        state_access_permissions=state_access_permissions
        if state_access_permissions is not None
        else [
            StatePermission(namespace="memory", access_mode=AccessMode.WRITE, taint_policy=TaintPolicy.CLEAN),
            StatePermission(namespace="scratch", access_mode=AccessMode.READ, taint_policy=TaintPolicy.SANITIZED),
            StatePermission(namespace="appendix", access_mode=AccessMode.APPEND, taint_policy=TaintPolicy.CLEAN),
        ],
        expires_at=BASE_TIME,
        lineage=[] if lineage is None else lineage,
        attestation=make_attestation("root-token"),
    )


def _narrow_scope(scope: str) -> str:
    return scope.replace(",", " ").split()[0]


def _narrow_access(access_mode: AccessMode) -> AccessMode:
    if access_mode is AccessMode.WRITE:
        return AccessMode.READ
    return AccessMode.NONE


def make_child_gco(
    parent: GCO,
    *,
    lineage: list[str] | None = None,
    tool_authority: list[ToolAuthority] | None = None,
    state_access_permissions: list[StatePermission] | None = None,
) -> GCO:
    child_tools = [
        ToolAuthority(
            tool_uri=tool.tool_uri,
            scope=_narrow_scope(tool.scope),
            max_depth=tool.max_depth - 1,
        )
        for tool in parent.tool_authority
        if tool.max_depth > 0
    ]
    child_permissions = [
        StatePermission(
            namespace=permission.namespace,
            access_mode=_narrow_access(permission.access_mode),
            taint_policy=permission.taint_policy,
        )
        for permission in parent.state_access_permissions
    ]
    return GCO(
        gco_version=parent.gco_version,
        trace_id=parent.trace_id,
        span_id=UUID("33333333-3333-4333-8333-333333333333"),
        parent_span_id=parent.span_id,
        policy_id=parent.policy_id,
        model_identity=parent.model_identity,
        intervention_version=parent.intervention_version,
        tool_authority=child_tools if tool_authority is None else tool_authority,
        state_access_permissions=child_permissions
        if state_access_permissions is None
        else state_access_permissions,
        expires_at=parent.expires_at,
        lineage=[*parent.lineage, canonical_gco_hash(parent)] if lineage is None else lineage,
        attestation=make_attestation("child-token"),
    )


@pytest.fixture
def valid_root_gco() -> GCO:
    return make_root_gco()


@pytest.fixture
def valid_child_gco():
    return make_child_gco


@pytest.fixture
def invalid_gco_factory(valid_child_gco):
    def factory(parent: GCO, mutation):
        child = valid_child_gco(parent)
        mutated = mutation(child)
        return child if mutated is None else mutated

    return factory
