from __future__ import annotations

from datetime import datetime, timedelta
from typing import Protocol
from uuid import uuid4

from pydantic import AwareDatetime, Field, field_validator

from gco.models import AttestationModel, GCO, StatePermission, StrictBaseModel, ToolAuthority
from gco.validator import (
    DerivationError,
    GCODerivationException,
    GCOValidator,
    _access_rank,
    _scope_is_subset,
    _taint_rank,
    canonical_gco_hash,
)


class DelegationRequest(StrictBaseModel):
    tool_authority: list[ToolAuthority] = Field(default_factory=list)
    state_access_permissions: list[StatePermission] = Field(default_factory=list)
    requested_expiry: AwareDatetime
    attestation_identity: str | None = None

    @field_validator("requested_expiry")
    @classmethod
    def requested_expiry_must_be_utc(cls, value: datetime) -> datetime:
        if value.utcoffset() != timedelta(0):
            raise ValueError("requested_expiry must be UTC")
        return value


class AttestationAuthority(Protocol):
    def issue(self, identity: str, gco_data: dict) -> AttestationModel:
        ...


class GCODerivationRuntime:
    def __init__(self, attestation_authority: AttestationAuthority) -> None:
        self.authority = attestation_authority
        self.validator = GCOValidator()

    def derive(self, parent: GCO, request: DelegationRequest) -> GCO:
        if len(parent.lineage) + 1 > 128:
            raise GCODerivationException(DerivationError.LINEAGE_FLOODED)

        self._validate_no_duplicate_namespaces(parent.state_access_permissions)
        self._validate_no_duplicate_namespaces(request.state_access_permissions)
        self._validate_no_duplicate_tool_uris(parent.tool_authority)
        self._validate_no_duplicate_tool_uris(request.tool_authority)

        child_tools = self._derive_tools(parent, request)
        child_permissions = self._derive_permissions(parent, request)
        child_without_attestation = GCO(
            gco_version=parent.gco_version,
            trace_id=parent.trace_id,
            span_id=uuid4(),
            parent_span_id=parent.span_id,
            policy_id=parent.policy_id,
            model_identity=parent.model_identity,
            intervention_version=parent.intervention_version,
            tool_authority=child_tools,
            state_access_permissions=child_permissions,
            expires_at=min(request.requested_expiry, parent.expires_at),
            lineage=[*parent.lineage, canonical_gco_hash(parent)],
            attestation=None,
        )
        identity = request.attestation_identity if request.attestation_identity is not None else parent.model_identity
        attestation = self.authority.issue(
            identity,
            child_without_attestation.model_dump(mode="json", exclude={"attestation"}),
        )
        child = child_without_attestation.model_copy(update={"attestation": attestation})
        self.validator.validate(parent, child)
        return child

    def _validate_no_duplicate_namespaces(self, permissions: list[StatePermission]) -> None:
        namespaces = [permission.namespace for permission in permissions]
        if len(namespaces) != len(set(namespaces)):
            raise GCODerivationException(DerivationError.STATE_PERMISSION_EXPANDED)

    def _validate_no_duplicate_tool_uris(self, tools: list[ToolAuthority]) -> None:
        tool_uris = [str(tool.tool_uri) for tool in tools]
        if len(tool_uris) != len(set(tool_uris)):
            raise GCODerivationException(DerivationError.TOOL_AUTHORITY_EXPANDED)

    def _derive_tools(self, parent: GCO, request: DelegationRequest) -> list[ToolAuthority]:
        parent_tools = {str(tool.tool_uri): tool for tool in parent.tool_authority}
        child_tools = []
        for requested_tool in request.tool_authority:
            parent_tool = parent_tools.get(str(requested_tool.tool_uri))
            if parent_tool is None:
                raise GCODerivationException(DerivationError.TOOL_AUTHORITY_EXPANDED)
            child_depth = parent_tool.max_depth - 1
            if child_depth < 0:
                raise GCODerivationException(DerivationError.MAX_DEPTH_INCREASED)
            if not _scope_is_subset(requested_tool.scope, parent_tool.scope):
                raise GCODerivationException(DerivationError.TOOL_AUTHORITY_EXPANDED)
            child_tools.append(
                ToolAuthority(
                    tool_uri=parent_tool.tool_uri,
                    scope=requested_tool.scope,
                    max_depth=child_depth,
                )
            )
        return child_tools

    def _derive_permissions(self, parent: GCO, request: DelegationRequest) -> list[StatePermission]:
        parent_permissions = {permission.namespace: permission for permission in parent.state_access_permissions}
        child_permissions = []
        for requested_permission in request.state_access_permissions:
            parent_permission = parent_permissions.get(requested_permission.namespace)
            if parent_permission is None:
                raise GCODerivationException(DerivationError.STATE_PERMISSION_EXPANDED)
            requested_access = _access_rank(requested_permission.access_mode)
            parent_access = _access_rank(parent_permission.access_mode)
            if requested_access is None or parent_access is None or requested_access > parent_access:
                raise GCODerivationException(DerivationError.STATE_PERMISSION_EXPANDED)
            requested_taint = _taint_rank(requested_permission.taint_policy)
            parent_taint = _taint_rank(parent_permission.taint_policy)
            if requested_taint is None or parent_taint is None or requested_taint < parent_taint:
                raise GCODerivationException(DerivationError.TAINT_DOWNGRADED)
            child_permissions.append(requested_permission)
        return child_permissions
