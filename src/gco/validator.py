from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import ValidationError

from gco.models import AccessMode, GCO, TaintPolicy


class DerivationError(Enum):
    VERSION_MISMATCH = "gco_version major version incompatible"
    TRACE_ID_CHANGED = "trace_id mutated from parent"
    POLICY_ID_CHANGED = "policy_id mutated from parent"
    MODEL_IDENTITY_CHANGED = "model_identity mutated from parent"
    INTERVENTION_CHANGED = "intervention_version mutated from parent"
    PARENT_LINKAGE_INVALID = "parent_span_id does not match parent span_id"
    LINEAGE_APPEND_FAILED = "lineage does not append parent digest"
    LINEAGE_FLOODED = "lineage exceeds 128 entries"
    MAX_DEPTH_INCREASED = "max_depth increased or unchanged"
    TOOL_AUTHORITY_EXPANDED = "tool authority scope expanded"
    STATE_PERMISSION_EXPANDED = "state access_mode expanded"
    TAINT_DOWNGRADED = "taint_policy downgraded"
    EXPIRY_EXTENDED = "expires_at exceeds parent expiry"
    EXPIRED = "gco expired"
    ATTESTATION_MISSING = "attestation field missing or empty"
    ATTESTATION_FORMAT_INVALID = "attestation format not in supported enum"
    CANONICAL_HASH_MISMATCH = "lineage digest does not match canonical parent hash"
    GCO_MALFORMED = "gco schema validation failed"


class GCODerivationException(Exception):
    def __init__(self, error: DerivationError, message: str | None = None) -> None:
        self.error = error
        super().__init__(message or error.value)


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    error_code: DerivationError | None = None
    message: str | None = None


ACCESS_RANK = {
    AccessMode.NONE: 0,
    AccessMode.READ: 1,
    AccessMode.APPEND: 2,
    AccessMode.WRITE: 3,
}

TAINT_RANK = {
    TaintPolicy.CLEAN: 0,
    TaintPolicy.SANITIZED: 1,
    TaintPolicy.TAINTED: 2,
    TaintPolicy.ISOLATED: 3,
}


def canonical_gco_hash(gco: GCO) -> str:
    payload = gco.model_dump(mode="json", exclude={"attestation"})
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _major(version: str) -> str:
    return version.split(".", maxsplit=1)[0]


def _scope_tokens(scope: str) -> set[str]:
    return set(scope.replace(",", " ").split())


def _scope_is_subset(child_scope: str, parent_scope: str) -> bool:
    return _scope_tokens(child_scope).issubset(_scope_tokens(parent_scope))


def _access_rank(access_mode: Any) -> int | None:
    return ACCESS_RANK.get(access_mode)


def _taint_rank(taint_policy: Any) -> int | None:
    return TAINT_RANK.get(taint_policy)


class GCOValidator:
    def __init__(self, now: Callable[[], datetime] | None = None) -> None:
        self._now = now or (lambda: datetime.now(timezone.utc))

    def validate_result(self, parent: GCO | Mapping[str, Any], child: GCO | Mapping[str, Any]) -> ValidationResult:
        try:
            self.validate(parent, child)
        except GCODerivationException as exc:
            return ValidationResult(valid=False, error_code=exc.error, message=str(exc))
        except ValidationError as exc:
            return ValidationResult(
                valid=False,
                error_code=DerivationError.GCO_MALFORMED,
                message=str(exc),
            )
        return ValidationResult(valid=True)

    def validate_root(self, root: GCO | Mapping[str, Any]) -> bool:
        root = self._coerce_gco(root)
        if root.parent_span_id is not None:
            raise GCODerivationException(DerivationError.PARENT_LINKAGE_INVALID)
        if root.lineage:
            raise GCODerivationException(DerivationError.LINEAGE_APPEND_FAILED)
        self._validate_expiry(root, root)
        self._validate_attestation(root)
        return True

    def validate(self, parent: GCO | Mapping[str, Any], child: GCO | Mapping[str, Any]) -> bool:
        parent = self._coerce_gco(parent)
        child = self._coerce_gco(child)
        self._validate_version(parent, child)
        self._validate_immutables(parent, child)
        self._validate_parent_linkage(parent, child)
        self._validate_lineage(parent, child)
        self._validate_tool_authority(parent, child)
        self._validate_state_permissions(parent, child)
        self._validate_expiry(parent, child)
        self._validate_attestation(child)
        return True

    def _coerce_gco(self, gco: GCO | Mapping[str, Any]) -> GCO:
        if isinstance(gco, GCO):
            return gco
        try:
            return GCO.model_validate(gco)
        except ValidationError as exc:
            if any(tuple(error["loc"]) == ("attestation", "format") for error in exc.errors()):
                raise GCODerivationException(DerivationError.ATTESTATION_FORMAT_INVALID) from exc
            raise

    def _validate_version(self, parent: GCO, child: GCO) -> None:
        if _major(child.gco_version) != _major(parent.gco_version):
            raise GCODerivationException(DerivationError.VERSION_MISMATCH)

    def _validate_immutables(self, parent: GCO, child: GCO) -> None:
        if child.trace_id != parent.trace_id:
            raise GCODerivationException(DerivationError.TRACE_ID_CHANGED)
        if child.policy_id != parent.policy_id:
            raise GCODerivationException(DerivationError.POLICY_ID_CHANGED)
        if child.model_identity != parent.model_identity:
            raise GCODerivationException(DerivationError.MODEL_IDENTITY_CHANGED)
        if child.intervention_version != parent.intervention_version:
            raise GCODerivationException(DerivationError.INTERVENTION_CHANGED)

    def _validate_parent_linkage(self, parent: GCO, child: GCO) -> None:
        if child.parent_span_id != parent.span_id:
            raise GCODerivationException(DerivationError.PARENT_LINKAGE_INVALID)

    def _validate_lineage(self, parent: GCO, child: GCO) -> None:
        if len(child.lineage) > 128:
            raise GCODerivationException(DerivationError.LINEAGE_FLOODED)
        if len(child.lineage) != len(parent.lineage) + 1 or child.lineage[:-1] != parent.lineage:
            raise GCODerivationException(DerivationError.LINEAGE_APPEND_FAILED)
        if child.lineage[-1] != canonical_gco_hash(parent):
            raise GCODerivationException(DerivationError.CANONICAL_HASH_MISMATCH)

    def _validate_tool_authority(self, parent: GCO, child: GCO) -> None:
        parent_tools = {str(tool.tool_uri): tool for tool in parent.tool_authority}
        for child_tool in child.tool_authority:
            parent_tool = parent_tools.get(str(child_tool.tool_uri))
            if parent_tool is None:
                raise GCODerivationException(DerivationError.TOOL_AUTHORITY_EXPANDED)
            if parent_tool.max_depth == 0 or child_tool.max_depth != parent_tool.max_depth - 1:
                raise GCODerivationException(DerivationError.MAX_DEPTH_INCREASED)
            if not _scope_is_subset(child_tool.scope, parent_tool.scope):
                raise GCODerivationException(DerivationError.TOOL_AUTHORITY_EXPANDED)

    def _validate_state_permissions(self, parent: GCO, child: GCO) -> None:
        parent_permissions = {permission.namespace: permission for permission in parent.state_access_permissions}
        for child_permission in child.state_access_permissions:
            parent_permission = parent_permissions.get(child_permission.namespace)
            if parent_permission is None:
                raise GCODerivationException(DerivationError.STATE_PERMISSION_EXPANDED)
            child_access = _access_rank(child_permission.access_mode)
            parent_access = _access_rank(parent_permission.access_mode)
            if child_access is None or parent_access is None or child_access > parent_access:
                raise GCODerivationException(DerivationError.STATE_PERMISSION_EXPANDED)
            child_taint = _taint_rank(child_permission.taint_policy)
            parent_taint = _taint_rank(parent_permission.taint_policy)
            if child_taint is None or parent_taint is None or child_taint < parent_taint:
                raise GCODerivationException(DerivationError.TAINT_DOWNGRADED)

    def _validate_expiry(self, parent: GCO, child: GCO) -> None:
        if child.expires_at > parent.expires_at:
            raise GCODerivationException(DerivationError.EXPIRY_EXTENDED)
        if child.expires_at <= self._now():
            raise GCODerivationException(DerivationError.EXPIRED)

    def _validate_attestation(self, child: GCO) -> None:
        if child.attestation is None or not child.attestation.value:
            raise GCODerivationException(DerivationError.ATTESTATION_MISSING)
