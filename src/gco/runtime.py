from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from pydantic import ValidationError

from gco.attestation import AttestationError, AttestationVerifier
from gco.derivation import AttestationAuthority, DelegationRequest, GCODerivationRuntime
from gco.models import AccessMode, GCO
from gco.state_store import GovernedStateStore, NamespaceAccessDenied, StateKeyNotFound, TaintedStateRead
from gco.trust import TrustBundle
from gco.validator import DerivationError, GCODerivationException, GCOValidator, _access_rank, _scope_is_subset


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str | None = None
    error_code: Any = None
    child: GCO | None = None
    value: bytes | None = None


class GovernanceRuntime:
    def __init__(
        self,
        trust_bundle: TrustBundle,
        *,
        verifier: AttestationVerifier | None = None,
        validator: GCOValidator | None = None,
        state_store: GovernedStateStore | None = None,
        attestation_authority: AttestationAuthority | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._now = now or (lambda: datetime.now(timezone.utc))
        self.trust_bundle = trust_bundle
        self.verifier = verifier or AttestationVerifier(trust_bundle, now=self._now)
        self.validator = validator or GCOValidator(now=self._now)
        self.state_store = state_store or GovernedStateStore()
        self.attestation_authority = attestation_authority

    def authorize_subcall(self, parent: Any, child: Any) -> Decision:
        try:
            parent_gco = self._coerce_gco(parent)
            parent_verified = self.verifier.verify(parent_gco.attestation, parent_gco)
            if not parent_verified.verified:
                return self._deny(parent_verified.error_code, parent_verified.message)
            child_gco = self._coerce_gco(child)
            verified = self.verifier.verify(child_gco.attestation, child_gco)
            if not verified.verified:
                return self._deny(verified.error_code, verified.message)
            self.validator.validate(parent_gco, child_gco)
        except GCODerivationException as exc:
            return self._deny(exc.error, str(exc))
        except (ValidationError, TypeError, ValueError, AttributeError) as exc:
            return self._deny(DerivationError.GCO_MALFORMED, str(exc))
        except Exception as exc:  # noqa: BLE001
            return self._deny(DerivationError.GCO_MALFORMED, str(exc))
        return Decision(allowed=True)

    def authorize_tool_call(self, gco: Any, tool_uri: str, requested_scope: str | None = None) -> Decision:
        """Authorize a tool call.

        When ``requested_scope`` is omitted, this only checks that the tool is
        available (delegated with remaining depth and a non-empty scope) -- it
        does NOT check that any particular operation is within scope. Callers
        that need to authorize a specific operation must pass
        ``requested_scope`` so it can be checked against the grant's scope.
        """
        try:
            subject = self._coerce_gco(gco)
            verified = self.verifier.verify(subject.attestation, subject)
            if not verified.verified:
                return self._deny(verified.error_code, verified.message)
            for authority in subject.tool_authority:
                if str(authority.tool_uri) == str(tool_uri) and authority.max_depth > 0:
                    if not authority.scope.strip():
                        continue
                    if requested_scope is None:
                        return Decision(allowed=True)
                    if _scope_is_subset(requested_scope, authority.scope):
                        return Decision(allowed=True)
                    return self._deny(
                        DerivationError.TOOL_AUTHORITY_EXPANDED,
                        f"scope {requested_scope!r} exceeds grant for tool {tool_uri}",
                    )
            return self._deny(DerivationError.TOOL_AUTHORITY_EXPANDED, f"tool {tool_uri} is not delegated")
        except (ValidationError, TypeError, ValueError, AttributeError) as exc:
            return self._deny(DerivationError.GCO_MALFORMED, str(exc))
        except Exception as exc:  # noqa: BLE001
            return self._deny(DerivationError.GCO_MALFORMED, str(exc))

    def authorize_state_access(self, gco: Any, namespace: str, mode: str | AccessMode) -> Decision:
        try:
            subject = self._coerce_gco(gco)
            verified = self.verifier.verify(subject.attestation, subject)
            if not verified.verified:
                return self._deny(verified.error_code, verified.message)
            try:
                requested_mode: Any = mode if isinstance(mode, AccessMode) else AccessMode(str(mode))
            except (TypeError, ValueError):
                requested_mode = mode
            permission = next(
                (permission for permission in subject.state_access_permissions if permission.namespace == namespace),
                None,
            )
            if permission is None:
                return self._deny(NamespaceAccessDenied, f"namespace {namespace} is not delegated")
            requested_rank = _access_rank(requested_mode)
            granted_rank = _access_rank(permission.access_mode)
            requested_label = requested_mode.value if isinstance(requested_mode, AccessMode) else str(mode)
            if requested_rank is None or granted_rank is None or requested_mode is AccessMode.NONE:
                return self._deny(NamespaceAccessDenied, f"{requested_label} denied for namespace {namespace}")
            # This seam checks only the ACL grant; taint and per-key state are enforced by the store at real access time.
            if granted_rank < requested_rank:
                return self._deny(NamespaceAccessDenied, f"{requested_label} denied for namespace {namespace}")
        except (ValidationError, TypeError, ValueError, AttributeError) as exc:
            return self._deny(DerivationError.GCO_MALFORMED, str(exc))
        except Exception as exc:  # noqa: BLE001
            return self._deny(DerivationError.GCO_MALFORMED, str(exc))
        return Decision(allowed=True)

    def read_state(self, gco: Any, namespace: str, key: str) -> Decision:
        try:
            subject = self._coerce_gco(gco)
            verified = self.verifier.verify(subject.attestation, subject)
            if not verified.verified:
                return self._deny(verified.error_code, verified.message)
            access = self.authorize_state_access(subject, namespace, AccessMode.READ)
            if not access.allowed:
                return access
            value = self.state_store.read(namespace, key, subject)
        except (NamespaceAccessDenied, StateKeyNotFound) as exc:
            return self._deny(NamespaceAccessDenied, str(exc))
        except TaintedStateRead as exc:
            return self._deny(TaintedStateRead, str(exc))
        except (ValidationError, TypeError, ValueError, AttributeError) as exc:
            return self._deny(DerivationError.GCO_MALFORMED, str(exc))
        except Exception as exc:  # noqa: BLE001
            return self._deny(DerivationError.GCO_MALFORMED, str(exc))
        return Decision(allowed=True, value=value)

    def write_state(self, gco: Any, namespace: str, key: str, value: bytes) -> Decision:
        try:
            subject = self._coerce_gco(gco)
            verified = self.verifier.verify(subject.attestation, subject)
            if not verified.verified:
                return self._deny(verified.error_code, verified.message)
            access = self.authorize_state_access(subject, namespace, AccessMode.WRITE)
            if not access.allowed:
                return access
            self.state_store.write(namespace, key, value, subject)
        except NamespaceAccessDenied as exc:
            return self._deny(NamespaceAccessDenied, str(exc))
        except (ValidationError, TypeError, ValueError, AttributeError) as exc:
            return self._deny(DerivationError.GCO_MALFORMED, str(exc))
        except Exception as exc:  # noqa: BLE001
            return self._deny(DerivationError.GCO_MALFORMED, str(exc))
        return Decision(allowed=True)

    def derive_for_subcall(self, parent: Any, request: Any) -> Decision:
        try:
            if self.attestation_authority is None:
                return self._deny(AttestationError.MALFORMED_ATTESTATION, "attestation authority is not configured")
            parent_gco = self._coerce_gco(parent)
            parent_verified = self.verifier.verify(parent_gco.attestation, parent_gco)
            if not parent_verified.verified:
                return self._deny(parent_verified.error_code, parent_verified.message)
            delegation_request = request if isinstance(request, DelegationRequest) else DelegationRequest.model_validate(request)
            child = GCODerivationRuntime(self.attestation_authority).derive(parent_gco, delegation_request)
            verified = self.verifier.verify(child.attestation, child)
            if not verified.verified:
                return self._deny(verified.error_code, verified.message)
            self.validator.validate(parent_gco, child)
        except GCODerivationException as exc:
            return self._deny(exc.error, str(exc))
        except (ValidationError, TypeError, ValueError, AttributeError) as exc:
            return self._deny(DerivationError.GCO_MALFORMED, str(exc))
        except Exception as exc:  # noqa: BLE001
            return self._deny(DerivationError.GCO_MALFORMED, str(exc))
        return Decision(allowed=True, child=child)

    def _coerce_gco(self, gco: Any) -> GCO:
        if isinstance(gco, GCO):
            return gco
        return GCO.model_validate(gco)

    def _deny(self, error_code: Any, reason: str | None = None) -> Decision:
        if reason is None and hasattr(error_code, "value"):
            reason = str(error_code.value)
        return Decision(allowed=False, reason=reason, error_code=error_code)
