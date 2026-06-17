from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from pydantic import ValidationError

from gco.attestation import AttestationError, AttestationVerifier
from gco.derivation import AttestationAuthority, DelegationRequest, GCODerivationRuntime
from gco.models import AccessMode, GCO
from gco.state_store import GovernedStateStore, NamespaceAccessDenied
from gco.trust import TrustBundle
from gco.validator import DerivationError, GCODerivationException, GCOValidator, _access_rank


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str | None = None
    error_code: Any = None
    child: GCO | None = None


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
            child_gco = self._coerce_gco(child)
            verified = self.verifier.verify(child_gco.attestation, child_gco)
            if not verified.verified:
                return self._deny(verified.error_code, verified.message)
            self.validator.validate(parent, child_gco)
        except GCODerivationException as exc:
            return self._deny(exc.error, str(exc))
        except (ValidationError, TypeError, ValueError, AttributeError) as exc:
            return self._deny(DerivationError.GCO_MALFORMED, str(exc))
        except Exception as exc:  # noqa: BLE001
            return self._deny(DerivationError.GCO_MALFORMED, str(exc))
        return Decision(allowed=True)

    def authorize_tool_call(self, gco: Any, tool_uri: str) -> Decision:
        try:
            subject = self._coerce_gco(gco)
            verified = self.verifier.verify(subject.attestation, subject)
            if not verified.verified:
                return self._deny(verified.error_code, verified.message)
            for authority in subject.tool_authority:
                if str(authority.tool_uri) == str(tool_uri) and authority.max_depth > 0:
                    if authority.scope.strip():
                        return Decision(allowed=True)
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
            minimum_rank = _access_rank(AccessMode.READ if requested_mode is AccessMode.READ else AccessMode.APPEND)
            if minimum_rank is None or granted_rank < minimum_rank:
                return self._deny(NamespaceAccessDenied, f"{requested_label} denied for namespace {namespace}")
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
