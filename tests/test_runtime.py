from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from conftest import BASE_TIME, make_child_gco, make_root_gco
from gco.attestation import AttestationError
from gco.derivation import DelegationRequest
from gco.models import AccessMode, AttestationFormat, AttestationModel, GCO, StatePermission, TaintPolicy, ToolAuthority
from gco.runtime import Decision, GovernanceRuntime
from gco.state_store import GovernedStateStore, NamespaceAccessDenied, TaintedStateRead
from gco.trust import TrustBundle
from gco.validator import DerivationError, canonical_gco_hash

SPIFFE_ID = "spiffe://example.org/ns/default/sa/model-alpha"
NOW = datetime(2099, 1, 1, 11, 0, tzinfo=timezone.utc)


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(private_key, kid: str) -> dict:
    payload = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    payload.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return payload


def _bundle(key, *, kid: str = "runtime") -> TrustBundle:
    return TrustBundle.from_mapping({"example.org": {"jwks": {"keys": [_jwk(key, kid)]}}})


def _claims(gco: GCO, *, exp: datetime | None = None) -> dict:
    return {
        "sub": gco.model_identity,
        "gco_hash": canonical_gco_hash(gco),
        "exp": int((exp or NOW + timedelta(hours=1)).timestamp()),
    }


def _attestation(gco: GCO, key, *, kid: str = "runtime") -> AttestationModel:
    return AttestationModel(
        format=AttestationFormat.JWT_SVID,
        value=jwt.encode(_claims(gco), key, algorithm="RS256", headers={"kid": kid}),
    )


def _with_identity(gco: GCO) -> GCO:
    return gco.model_copy(update={"model_identity": SPIFFE_ID})


def _sign(gco: GCO, key, *, kid: str = "runtime") -> GCO:
    return gco.model_copy(update={"attestation": _attestation(gco, key, kid=kid)})


def _parent_child(key):
    parent = _with_identity(make_root_gco())
    child = make_child_gco(parent)
    return _sign(parent, key), _sign(child, key)


class SigningAuthority:
    def __init__(self, key, *, kid: str = "runtime") -> None:
        self.key = key
        self.kid = kid

    def issue(self, identity: str, gco_data: dict) -> AttestationModel:
        subject = GCO.model_validate({**gco_data, "attestation": None})
        subject = subject.model_copy(update={"model_identity": identity})
        return _attestation(subject, self.key, kid=self.kid)


def test_decision_is_frozen():
    decision = Decision(allowed=True)

    with pytest.raises(Exception):  # noqa: B017
        decision.allowed = False


def test_authorize_subcall_allows_authentic_tightening():
    key = _key()
    parent, child = _parent_child(key)

    decision = GovernanceRuntime(_bundle(key), now=lambda: NOW).authorize_subcall(parent, child)

    assert decision == Decision(allowed=True)


def test_authorize_subcall_denies_authentic_expansion_with_derivation_error():
    key = _key()
    parent, child = _parent_child(key)
    expanded = child.model_copy(
        update={"tool_authority": [ToolAuthority(tool_uri="https://tools.example/search", scope="read write admin", max_depth=1)]}
    )
    expanded = _sign(expanded, key)

    decision = GovernanceRuntime(_bundle(key), now=lambda: NOW).authorize_subcall(parent, expanded)

    assert decision.allowed is False
    assert decision.error_code is DerivationError.TOOL_AUTHORITY_EXPANDED
    assert decision.reason == DerivationError.TOOL_AUTHORITY_EXPANDED.value


def test_authorize_subcall_denies_unauthentic_perfect_tightening_before_validation():
    trusted = _key()
    forged = _key()
    parent = _sign(_with_identity(make_root_gco()), trusted)
    child = make_child_gco(parent)
    child = _sign(child, forged, kid="forged")

    decision = GovernanceRuntime(_bundle(trusted), now=lambda: NOW).authorize_subcall(parent, child)

    assert decision.allowed is False
    assert decision.error_code is AttestationError.UNTRUSTED_KEY
    assert decision.reason == "JWS key id is not trusted"


def test_authorize_subcall_denies_when_parent_attestation_unverified():
    trusted = _key()
    forged = _key()
    parent = _sign(_with_identity(make_root_gco()), forged, kid="forged")
    child = make_child_gco(parent)
    child = _sign(child, trusted)

    decision = GovernanceRuntime(_bundle(trusted), now=lambda: NOW).authorize_subcall(parent, child)

    assert decision.allowed is False
    assert decision.error_code is AttestationError.UNTRUSTED_KEY


def test_authorize_subcall_denies_synthetic_never_attested_parent():
    key = _key()
    parent = _with_identity(make_root_gco())
    parent = parent.model_copy(update={"attestation": None})
    child = make_child_gco(parent)
    child = _sign(child, key)

    decision = GovernanceRuntime(_bundle(key), now=lambda: NOW).authorize_subcall(parent, child)

    assert decision.allowed is False
    assert decision.error_code is AttestationError.MALFORMED_ATTESTATION


def test_authorize_subcall_malformed_input_denies_without_raise():
    key = _key()

    decision = GovernanceRuntime(_bundle(key), now=lambda: NOW).authorize_subcall(None, {"not": "a gco"})

    assert decision.allowed is False
    assert decision.error_code is DerivationError.GCO_MALFORMED


def test_authorize_subcall_unexpected_error_denies_without_raise():
    class ExplodingVerifier:
        def verify(self, attestation, gco):
            raise RuntimeError("boom")

    key = _key()
    parent, child = _parent_child(key)

    decision = GovernanceRuntime(_bundle(key), verifier=ExplodingVerifier(), now=lambda: NOW).authorize_subcall(parent, child)

    assert decision.allowed is False
    assert decision.error_code is DerivationError.GCO_MALFORMED
    assert decision.reason == "boom"


def test_authorize_tool_call_authentic_valid_and_invalid():
    key = _key()
    parent = _sign(_with_identity(make_root_gco()), key)
    runtime = GovernanceRuntime(_bundle(key), now=lambda: NOW)

    allowed = runtime.authorize_tool_call(parent, "https://tools.example/search")
    absent = runtime.authorize_tool_call(parent, "https://tools.example/missing")
    exhausted = runtime.authorize_tool_call(
        _sign(
            parent.model_copy(update={"tool_authority": [ToolAuthority(tool_uri="https://tools.example/search", scope="read", max_depth=0)]}),
            key,
        ),
        "https://tools.example/search",
    )
    empty_scope = runtime.authorize_tool_call(
        _sign(
            parent.model_copy(update={"tool_authority": [ToolAuthority(tool_uri="https://tools.example/search", scope=" ", max_depth=1)]}),
            key,
        ),
        "https://tools.example/search",
    )

    assert allowed.allowed is True
    assert absent.error_code is DerivationError.TOOL_AUTHORITY_EXPANDED
    assert absent.reason == "tool https://tools.example/missing is not delegated"
    assert exhausted.error_code is DerivationError.TOOL_AUTHORITY_EXPANDED
    assert empty_scope.error_code is DerivationError.TOOL_AUTHORITY_EXPANDED


@pytest.mark.parametrize(
    "operation",
    [
        "authorize_tool_call",
        "authorize_state_access",
        "read_state",
        "write_state",
    ],
)
def test_runtime_authority_denies_expired_gco_even_with_valid_attestation(operation):
    key = _key()
    subject = _with_identity(
        make_root_gco(
            state_access_permissions=[StatePermission(namespace="memory", access_mode=AccessMode.WRITE)],
        ).model_copy(update={"expires_at": NOW - timedelta(seconds=1)})
    )
    subject = _sign(subject, key)
    store = GovernedStateStore()
    runtime = GovernanceRuntime(_bundle(key), state_store=store, now=lambda: NOW)

    if operation == "authorize_tool_call":
        decision = runtime.authorize_tool_call(subject, "https://tools.example/search")
    elif operation == "authorize_state_access":
        decision = runtime.authorize_state_access(subject, "memory", AccessMode.READ)
    elif operation == "read_state":
        decision = runtime.read_state(subject, "memory", "answer")
    else:
        decision = runtime.write_state(subject, "memory", "answer", b"42")

    assert decision.allowed is False
    assert decision.error_code is DerivationError.EXPIRED
    assert store._values == {}


def test_authorize_tool_call_enforces_requested_scope_when_provided():
    key = _key()
    parent = _sign(
        _with_identity(
            make_root_gco(
                tool_authority=[ToolAuthority(tool_uri="https://tools.example/search", scope="read write", max_depth=2)]
            )
        ),
        key,
    )
    runtime = GovernanceRuntime(_bundle(key), now=lambda: NOW)

    within_scope = runtime.authorize_tool_call(parent, "https://tools.example/search", requested_scope="read")
    outside_scope = runtime.authorize_tool_call(parent, "https://tools.example/search", requested_scope="admin")

    assert within_scope.allowed is True
    assert outside_scope.allowed is False
    assert outside_scope.error_code is DerivationError.TOOL_AUTHORITY_EXPANDED


def test_authorize_tool_call_without_requested_scope_only_checks_availability():
    key = _key()
    parent = _sign(
        _with_identity(
            make_root_gco(
                tool_authority=[ToolAuthority(tool_uri="https://tools.example/search", scope="read", max_depth=2)]
            )
        ),
        key,
    )
    runtime = GovernanceRuntime(_bundle(key), now=lambda: NOW)

    decision = runtime.authorize_tool_call(parent, "https://tools.example/search")

    assert decision.allowed is True


def test_authorize_tool_call_unauthentic_denied_before_authority_check():
    trusted = _key()
    forged = _key()
    gco = _sign(_with_identity(make_root_gco(tool_authority=[])), forged, kid="forged")

    decision = GovernanceRuntime(_bundle(trusted), now=lambda: NOW).authorize_tool_call(gco, "https://tools.example/search")

    assert decision.allowed is False
    assert decision.error_code is AttestationError.UNTRUSTED_KEY
    assert decision.reason == "JWS key id is not trusted"


def test_authorize_tool_call_malformed_and_unexpected_errors_deny():
    class ExplodingVerifier:
        def verify(self, attestation, gco):
            raise RuntimeError("tool boom")

    key = _key()
    gco = _sign(_with_identity(make_root_gco()), key)
    runtime = GovernanceRuntime(_bundle(key), now=lambda: NOW)

    malformed = runtime.authorize_tool_call({"not": "a gco"}, "https://tools.example/search")
    exploded = GovernanceRuntime(_bundle(key), verifier=ExplodingVerifier(), now=lambda: NOW).authorize_tool_call(
        gco,
        "https://tools.example/search",
    )

    assert malformed.allowed is False
    assert malformed.error_code is DerivationError.GCO_MALFORMED
    assert exploded.allowed is False
    assert exploded.error_code is DerivationError.GCO_MALFORMED
    assert exploded.reason == "tool boom"


def test_authorize_state_access_authentic_valid_invalid_and_no_store_mutation():
    key = _key()
    store = GovernedStateStore()
    writer = _sign(
        _with_identity(make_root_gco(state_access_permissions=[StatePermission(namespace="memory", access_mode=AccessMode.WRITE)])),
        key,
    )
    none = _sign(
        _with_identity(
            make_root_gco(state_access_permissions=[StatePermission(namespace="memory", access_mode=AccessMode.NONE)])
        ),
        key,
    )
    runtime = GovernanceRuntime(_bundle(key), state_store=store, now=lambda: NOW)

    assert runtime.authorize_state_access(writer, "memory", AccessMode.WRITE).allowed is True
    denied = runtime.authorize_state_access(none, "memory", "write")
    missing = runtime.authorize_state_access(writer, "missing", "read")

    assert denied.allowed is False
    assert denied.reason == "write denied for namespace memory"
    assert missing.allowed is False
    assert missing.reason == "namespace missing is not delegated"
    assert store._values == {}
    assert store._taints == {}
    assert not any(key == "__gco_runtime_probe__" for _, key in store._values | store._taints)


def test_authorize_state_access_append_idempotent_and_unknown_mode_denies():
    key = _key()
    append = _sign(
        _with_identity(make_root_gco(state_access_permissions=[StatePermission(namespace="log", access_mode=AccessMode.APPEND)])),
        key,
    )
    writer = _sign(
        _with_identity(make_root_gco(state_access_permissions=[StatePermission(namespace="memory", access_mode=AccessMode.WRITE)])),
        key,
    )
    runtime = GovernanceRuntime(_bundle(key), now=lambda: NOW)

    first = runtime.authorize_state_access(append, "log", AccessMode.APPEND)
    second = runtime.authorize_state_access(append, "log", AccessMode.APPEND)
    none_mode = runtime.authorize_state_access(writer, "memory", AccessMode.NONE)
    unknown_mode = runtime.authorize_state_access(writer, "memory", "bogus")

    assert first == Decision(allowed=True)
    assert second == first
    assert none_mode.allowed is False
    assert none_mode.reason == "none denied for namespace memory"
    assert none_mode.error_code is NamespaceAccessDenied
    assert unknown_mode.allowed is False
    assert unknown_mode.reason == "bogus denied for namespace memory"
    assert unknown_mode.error_code is NamespaceAccessDenied
    assert runtime.state_store._values == {}
    assert runtime.state_store._taints == {}


def test_authorize_state_access_write_requires_write_grant_not_append():
    key = _key()
    append_only = _sign(
        _with_identity(make_root_gco(state_access_permissions=[StatePermission(namespace="memory", access_mode=AccessMode.APPEND)])),
        key,
    )
    writer = _sign(
        _with_identity(make_root_gco(state_access_permissions=[StatePermission(namespace="memory", access_mode=AccessMode.WRITE)])),
        key,
    )
    runtime = GovernanceRuntime(_bundle(key), now=lambda: NOW)

    append_requests_write = runtime.authorize_state_access(append_only, "memory", AccessMode.WRITE)
    append_requests_append = runtime.authorize_state_access(append_only, "memory", AccessMode.APPEND)
    writer_requests_write = runtime.authorize_state_access(writer, "memory", AccessMode.WRITE)

    assert append_requests_write.allowed is False
    assert append_requests_write.reason == "write denied for namespace memory"
    assert append_requests_append.allowed is True
    assert writer_requests_write.allowed is True


@pytest.mark.parametrize("granted_mode", [AccessMode.NONE, AccessMode.READ, AccessMode.APPEND, AccessMode.WRITE])
@pytest.mark.parametrize("requested_mode", [AccessMode.READ, AccessMode.WRITE, AccessMode.APPEND])
def test_authorize_state_access_is_at_least_as_strict_as_store_permission_gate(
    granted_mode: AccessMode, requested_mode: AccessMode
):
    # The runtime gate requires granted_rank >= requested_rank (strict rank comparison).
    # The store's own write() gate is coarser (WRITE and APPEND grants can both call
    # write()), so the runtime must never be more permissive than the store, but it can
    # be stricter (e.g. an APPEND grant no longer satisfies a WRITE request here).
    key = _key()
    namespace = "memory"
    store = GovernedStateStore()
    seed_writer = _sign(
        _with_identity(make_root_gco(state_access_permissions=[StatePermission(namespace=namespace, access_mode=AccessMode.WRITE)])),
        key,
    )
    store.write(namespace, "existing", b"value", seed_writer)
    subject = _sign(
        _with_identity(make_root_gco(state_access_permissions=[StatePermission(namespace=namespace, access_mode=granted_mode)])),
        key,
    )
    runtime = GovernanceRuntime(_bundle(key), state_store=GovernedStateStore(), now=lambda: NOW)

    decision = runtime.authorize_state_access(subject, namespace, requested_mode)
    try:
        if requested_mode is AccessMode.READ:
            store.read(namespace, "existing", subject)
        else:
            store.write(namespace, f"{requested_mode.value}-{granted_mode.value}", b"value", subject)
    except NamespaceAccessDenied:
        store_allowed = False
    else:
        store_allowed = True

    if decision.allowed:
        assert store_allowed is True


def test_authorize_state_access_ungranted_namespace_reason():
    key = _key()
    gco = _sign(_with_identity(make_root_gco(state_access_permissions=[])), key)

    decision = GovernanceRuntime(_bundle(key), now=lambda: NOW).authorize_state_access(gco, "memory", "read")

    assert decision.allowed is False
    assert decision.error_code is NamespaceAccessDenied
    assert decision.reason == "namespace memory is not delegated"


def test_authorize_state_access_malformed_and_unexpected_errors_deny():
    class ExplodingVerifier:
        def verify(self, attestation, gco):
            raise RuntimeError("state boom")

    key = _key()
    gco = _sign(_with_identity(make_root_gco()), key)
    runtime = GovernanceRuntime(_bundle(key), now=lambda: NOW)

    malformed = runtime.authorize_state_access({"not": "a gco"}, "memory", "read")
    exploded = GovernanceRuntime(_bundle(key), verifier=ExplodingVerifier(), now=lambda: NOW).authorize_state_access(
        gco,
        "memory",
        "read",
    )

    assert malformed.allowed is False
    assert malformed.error_code is DerivationError.GCO_MALFORMED
    assert exploded.allowed is False
    assert exploded.error_code is DerivationError.GCO_MALFORMED
    assert exploded.reason == "state boom"


def test_authorize_state_access_unauthentic_denied_before_permission_check():
    trusted = _key()
    forged = _key()
    gco = _sign(_with_identity(make_root_gco(state_access_permissions=[])), forged, kid="forged")

    decision = GovernanceRuntime(_bundle(trusted), now=lambda: NOW).authorize_state_access(gco, "memory", "read")

    assert decision.allowed is False
    assert decision.error_code is AttestationError.UNTRUSTED_KEY
    assert decision.reason == "JWS key id is not trusted"


def test_derive_for_subcall_returns_verified_child_and_denies_expansion():
    key = _key()
    parent = _sign(_with_identity(make_root_gco()), key)
    runtime = GovernanceRuntime(_bundle(key), attestation_authority=SigningAuthority(key), now=lambda: NOW)
    valid_request = DelegationRequest(
        tool_authority=[ToolAuthority(tool_uri="https://tools.example/search", scope="read", max_depth=99)],
        state_access_permissions=[StatePermission(namespace="memory", access_mode=AccessMode.READ)],
        requested_expiry=NOW + timedelta(minutes=30),
    )
    expanding_request = DelegationRequest(
        tool_authority=[ToolAuthority(tool_uri="https://tools.example/search", scope="admin", max_depth=99)],
        requested_expiry=NOW + timedelta(minutes=30),
    )

    allowed = runtime.derive_for_subcall(parent, valid_request)
    denied = runtime.derive_for_subcall(parent, expanding_request)

    assert allowed.allowed is True
    assert allowed.child is not None
    assert runtime.authorize_subcall(parent, allowed.child).allowed is True
    assert denied.allowed is False
    assert denied.error_code is DerivationError.TOOL_AUTHORITY_EXPANDED
    assert denied.reason == DerivationError.TOOL_AUTHORITY_EXPANDED.value


def test_derive_for_subcall_uses_configured_clock_for_derivation_validation():
    key = _key()
    frozen_now = datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc)
    parent = _sign(
        _with_identity(make_root_gco()).model_copy(
            update={"expires_at": datetime(2025, 1, 1, tzinfo=timezone.utc)}
        ),
        key,
    )
    runtime = GovernanceRuntime(_bundle(key), attestation_authority=SigningAuthority(key), now=lambda: frozen_now)
    request = DelegationRequest(requested_expiry=datetime(2024, 6, 1, tzinfo=timezone.utc))

    decision = runtime.derive_for_subcall(parent, request)

    assert decision.allowed is True
    assert decision.child is not None
    assert decision.child.expires_at == request.requested_expiry


def test_derive_for_subcall_denies_untrusted_minted_attestation_and_missing_authority():
    trusted = _key()
    untrusted = _key()
    parent = _sign(_with_identity(make_root_gco()), trusted)
    request = DelegationRequest(
        tool_authority=[],
        state_access_permissions=[],
        requested_expiry=NOW + timedelta(minutes=30),
    )

    untrusted_decision = GovernanceRuntime(
        _bundle(trusted),
        attestation_authority=SigningAuthority(untrusted, kid="untrusted"),
        now=lambda: NOW,
    ).derive_for_subcall(parent, request)
    missing_authority = GovernanceRuntime(_bundle(trusted), now=lambda: NOW).derive_for_subcall(parent, request)

    assert untrusted_decision.allowed is False
    assert untrusted_decision.error_code is AttestationError.UNTRUSTED_KEY
    assert untrusted_decision.reason == "JWS key id is not trusted"
    assert missing_authority.allowed is False
    assert missing_authority.error_code is AttestationError.MALFORMED_ATTESTATION
    assert missing_authority.reason == "attestation authority is not configured"


def test_derive_for_subcall_denies_synthetic_never_attested_parent():
    key = _key()
    parent = _with_identity(make_root_gco()).model_copy(update={"attestation": None})
    runtime = GovernanceRuntime(_bundle(key), attestation_authority=SigningAuthority(key), now=lambda: NOW)
    request = DelegationRequest(
        tool_authority=[],
        state_access_permissions=[],
        requested_expiry=NOW + timedelta(minutes=30),
    )

    decision = runtime.derive_for_subcall(parent, request)

    assert decision.allowed is False
    assert decision.error_code is AttestationError.MALFORMED_ATTESTATION


def test_derive_for_subcall_denies_when_parent_attestation_untrusted():
    trusted = _key()
    forged = _key()
    parent = _sign(_with_identity(make_root_gco()), forged, kid="forged")
    runtime = GovernanceRuntime(_bundle(trusted), attestation_authority=SigningAuthority(trusted), now=lambda: NOW)
    request = DelegationRequest(
        tool_authority=[],
        state_access_permissions=[],
        requested_expiry=NOW + timedelta(minutes=30),
    )

    decision = runtime.derive_for_subcall(parent, request)

    assert decision.allowed is False
    assert decision.error_code is AttestationError.UNTRUSTED_KEY


def test_derive_for_subcall_malformed_request_unexpected_error_and_default_reason():
    class ExplodingAuthority:
        def issue(self, identity: str, gco_data: dict) -> AttestationModel:
            raise RuntimeError("derive boom")

    key = _key()
    parent = _sign(_with_identity(make_root_gco()), key)
    runtime = GovernanceRuntime(_bundle(key), attestation_authority=SigningAuthority(key), now=lambda: NOW)
    malformed = runtime.derive_for_subcall(parent, {"requested_expiry": "not a date"})
    exploded = GovernanceRuntime(_bundle(key), attestation_authority=ExplodingAuthority(), now=lambda: NOW).derive_for_subcall(
        parent,
        DelegationRequest(requested_expiry=NOW + timedelta(minutes=30)),
    )
    default_reason = runtime._deny(DerivationError.EXPIRED)

    assert malformed.allowed is False
    assert malformed.error_code is DerivationError.GCO_MALFORMED
    assert exploded.allowed is False
    assert exploded.error_code is DerivationError.GCO_MALFORMED
    assert exploded.reason == "derive boom"
    assert default_reason.reason == DerivationError.EXPIRED.value


def test_authorize_tool_call_requested_scope_subset_allowed_and_superset_denied():
    key = _key()
    parent = _sign(_with_identity(make_root_gco()), key)
    runtime = GovernanceRuntime(_bundle(key), now=lambda: NOW)

    subset = runtime.authorize_tool_call(parent, "https://tools.example/search", requested_scope="read")
    exact = runtime.authorize_tool_call(parent, "https://tools.example/search", requested_scope="read write")
    superset = runtime.authorize_tool_call(parent, "https://tools.example/search", requested_scope="admin")
    mixed = runtime.authorize_tool_call(parent, "https://tools.example/search", requested_scope="read admin")

    assert subset.allowed is True
    assert exact.allowed is True
    assert superset.allowed is False
    assert superset.error_code is DerivationError.TOOL_AUTHORITY_EXPANDED
    assert mixed.allowed is False
    assert mixed.error_code is DerivationError.TOOL_AUTHORITY_EXPANDED


def test_authorize_tool_call_requested_scope_requires_remaining_depth():
    key = _key()
    exhausted = _sign(
        _with_identity(
            make_root_gco(tool_authority=[ToolAuthority(tool_uri="https://tools.example/search", scope="read", max_depth=0)])
        ),
        key,
    )

    decision = GovernanceRuntime(_bundle(key), now=lambda: NOW).authorize_tool_call(
        exhausted, "https://tools.example/search", requested_scope="read"
    )

    assert decision.allowed is False
    assert decision.error_code is DerivationError.TOOL_AUTHORITY_EXPANDED


def test_authorize_subcall_denies_unattested_parent():
    trusted = _key()
    forged = _key()
    parent = _with_identity(make_root_gco())
    child = _sign(make_child_gco(parent), trusted)
    forged_parent = _sign(parent, forged, kid="forged")

    decision = GovernanceRuntime(_bundle(trusted), now=lambda: NOW).authorize_subcall(forged_parent, child)

    assert decision.allowed is False
    assert decision.error_code is AttestationError.UNTRUSTED_KEY


def test_derive_for_subcall_denies_unattested_parent():
    trusted = _key()
    forged = _key()
    parent = _sign(_with_identity(make_root_gco()), forged, kid="forged")
    runtime = GovernanceRuntime(_bundle(trusted), attestation_authority=SigningAuthority(trusted), now=lambda: NOW)

    decision = runtime.derive_for_subcall(parent, DelegationRequest(requested_expiry=NOW + timedelta(minutes=30)))

    assert decision.allowed is False
    assert decision.error_code is AttestationError.UNTRUSTED_KEY


def test_read_state_and_write_state_round_trip():
    key = _key()
    store = GovernedStateStore()
    writer = _sign(
        _with_identity(make_root_gco(state_access_permissions=[StatePermission(namespace="memory", access_mode=AccessMode.WRITE)])),
        key,
    )
    runtime = GovernanceRuntime(_bundle(key), state_store=store, now=lambda: NOW)

    written = runtime.write_state(writer, "memory", "answer", b"42")
    read = runtime.read_state(writer, "memory", "answer")

    assert written == Decision(allowed=True)
    assert read.allowed is True
    assert read.value == b"42"


def test_write_state_denies_read_only_grant_and_read_state_denies_undelegated():
    key = _key()
    store = GovernedStateStore()
    reader = _sign(
        _with_identity(make_root_gco(state_access_permissions=[StatePermission(namespace="memory", access_mode=AccessMode.READ)])),
        key,
    )
    runtime = GovernanceRuntime(_bundle(key), state_store=store, now=lambda: NOW)

    denied_write = runtime.write_state(reader, "memory", "answer", b"42")
    denied_read = runtime.read_state(reader, "missing", "answer")

    assert denied_write.allowed is False
    assert denied_write.error_code is NamespaceAccessDenied
    assert denied_read.allowed is False
    assert denied_read.error_code is NamespaceAccessDenied
    assert store._values == {}


def test_read_state_missing_key_and_write_state_unauthentic_deny():
    trusted = _key()
    forged = _key()
    store = GovernedStateStore()
    reader = _sign(
        _with_identity(make_root_gco(state_access_permissions=[StatePermission(namespace="memory", access_mode=AccessMode.READ)])),
        trusted,
    )
    forged_writer = _sign(
        _with_identity(make_root_gco(state_access_permissions=[StatePermission(namespace="memory", access_mode=AccessMode.WRITE)])),
        forged,
        kid="forged",
    )
    runtime = GovernanceRuntime(_bundle(trusted), state_store=store, now=lambda: NOW)

    missing = runtime.read_state(reader, "memory", "never-written")
    unauthentic = runtime.write_state(forged_writer, "memory", "answer", b"42")

    assert missing.allowed is False
    assert missing.error_code is NamespaceAccessDenied
    assert unauthentic.allowed is False
    assert unauthentic.error_code is AttestationError.UNTRUSTED_KEY
    assert store._values == {}


def test_read_state_unverified_attestation_denies_before_store_access():
    trusted = _key()
    forged = _key()
    store = GovernedStateStore()
    forged_reader = _sign(
        _with_identity(make_root_gco(state_access_permissions=[StatePermission(namespace="memory", access_mode=AccessMode.READ)])),
        forged,
        kid="forged",
    )

    decision = GovernanceRuntime(_bundle(trusted), state_store=store, now=lambda: NOW).read_state(
        forged_reader,
        "memory",
        "answer",
    )

    assert decision.allowed is False
    assert decision.error_code is AttestationError.UNTRUSTED_KEY
    assert store._values == {}


def test_read_state_tainted_and_unexpected_store_errors_deny():
    class ExplodingStore(GovernedStateStore):
        def read(self, namespace: str, key: str, gco: GCO) -> bytes:
            raise RuntimeError("read boom")

    key = _key()
    tainted_writer = _sign(
        _with_identity(
            make_root_gco(
                state_access_permissions=[
                    StatePermission(namespace="memory", access_mode=AccessMode.WRITE, taint_policy=TaintPolicy.TAINTED)
                ]
            )
        ),
        key,
    )
    clean_reader = _sign(
        _with_identity(
            make_root_gco(
                state_access_permissions=[
                    StatePermission(namespace="memory", access_mode=AccessMode.READ, taint_policy=TaintPolicy.CLEAN)
                ]
            )
        ),
        key,
    )
    store = GovernedStateStore()
    store.write("memory", "answer", b"42", tainted_writer)

    tainted = GovernanceRuntime(_bundle(key), state_store=store, now=lambda: NOW).read_state(clean_reader, "memory", "answer")
    exploded = GovernanceRuntime(_bundle(key), state_store=ExplodingStore(), now=lambda: NOW).read_state(
        clean_reader,
        "memory",
        "answer",
    )

    assert tainted.allowed is False
    assert tainted.error_code is TaintedStateRead
    assert exploded.allowed is False
    assert exploded.error_code is DerivationError.GCO_MALFORMED
    assert exploded.reason == "read boom"


def test_read_state_malformed_input_denies():
    key = _key()

    decision = GovernanceRuntime(_bundle(key), now=lambda: NOW).read_state({"not": "a gco"}, "memory", "answer")

    assert decision.allowed is False
    assert decision.error_code is DerivationError.GCO_MALFORMED


def test_write_state_store_denials_malformed_input_and_unexpected_error_deny():
    class DenyingStore(GovernedStateStore):
        def write(self, namespace: str, key: str, value: bytes, gco: GCO) -> None:
            raise NamespaceAccessDenied("store denied")

    class ExplodingStore(GovernedStateStore):
        def write(self, namespace: str, key: str, value: bytes, gco: GCO) -> None:
            raise RuntimeError("write boom")

    key = _key()
    reader = _sign(
        _with_identity(make_root_gco(state_access_permissions=[StatePermission(namespace="memory", access_mode=AccessMode.READ)])),
        key,
    )
    writer = _sign(
        _with_identity(make_root_gco(state_access_permissions=[StatePermission(namespace="memory", access_mode=AccessMode.WRITE)])),
        key,
    )

    auth_denied = GovernanceRuntime(_bundle(key), now=lambda: NOW).write_state(reader, "memory", "answer", b"42")
    store_denied = GovernanceRuntime(_bundle(key), state_store=DenyingStore(), now=lambda: NOW).write_state(
        writer,
        "memory",
        "answer",
        b"42",
    )
    malformed = GovernanceRuntime(_bundle(key), now=lambda: NOW).write_state({"not": "a gco"}, "memory", "answer", b"42")
    exploded = GovernanceRuntime(_bundle(key), state_store=ExplodingStore(), now=lambda: NOW).write_state(
        writer,
        "memory",
        "answer",
        b"42",
    )

    assert auth_denied.allowed is False
    assert auth_denied.error_code is NamespaceAccessDenied
    assert store_denied.allowed is False
    assert store_denied.error_code is NamespaceAccessDenied
    assert store_denied.reason == "store denied"
    assert malformed.allowed is False
    assert malformed.error_code is DerivationError.GCO_MALFORMED
    assert exploded.allowed is False
    assert exploded.error_code is DerivationError.GCO_MALFORMED
    assert exploded.reason == "write boom"
