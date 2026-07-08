"""Independent adversarial audit of gco.validator.GCOValidator.

Does NOT import or reuse the repo's test fixtures (conftest). Builds its own
parent/child GCO pairs from scratch. Run with:  python audit_attacks.py
Each attack reports PASS (validator behaved safely) or **HOLE** (validator
returned valid=True when it should not, or raised an uncaught exception).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from pydantic import ValidationError

from gco.models import (
    AccessMode,
    AttestationModel,
    GCO,
    StatePermission,
    TaintPolicy,
    ToolAuthority,
)
from gco.validator import GCODerivationException, GCOValidator, canonical_gco_hash

TRACE = UUID("11111111-1111-4111-8111-111111111111")
PARENT_SPAN = UUID("22222222-2222-4222-8222-222222222222")
CHILD_SPAN = UUID("33333333-3333-4333-8333-333333333333")

results: list[tuple[str, str, str]] = []


def record(name: str, ok: bool, detail: str) -> None:
    results.append((name, "PASS" if ok else "**HOLE**", detail))


def build_parent(expires_at: datetime, **over) -> GCO:
    base = dict(
        gco_version="1.0.0",
        trace_id=TRACE,
        span_id=PARENT_SPAN,
        parent_span_id=None,
        policy_id="policy-x",
        model_identity="spiffe://example.org/ns/default/sa/model-x",
        intervention_version="iv-1",
        tool_authority=[ToolAuthority(tool_uri="https://t.example/a", scope="read write", max_depth=2)],
        state_access_permissions=[
            StatePermission(namespace="ns", access_mode=AccessMode.WRITE, taint_policy=TaintPolicy.SANITIZED)
        ],
        expires_at=expires_at,
        lineage=[],
        attestation=AttestationModel(format="jwt-svid", value="parent"),
    )
    base.update(over)
    return GCO(**base)


def build_child(parent: GCO, expires_at: datetime, **over) -> GCO:
    base = dict(
        gco_version=parent.gco_version,
        trace_id=parent.trace_id,
        span_id=CHILD_SPAN,
        parent_span_id=parent.span_id,
        policy_id=parent.policy_id,
        model_identity=parent.model_identity,
        intervention_version=parent.intervention_version,
        tool_authority=[ToolAuthority(tool_uri="https://t.example/a", scope="read", max_depth=1)],
        state_access_permissions=[
            StatePermission(namespace="ns", access_mode=AccessMode.READ, taint_policy=TaintPolicy.SANITIZED)
        ],
        expires_at=expires_at,
        lineage=[canonical_gco_hash(parent)],
        attestation=AttestationModel(format="jwt-svid", value="child"),
    )
    base.update(over)
    return GCO(**base)


V = GCOValidator()
FUTURE = datetime(2099, 1, 1, 12, 0, tzinfo=timezone.utc)
PAST = datetime(2000, 1, 1, 12, 0, tzinfo=timezone.utc)


# --- Attack 1: already-expired child (expires_at in the past, <= parent) ----
try:
    parent = build_parent(PAST)
    child = build_child(parent, PAST)  # already expired, not extended vs parent
    ok = V.validate(parent, child)
    # Safe behaviour would be a rejection (EXPIRED). valid=True here is a HOLE.
    record(
        "expired-child-in-past",
        ok is not True,
        f"validate returned {ok!r}; an already-expired credential (2000) was accepted",
    )
except GCODerivationException as e:
    record("expired-child-in-past", True, f"rejected with {e.error.name}")
except Exception as e:  # noqa: BLE001
    record("expired-child-in-past", False, f"uncaught {type(e).__name__}: {e}")


# --- Attack 2: max_depth smuggled as a string -------------------------------
try:
    parent = build_parent(FUTURE)
    child = build_child(
        parent, FUTURE,
        tool_authority=[ToolAuthority(tool_uri="https://t.example/a", scope="read", max_depth="1")],
    )
    ok = V.validate(parent, child)
    record("max_depth-as-string", ok is True, f"pydantic coerced '1'->1; validate={ok!r} (coercion, not bypass)")
except ValidationError:
    record("max_depth-as-string", True, "rejected at model construction (ValidationError)")
except Exception as e:  # noqa: BLE001
    record("max_depth-as-string", False, f"uncaught {type(e).__name__}: {e}")


# --- Attack 3: tool_authority as a dict where a list is expected ------------
try:
    parent = build_parent(FUTURE)
    child = build_child(parent, FUTURE, tool_authority={"tool_uri": "https://t.example/a"})
    ok = V.validate(parent, child)
    record("tool_authority-type-confusion", False, f"validate returned {ok!r} for malformed tool_authority")
except ValidationError:
    record("tool_authority-type-confusion", True, "rejected at model construction (ValidationError)")
except Exception as e:  # noqa: BLE001
    record("tool_authority-type-confusion", False, f"uncaught {type(e).__name__}: {e}")


# --- Attack 4: lineage correct length, wrong content digest -----------------
try:
    parent = build_parent(FUTURE)
    child = build_child(parent, FUTURE, lineage=["a" * 64])
    ok = V.validate(parent, child)
    record("lineage-wrong-digest", False, f"validate returned {ok!r} for forged digest")
except GCODerivationException as e:
    record("lineage-wrong-digest", e.error.name == "CANONICAL_HASH_MISMATCH", f"rejected with {e.error.name}")
except Exception as e:  # noqa: BLE001
    record("lineage-wrong-digest", False, f"uncaught {type(e).__name__}: {e}")


# --- Attack 5: canonical digest stability under key reorder / whitespace ----
try:
    parent = build_parent(FUTURE)
    h1 = canonical_gco_hash(parent)
    # rebuild an identical parent with permissions/tools given in different list order
    parent2 = build_parent(
        FUTURE,
        state_access_permissions=[
            StatePermission(namespace="ns", access_mode=AccessMode.WRITE, taint_policy=TaintPolicy.SANITIZED)
        ],
    )
    h2 = canonical_gco_hash(parent2)
    record("canonical-digest-stable", h1 == h2, f"h1==h2: {h1 == h2} (sort_keys makes ordering irrelevant)")
except Exception as e:  # noqa: BLE001
    record("canonical-digest-stable", False, f"uncaught {type(e).__name__}: {e}")


# --- Attack 6: expires_at malformed / non-ISO string ------------------------
try:
    parent = build_parent(FUTURE)
    child = build_child(parent, "not-a-date")
    ok = V.validate(parent, child)
    record("expires_at-malformed", False, f"validate returned {ok!r} for non-ISO expiry")
except ValidationError:
    record("expires_at-malformed", True, "rejected at model construction (ValidationError)")
except Exception as e:  # noqa: BLE001
    record("expires_at-malformed", False, f"uncaught {type(e).__name__}: {e}")


# --- Attack 7: permissions/tools passed as None instead of [] ---------------
try:
    parent = build_parent(FUTURE)
    child = build_child(parent, FUTURE, state_access_permissions=None)
    ok = V.validate(parent, child)
    record("permissions-none", False, f"validate returned {ok!r} for None permissions")
except ValidationError:
    record("permissions-none", True, "rejected at model construction (ValidationError)")
except Exception as e:  # noqa: BLE001
    record("permissions-none", False, f"uncaught {type(e).__name__}: {e}")


# --- Attack 8: non-root child (non-empty lineage) with parent_span_id=None ---
# Build via model_construct so we bypass the Optional check and test the validator directly.
try:
    parent = build_parent(FUTURE)
    child = build_child(parent, FUTURE)
    forged = child.model_copy(update={"parent_span_id": None})
    ok = V.validate(parent, forged)
    record("nonroot-parentspan-none", False, f"validate returned {ok!r}; None parent_span_id accepted")
except GCODerivationException as e:
    record("nonroot-parentspan-none", e.error.name == "PARENT_LINKAGE_INVALID", f"rejected with {e.error.name}")
except Exception as e:  # noqa: BLE001
    record("nonroot-parentspan-none", False, f"uncaught {type(e).__name__}: {e}")


# --- Attack 9: spec-mandated attestation format tpm-quote --------------------
# Spec contract requires format in {jwt-svid, x509-svid, raw-jws, tpm-quote}.
try:
    parent = build_parent(FUTURE)
    child = build_child(parent, FUTURE, attestation=AttestationModel(format="tpm-quote", value="c"))
    ok = V.validate(parent, child)
    record("attestation-tpm-quote", ok is True, f"accepted tpm-quote: validate={ok!r}")
except ValidationError:
    record(
        "attestation-tpm-quote", False,
        "REJECTED at model construction: spec requires "
        "{jwt-svid,x509-svid,raw-jws,tpm-quote}",
    )
except Exception as e:  # noqa: BLE001
    record("attestation-tpm-quote", False, f"uncaught {type(e).__name__}: {e}")


# --- Attack 10: child expiry far in the past but parent expiry in future -----
# This is the canonical "expiry-vs-now" regression: child <= parent, but child
# is already dead. Safe = reject.
try:
    parent = build_parent(FUTURE)
    child = build_child(parent, PAST)  # PAST < parent FUTURE, so EXPIRY_EXTENDED won't fire
    ok = V.validate(parent, child)
    record(
        "expiry-vs-now-independent",
        ok is not True,
        f"validate returned {ok!r}; child expiring in 2000 accepted under a 2031 parent",
    )
except GCODerivationException as e:
    record("expiry-vs-now-independent", True, f"rejected with {e.error.name}")
except Exception as e:  # noqa: BLE001
    record("expiry-vs-now-independent", False, f"uncaught {type(e).__name__}: {e}")


print(f"\n{'ATTACK':<32} {'RESULT':<10} DETAIL")
print("-" * 100)
holes = 0
for name, verdict, detail in results:
    if verdict == "**HOLE**":
        holes += 1
    print(f"{name:<32} {verdict:<10} {detail}")
print("-" * 100)
print(f"{holes} hole(s) found out of {len(results)} attacks "
      f"(note: 'None' verdicts are informational contract-drift findings)")
