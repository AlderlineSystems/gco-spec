"""Independent adversarial audit of gco.state_store.GovernedStateStore.

Does NOT reuse repo test fixtures. Builds its own GCOs/permissions from scratch.
Run: python audit_state_attacks.py
PASS  = store behaved safely (rejected, or served only what the grant allows).
HOLE  = served something it should not, OR raised an UNCAUGHT exception
        (the contract: fail closed, never raise uncaught).
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from gco.models import AccessMode, AttestationModel, GCO, StatePermission, TaintPolicy
from gco.state_store import GovernedStateStore, NamespaceAccessDenied, TaintedStateRead

results: list[tuple[str, str, str]] = []


def record(name: str, ok: bool, detail: str) -> None:
    verdict = "INFO" if ok is None else ("PASS" if ok else "**HOLE**")
    results.append((name, verdict, detail))


def gco_with(*perms: StatePermission) -> GCO:
    return GCO(
        gco_version="1.0.0",
        trace_id=uuid4(),
        span_id=uuid4(),
        parent_span_id=None,
        policy_id="p",
        model_identity="spiffe://example.org/ns/default/sa/model-state-attacks",
        intervention_version="iv",
        tool_authority=[],
        state_access_permissions=list(perms),
        expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
        lineage=[],
        attestation=AttestationModel(format="jwt-svid", value="t"),
    )


# --- Attack 1: read a key that was never written (delegated namespace) ------
try:
    store = GovernedStateStore()
    g = gco_with(StatePermission(namespace="ns", access_mode=AccessMode.READ, taint_policy=TaintPolicy.CLEAN))
    out = store.read("ns", "never-written", g)
    record("read-missing-key", False, f"returned {out!r} for a key never written")
except (NamespaceAccessDenied, TaintedStateRead) as e:
    record("read-missing-key", True, f"controlled rejection: {type(e).__name__}")
except Exception as e:  # noqa: BLE001
    record("read-missing-key", False, f"UNCAUGHT {type(e).__name__}: {e}")


# --- Attack 2: get_taint on a key that was never written --------------------
try:
    store = GovernedStateStore()
    g = gco_with(StatePermission(namespace="ns", access_mode=AccessMode.READ, taint_policy=TaintPolicy.CLEAN))
    out = store.get_taint("ns", "never-written", g)
    record("get_taint-missing-key", False, f"returned {out!r} for a key never written")
except KeyError as e:
    record("get_taint-missing-key", False, f"UNCAUGHT KeyError: {e}")
except NamespaceAccessDenied as e:
    record("get_taint-missing-key", True, f"controlled rejection: {type(e).__name__}")
except Exception as e:  # noqa: BLE001
    record("get_taint-missing-key", False, f"UNCAUGHT {type(e).__name__}: {e}")


# --- Attack 3: taint laundering via overwrite -------------------------------
# A sub-call writes TAINTED. A different GCO with WRITE+CLEAN on the same
# namespace overwrites the same key. Does the stored taint stay >= tainted,
# or is it silently downgraded to clean and made readable?
try:
    store = GovernedStateStore()
    tainted_writer = gco_with(
        StatePermission(namespace="ns", access_mode=AccessMode.WRITE, taint_policy=TaintPolicy.TAINTED)
    )
    clean_writer = gco_with(
        StatePermission(namespace="ns", access_mode=AccessMode.WRITE, taint_policy=TaintPolicy.CLEAN)
    )
    store.write("ns", "k", b"secret", tainted_writer)          # quarantined
    store.write("ns", "k", b"laundered", clean_writer)         # overwrite as clean
    taint_after = store.get_taint("ns", "k", clean_writer)
    served = store.read("ns", "k", clean_writer)               # now readable?
    record(
        "taint-laundering-overwrite",
        False,
        f"taint after overwrite={taint_after.value!r}; read served {served!r} "
        f"(TAINTED data laundered to readable)",
    )
except TaintedStateRead:
    record("taint-laundering-overwrite", True, "read still blocked for taint after overwrite")
except Exception as e:  # noqa: BLE001
    record("taint-laundering-overwrite", False, f"UNCAUGHT {type(e).__name__}: {e}")


# --- Attack 4: unknown taint_policy at the read gate (fail-open?) ------------
# model_construct bypasses enum validation to inject an unknown taint value.
try:
    store = GovernedStateStore()
    bad = StatePermission.model_construct(namespace="ns", access_mode=AccessMode.WRITE, taint_policy="superbad")
    g = gco_with()  # start clean, then inject the malformed permission
    g = g.model_copy(update={"state_access_permissions": [bad]})
    store.write("ns", "k", b"x", g)
    served = store.read("ns", "k", g)
    record(
        "unknown-taint-read-gate",
        False,
        f"unknown taint {bad.taint_policy!r} served {served!r} at read (fail-OPEN; "
        f"not in TAINTED/ISOLATED set => treated readable)",
    )
except TaintedStateRead:
    record("unknown-taint-read-gate", True, "unknown taint treated as tainted (fail-closed)")
except Exception as e:  # noqa: BLE001
    record("unknown-taint-read-gate", False, f"UNCAUGHT {type(e).__name__}: {e}")


# --- Attack 5: unknown access_mode on write (fail-closed?) -------------------
try:
    store = GovernedStateStore()
    bad = StatePermission.model_construct(namespace="ns", access_mode="superuser", taint_policy=TaintPolicy.CLEAN)
    g = gco_with().model_copy(update={"state_access_permissions": [bad]})
    store.write("ns", "k", b"x", g)
    record("unknown-access-write", False, "write SUCCEEDED with unknown access_mode 'superuser'")
except NamespaceAccessDenied:
    record("unknown-access-write", True, "unknown access_mode denied write (fail-closed)")
except Exception as e:  # noqa: BLE001
    record("unknown-access-write", False, f"UNCAUGHT {type(e).__name__}: {e}")


# --- Attack 6: read a namespace never granted -------------------------------
try:
    store = GovernedStateStore()
    writer = gco_with(StatePermission(namespace="ns", access_mode=AccessMode.WRITE, taint_policy=TaintPolicy.CLEAN))
    store.write("ns", "k", b"x", writer)
    reader = gco_with(StatePermission(namespace="other", access_mode=AccessMode.READ))
    served = store.read("ns", "k", reader)
    record("read-undelegated-namespace", False, f"served {served!r} for an undelegated namespace")
except NamespaceAccessDenied:
    record("read-undelegated-namespace", True, "undelegated namespace denied")
except Exception as e:  # noqa: BLE001
    record("read-undelegated-namespace", False, f"UNCAUGHT {type(e).__name__}: {e}")


# --- Attack 7: namespace case-variance is not collapsed ----------------------
# Grant on "Memory"; attempt read on "memory". Safe = denied (no fold).
try:
    store = GovernedStateStore()
    writer = gco_with(StatePermission(namespace="Memory", access_mode=AccessMode.WRITE, taint_policy=TaintPolicy.CLEAN))
    store.write("Memory", "k", b"x", writer)
    reader = gco_with(StatePermission(namespace="memory", access_mode=AccessMode.READ))
    served = store.read("memory", "k", reader)
    record("namespace-case-variance", False, f"case-folded access served {served!r}")
except NamespaceAccessDenied:
    record("namespace-case-variance", True, "case-sensitive namespaces (no accidental fold) — denied")
except Exception as e:  # noqa: BLE001
    record("namespace-case-variance", False, f"UNCAUGHT {type(e).__name__}: {e}")


# --- Attack 8: sanitized data read by a clean-expecting reader --------------
# Sub-call writes SANITIZED. A reader granted CLEAN reads it. The reader's
# expected taint level is now enforced (alignment): a CLEAN-policy reader may
# not receive data whose stored taint rank exceeds its own grant's taint rank.
try:
    store = GovernedStateStore()
    sani_writer = gco_with(
        StatePermission(namespace="ns", access_mode=AccessMode.WRITE, taint_policy=TaintPolicy.SANITIZED)
    )
    clean_reader = gco_with(
        StatePermission(namespace="ns", access_mode=AccessMode.READ, taint_policy=TaintPolicy.CLEAN)
    )
    store.write("ns", "k", b"sanitized-bytes", sani_writer)
    served = store.read("ns", "k", clean_reader)
    record(
        "sanitized-read-by-clean-reader",
        False,
        f"clean reader received SANITIZED data {served!r}; taint alignment check did not fire",
    )
except TaintedStateRead:
    record("sanitized-read-by-clean-reader", True, "blocked for taint alignment")
except Exception as e:  # noqa: BLE001
    record("sanitized-read-by-clean-reader", False, f"UNCAUGHT {type(e).__name__}: {e}")


# --- Attack 9: ISOLATED read is rejected (parity with TAINTED) --------------
try:
    store = GovernedStateStore()
    g = gco_with(StatePermission(namespace="ns", access_mode=AccessMode.WRITE, taint_policy=TaintPolicy.ISOLATED))
    store.write("ns", "k", b"x", g)
    served = store.read("ns", "k", g)
    record("isolated-read", False, f"ISOLATED data served {served!r}")
except TaintedStateRead:
    record("isolated-read", True, "ISOLATED read blocked")
except Exception as e:  # noqa: BLE001
    record("isolated-read", False, f"UNCAUGHT {type(e).__name__}: {e}")


print(f"\n{'ATTACK':<34} {'RESULT':<10} DETAIL")
print("-" * 110)
holes = 0
for name, verdict, detail in results:
    if verdict == "**HOLE**":
        holes += 1
    print(f"{name:<34} {verdict:<10} {detail}")
print("-" * 110)
print(f"{holes} hole(s) found out of {len(results)} attacks "
      f"('None'/informational rows describe contract gaps, not crashes)")
