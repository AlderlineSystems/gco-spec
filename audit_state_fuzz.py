"""Fuzz gco.state_store.GovernedStateStore against an independent oracle.

Random sequences of writes/reads across namespaces with random (and some
malformed) access/taint values. Independent shadow model decides what a read
SHOULD return. Flags:
  - access_violation : store served a read the grant forbids
  - taint_violation  : store served data whose CURRENT taint is tainted/isolated
  - laundering       : store served data whose key was EVER written tainted/isolated
                       (the 'taint only rises' invariant)
  - uncaught         : store raised something other than NamespaceAccessDenied/
                       TaintedStateRead

Run: python audit_state_fuzz.py
"""
from __future__ import annotations

import random
from datetime import datetime, timezone
from uuid import uuid4

from gco.models import AccessMode, AttestationModel, GCO, StatePermission, TaintPolicy
from gco.state_store import GovernedStateStore, NamespaceAccessDenied, TaintedStateRead

ACCESS = [AccessMode.NONE, AccessMode.READ, AccessMode.APPEND, AccessMode.WRITE]
TAINT = [TaintPolicy.CLEAN, TaintPolicy.SANITIZED, TaintPolicy.TAINTED, TaintPolicy.ISOLATED]
TAINT_RANK = {t: i for i, t in enumerate(TAINT)}
READ_OK = {AccessMode.READ, AccessMode.WRITE}
WRITE_OK = {AccessMode.WRITE, AccessMode.APPEND}
BLOCKED_TAINT = {TaintPolicy.TAINTED, TaintPolicy.ISOLATED}
NAMESPACES = ["a", "b", "c"]
KEYS = ["k1", "k2"]


def make_gco(perm: StatePermission) -> GCO:
    return GCO(
        gco_version="1.0.0",
        trace_id=uuid4(),
        span_id=uuid4(),
        parent_span_id=None,
        policy_id="p",
        model_identity="spiffe://example.org/ns/default/sa/model-state-fuzz",
        intervention_version="iv",
        tool_authority=[],
        state_access_permissions=[perm],
        expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
        lineage=[],
        attestation=AttestationModel(format="jwt-svid", value="t"),
    )


def random_permission(rng: random.Random) -> StatePermission:
    ns = rng.choice(NAMESPACES)
    # 8% malformed access, 8% malformed taint via model_construct (validation bypass)
    access = rng.choice(ACCESS)
    taint = rng.choice(TAINT)
    malformed = rng.random()
    if malformed < 0.08:
        return StatePermission.model_construct(namespace=ns, access_mode="weird", taint_policy=taint)
    if malformed < 0.16:
        return StatePermission.model_construct(namespace=ns, access_mode=access, taint_policy="weird")
    return StatePermission(namespace=ns, access_mode=access, taint_policy=taint)


def main() -> None:
    rng = random.Random(20260613)
    store = GovernedStateStore()
    # shadow: (ns,key) -> current taint ; and max taint rank ever written
    current_taint: dict[tuple[str, str], TaintPolicy] = {}
    written: set[tuple[str, str]] = set()
    ever_tainted: set[tuple[str, str]] = set()

    counts = {"access_violation": 0, "taint_violation": 0, "laundering": 0, "uncaught": 0,
              "writes_ok": 0, "reads_served": 0, "controlled_reject": 0}
    examples: list[str] = []

    def note(kind: str, msg: str) -> None:
        counts[kind] += 1
        if len(examples) < 6:
            examples.append(f"[{kind}] {msg}")

    N = 20000
    for _ in range(N):
        perm = random_permission(rng)
        g = make_gco(perm)
        ns = perm.namespace
        key = rng.choice(KEYS)
        sk = (ns, key)

        if rng.random() < 0.5:
            # WRITE
            try:
                store.write(ns, key, b"v", g)
                # store accepted -> shadow update mirrors store semantics
                written.add(sk)
                current_taint[sk] = perm.taint_policy
                if perm.taint_policy in BLOCKED_TAINT:
                    ever_tainted.add(sk)
                counts["writes_ok"] += 1
                # was this write something the grant should forbid?
                if perm.access_mode not in WRITE_OK:
                    note("access_violation", f"write accepted with access={perm.access_mode!r} on {sk}")
            except NamespaceAccessDenied:
                pass
            except Exception as e:  # noqa: BLE001
                note("uncaught", f"write {sk} access={perm.access_mode!r}: {type(e).__name__}")
        else:
            # READ
            try:
                out = store.read(ns, key, g)
                counts["reads_served"] += 1
                # store served a value: judge it against the oracle
                if perm.access_mode not in READ_OK:
                    note("access_violation", f"read served with access={perm.access_mode!r} on {sk}")
                cur = current_taint.get(sk)
                if cur in BLOCKED_TAINT:
                    note("taint_violation", f"read served CURRENT-tainted {sk} taint={cur}")
                elif sk in ever_tainted:
                    note("laundering", f"read served {sk} that was once tainted; now taint={cur}")
            except (NamespaceAccessDenied, TaintedStateRead):
                counts["controlled_reject"] += 1
            except Exception as e:  # noqa: BLE001
                note("uncaught", f"read {sk} access={perm.access_mode!r}: {type(e).__name__}")

    print(f"iterations: {N}")
    for k, v in counts.items():
        print(f"  {k:18}: {v}")
    print("examples:")
    for ex in examples:
        print("   ", ex)
    bad = counts["access_violation"] + counts["taint_violation"] + counts["laundering"] + counts["uncaught"]
    print("RESULT:", "PASS" if bad == 0 else f"**FAIL** ({bad} contract violations)")
    if bad:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
