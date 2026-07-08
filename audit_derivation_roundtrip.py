"""Round-trip property audit of gco.derivation.GCODerivationRuntime.

Property 1 (agreement): every child the runtime RETURNS must pass
    validator.validate(parent, child).  Derivation and validation must not
    disagree.
Property 2 (fail-first): an authority-EXPANDING request must be REFUSED by the
    runtime (GCODerivationException) -- it must be impossible to get an
    expansion returned that the validator would later catch.

Also directly probes lineage-append and parent_span_id linkage on returned
children. Does NOT reuse repo fixtures. Run: python audit_derivation_roundtrip.py
"""
from __future__ import annotations

import random
from datetime import datetime, timezone
from uuid import uuid4

from gco.models import (
    AccessMode,
    AttestationModel,
    GCO,
    StatePermission,
    TaintPolicy,
    ToolAuthority,
)
from gco.derivation import DelegationRequest, GCODerivationRuntime
from gco.validator import GCODerivationException, GCOValidator, _access_allows, canonical_gco_hash

ACCESS = [AccessMode.NONE, AccessMode.READ, AccessMode.APPEND, AccessMode.WRITE]
TAINT = [TaintPolicy.CLEAN, TaintPolicy.SANITIZED, TaintPolicy.TAINTED, TaintPolicy.ISOLATED]
TOOL = "https://tools.example/a"
PARENT_EXP = datetime(2099, 1, 1, tzinfo=timezone.utc)
REQ_EXP = datetime(2098, 1, 1, tzinfo=timezone.utc)  # <= parent, > now


class Authority:
    def issue(self, identity: str, gco_data: dict) -> AttestationModel:
        return AttestationModel(format="jwt-svid", value=f"issued:{identity}")


def make_parent(rng: random.Random) -> GCO:
    return GCO(
        gco_version="1.0.0",
        trace_id=uuid4(),
        span_id=uuid4(),
        parent_span_id=None,
        policy_id="p",
        model_identity="spiffe://example.org/ns/default/sa/model-derivation",
        intervention_version="iv",
        tool_authority=[ToolAuthority(tool_uri=TOOL, scope="read write admin", max_depth=rng.randint(1, 6))],
        state_access_permissions=[
            StatePermission(namespace="ns", access_mode=rng.choice(ACCESS[1:]), taint_policy=rng.choice(TAINT))
        ],
        expires_at=PARENT_EXP,
        lineage=[f"{i:064x}" for i in range(rng.randint(0, 3))],
        attestation=AttestationModel(format="jwt-svid", value="parent"),
    )


def tightening_request(parent: GCO, rng: random.Random) -> DelegationRequest:
    pp = parent.state_access_permissions[0]
    p_taint = TAINT.index(pp.taint_policy)
    allowed_access = [access_mode for access_mode in ACCESS if _access_allows(pp.access_mode, access_mode)]
    return DelegationRequest(
        tool_authority=[ToolAuthority(tool_uri=TOOL, scope="read", max_depth=0)],
        state_access_permissions=[
            StatePermission(
                namespace="ns",
                access_mode=rng.choice(allowed_access),
                taint_policy=TAINT[rng.randint(p_taint, len(TAINT) - 1)],  # >= parent
            )
        ],
        requested_expiry=REQ_EXP,
    )


def expanding_request(parent: GCO, rng: random.Random) -> DelegationRequest:
    pp = parent.state_access_permissions[0]
    p_access = ACCESS.index(pp.access_mode)
    p_taint = TAINT.index(pp.taint_policy)
    kind = rng.choice(["new_tool", "scope", "access", "taint", "namespace"])
    tools = [ToolAuthority(tool_uri=TOOL, scope="read", max_depth=0)]
    perms = [StatePermission(namespace="ns", access_mode=AccessMode.NONE, taint_policy=pp.taint_policy)]
    if kind == "new_tool":
        tools = [ToolAuthority(tool_uri="https://tools.example/UNKNOWN", scope="read", max_depth=0)]
    elif kind == "scope":
        tools = [ToolAuthority(tool_uri=TOOL, scope="read write admin root", max_depth=0)]
    elif kind == "access" and p_access < 3:
        perms = [StatePermission(namespace="ns", access_mode=ACCESS[rng.randint(p_access + 1, 3)], taint_policy=pp.taint_policy)]
    elif kind == "taint" and p_taint > 0:
        perms = [StatePermission(namespace="ns", access_mode=AccessMode.NONE, taint_policy=TAINT[rng.randint(0, p_taint - 1)])]
    elif kind == "namespace":
        perms = [StatePermission(namespace="UNKNOWN", access_mode=AccessMode.READ, taint_policy=TaintPolicy.ISOLATED)]
    else:  # access/taint not expandable for this parent -> fall back to new_tool
        tools = [ToolAuthority(tool_uri="https://tools.example/UNKNOWN", scope="read", max_depth=0)]
    return DelegationRequest(tool_authority=tools, state_access_permissions=perms, requested_expiry=REQ_EXP)


def main() -> None:
    rng = random.Random(424242)
    runtime = GCODerivationRuntime(Authority())
    validator = GCOValidator()  # default clock; parent/child expiries are far future

    c = {"returned": 0, "disagree": 0, "expansion_leaked": 0, "refused": 0,
         "uncaught": 0, "lineage_bad": 0, "linkage_bad": 0, "over_refused": 0}
    examples: list[str] = []

    def note(kind: str, msg: str) -> None:
        c[kind] += 1
        if len(examples) < 8:
            examples.append(f"[{kind}] {msg}")

    N = 20000
    for i in range(N):
        parent = make_parent(rng)
        expanding = (i % 2 == 0)
        req = expanding_request(parent, rng) if expanding else tightening_request(parent, rng)
        try:
            child = runtime.derive(parent, req)
        except GCODerivationException:
            c["refused"] += 1
            if not expanding:
                c["over_refused"] += 1
            continue
        except Exception as e:  # noqa: BLE001
            note("uncaught", f"{type(e).__name__}: {e}")
            continue

        c["returned"] += 1
        # Property 1: returned child must validate
        try:
            ok = validator.validate(parent, child)
            if ok is not True:
                note("disagree", f"validate returned {ok!r}")
        except GCODerivationException as e:
            note("disagree", f"runtime returned a child the validator REJECTS: {e.error.name}")
        # Property 2: an expanding request must never produce a returned child
        if expanding:
            note("expansion_leaked", "expanding request produced a returned child")
        # lineage append + linkage on returned child
        if child.lineage[-1] != canonical_gco_hash(parent) or child.lineage[:-1] != parent.lineage:
            note("lineage_bad", "returned child lineage does not append parent digest")
        if child.parent_span_id != parent.span_id:
            note("linkage_bad", "returned child parent_span_id != parent.span_id")

    print(f"iterations: {N}")
    for k, v in c.items():
        print(f"  {k:18}: {v}")
    for ex in examples:
        print("   ", ex)
    bad = (
        c["disagree"]
        + c["expansion_leaked"]
        + c["uncaught"]
        + c["lineage_bad"]
        + c["linkage_bad"]
        + c["over_refused"]
    )
    print("RESULT:", "PASS" if bad == 0 else f"**FAIL** ({bad} property violations)")
    if bad:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
