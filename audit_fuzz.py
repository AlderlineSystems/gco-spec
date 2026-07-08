"""Property/fuzz test the repo lacks. Generates authority-expanding and
malformed children and asserts the validator NEVER returns valid=True for an
authority expansion and NEVER raises an uncaught (non-GCODerivationException)
exception for an in-model input. Run: python audit_fuzz.py
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from pydantic import ValidationError

from gco.models import AccessMode, AttestationModel, GCO, StatePermission, TaintPolicy, ToolAuthority
from gco.validator import GCODerivationException, GCOValidator, canonical_gco_hash

ACCESS = [AccessMode.NONE, AccessMode.READ, AccessMode.APPEND, AccessMode.WRITE]
TAINT = [TaintPolicy.CLEAN, TaintPolicy.SANITIZED, TaintPolicy.TAINTED, TaintPolicy.ISOLATED]
ARANK = {m: i for i, m in enumerate(ACCESS)}
TRANK = {t: i for i, t in enumerate(TAINT)}
FUTURE = datetime(2099, 1, 1, tzinfo=timezone.utc)
V = GCOValidator()


def rand_parent(rng: random.Random) -> GCO:
    return GCO(
        gco_version="1.0.0",
        trace_id=uuid4(),
        span_id=uuid4(),
        parent_span_id=None,
        policy_id="p",
        model_identity="spiffe://example.org/ns/default/sa/model-fuzz",
        intervention_version="iv",
        tool_authority=[ToolAuthority(tool_uri="https://t.example/a", scope="read write admin", max_depth=rng.randint(1, 5))],
        state_access_permissions=[StatePermission(namespace="ns", access_mode=rng.choice(ACCESS), taint_policy=rng.choice(TAINT))],
        expires_at=FUTURE,
        lineage=[],
        attestation=AttestationModel(format="jwt-svid", value="p"),
    )


def expanded_child(parent: GCO, rng: random.Random) -> tuple[GCO, bool]:
    """Return (child, is_expansion). is_expansion=True means the child grants
    strictly more authority than parent on at least one axis."""
    pt = parent.tool_authority[0]
    pp = parent.state_access_permissions[0]
    expansion = False

    # authority-expanding choices
    new_depth = pt.max_depth - 1
    if rng.random() < 0.4:
        new_depth = rng.randint(pt.max_depth, pt.max_depth + 3)  # too deep
        expansion = True
    scope = "read"
    if rng.random() < 0.3:
        scope = "read write admin root"  # superset
        expansion = True
    am = AccessMode.NONE if ARANK[pp.access_mode] == 0 else ACCESS[rng.randint(0, ARANK[pp.access_mode])]
    if rng.random() < 0.3 and ARANK[pp.access_mode] < 3:
        am = ACCESS[rng.randint(ARANK[pp.access_mode] + 1, 3)]  # higher access
        expansion = True
    tp = pp.taint_policy
    if rng.random() < 0.3 and TRANK[pp.taint_policy] > 0:
        tp = TAINT[rng.randint(0, TRANK[pp.taint_policy] - 1)]  # downgrade taint
        expansion = True

    tools = [ToolAuthority(tool_uri="https://t.example/a", scope=scope, max_depth=max(new_depth, 0))]
    if rng.random() < 0.15:
        tools.append(ToolAuthority(tool_uri="https://t.example/new", scope="read", max_depth=0))  # new tool
        expansion = True

    child = GCO(
        gco_version=parent.gco_version,
        trace_id=parent.trace_id,
        span_id=uuid4(),
        parent_span_id=parent.span_id,
        policy_id=parent.policy_id,
        model_identity=parent.model_identity,
        intervention_version=parent.intervention_version,
        tool_authority=tools,
        state_access_permissions=[StatePermission(namespace="ns", access_mode=am, taint_policy=tp)],
        expires_at=parent.expires_at,
        lineage=[canonical_gco_hash(parent)],
        attestation=AttestationModel(format="jwt-svid", value="c"),
    )
    # new_depth<0 forced to 0 may accidentally be valid; recompute expansion for depth
    if new_depth > pt.max_depth - 1:
        expansion = True
    return child, expansion


def main() -> None:
    rng = random.Random(1337)
    N = 20000
    expansion_accepted = 0
    uncaught = 0
    examples: list[str] = []
    for _ in range(N):
        parent = rand_parent(rng)
        try:
            child, is_exp = expanded_child(parent, rng)
        except ValidationError:
            continue  # malformed at construction = fail-closed at model layer
        try:
            ok = V.validate(parent, child)
            if is_exp and ok is True:
                expansion_accepted += 1
                if len(examples) < 3:
                    examples.append(
                        f"depth p={parent.tool_authority[0].max_depth} c={child.tool_authority[0].max_depth} "
                        f"scope={child.tool_authority[0].scope!r} access p={parent.state_access_permissions[0].access_mode.value} "
                        f"c={child.state_access_permissions[0].access_mode.value}"
                    )
        except GCODerivationException:
            pass  # expected rejection path
        except Exception as e:  # noqa: BLE001
            uncaught += 1
            if len(examples) < 3:
                examples.append(f"UNCAUGHT {type(e).__name__}: {e}")

    print(f"iterations:            {N}")
    print(f"authority expansions accepted (valid=True): {expansion_accepted}")
    print(f"uncaught exceptions:   {uncaught}")
    for ex in examples:
        print("  example:", ex)
    bad = expansion_accepted + uncaught
    print("RESULT:", "PASS" if bad == 0 else "**FAIL**")
    if bad:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
