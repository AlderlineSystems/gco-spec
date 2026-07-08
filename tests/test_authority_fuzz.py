from __future__ import annotations

import random
from datetime import timedelta
from uuid import uuid4

from gco.models import AccessMode, AttestationModel, GCO, StatePermission, TaintPolicy, ToolAuthority
from gco.validator import GCODerivationException, GCOValidator, canonical_gco_hash
from conftest import BASE_TIME


ACCESS = [AccessMode.NONE, AccessMode.READ, AccessMode.APPEND, AccessMode.WRITE]
TAINT = [TaintPolicy.CLEAN, TaintPolicy.SANITIZED, TaintPolicy.TAINTED, TaintPolicy.ISOLATED]
ACCESS_RANK = {mode: index for index, mode in enumerate(ACCESS)}
TAINT_RANK = {policy: index for index, policy in enumerate(TAINT)}


def _random_parent(rng: random.Random) -> GCO:
    return GCO(
        gco_version="1.0.0",
        trace_id=uuid4(),
        span_id=uuid4(),
        parent_span_id=None,
        policy_id="policy",
        model_identity="spiffe://example.org/model/fuzz",
        intervention_version="intervention",
        tool_authority=[
            ToolAuthority(
                tool_uri="https://tools.example/fuzz",
                scope="read write admin",
                max_depth=rng.randint(1, 5),
            )
        ],
        state_access_permissions=[
            StatePermission(
                namespace="ns",
                access_mode=rng.choice(ACCESS),
                taint_policy=rng.choice(TAINT),
            )
        ],
        expires_at=BASE_TIME,
        lineage=[],
        attestation=AttestationModel(format="jwt-svid", value="parent"),
    )


def _random_child(parent: GCO, rng: random.Random) -> tuple[GCO, bool]:
    parent_tool = parent.tool_authority[0]
    parent_permission = parent.state_access_permissions[0]
    is_expansion = False

    max_depth = parent_tool.max_depth - 1
    if rng.random() < 0.35:
        max_depth = rng.randint(parent_tool.max_depth, parent_tool.max_depth + 3)
        is_expansion = True

    scope = "read"
    if rng.random() < 0.35:
        scope = "read write admin root"
        is_expansion = True

    parent_access_rank = ACCESS_RANK[parent_permission.access_mode]
    access_mode = ACCESS[rng.randint(0, parent_access_rank)]
    if rng.random() < 0.35 and parent_access_rank < len(ACCESS) - 1:
        access_mode = ACCESS[rng.randint(parent_access_rank + 1, len(ACCESS) - 1)]
        is_expansion = True

    parent_taint_rank = TAINT_RANK[parent_permission.taint_policy]
    taint_policy = TAINT[rng.randint(parent_taint_rank, len(TAINT) - 1)]
    if rng.random() < 0.35 and parent_taint_rank > 0:
        taint_policy = TAINT[rng.randint(0, parent_taint_rank - 1)]
        is_expansion = True

    tools = [ToolAuthority(tool_uri=parent_tool.tool_uri, scope=scope, max_depth=max_depth)]
    if rng.random() < 0.15:
        tools.append(ToolAuthority(tool_uri="https://tools.example/new", scope="read", max_depth=0))
        is_expansion = True

    child = GCO(
        gco_version=parent.gco_version,
        trace_id=parent.trace_id,
        span_id=uuid4(),
        parent_span_id=parent.span_id,
        policy_id=parent.policy_id,
        model_identity=parent.model_identity,
        intervention_version=parent.intervention_version,
        tool_authority=tools,
        state_access_permissions=[
            StatePermission(namespace="ns", access_mode=access_mode, taint_policy=taint_policy)
        ],
        expires_at=parent.expires_at,
        lineage=[canonical_gco_hash(parent)],
        attestation=AttestationModel(format="jwt-svid", value="child"),
    )
    return child, is_expansion


def test_randomized_authority_expansions_never_validate():
    rng = random.Random(1337)
    validator = GCOValidator(now=lambda: BASE_TIME - timedelta(days=1))

    for _ in range(2000):
        parent = _random_parent(rng)
        child, is_expansion = _random_child(parent, rng)
        try:
            valid = validator.validate(parent, child)
        except GCODerivationException:
            continue

        assert valid is True
        assert not is_expansion
