"""Fuzz the runtime enforcement seam.

Oracle: allowed=True implies the child is authentic and non-expanding.
Run: python audit_runtime_fuzz.py
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from gco.models import AccessMode, AttestationFormat, AttestationModel, GCO, StatePermission, TaintPolicy, ToolAuthority
from gco.runtime import GovernanceRuntime
from gco.trust import TrustBundle
from gco.validator import ACCESS_RANK, TAINT_RANK, canonical_gco_hash

NOW = datetime(2099, 1, 1, 12, 0, tzinfo=timezone.utc)
SPIFFE_ID = "spiffe://example.org/ns/default/sa/model-alpha"
ACCESS = [AccessMode.NONE, AccessMode.READ, AccessMode.APPEND, AccessMode.WRITE]
TAINT = [TaintPolicy.CLEAN, TaintPolicy.SANITIZED, TaintPolicy.TAINTED, TaintPolicy.ISOLATED]


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


TRUSTED_KEY = _key()
FORGED_KEY = _key()


def _jwk(private_key, kid: str) -> dict:
    payload = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    payload.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return payload


BUNDLE = TrustBundle.from_mapping({"example.org": {"jwks": {"keys": [_jwk(TRUSTED_KEY, "trusted")]}}})
RUNTIME = GovernanceRuntime(BUNDLE, now=lambda: NOW)


def _attestation(gco: GCO, *, authentic: bool) -> AttestationModel:
    key = TRUSTED_KEY if authentic else FORGED_KEY
    kid = "trusted" if authentic else "forged"
    token = jwt.encode(
        {
            "sub": gco.model_identity,
            "gco_hash": canonical_gco_hash(gco),
            "exp": int((NOW + timedelta(hours=1)).timestamp()),
        },
        key,
        algorithm="RS256",
        headers={"kid": kid},
    )
    return AttestationModel(format=AttestationFormat.JWT_SVID, value=token)


def rand_parent(rng: random.Random) -> GCO:
    parent = GCO(
        gco_version="1.0.0",
        trace_id=uuid4(),
        span_id=uuid4(),
        parent_span_id=None,
        policy_id="p",
        model_identity=SPIFFE_ID,
        intervention_version="iv",
        tool_authority=[ToolAuthority(tool_uri="https://tools.example/a", scope="read write admin", max_depth=rng.randint(1, 5))],
        state_access_permissions=[StatePermission(namespace="ns", access_mode=rng.choice(ACCESS), taint_policy=rng.choice(TAINT))],
        expires_at=NOW + timedelta(days=1),
        lineage=[],
        attestation=None,
    )
    return parent.model_copy(update={"attestation": _attestation(parent, authentic=True)})


def rand_child(parent: GCO, rng: random.Random, *, authentic: bool, expanding: bool) -> GCO:
    parent_tool = parent.tool_authority[0]
    parent_permission = parent.state_access_permissions[0]
    scope = "read"
    depth = parent_tool.max_depth - 1
    access = ACCESS[rng.randint(0, ACCESS_RANK[parent_permission.access_mode])]
    taint = TAINT[rng.randint(TAINT_RANK[parent_permission.taint_policy], len(TAINT) - 1)]
    tools = [ToolAuthority(tool_uri=parent_tool.tool_uri, scope=scope, max_depth=depth)]
    permissions = [StatePermission(namespace="ns", access_mode=access, taint_policy=taint)]

    if expanding:
        choice = rng.randrange(5)
        if choice == 0:
            tools = [ToolAuthority(tool_uri=parent_tool.tool_uri, scope="read write admin root", max_depth=depth)]
        elif choice == 1:
            tools = [ToolAuthority(tool_uri=parent_tool.tool_uri, scope=scope, max_depth=parent_tool.max_depth)]
        elif choice == 2:
            tools.append(ToolAuthority(tool_uri="https://tools.example/new", scope="read", max_depth=0))
        elif choice == 3 and ACCESS_RANK[parent_permission.access_mode] < ACCESS_RANK[AccessMode.WRITE]:
            permissions = [
                StatePermission(
                    namespace="ns",
                    access_mode=ACCESS[ACCESS_RANK[parent_permission.access_mode] + 1],
                    taint_policy=taint,
                )
            ]
        elif TAINT_RANK[parent_permission.taint_policy] > TAINT_RANK[TaintPolicy.CLEAN]:
            permissions = [
                StatePermission(
                    namespace="ns",
                    access_mode=access,
                    taint_policy=TAINT[TAINT_RANK[parent_permission.taint_policy] - 1],
                )
            ]
        else:
            tools = [ToolAuthority(tool_uri=parent_tool.tool_uri, scope=scope, max_depth=parent_tool.max_depth)]

    child = GCO(
        gco_version=parent.gco_version,
        trace_id=parent.trace_id,
        span_id=uuid4(),
        parent_span_id=parent.span_id,
        policy_id=parent.policy_id,
        model_identity=parent.model_identity,
        intervention_version=parent.intervention_version,
        tool_authority=tools,
        state_access_permissions=permissions,
        expires_at=parent.expires_at,
        lineage=[*parent.lineage, canonical_gco_hash(parent)],
        attestation=None,
    )
    return child.model_copy(update={"attestation": _attestation(child, authentic=authentic)})


def main() -> None:
    rng = random.Random(20260617)
    iterations = 20000
    unauthentic_allowed = 0
    expansion_allowed = 0
    uncaught = 0
    examples: list[str] = []

    for _ in range(iterations):
        authentic = rng.random() < 0.5
        expanding = rng.random() < 0.5
        try:
            parent = rand_parent(rng)
            child = rand_child(parent, rng, authentic=authentic, expanding=expanding)
            decision = RUNTIME.authorize_subcall(parent, child)
            if decision.allowed and not authentic:
                unauthentic_allowed += 1
                if len(examples) < 3:
                    examples.append("unauthentic child allowed")
            if decision.allowed and expanding:
                expansion_allowed += 1
                if len(examples) < 3:
                    examples.append("expanding child allowed")
        except Exception as exc:  # noqa: BLE001
            uncaught += 1
            if len(examples) < 3:
                examples.append(f"UNCAUGHT {type(exc).__name__}: {exc}")

    print(f"iterations:            {iterations}")
    print(f"unauthentic allowed:   {unauthentic_allowed}")
    print(f"expansions allowed:    {expansion_allowed}")
    print(f"uncaught exceptions:   {uncaught}")
    for example in examples:
        print("  example:", example)
    print("RESULT:", "PASS" if unauthentic_allowed == 0 and expansion_allowed == 0 and uncaught == 0 else "**FAIL**")


if __name__ == "__main__":
    main()
