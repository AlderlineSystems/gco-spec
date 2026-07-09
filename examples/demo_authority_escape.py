from __future__ import annotations

import sys
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from gco.models import ToolAuthority  # noqa: E402
from gco.runtime import GovernanceRuntime  # noqa: E402
from gco.validator import canonical_gco_hash  # noqa: E402

from _support import NOW, TOOL_URI, make_private_key, root_gco, sign, trust_bundle_for  # noqa: E402


def naive_ungoverned_delegation(child_scope: str) -> bool:
    """A host that only forwards a sub-call request can silently widen authority."""
    return "admin" in child_scope.split()


def main() -> None:
    key = make_private_key()
    runtime = GovernanceRuntime(trust_bundle_for(key), now=lambda: NOW)

    parent = sign(root_gco(), key)
    malicious_child = parent.model_copy(
        update={
            "span_id": uuid4(),
            "parent_span_id": parent.span_id,
            "tool_authority": [ToolAuthority(tool_uri=TOOL_URI, scope="admin delete", max_depth=0)],
            "lineage": [*parent.lineage, canonical_gco_hash(parent)],
            "attestation": None,
        }
    )
    malicious_child = sign(malicious_child, key)

    governed = runtime.authorize_subcall(parent, malicious_child)
    naive_allowed = naive_ungoverned_delegation(malicious_child.tool_authority[0].scope)

    print("Delegated child requested widened scope: admin delete")
    print(f"Naive ungoverned delegation allowed? {naive_allowed}")
    print(f"GovernanceRuntime decision: {governed}")

    if naive_allowed is not True:
        raise SystemExit("demo invariant failed: naive path should allow the widened request")
    if governed.allowed is not False:
        raise SystemExit("demo invariant failed: GovernanceRuntime should deny the widened request")


if __name__ == "__main__":
    main()
