from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from gco.runtime import GovernanceRuntime  # noqa: E402

from _support import (  # noqa: E402
    NOW,
    TOOL_URI,
    SigningAuthority,
    make_private_key,
    root_gco,
    sign,
    trust_bundle_for,
    valid_delegation_request,
)


def main() -> None:
    key = make_private_key()
    bundle = trust_bundle_for(key)
    runtime = GovernanceRuntime(bundle, attestation_authority=SigningAuthority(key), now=lambda: NOW)

    parent = sign(root_gco(), key)

    derived = runtime.derive_for_subcall(parent, valid_delegation_request())
    child = derived.child
    if child is None:
        raise SystemExit(f"derive denied: {derived}")

    subcall = runtime.authorize_subcall(parent, child)
    tool_call = runtime.authorize_tool_call(child, TOOL_URI, requested_scope="read")

    print(f"derive_for_subcall: {derived}")
    print(f"authorize_subcall: {subcall}")
    print(f"authorize_tool_call: {tool_call}")


if __name__ == "__main__":
    main()
