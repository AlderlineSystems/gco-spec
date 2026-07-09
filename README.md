# GCO Reference Implementation

Governance scoped to a single model forward pass does not automatically cover
recursive or delegated computation. A Governance Context Object (GCO) is the
authority-propagation primitive that travels with the call tree: each child
context must be attested, linked to its parent, and no broader than the authority
it inherited.

This repository is the reference Python implementation of the GCO concept from
the position paper **"The Recursion Blindspot."** The bundled JSON Schema is the
implementation-facing contract for serialized GCOs.

The schema identifier
`https://alderlinesystems.com/schemas/gco_schema_v1.json` is the JSON Schema
namespace. The URL should be hosted or resolved separately when the namespace is
made externally fetchable.

## Components

1. `src/gco/models.py` defines the strict Pydantic data model.
2. `src/gco/validator.py` validates child GCOs against parent GCOs. The existing `validate()` API returns `True` or raises `GCODerivationException`; `validate_result()` returns a `ValidationResult(valid=False, error_code=...)` for callers that prefer non-throwing fail-closed handling, including malformed raw payloads via `GCO_MALFORMED`. Tool depth may only shrink: a child can request a lower `max_depth`, but never more than the parent's remaining depth.
3. `src/gco/derivation.py` mints tightened child GCOs from delegation requests. Requested tool depth is capped to the parent's remaining depth, immutable parent fields are copied from the shared validator field set, and `attestation_identity` overrides are rejected; children are validated before attestation and attested for the parent's `model_identity`.
4. `src/gco/state_store.py` enforces namespace ACLs and taint labels.
5. `src/gco/trust.py` loads offline trust bundles for SPIFFE trust domains.
6. `src/gco/attestation.py` verifies supported attestations against those bundles.
7. `src/gco/runtime.py` composes verification, validation, derivation, and state access behind `Decision`-returning authorization methods.
8. `src/gco/der_harness.py` implements the paper's Differential Evaluation under Recursion (DER) / governance-coverage scoring proposal for pre-recorded recursive transcripts. It is instrumentation, not an attack generator.

## Usage quickstart

Run the checked example:

```bash
python examples/quickstart.py
```

The example loads a `TrustBundle`, constructs `GovernanceRuntime`, derives and
authorizes a delegated sub-call, and authorizes a scoped tool call:

```python
from gco.runtime import GovernanceRuntime

from examples._support import (
    NOW,
    TOOL_URI,
    SigningAuthority,
    make_private_key,
    root_gco,
    sign,
    trust_bundle_for,
    valid_delegation_request,
)

key = make_private_key()
bundle = trust_bundle_for(key)
runtime = GovernanceRuntime(bundle, attestation_authority=SigningAuthority(key), now=lambda: NOW)

parent = sign(root_gco(), key)
derived = runtime.derive_for_subcall(parent, valid_delegation_request())
child = derived.child

subcall = runtime.authorize_subcall(parent, child)
tool_call = runtime.authorize_tool_call(child, TOOL_URI, requested_scope="read")

print(subcall)
print(tool_call)
```

Expected decisions:

```text
Decision(allowed=True, ...)
Decision(allowed=True, ...)
```

For the authority-escape contrast, run:

```bash
python examples/demo_authority_escape.py
```

It shows a delegated child attempting to widen `read summarize` authority into
`admin delete`: naive ungoverned delegation would allow the request, while
`GovernanceRuntime.authorize_subcall()` denies it.

## Development

```bash
python -m pip install -e ".[test]"
pytest --cov=src/gco --cov-branch --cov-report=term-missing -q
```

The intended build order is validator, derivation runtime, state store, then DER harness. Each phase is covered by focused tests in `tests/`.

Model and schema URI fields intentionally accept generic URI schemes, including
SPIFFE IDs and URNs, rather than only HTTP(S) URLs.

## Project status

This repository is prepared for public open-source review, but some release
operations remain maintainer-owned: publishing the schema namespace URL,
publishing the updated position paper, and changing repository visibility.

Historical audit reports live in `docs/audits/`; all listed findings are
resolved, and the current validation posture is represented by the pytest
coverage gate and the root-level `audit_*.py` harnesses.

## Taint Handling

The state store enforces a binary quarantine gate: `clean` and `sanitized` state may be read, while `tainted`, `isolated`, and unknown or unrankable taint labels fail closed. Stored taint is monotonic across overwrites, so later writes cannot launder a key back to a lower taint rank.

Per-read reader-vs-data taint alignment is enforced in `src/gco/state_store.py`: a reader may only receive data whose stored taint rank is no higher than its own grant. Grant-time validation in `src/gco/validator.py` still owns taint narrowing at delegation time.

## Cryptographic Verification

The supported attestation formats are `jwt-svid`, `x509-svid`, `raw-jws`, and `tpm-quote`.

`jwt-svid` and `x509-svid` attestations are cryptographically verified by `src/gco/attestation.py` against an offline `TrustBundle`: signature or chain trust, SPIFFE identity binding, canonical GCO digest binding, and expiry are checked before the runtime seam allows authority to be used.

`raw-jws` and `tpm-quote` are declared formats but are not cryptographically verified by this reference implementation. They fail closed as unsupported at the verifier/runtime seam until a dedicated verifier exists.

Trust bundles may be loaded from a mapping or JSON file shaped as either
`{"trust_domains": {"example.org": {...}}}` or directly as
`{"example.org": {...}}`. Each trust-domain entry may include a `jwks` (or
`jwk_set`) object for `jwt-svid` verification and `ca_certs` (or
`ca_certificates`) as PEM certificates for `x509-svid` chain validation.

## Security enforcement

**Use `GovernanceRuntime` as the authority gate.** The package also exports `GCOValidator`, `GovernedStateStore`, `GCODerivationRuntime`, and `AttestationVerifier` for testing and composition, but calling them directly bypasses attestation verification. Production hosts should route tool calls, sub-call authorization, derivation, and state access through `GovernanceRuntime` methods (`authorize_tool_call`, `authorize_subcall`, `derive_for_subcall`, `read_state`, `write_state`). Use `write_state(..., mode=AccessMode.APPEND)` for append-only writes; the default `AccessMode.WRITE` remains required for overwrite-capable writes.

**State access is two-step by design.** `authorize_state_access()` checks ACL grants only; `read_state()` / `write_state()` also enforce per-key taint at access time. `AccessMode.APPEND` allows creating new keys but does not grant reads or overwrites; `AccessMode.WRITE` grants read, append, and overwrite authority. Do not call `GovernedStateStore` directly from host code.

**Attestation verification limits.** JWT verification pins algorithms to the trusted key type, binds attestations to `canonical_gco_hash(gco)`, and checks `exp`, `nbf`, and `iat` against the injected clock. `aud` (audience) is not verified (`verify_aud: False`), and there is no revocation or `jti` replay cache — a valid `(GCO, attestation)` pair may be replayed until expiry.
