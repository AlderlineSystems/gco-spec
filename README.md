# GCO Reference Implementation

Reference Python implementation for the Sovereign Safety Labs SSL-TS-2026-001 GCO derivation contract.

## Components

1. `src/gco/models.py` defines the strict Pydantic data model.
2. `src/gco/validator.py` validates child GCOs against parent GCOs. The existing `validate()` API returns `True` or raises `GCODerivationException`; `validate_result()` returns a `ValidationResult(valid=False, error_code=...)` for callers that prefer non-throwing fail-closed handling, including malformed raw payloads via `GCO_MALFORMED`.
3. `src/gco/derivation.py` mints tightened child GCOs from delegation requests.
4. `src/gco/state_store.py` enforces namespace ACLs and taint labels.
5. `src/gco/der_harness.py` scores pre-recorded recursive transcripts.

## Development

```bash
python -m pip install -e ".[test]"
pytest --cov=src/gco --cov-branch --cov-report=term-missing
```

The intended build order is validator, derivation runtime, state store, then DER harness. Each phase is covered by focused tests in `tests/`.

## Taint Handling

The state store enforces a binary quarantine gate: `clean` and `sanitized` state may be read, while `tainted`, `isolated`, and unknown or unrankable taint labels fail closed. Stored taint is monotonic across overwrites, so later writes cannot launder a key back to a lower taint rank.

Reader-vs-data taint alignment beyond that quarantine gate is not enforced by `src/gco/state_store.py`; grant-time validation in `src/gco/validator.py` owns taint narrowing today. Per-read alignment may be added as future work if the spec requires it.

## Cryptographic Verification

The supported attestation formats are `jwt-svid`, `x509-svid`, `raw-jws`, and `tpm-quote`.

`jwt-svid` and `x509-svid` attestations are cryptographically verified by `src/gco/attestation.py` against an offline `TrustBundle`: signature or chain trust, SPIFFE identity binding, canonical GCO digest binding, and expiry are checked before the runtime seam allows authority to be used.

`raw-jws` and `tpm-quote` are declared formats but are not cryptographically verified by this reference implementation. They fail closed as unsupported at the verifier/runtime seam until a dedicated verifier exists.
