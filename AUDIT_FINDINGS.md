# Adversarial Audit — `src/gco/validator.py`

**Date:** 2026-06-13 · **Scope:** validator security logic + test suite quality · **Mode:** historical audit.

> **Resolution note:** the fix passes after this audit addressed the blocking findings and the later low-severity `validate_result()` raw-dict robustness gap. Current status: `73 passed` with 100% branch coverage, `audit_attacks.py` reports 0 holes, and `audit_fuzz.py` reports 20,000 randomized authority-expansion attempts with 0 accepted and 0 uncaught exceptions. The fixes added `EXPIRED` with an injected validator clock, aligned attestation formats to `{jwt-svid, x509-svid, raw-jws, tpm-quote}`, removed the unreachable attestation-format validator branch in favor of raw payload parsing, added `validate_result()`, mapped malformed raw payloads to `GCO_MALFORMED`, added in-repo randomized authority tests, added root-shape validation tests, closed schema/model taint-policy drift, and made rank-map drift fail closed.

**Reproduced build claim:** `51 passed`, **100% branch coverage** (validator.py: 99 stmts / 40 branches, 0 missing). The number is real. It does not mean what it appears to mean — see below.

---

## (a) DerivationError → code-path map

| Error code | Returning path | Status |
|---|---|---|
| `VERSION_MISMATCH` | validator.py:82 | reachable ✓ tested ✓ |
| `TRACE_ID_CHANGED` | :86 | reachable ✓ tested ✓ |
| `POLICY_ID_CHANGED` | :88 | reachable ✓ tested ✓ |
| `MODEL_IDENTITY_CHANGED` | :90 | reachable ✓ tested ✓ |
| `INTERVENTION_CHANGED` | :92 | reachable ✓ tested ✓ |
| `PARENT_LINKAGE_INVALID` | :96 | reachable ✓ tested ✓ |
| `LINEAGE_APPEND_FAILED` | :102 | reachable ✓ tested ✓ |
| `LINEAGE_FLOODED` | :100 | reachable ✓ tested ✓ |
| `MAX_DEPTH_INCREASED` | :113 | reachable ✓ tested ✓ |
| `TOOL_AUTHORITY_EXPANDED` | :111, :115 | reachable ✓ tested ✓ |
| `STATE_PERMISSION_EXPANDED` | :122, :124 | reachable ✓ tested ✓ |
| `TAINT_DOWNGRADED` | :126 | reachable ✓ tested ✓ |
| `EXPIRY_EXTENDED` | :130 | reachable ✓ tested ✓ |
| `ATTESTATION_MISSING` | :134 | reachable ✓ tested ✓ |
| `ATTESTATION_FORMAT_INVALID` | :136 | **effectively UNREACHABLE** via the validated data path |
| `CANONICAL_HASH_MISMATCH` | :104 | reachable ✓ tested ✓ |
| **`EXPIRED` (expiry-vs-now)** | **— none —** | **MISSING: no constant, no check, no test** |

### Dead / missing error paths
- **`ATTESTATION_FORMAT_INVALID` — defined but unreachable in production.** `_validate_attestation` checks `isinstance(child.attestation.format, AttestationFormat)`. Because `AttestationModel.format` is a strict Pydantic enum, any validated GCO *always* has a valid enum member, so the `isinstance` is always True and the branch is never taken. The only thing that reaches it is `test_validator.py:96`, which uses `AttestationModel.model_construct(format="raw", ...)` to **bypass Pydantic validation** and manufacture a state the real system cannot produce. 100% branch coverage here is an artifact of a validation-bypassing test, not evidence the check guards anything reachable.
- **`EXPIRED` / expiry-vs-now — does not exist.** The spec's "must not already be in the past relative to an injected `now`" check is entirely absent. `_validate_expiry` (validator.py:128-130) only compares `child.expires_at > parent.expires_at`. There is no `now` parameter anywhere in the validator, no `EXPIRED` enum constant, and no test. This is not dead code that was wired up — it was never implemented.

---

## (b) Assertion quality — tests that assert only "valid is False"

The validator is **exception-based**, not result-object-based: `validate()` returns `True` or raises `GCODerivationException(error=...)`. There is no `result.valid` / `result.error_code`. Every negative test asserts the **specific** error (`exc_info.value.error is DerivationError.X`), so there are **no weak "only valid is False" assertions** — good.

Two caveats that the strong-looking assertions mask:
1. The one path proven only through a `model_construct` bypass (`ATTESTATION_FORMAT_INVALID`, above). Its assertion is specific but tests an unreachable state.
2. **API-shape deviation from the stated contract.** The contract says fail-closed = "`valid=False` with a specific error code." The implementation never returns `valid=False`; it raises. That is fail-closed *only if every caller wraps the call in try/except*. A caller writing `if validator.validate(p, c): ...` crashes on rejection rather than getting a `False`. Acceptable if documented, but it is not the contract as described.

Isolation spot-checks (confirmed each test fires on its *named* check, not an earlier one): `LINEAGE_FLOODED` (129 entries hits the length guard first), `CANONICAL_HASH_MISMATCH` (passes append checks, fails digest), `TAINT_DOWNGRADED` (access check passes, taint fails), `STATE_PERMISSION_EXPANDED` (access fires before taint). All correct.

---

## (c) Independent attacks — `audit_attacks.py` (own fixtures, no conftest reuse)

| Attack | Result | Notes |
|---|---|---|
| already-expired child (expires 2000, == parent) | **HOLE** | `validate` returned `True` — an already-dead credential accepted |
| **child expires 2000 under a 2031 parent** | **HOLE** | `validate` returned `True` — proves no independent now-check |
| max_depth as string `"1"` | pass | Pydantic coerces `"1"→1`; not a bypass |
| tool_authority as dict not list | pass | rejected at model construction |
| lineage correct-length / forged digest | pass | `CANONICAL_HASH_MISMATCH` |
| canonical digest stability (reorder) | pass | `sort_keys` makes ordering irrelevant |
| expires_at malformed / non-ISO | pass | rejected at model construction |
| permissions = None instead of `[]` | pass | rejected at model construction |
| non-root child, parent_span_id = None | pass | `PARENT_LINKAGE_INVALID` (parent.span_id is a mandatory UUID, so None≠UUID) |
| spec attestation format `tpm-quote` | **HOLE (contract drift)** | rejected — see (f) |

**Net: 1 real security hole** (the already-expired credential, shown two ways) **+ 1 contract-drift hole** (attestation format set). No uncaught exceptions on in-model inputs.

---

## (d) The three regression tests + the fuzz test

1. **Expiry-vs-now → `EXPIRED`** — **ABSENT.** No check, no error code, no test. `audit_attacks.py` proves a child expiring in the year 2000 validates `True` under a 2031 parent. **Refuted.**
2. **Unknown enum fails closed (validator-level, incl. unknown-taint-vs-clean-parent)** — **ABSENT at the validator.** There is no unknown-enum `DerivationError` and no validator test. Fail-closed for unknown enums happens only at the Pydantic/JSON-schema layer (`test_schema.py:29-45` rejects unknown enums via jsonschema, and `StrictBaseModel` rejects them at construction). The validator's `ACCESS_RANK[...]` / `TAINT_RANK[...]` dict lookups would `KeyError` (uncaught) if a new enum member were ever added without updating the rank maps — a latent fail-*open*-to-crash, not a clean rejection. The specific requested test does not exist.
3. **Root-linkage None==None for non-roots** — **not exploitable, but untested and under-enforced.** Because `GCO.span_id` is a mandatory (non-Optional) UUID, a parent always has a real span_id, so `child.parent_span_id (None) != parent.span_id (UUID)` rejects correctly (verified in `audit_attacks.py`). However: (i) there is no dedicated test for it, and (ii) the validator never enforces the full standalone invariant "root iff `lineage==[]` AND `parent_span_id is None`" — it only does pairwise linkage equality. A malformed root is caught incidentally by the lineage-append check, not by an explicit root rule.
4. **Fuzz / property test** — **DOES NOT EXIST** in the repo (no `hypothesis`, no `random`, no property test; grep-confirmed). I wrote one (`audit_fuzz.py`): 20,000 randomized authority-expanding/malformed children. Result: **0 expansions accepted, 0 uncaught exceptions.** The tool/scope/access/taint tightening core is robust; the fuzzer does not exercise the expiry hole because that requires time, not authority, manipulation.

---

## (e) Reproduced coverage output

```
Name                     Stmts   Miss Branch BrPart  Cover   Missing
--------------------------------------------------------------------
src/gco/__init__.py          6      0      0      0   100%
src/gco/der_harness.py      87      0     26      0   100%
src/gco/derivation.py       60      0     20      0   100%
src/gco/models.py           53      0      2      0   100%
src/gco/state_store.py      34      0     12      0   100%
src/gco/validator.py        99      0     40      0   100%
--------------------------------------------------------------------
TOTAL                      339      0    100      0   100%
Required test coverage of 100.0% reached. Total coverage: 100.00%
51 passed in 0.32s
```
No branch appears in `term-missing`. **This is exactly the trap:** 100% branch coverage proves every *existing* branch ran. It cannot reveal the **missing** expiry-vs-now branch (you can't cover a branch that was never written), and it rewarded a validation-bypassing test for "covering" an otherwise-unreachable attestation branch.

---

## (f) Layer-boundary & contract findings

- **`der_harness.py`** imports no model/LLM client (only `gco.models.GCO`), takes its judge as an injected `Callable`, and does static transcript scoring with no recursive-input or prompt generation. **Boundary clean.** ✓
- **Tightening logic location.** All authority/lineage/expiry/attestation tightening lives in `validator.py` (and is re-applied in `derivation.py` for minting). It was **not** smuggled into Pydantic model validators — `models.py` contains only a UTC-format check on `expires_at`. ✓
- **`models.py` ↔ `schemas/gco_schema_v1.json` round-trip.** `test_schema.py:19` validates the example through both and asserts a dump→validate→dump round-trip equality, and would fail on divergence of the *example*. **Gap:** it only exercises a fully-populated example. Schema marks `taint_policy` **required**; `models.py:50` gives it a default (`TaintPolicy.CLEAN`). A model-valid GCO that omits `taint_policy` would be **schema-invalid**, and the round-trip test would not catch it. Minor, but a real drift the test cannot see.
- **Attestation contract drift (security-relevant).** Spec requires `format ∈ {jwt-svid, x509-svid, raw-jws, tpm-quote}`. Implementation (`models.py:11-14` and the JSON schema) defines `{jwt-svid, dsse, cose}`. Consequences: (i) spec-legitimate attestations (`x509-svid`, `raw-jws`, `tpm-quote`) are **rejected**; (ii) formats the spec never sanctioned (`dsse`, `cose`) are **accepted**. The implementation is internally consistent (models == schema) but **diverges from the SSL-TS-2026-001 contract**.
- **Attestation honesty.** The code does presence + enum-membership only and does **not** claim or imply signature verification; README explicitly scopes crypto verification as not implemented. **Honestly scoped.** ✓

---

## (g) Verdict

**Not release-ready as a security-critical component.** The authority-tightening core (tools, scope, access mode, taint, lineage, canonical hashing) is genuinely solid and survived 20k fuzz iterations. But three defects block release:

1. **CRITICAL — expiry-vs-now is unimplemented.** An already-expired GCO validates `True` (proven). The "previously dead code" was not revived; it is simply missing — no `now`, no `EXPIRED` code, no test. A credential expired years ago passes.
2. **HIGH — attestation format contract drift.** Wrong format set; rejects spec-valid attestations and accepts spec-invalid ones.
3. **MEDIUM — coverage theatre around `ATTESTATION_FORMAT_INVALID`.** A real-world-unreachable branch is marked covered only because a test uses `model_construct` to bypass validation. The "100% / 51 tests" headline gives false assurance.

**Secondary gaps to close in the fix pass:** no fuzz/property test in-repo; no validator-level unknown-enum handling (latent `KeyError` if enums grow); no explicit standalone root-linkage invariant and no test for it; schema/model `taint_policy` required-vs-default drift; and the exception-based API does not match the documented `valid=False`/`error_code` fail-closed contract.

Fixing is out of scope for this pass per instructions.
