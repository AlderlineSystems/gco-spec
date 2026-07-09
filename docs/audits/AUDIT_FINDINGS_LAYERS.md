# Historical Audit — `state_store.py` and `derivation.py`

> **HISTORICAL — ALL FINDINGS RESOLVED.** This report is archived for
> engineering traceability. Its original failure language below is no longer
> the current release posture; the audit harnesses still gate CI.

**Date:** 2026-06-13 · **Mode:** audit findings below are historical; `state_store.py` blockers are now resolved (see resolution note) · **Method:** same as the validator audit (per-path reachability, independent attacks, ≥20k fuzz, round-trip property).

> **Resolution note (state_store.py):** the three release-blocking findings — uncaught `KeyError` on missing-key `read`/`get_taint`, taint laundering via overwrite, and unknown-`taint_policy` failing open at the read gate — were fixed and independently re-verified. The fix: missing keys now raise a controlled `StateKeyNotFound(NamespaceAccessDenied)` instead of `KeyError`; write taint is monotonic high-water-mark (`stored = max(existing, writer)` by rank, reusing `validator._taint_rank` — no lattice duplication) so a once-tainted key stays quarantined through clean overwrites; and the read gate is rank-based, failing closed on unrankable values. A later fix also added per-read reader-vs-data taint alignment: a reader can only receive data whose stored taint rank is no higher than its own grant. Current status: the full pytest suite remains at 100% branch coverage; `audit_state_attacks.py` reports 0 holes, and `audit_state_fuzz.py` reports 20,000 iterations with 0 access / 0 taint / 0 laundering / 0 uncaught. **state_store.py verdict flips from NOT release-ready → release-ready.** The `derivation.py` low-severity flags (immutable-set duplication, attestation-minted-before-validate) remain open.

**Reproduced build claim:** `73 passed`, **100% branch coverage**, nothing in `term-missing`. Confirmed. As with the validator, 100% branch coverage proves every *existing* branch ran; it does not prove the assertions encode the contract, and it cannot flag a missing check (e.g. a `KeyError` path that is a bare dict access, not a branch).

Independent harnesses (repo root, **not** collected by pytest — `testpaths=["tests"]`):
`audit_state_attacks.py`, `audit_state_fuzz.py`, `audit_derivation_roundtrip.py`.

---

## PART 1 — `state_store.py` (GovernedStateStore) — ~~NOT release-ready~~ → **RESOLVED, release-ready** (findings below are historical; see resolution note at top)

### (a) Rejection-path → code → test map

| Reject reason | Code | Test | Assertion quality |
|---|---|---|---|
| namespace not delegated | `_permission_for` raise, [state_store.py:45](src/gco/state_store.py:45) | `test_write_rejects_missing_namespace` | type only (`NamespaceAccessDenied`) |
| write denied (access ∉ {write,append}) | [:21-22](src/gco/state_store.py:21) | `test_write_rejects_none_access` | type only |
| append denied (key exists) | [:24-25](src/gco/state_store.py:24) | `test_append_allows_new_key_and_rejects_existing_key` | type only |
| read denied (access ∉ {read,write}) | [:31-32](src/gco/state_store.py:31) | `test_read_rejects_none_access` | type only |
| tainted read (taint ∈ {tainted,isolated}) | [:34-35](src/gco/state_store.py:34) | `test_read_rejects_tainted_state` | type (`TaintedStateRead`) — distinct from ACL ✓ |

**Historical flags:**
- **Taint-vs-ACL is distinguishable** (two exception classes) — good. **But the three ACL sub-reasons all collapse to `NamespaceAccessDenied`** with only the message differing, and **no test asserts the message**. A write rejected for the *wrong* ACL reason (e.g. "not delegated" when the test intends "append denied") passes. The task's exact concern.
- **`ISOLATED` read rejection is not independently asserted** — only `TAINTED` is tested; `ISOLATED` rides the same set-membership branch. (My attack confirms it does reject — see below — but no repo test pins it.)
- **No test exists** for: reading a delegated-but-unwritten key, `get_taint` on a missing key, taint downgrade via overwrite, or unknown-enum taint at the read gate. These are the uncovered-by-assertion holes that 100% branch coverage hides.

### (b) Taint-propagation probe

- Sub-call writes `TAINTED` → any later read is **blocked with `TaintedStateRead`** (taint reason specifically). ✓ — the documented quarantine works for *currently*-tainted data.
- **Historical:** the original audited store consulted only the stored (writer) taint, never the reader's. Current code also checks reader-vs-data alignment, so `SANITIZED` data is denied to a `CLEAN`-only reader.

### (c) Independent attacks — `audit_state_attacks.py` (own fixtures)

| Attack | Result | Detail |
|---|---|---|
| read a delegated key never written | **HOLE** | `UNCAUGHT KeyError ('ns','never-written')` — `self._taints[sk]` / `self._values[sk]` at [:34/:36] |
| `get_taint` on missing key | **HOLE** | `UNCAUGHT KeyError` at [:39] |
| taint laundering via overwrite | **HOLE** | write `TAINTED` then overwrite with `WRITE+CLEAN` → stored taint = `clean`, read serves `b'laundered'`. "Taint only rises" not enforced on write. |
| unknown `taint_policy` at read gate | **HOLE** | injected `"superbad"` → not in {tainted,isolated} ⇒ **served** (fail-OPEN) |
| unknown `access_mode` on write | PASS | denied (membership test fails closed) |
| read undelegated namespace | PASS | denied |
| namespace case-variance (`Memory` vs `memory`) | **HOLE** | namespaces are case-sensitive (correct), but the read leaks `UNCAUGHT KeyError` instead of a clean denial — same root cause as missing-key |
| sanitized data → clean reader | resolved | now rejected by reader-vs-data taint alignment |
| `ISOLATED` read | PASS | blocked |

### (d) Fuzz — `audit_state_fuzz.py`, **20,000 iterations**, independent oracle

```
access_violation : 0
taint_violation  : 0     (current-taint gate is sound)
laundering       : 4085  (served data on keys once written tainted/isolated)
uncaught         : 14    (KeyError on reading delegated-but-unwritten keys)
RESULT: **FAIL** (4099 contract violations)
```
The current-taint gate and the access gate never leaked. The two systemic failures are **uncaught `KeyError`** and **taint laundering** — both reproduced thousands of times, not corner cases.

### state_store.py verdict — **NOT release-ready**
Specific gaps, in severity order:
1. **Uncaught `KeyError`** on `read`/`get_taint` of any delegated-but-unwritten key. Violates "never raise an uncaught exception." Expected: controlled rejection; Actual: `KeyError` leaks.
2. **Taint laundering**: a lower-taint write silently downgrades a key's taint label; quarantined data becomes readable. The "taint only rises" invariant is enforced in the validator/derivation but **not** at the store's write path.
3. **Unknown `taint_policy` fails OPEN** at the read gate (served), versus fail-closed elsewhere.
4. **No reader/data taint alignment** + **undocumented contract** (`SANITIZED`→`CLEAN` reader passes). **Resolved by later reader-vs-data alignment.**
5. **Test-quality:** ACL sub-reasons share one exception with no message assertion; `ISOLATED` not independently pinned.

---

## PART 2 — `derivation.py` (GCODerivationRuntime) — **release-ready on the core property, with low-severity flags**

### (a) Refusal-path → code → test map (all assert the SPECIFIC error code ✓)

| Refusal | Code | Test | Specific-code assert? |
|---|---|---|---|
| lineage flood (parent+1 > 128) | [derivation.py:46-47](src/gco/derivation.py:46) | `test_lineage_growth_to_128_and_rejection_at_129` | ✓ `LINEAGE_FLOODED` |
| tool not in parent | [:79-80](src/gco/derivation.py:79) | `test_impossible_requests_rejected[0]` | ✓ `TOOL_AUTHORITY_EXPANDED` |
| depth exhausted (parent depth 0) | [:82-83](src/gco/derivation.py:82) | `test_depth_exhaustion_rejected` | ✓ `MAX_DEPTH_INCREASED` |
| scope not subset | [:84-85](src/gco/derivation.py:84) | `test_impossible_requests_rejected[1]` | ✓ `TOOL_AUTHORITY_EXPANDED` |
| namespace not in parent | [:100-101](src/gco/derivation.py:100) | `test_impossible_requests_rejected[2]` | ✓ `STATE_PERMISSION_EXPANDED` |
| access > parent / unknown access | [:104-105](src/gco/derivation.py:104) | `test_impossible_requests_rejected[3]` | ✓ `STATE_PERMISSION_EXPANDED` |
| taint < parent / unknown taint | [:108-109](src/gco/derivation.py:108) | `test_impossible_requests_rejected[4]` | ✓ `TAINT_DOWNGRADED` |
| validate-stage (e.g. expired parent) | final `self.validator.validate` [:71] | `test_expired_parent_cannot_mint_valid_child` | ✓ `EXPIRED` |

No refusal path asserts only "failure" — all pin the code. Better than the store.

### (b) Round-trip property — `audit_derivation_roundtrip.py`, **20,000 iterations** — **PASS**

```
returned         : 10000   refused          : 10000
disagree         : 0       expansion_leaked : 0
uncaught         : 0       lineage_bad      : 0     linkage_bad : 0
over_refused     : 0
RESULT: PASS
```
- **Property 1 (agreement):** every child the runtime returned passed `validator.validate(parent, child)`.
- **Property 2 (fail-first):** every authority-expanding request (new tool, scope superset, access↑, taint↓, unknown namespace) was refused — none produced a returned child.
- Lineage append (`child.lineage[-1] == canonical_gco_hash(parent)`, prefix == parent.lineage) and `parent_span_id == parent.span_id` held on **every** returned child. The direct lineage/linkage attack could not produce a divergent child: the runtime builds both by construction *and* the final `validate()` would catch any mismatch.

### (c) Lattice / immutable-set duplication

- **Lattices and helpers are SHARED, not duplicated.** `derivation.py` imports `_access_rank`, `_taint_rank`, `_scope_is_subset`, `canonical_gco_hash` from `validator.py` ([derivation.py:10-18](src/gco/derivation.py:10)). `ACCESS_RANK`/`TAINT_RANK` exist only in the validator. ✓ No drift risk on the orderings.
- **FLAG (LOW, drift):** the **immutable-field set is duplicated implicitly.** The validator enumerates it as equality checks (`gco_version` major, `trace_id`, `policy_id`, `model_identity`, `intervention_version`); `derive()` re-enumerates the same fields as constructor copies from the parent. Two literal lists, no shared constant. Same class as the schema/model taint drift found earlier. Currently low-risk because `DelegationRequest` cannot set any immutable field, but a newly-added immutable field would need synchronizing in both places with nothing enforcing it.

### (d) Independent linkage attack
Probed directly across 20k random parents (varying lineage depth 0–3): could not drive the runtime to emit a child whose lineage fails to append the parent digest or whose `parent_span_id` mismatches. Both are guaranteed by construction and re-checked by the final `validate()`.

### derivation.py verdict — **release-ready for the round-trip security property**, with two low-severity flags:
- **(LOW, drift)** immutable-field set duplicated between validator equality checks and `derive()` constructor — should share one source of truth.
- **(LOW, fail-first imperfection)** `authority.issue()` is called **before** the final `validate()` ([:66-71](src/gco/derivation.py:66)), so a validate-stage rejection (e.g. expired parent) mints an attestation it then discards. Tool/permission expansions correctly fail *before* `issue()`. Not a security hole (no child returned), but the expiry check should ideally precede minting. The runtime now passes its injected `GCOValidator` into derivation, so host-level derivation uses the same injected clock as the runtime seam.

---

## Reproduced coverage

```
Name                     Stmts   Miss Branch BrPart  Cover   Missing
--------------------------------------------------------------------
src/gco/__init__.py          6      0      0      0   100%
src/gco/der_harness.py      87      0     26      0   100%
src/gco/derivation.py       64      0     20      0   100%
src/gco/models.py           54      0      2      0   100%
src/gco/state_store.py      34      0     12      0   100%
src/gco/validator.py       149      0     48      0   100%
--------------------------------------------------------------------
TOTAL                      394      0    108      0   100%
73 passed
```
No branch is missing. The historical state-store holes (KeyError, laundering, fail-open taint, alignment) all sat *under* 100% branch coverage: the KeyError was a bare dict access (no branch), and laundering/alignment were behaviors no test asserted.

## Per-file verdict
- **`state_store.py`: RESOLVED → release-ready** (was NOT release-ready at audit time). The audit found uncaught `KeyError` (14/20k), taint laundering (4085/20k), unknown-taint fail-open, no reader alignment, plus test-quality gaps — fuzz then **FAILED** with 4099 violations. After the fixes (see resolution note at top), the state store denies missing keys cleanly, preserves taint monotonically, fails closed on unrankable taint, and enforces reader-vs-data taint alignment.
- **`derivation.py`: release-ready for the core round-trip property** (20k iters: 0 disagreements, 0 expansion leaks, 0 uncaught, lineage/linkage intact; all refusal paths pin specific codes). Two low-severity flags remain open: implicit immutable-set duplication and attestation-minted-before-validate; the earlier runtime clock-injection concern is resolved.

The state-store fix has landed; the two `derivation.py` low-severity flags are still open.
