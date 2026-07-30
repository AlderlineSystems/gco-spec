# Policy deployment ledger (v1)

The policy deployment ledger records **which policies were activated when**, for
accountability and forensics. It is complementary to GCO attestation crypto: a
GCO still carries `policy_id` and `intervention_version` on each call, while the
ledger is the host-side history of activation / supersession / deactivation
events that explain *why* those identifiers were in use.

## API

```python
from gco import ActivationEventType, PolicyDeploymentLedger

ledger = PolicyDeploymentLedger(path="deployments.jsonl")  # or in-memory

record = ledger.record_activation(
    policy_id="policy-alpha",
    intervention_version="intervention-v2",
    event_type=ActivationEventType.ACTIVATE,
    deployment_id="deploy-2026-07-29",
    actor="spiffe://ops.example/deployer",
    reason="promote canary",
    metadata={"channel": "prod"},
)

# Or derive identifiers from a GCO about to be issued under that policy:
# ledger.record_from_gco(gco, event_type=ActivationEventType.ACTIVATE)

ledger.verify()
ledger.verify(expected_head=record.entry_hash)  # pin an externally sealed head
active = ledger.active_policies()               # policy_id -> latest active record
as_of = ledger.active_policies(at=some_utc_time)
```

As-of replay applies qualifying events in `recorded_at` order; append sequence
and `event_id` provide deterministic tie-breakers for equal timestamps.

### Wire points

Hosts should call the ledger when a deployment control plane changes the policy
material that will appear on newly issued GCOs:

| Event | When to record |
| --- | --- |
| `activate` | A policy version becomes eligible for new GCOs |
| `supersede` | A new intervention version replaces an active one for the same `policy_id` |
| `deactivate` | A policy is withdrawn and should no longer appear as active |

The ledger is **not** invoked automatically by `GovernanceRuntime`. Authorization
and deployment history are separate concerns; compose them at the host boundary.

## Integrity model

Each entry stores:

* monotonic `sequence` (0-based)
* body fields (`event_type`, `policy_id`, `intervention_version`, timestamps, …)
* `prev_entry_hash` (genesis uses 64 zero hex digits)
* `entry_hash` = SHA-256 of canonical JSON of the body **including** `prev_entry_hash`

`verify()` recomputes the chain and optionally checks `expected_head` against
`head_hash()`.

### What this detects

* middle-entry mutation without coordinated re-hash of the suffix
* reordering or sequence gaps
* append truncation relative to a previously published head hash

### What this does not provide (v1 limits)

* **Not multi-party consensus.** An attacker who can rewrite the entire store
  and recompute hashes from genesis can forge history unless an external seal of
  `head_hash()` (signed checkpoint, transparency log, WORM object store) is
  compared via `verify(expected_head=...)`.
* **Not multi-tenant control plane.** Single-writer JSONL or in-memory; no
  leases, no multi-writer merge.
* **Does not replace TrustBundle / GCO crypto.** Attestation authenticity and
  authority tightening remain the job of `AttestationVerifier` and
  `GovernanceRuntime`.
* **Metadata is string→string only** so canonical hashing stays unambiguous.

## CLI

```bash
gco ledger-record deployments.jsonl \
  --policy-id policy-alpha \
  --intervention-version intervention-v2 \
  --actor spiffe://ops.example/deployer \
  --reason "promote canary"

gco ledger-show deployments.jsonl
gco --json ledger-verify deployments.jsonl --expected-head "<head hash>"
```

## Persistence

* Default: in-memory list (tests / single process).
* `path=...`: append-only JSONL; each `record_*` call appends one line and
  `fsync`s. Loading a path verifies the chain by default.
* `export_jsonl(path)` rewrites a full snapshot (operator export, not the live
  append path).
