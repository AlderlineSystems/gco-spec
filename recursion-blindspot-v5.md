# The Recursion Blindspot: Why Single-Pass Governance Does Not Cover Recursive Inference

**A position paper and research agenda**
Stephen Brouhard
Alderline Systems · Draft for public discussion · v5

---

## Summary

A growing class of LLM safety mechanisms operates *inside the model's forward pass*: steering vectors, representation-level interventions, classifier heads reading the residual stream, and circuit-breaker-style suppression. These techniques are typically defined, trained, and evaluated with respect to a single governed model execution.

Recursive inference changes the relevant unit of safety. When a model can treat its input as an external environment, decompose a task, and recursively call itself or auxiliary models over the pieces, accumulating state outside the token stream as it goes, the governed execution is no longer the whole computation. A safety intervention scoped to one execution does not automatically provide governance coverage over the recursive call graph, the delegated sub-calls, the external state store, or the final aggregation.

We call this the **recursion blindspot**. The mechanism may still work where it is applied; the point is jurisdictional, not adversarial. Parts of the computation simply fall outside the intervention's coverage. This paper states the problem at the architectural level, distinguishes *model governance* from *system governance*, positions the claim against adjacent prior work, and proposes a defensive research agenda. A reference implementation of parts of that agenda now exists as open-source software; we describe what it covers and what it deliberately does not. We deliberately do not publish operational exploitation procedures; the contribution is the problem framing and the defensive directions, which the field needs before recursive inference is widely deployed in high-stakes settings.

## 1. Background: two trends on a collision course

**In-forward-pass governance.** Representation engineering established that high-level concepts, including safety-relevant ones like refusal, correspond to low-rank directions in a model's activation space, and that monitoring or manipulating those directions can steer behavior (Zou et al., 2023a). Circuit breakers build on this by directly controlling the representations responsible for harmful outputs and interrupting harmful generation as it is produced, rather than relying on refusal training or adversarial training (Zou et al., 2024). These methods are attractive because they are cheap, interpretable, and act directly on the model's internal state. They share a common property: the intervention is scoped to the model's own forward computation.

**Recursive inference.** Recursive Language Models (Zhang, Kraska, and Khattab, 2026) propose treating a long prompt as an external, programmable environment that the model examines, decomposes, and recursively calls itself over. In their instantiation, this means storing the input as a variable in a persistent code-execution environment and launching sub-calls inside it. The reported results are substantial: a post-trained RLM-Qwen3-8B outperforms its base model by 28.3% on average across long-context tasks and handles inputs roughly two orders of magnitude beyond the base context window. Recursive and agentic inference patterns are moving quickly from research into deployment.

The collision: in-forward-pass governance is scoped to one execution; recursive inference spans many executions plus state that persists outside any single one. Governance designed for the first does not transfer cleanly to the second.

## 2. The recursion blindspot, stated abstractly

Let a governance mechanism `G` be any intervention applied to a model `M`'s forward computation: a steering vector added to the residual stream, a classifier head reading pooled activations, a suppression direction. `G` is defined and trained with respect to a single governed execution of `M`.

A standard governed inference maps an input `X` to a safe output `Y` through that single execution:

```
M_G(X) -> Y
```

A recursive system instead executes a *tree* of calls, where the final output is a function of nested executions and an external state store `S` that persists across them:

```
M(X_i, S_{i-1}) -> (X_{i+1}, S_i)
```

Because `G` evaluates only the inputs and outputs of governed executions, the intermediate state transitions `S_i`, and any executions that do not carry `G`, lie outside the safety manifold it enforces.

Three properties of this structure can fall outside the coverage of a single-execution intervention:

**Descendant ungovernedness.** `G` is bound to the executions that carry it. Sub-calls are separate executions (possibly to lighter, ungoverned auxiliary models, possibly through a different code path) that do not inherit `G` unless something explicitly propagates it. This is not only a propagation failure but an *asymmetric security boundary*: a high-level policy enforced on a governed frontier root cannot, by default, be enforced on a low-overhead open-weight node the root delegates to. The root can produce a compliant decomposition while a descendant, operating without `G`, performs work the root would not have.

That boundary is already present in production agentic systems, before any RLM-style self-recursion is required. When a governed root calls an external tool process, including an MCP server, the descendant carries none of the root's in-forward-pass governance. That is descendant ungovernedness at the host/tool boundary. It is not a claim that MCP implements recursive self-inference, and it is not a claim that every tool call is a recursive model call. Protocol-level substrate for propagating governance across that boundary belongs in §5.1.

**Out-of-stream state.** In-forward-pass interventions rely on the *ephemerality* of the residual stream: activation vectors that exist only during generation. Recursive inference introduces *persistent* external memory: variables in a code environment, cached intermediate results, memory writes. The intervention governs the processor; it does not see the RAM or the disk. State accumulated outside the token stream is a post-generation artifact `G` has no visibility into. A name for that state, such as a handle, is not taint-aware governance: it can point at intermediate results without saying whether any of them came from an ungoverned descendant.

**Aggregation.** Because a root execution sees only its sub-calls' returned summaries, the relationship between a benign-looking root trajectory and the aggregate behavior of the whole tree is not something `G` can assess from any single governed pass. Individually benign tool calls that compose into harm across a sequence or across nodes are the same structural problem at the leaf: content monitors that inspect each action can pass every step while the composition escapes. That is a system-governance problem, not a better-classifier problem.

None of these require defeating `G` directly. They follow from `G` being scoped to a unit of computation that is no longer the whole computation. This is why the blindspot is architectural rather than a tuning problem: a better steering vector does not help, because the vector's *scope* is the issue.

Put differently, recursive inference shifts the safety problem from **model governance** to **system governance**. A representation-level intervention may still govern a particular model invocation. It does not, by itself, govern delegation, state mutation, code execution, memory writes, sub-call policy inheritance, or result aggregation. That distinction is the anchor of this paper.

## 3. Positioning relative to prior work

This paper does not claim the general agent-governance problem as new. It is established that an isolated benchmark score may not predict behavior once a model is wrapped in an agentic scaffold; one large controlled study reports that map-reduce-style scaffolding measurably degrades safety, even while other scaffold architectures preserve it within meaningful margins (Gringras, 2026). Related work shows that safety propensities are fragile to scaffolding and incentive variation, so a low rate measured in one configuration provides limited assurance about nearby ones.

Our contribution is narrower and more specific than "agents are hard to govern." We isolate a particular, evaluation-invisible mechanism: the mismatch between *representation-level, in-forward-pass* governance and recursive inference whose effective computation spans multiple governed-or-ungoverned executions plus persistent external state. The prior work establishes *that* scaffold conditions move measured safety. This paper accounts for *why* recursion in particular escapes the jurisdiction of an in-forward-pass intervention, and why standard evaluation does not see it: the root execution still looks governed.

## 4. Why this matters now, and why evaluation misses it

The blindspot is latent today because most production deployments still run effectively monolithic inference, and most in-forward-pass governance is validated against that. But recursive and agentic patterns are improving fast, are cost-competitive, and are being adopted for exactly the long-horizon, high-stakes tasks where governance matters most. Tool-protocol standardization (MCP and its extensions track) accelerates that adoption by making multi-server, multi-hop agent graphs routine rather than bespoke.

The failure mode is pernicious because it is invisible to standard evaluation. A governed model tested in isolation passes. The same model embedded in a recursive harness can behave differently, and the governance dashboard has no signal that anything changed, because the governed executions it monitors still look governed. The gap is in the parts of the computation it never sees.

## 5. Research agenda

We state these as open problems and defensive design targets, not finished solutions. Section 6 records which pieces now have a concrete reference implementation and which remain open.

**5.1 Hereditary governance.** Can governance state be made a first-class property that propagates across the recursion tree? A practical version would require every recursive sub-call to carry a verifiable **governance context object**: active policy, model identity, intervention version, tool authority, state-access permissions, and parent-call lineage, borrowing established patterns from distributed-systems context propagation (e.g., W3C Trace Context) and workload identity attestation (e.g., SPIFFE/SPIRE). A root would refuse to delegate to an endpoint that cannot attest it enforces the same context; absent a governed descendant, execution falls back to a single governed instance.

MCP's `2026-07-28` design makes this more concrete than it was when the protocol treated sessions as ambient transport state. Trace Context keys are fixed in `_meta`; extensions are a first-class, reverse-DNS-identified negotiation surface; and explicit handles force application-level state into the payload. A governance-context extension can therefore travel the same way as any other negotiated capability: advertise, bind, tighten on derivation, and fail closed when a descendant cannot attest. Open questions remain: the right trust and attestation model between root and descendants; acceptable overhead; composition across heterogeneous models; and whether hosts gate tool calls on verified context rather than treating context as advisory telemetry.

One invariant of this design should be stated plainly, because it is the most common misreading of hereditary governance: the goal is not the impossible task of forcing an uncooperative downstream node to comply by payload alone. No protocol can make a hostile process execute a validation routine it chooses to skip. The goal is to give the governed root the means to *detect* non-compliance, *measure* its own governance coverage, and *fail closed* away from environments that cannot attest enforcement. The analogy is TLS: the protocol does not physically stop a malicious router from tampering with traffic; it guarantees the endpoint detects the breach and tears the connection down safely. Hereditary governance makes ungoverned delegation visible and refusable, not impossible.

**5.2 Out-of-stream state governance.** If meaningful computation happens in external state, governance must extend there, and this can be treated as a classic information-flow-control problem. Outputs of ungoverned or semi-governed sub-calls can be treated as *tainted*; before tainted state is read back into a governed context, an explicit sanitization or representation-alignment step is required. Candidate enforcement boundaries for such state include trusted execution environments or encrypted state stores, though both carry latency costs that may be prohibitive for high-throughput recursive workloads. Open questions: how to inspect or constrain state without destroying the utility that makes recursive inference valuable; what the latency budget is for code-heavy workloads; how to avoid an arms race over encoded content.

**5.3 Robustness of representation-level interventions.** Independent of recursion, steering-based governance is known to be brittle to adversarial perturbation of the input representation (Zhang et al., 2024; and the broader jailbreak literature, e.g., diffusion-based prompt rewriting, Wang et al., 2025). Recursion compounds this by multiplying the points at which a perturbation could enter. Open questions: multi-layer and ensemble interventions; representation normalization toward a learned safe manifold; adversarial training that includes recursive surfaces in its threat model.

**5.4 Recursion-aware evaluation.** The most immediately actionable item, and the one that turns this from observation into agenda. Safety evaluations should test governed models *inside* representative recursive harnesses, not only in isolation, and report governance behavior under recursion as a distinct metric. Two concrete proposals:

- **Differential Evaluation under Recursion (DER).** Measure a model's safety rate in isolation (`R_iso`) and again with the same model embedded in a recursive harness (`R_rec`). The **Recursion Degradation Delta**, `ΔR = R_iso − R_rec`, becomes a standard metric for the blindspot. (The harness should be a fixed, disclosed measurement instrument; this paper does not specify input strategies for maximizing `ΔR`.)
- **Governance coverage.** Measure the fraction of nodes, state transitions, tool calls, and aggregation steps in the recursion tree for which an enforcing governance context is present, attested, and logged. Coverage of 1.0 means every unit of the computation is governed; anything less names the exposed surface.

Open questions: what a standard recursion-aware safety benchmark should contain; how to make coverage reporting a default rather than an afterthought; and whether attestation failures and coverage gaps should be logged in a standardized, cross-host audit schema so independent perimeters can be compared and aggregated.

A note on instrumentation: a useful open contribution is a *scorer*: given a recorded recursion transcript tree, compute its governance coverage and, where isolated and recursive runs are both available, its `ΔR`. We distinguish this deliberately from a library of adversarial decomposition inputs designed to maximize `ΔR`; the former is defensive instrumentation, the latter is closer to an exploitation toolkit and is out of scope for this work. Any harness released to support this agenda should ship the scoring, not the attack inputs.

## 6. Reference implementation

Parts of the agenda in §5 now exist as a tested open-source Python package, **`gco-spec`** version **0.1.0** (Alderline Systems; Apache-2.0). Source is at `https://github.com/AlderlineSystems/gco-spec`. Cite git tag `v0.1.0` until a PyPI package exists. Claims below are pinned to commit **`89bf058016dc5040dece15dcc910ec35725ec68a`** (2026-07-30) on the repository's default branch. The GitHub repository is public as of 2026-09-21. The schema namespace is hosted at `https://alderlinesystems.com/schemas/gco_schema_v1.json` and matches this pin.

The package is a *reference implementation of authority-propagation primitives*, not a complete agent security product and not a claim that the blindspot is empirically closed for any particular frontier model. We include it to anchor the theoretical framework and make its propositions falsifiable: an inspectable baseline for the propagation contract, not a production agent firewall. Readers should be able to tell exactly what is implemented from what is not, which is why the two subsections below are separated.

### 6.1 What is implemented

**Governance Context Object (GCO) (§5.1).** A strict Pydantic model and JSON Schema encode the context object proposed in §5.1: policy identity, model identity (URI, including SPIFFE IDs and URNs), intervention version, tool authority with per-tool remaining depth, state-access permissions, expiry, parent/child span lineage (`trace_id`, `span_id`, `parent_span_id`), and an optional attestation. Child GCOs are *minted by derivation*, not copied: requested tool depth is capped to the parent's remaining depth (it may only shrink), `attestation_identity` overrides are rejected, and children are attested for the parent's `model_identity`. Validation fails closed on malformed payloads and on any attempted widening of authority.

**Cryptographic attestation.** Supported formats declared by the model are `jwt-svid`, `x509-svid`, `raw-jws`, and `tpm-quote`. The reference verifier cryptographically checks **`jwt-svid` and `x509-svid`** against an offline SPIFFE trust bundle: signature or chain trust, SPIFFE identity binding to the GCO's model identity, binding to a canonical GCO digest, and expiry / not-before / issued-at against an injected clock. When an expected audience is configured (on the verifier/runtime or as trust-bundle metadata), missing or mismatched JWT `aud` fails closed. When a pluggable `ReplayCache` is configured, attestations must carry a non-empty `jti`, and reuse of a seen `jti` fails closed. Production hosts are expected to route tool calls, sub-call authorization, derivation, and state access through a `GovernanceRuntime` seam that returns `Decision`s; calling lower-level helpers directly bypasses that gate by design and is documented as a testing/composition surface, not a production API.

**Taint-based state governance (§5.2).** A governed state store enforces namespace ACLs and monotonic taint labels (`clean`, `sanitized`, `tainted`, `isolated`). Reads of `tainted` / `isolated` / unrankable labels fail closed; later writes cannot launder a key back to a lower taint rank. Per-read reader-vs-data alignment is enforced: a reader may only receive data whose stored taint rank is no higher than its own grant. Access is two-step by design: ACL grant checks are separate from per-key taint enforcement at real read/write time, and append-only writes are first-class (`AccessMode.APPEND` creates but does not grant read or overwrite).

**MCP adapter (P0; §5.1 substrate).** An SDK-agnostic adapter package (`gco_mcp`) carries attested GCOs on MCP `tools/call` through reverse-DNS `_meta` keys under the extension id `com.alderlinesystems.gco`. Client pre-send, server pre-execute, and server fan-out boundaries compose `GovernanceRuntime` for authorization, derivation, and attestation verification; they do not reimplement crypto or tightening logic, and they do not put GCO fields into tool `inputSchema`. Capability advertisement uses the final MCP extensions surface (`capabilities.extensions` / per-request client capabilities in `_meta`). Handles are reserved on the wire profile (`handleSupport: false` in P0); tasks-lifecycle glue and handle-store resolution remain deliberately out of P0 scope even though the MCP `2026-07-28` specification is now final.

**CLI.** A `gco` console script exposes adopter-facing debugging for trust bundles and GCO chains (validate, verify, inspect, derive, schema) and for policy-ledger record/show/verify operations. Failures fail closed with stable error codes and non-zero exit status.

**Policy deployment ledger.** A host-side, append-only, hash-chained ledger (`PolicyDeploymentLedger`) records `activate` / `supersede` / `deactivate` events for `policy_id` / `intervention_version` pairs, with JSONL or in-memory persistence and `verify()` / active-policy replay helpers. It is complementary to GCO attestation: the GCO still carries policy identifiers on each call; the ledger is the deployment-history explanation of *why* those identifiers were in force. Hosts record activations at the deploy boundary; the ledger is not folded into `GovernanceRuntime` authorization. Integrity is tamper-evident (middle mutation, reorder, truncation relative to a published head), not multi-writer consensus.

**DER / governance-coverage scorer (§5.4).** A `DERHarness` scores *pre-recorded* recursive transcripts. Given isolated and recursive runs plus an external safety judge (or pre-labeled judgments), it reports `R_iso`, `R_rec`, `ΔR`, and coverage fractions over nodes, state transitions, tool calls, and aggregation steps (plus a harmonic-mean overall and a rejection log of missing GCOs / unsafe responses). It ships scoring, not attack inputs.

**Verification posture of the package itself.** As of **2026-07-30**, commit **`89bf058`**, the suite reports **337 tests passed** with **100% statement and branch coverage** of `src/gco` and `src/gco_mcp` (combined under the repository coverage gate). Eight adversarial / fuzz audit harnesses at the repository root exercise derivation, state, runtime, attestation, and MCP boundary surfaces. These numbers describe the package under test, not measured safety rates of any deployed model.

### 6.2 Limits of the implementation

Honesty about limits is part of the contribution. Several controls are implemented but bounded; the boundaries are as important as the features:

- **`raw-jws` and `tpm-quote` fail closed as unsupported.** They are declared format tags so the schema can evolve, but the reference verifier returns `unsupported_format` and the runtime will not treat them as verified authority. There is no partial "best effort" accept path.
- **Audience verification and replay protection are configuration-dependent.** When an expected audience is configured, tokens with a missing or mismatched `aud` fail closed; bundles without audience configuration remain compatible but do not check `aud`, and the documented production posture is to configure it. Replay protection is a pluggable `jti` cache with an atomic check-and-record contract; with a cache configured, replayed and `jti`-less tokens fail closed. The bundled in-memory cache protects a single process only, so horizontally scaled hosts must supply a state-synchronized cache implementation or keep attestation lifetimes short enough to suppress the cross-instance replay window; short-lived attestations are the recommended default. There is still no revocation list: revocation-grade invalidation before expiry remains host infrastructure.
- **MCP adapter is P0 wire glue, not a full MCP product.** It is dict-in / dict-out over `_meta`; it does not ship an MCP SDK dependency, does not implement tasks lifecycle or handle resolution, and does not publish a ratified SEP. Enforcement still requires a host that composes the adapter with a real transport and that refuses tool execution on denial.
- **Policy ledger is tamper-evident, not multi-party consensus.** An attacker who can rewrite the entire store and recompute hashes from genesis can forge history unless an external seal of `head_hash()` is compared. It is single-writer accountability storage, not a multi-tenant control plane.
- **No action-content monitoring.** The GCO layer asks whether a node still holds the authority its parent had; it does not decide whether a particular command is dangerous, perform DLP, block secrets, or sandbox the host. Content monitors and GCO are complementary layers; neither replaces the other.
- **No live model evaluation in this paper.** The harness scores transcripts you already have. This paper still states no frontier-model `ΔR` numbers of its own; establishing those numbers on standard recursive harnesses remains open work under §5.4.
- **Enforcement is host-mediated.** The runtime returns decisions; a host that ignores them has no governance. The package is a primitive, not a drop-in agent firewall.
- **No PyPI package.** The GitHub repository is public. Cite git tag `v0.1.0` until a PyPI package exists.

### 6.3 How to read this relative to the agenda

The reference implementation is progress on the *defensive instrumentation and propagation contract* side of the agenda: hereditary context objects, taint-aware state, attested derivation that only tightens, MCP `_meta` carriage of GCOs at the tool boundary, deployment-history accountability, a debugging CLI, and a coverage/`ΔR` scorer that does not ship attack recipes. It is not a proof that in-forward-pass interventions are obsolete, and it is not a claim that installing the package closes the blindspot. The jurisdictional argument of §§2–4 stands either way: without hereditary, state-aware system governance, single-pass model governance remains incomplete under recursion.

## 7. Scope and disclosure note

This paper describes the problem at the architectural level and proposes defenses. It does not provide operational procedures for exploiting the blindspot. We believe the structural insight (*governance scoped to a single forward pass does not extend to recursive inference or out-of-stream state*) can be conveyed, and defenses developed, without publishing attack recipes. Researchers wishing to validate the blindspot empirically can do so against publicly available recursive-inference implementations; those investigating specific deployed systems should follow coordinated disclosure with the affected vendors.

The reference implementation in §6 provides executable primitives and a scorer; it does not replace empirical measurement of coverage rates, defense overhead, or residual risk on real recursive workloads. Establishing those numbers is still the work the agenda is meant to motivate, now with a shared baseline to instrument against.

We note, without making any legal claim, that an auditable attestation chain of the kind described in §5.1 may also have value for accountability and incident forensics in recursive systems: a verifiable record of which governance context was present at each node makes it possible to reconstruct, after the fact, where coverage was and was not enforced. How responsibility should attach in such systems is an open question we do not attempt to resolve here.

## References

Gringras, D. (2026). *Safety Under Scaffolding: How Evaluation Conditions Shape Measured Safety.* arXiv:2603.10044v2.

Wang, H., Li, H., Zhu, J., Wang, X., Pan, C., Huang, M., and Sha, L. (2025). *DiffusionAttacker: Diffusion-Driven Prompt Manipulation for LLM Jailbreak.* Proceedings of the 2025 Conference on Empirical Methods in Natural Language Processing (EMNLP 2025), pp. 22182–22194. ACL Anthology: 2025.emnlp-main.1128. Also arXiv:2412.17522.

Zhang, A. L., Kraska, T., and Khattab, O. (2026). *Recursive Language Models.* arXiv:2512.24601v3. (v1 submitted 31 Dec 2025; this citation is to the 11 May 2026 revision.)

Zhang, Y., Wei, Z., Sun, J., and Sun, M. (2024). *Adversarial Representation Engineering: A General Model Editing Framework for Large Language Models.* arXiv:2404.13752v3.

Zou, A., Phan, L., Chen, S., Campbell, J., Guo, P., Ren, R., et al. (2023a). *Representation Engineering: A Top-Down Approach to AI Transparency.* arXiv:2310.01405.

Zou, A., Wang, Z., Carlini, N., Nasr, M., Kolter, J. Z., and Fredrikson, M. (2023b). *Universal and Transferable Adversarial Attacks on Aligned Language Models.* arXiv:2307.15043. (Source of the AdvBench harmful-behavior benchmark; author list updated to the current arXiv record.)

Zou, A., Phan, L., Wang, J., Duenas, D., Lin, M., Andriushchenko, M., Wang, R., Kolter, Z., Fredrikson, M., and Hendrycks, D. (2024). *Improving Alignment and Robustness with Circuit Breakers.* arXiv:2406.04313.

Model Context Protocol. (2026). *The 2026-07-28 Specification.* https://blog.modelcontextprotocol.io/posts/2026-07-28/ (final specification published 28 July 2026). See also the normative specification and changelog: https://modelcontextprotocol.io/specification/2026-07-28 and https://modelcontextprotocol.io/specification/2026-07-28/changelog.

Alderline Systems. (2026). *gco-spec* (version 0.1.0) [Computer software]. https://github.com/AlderlineSystems/gco-spec (git tag `v0.1.0`). Schema: https://alderlinesystems.com/schemas/gco_schema_v1.json.

---

*This is a draft for public discussion. Feedback and empirical validation are welcomed. Contact, ORCID, and venue selection remain open and are not fixed by this draft.*
