# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- Add durable project-specific notes here as they are discovered through real work.
- Do not reintroduce the obsolete identifier for a nonexistent normative spec document. The governing public framing is the position paper "The Recursion Blindspot" (`recursion-blindspot-v5.md`); this repository is the GCO reference implementation, and `schemas/gco_schema_v1.json` is the implementation-facing contract.
- Keep `recursion-governance-blindspot-v3.md` untracked if it appears at the repo root. It is superseded draft context and contains old branding; v5 is canonical.
- The root-level `audit_*.py` harnesses are part of the release posture and CI gate. Historical reports live under `docs/audits/` and should stay clearly marked as resolved historical audits.
- The P0 MCP adapter lives in `src/gco_mcp/` and is intentionally SDK-agnostic: plain `_meta` dicts in/out, no MCP SDK dependency, and GCO material only under reverse-DNS `_meta` keys. Do not add GCO fields to tool `inputSchema`.
- Adapter enforcement must compose `GovernanceRuntime` for authorization, derivation, attestation verification, and parent-child tightening. Do not reimplement crypto or GCO tightening logic in `gco_mcp`.
- Tasks lifecycle glue, handle-store resolution, and SEP publication remain out of P0 even though the MCP 2026-07-28 specification is final.
- Policy/deployment activation history lives in `src/gco/policy_ledger.py` (`PolicyDeploymentLedger`): append-only hash-chained events for `policy_id` / `intervention_version`. Hosts record activations at the deploy boundary; do not fold this into `GovernanceRuntime` authorization. See `docs/policy-ledger.md` for integrity limits (tamper-evident, not multi-writer consensus).
- Public 0.1.0 citation is git tag `v0.1.0` until a PyPI package exists. Release notes live in `docs/releases/0.1.0.md`. The hosted schema at `https://alderlinesystems.com/schemas/gco_schema_v1.json` matches `schemas/gco_schema_v1.json`; blob SHA-256 `fd0d9aa803af0c5761bc9f99046b29abc86e54a93ccf8761d91096b878db650f`, last content-changing commit `531a134`, identical at pin `89bf058` and later `main`.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
