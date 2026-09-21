# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- Added the v5 Recursion Blindspot position paper as the canonical in-repo
  paper (`recursion-blindspot-v5.md`) and linked it from the README.
- Documented that the schema namespace URL is hosted and matches pin `89bf058`.
- Added README status badges for Apache-2.0, GitHub Actions CI, and Python 3.11+.
- Added a tamper-evident append-only policy/deployment activation ledger
  (`PolicyDeploymentLedger`) with SHA-256 hash chaining, JSONL persistence,
  active-policy replay helpers, CLI `ledger-record` / `ledger-show` /
  `ledger-verify` commands, and docs in `docs/policy-ledger.md`. v1 is
  single-writer accountability storage; it does not replace TrustBundle / GCO
  crypto or provide multi-tenant control-plane consensus.
- Added Apache-2.0 license metadata and public governance documents.
- Added GitHub issue templates, pull request template, CODEOWNERS, Dependabot,
  and security reporting contact link.
- Added GitHub Actions CI for Python test, coverage, audit, and wheel checks.
- Added runnable quickstart and authority-escape demo examples, with pytest
  coverage so they stay executable.
- Included the canonical JSON Schema in built wheel artifacts.
- Clarified public-readiness notes for the stable schema namespace and the
  separately published Recursion Blindspot position paper.
- Reframed the repository as the reference implementation of the GCO concept,
  with the bundled JSON Schema as the implementation-facing contract.
- Moved historical audit reports under `docs/audits/` with resolved-status
  banners.
- Moved the JSON Schema namespace and maintainer metadata under Alderline
  Systems branding.
- Accepted generic URI identities in the model and schema for SPIFFE and URN
  values.
- Tightened runtime state access, append-only writes, expiry checks, JWT time
  claims, and derivation depth capping.
- Added opt-in attestation audience verification and replay protection with a
  bounded in-memory `ReplayCache` implementation.
- Hardened derivation to share immutable-field definitions with validation and
  validate children before issuing attestations.
- Added the SDK-agnostic P0 MCP adapter, `com.alderlinesystems.gco` extension
  profile, and MCP boundary audit harness.
- Added the `gco` console script for validating parent/child chains, verifying
  attestations against trust bundles, inspecting authority, deriving tightened
  children, and printing the bundled schema.
