# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

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
- Hardened derivation to share immutable-field definitions with validation and
  validate children before issuing attestations.
- Added the SDK-agnostic P0 MCP adapter, `com.alderlinesystems.gco` extension
  profile, and MCP boundary audit harness.
- Added the `gco` console script for validating parent/child chains, verifying
  attestations against trust bundles, inspecting authority, deriving tightened
  children, and printing the bundled schema.
