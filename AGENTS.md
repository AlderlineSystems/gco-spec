# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- Add durable project-specific notes here as they are discovered through real work.
- Do not reintroduce the obsolete identifier for a nonexistent normative spec document. The governing public framing is the position paper "The Recursion Blindspot"; this repository is the GCO reference implementation, and `schemas/gco_schema_v1.json` is the implementation-facing contract.
- Keep `recursion-governance-blindspot-v3.md` untracked if it appears at the repo root. It is draft context only and contains old branding.
- The root-level `audit_*.py` harnesses are part of the release posture and CI gate. Historical reports live under `docs/audits/` and should stay clearly marked as resolved historical audits.
