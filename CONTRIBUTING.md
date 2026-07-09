# Contributing

Thank you for considering a contribution to `gco-spec`.

## Development setup

```bash
python -m pip install -e ".[test]"
pytest --cov=src/gco --cov=src/gco_mcp --cov-branch --cov-report=term-missing -q
```

The repository currently supports Python 3.11 and newer. Keep changes focused,
add or update tests for behavioral changes, and preserve the configured 100%
branch coverage gate.

## Pull requests

Before opening a pull request:

1. Run the full pytest coverage command above.
2. Run each root-level `audit_*.py` harness.
3. Build a wheel with `python -m build --wheel`.
4. Confirm `schemas/gco_schema_v1.json` remains packaged.

The JSON Schema `$id` is a stable namespace identifier. Do not change
`https://alderlinesystems.com/schemas/gco_schema_v1.json` without an
explicit maintainer decision.

## Contribution terms

By submitting a contribution, you agree that it is provided under the
Apache License, Version 2.0.
