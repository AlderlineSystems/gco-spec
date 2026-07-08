# Security Policy

## Supported versions

Security reports should target the current `main` branch until the project
publishes release branches or version-specific support windows.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's private
vulnerability reporting flow when available, or by contacting the maintainers
listed in `pyproject.toml`.

Do not open a public issue for exploitable security findings until maintainers
have had a chance to triage.

## Reference implementation limits

This project is a reference implementation for the GCO derivation contract. The
runtime verifies `jwt-svid` and `x509-svid` attestations against an offline
trust bundle, SPIFFE identity binding, GCO digest binding, and expiry.

The `raw-jws` and `tpm-quote` formats are declared by the model but are not
cryptographically verified here; they fail closed at the verifier/runtime seam.
JWT audience is not verified, and there is no revocation or `jti` replay cache.
A valid `(GCO, attestation)` pair can be replayed until expiry.
