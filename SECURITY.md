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
JWT `exp`, `nbf`, and `iat` claims are checked against the injected clock.

Audience and replay checks are implemented as verifier/runtime configuration.
Existing bundles without `expected_audience` remain compatible and do not check
`aud`; production deployments should configure the expected audience as the
receiving trust domain or endpoint identity, which makes missing or mismatched
`aud` fail closed. Tokens without `jti` are accepted only when replay protection
is not configured. When a `ReplayCache` is configured, missing `jti` and replay
of a seen `jti` fail closed, with cache entries expiring at token `exp`.

The bundled `InMemoryReplayCache` is bounded but protects only one process.
Issue short-lived attestations by default so any replay window is narrow.
Horizontally scaled or multi-instance hosts must either supply a shared or
state-synchronized `ReplayCache` implementation with the same atomic
check-and-record semantics, or keep attestation TTLs short enough to suppress
the cross-instance replay window. This implementation does not provide
revocation.
