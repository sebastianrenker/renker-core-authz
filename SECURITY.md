# Security Policy

## Supported versions
`renker-core-authz` is pre-1.0. Only the latest `0.x` release on `main` receives security fixes.

## Reporting a vulnerability
Please report security issues **privately**, not via public issues:

- Preferred: GitHub **Security Advisories** ("Report a vulnerability" on the Security tab).
- Alternative: email the maintainer.

Please include a description, affected version/commit, reproduction steps, and impact. We aim to acknowledge
within a few days and to coordinate disclosure.

## Scope and honest limitations
This library is an **authorization decision** engine. It is **not** externally audited. In particular it does
**not**:

- cryptographically **authenticate** actors (identity is validated, not authenticated — the caller must
  supply a trusted `Identity`/`Actor`);
- protect against a fully compromised host account (an attacker who can rewrite both the audit log and its
  `.head` anchor can erase history — the audit is **tamper-evident, not immutable**);
- enforce anything for actions that are **not routed through** the guard/authorizer.

See the README "Security model (honest)" section for the full list. Do not deploy this as your only security
boundary; run it alongside OS-level sandboxing.

## Security properties (verified by tests)
Deterministic, fail-closed decisions; least-privilege capabilities; traversal/prefix/case-safe scope
matching; tamper-evident sha256 hash-chain audit. Adversarial, property-based, and fuzz tests run in CI.
