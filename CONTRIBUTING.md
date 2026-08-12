# Contributing to renker-core-authz

Thanks for your interest. This is a small, security-critical, dependency-free library; contributions are held
to a high bar.

## Ground rules
- **No new runtime dependencies.** The library is standard-library only by design.
- **No home-grown cryptography.** Signature/crypto belongs behind an interface, implemented elsewhere on
  established primitives.
- **Fail closed.** Authorization code never returns "allow" on error, and never contains `return True`
  placeholders.
- **No secrets** in commits.

## Local checks (must pass)
```bash
pip install -e ".[dev]"
ruff format --check .
ruff check .
mypy
pytest -q
```
CI runs the same gate plus a build and a `pip-audit` dependency scan.

## Security-relevant changes
Anything touching capabilities, policy, scope matching, replay/approval, or audit must:
1. include adversarial tests (attempt to bypass the boundary), and
2. keep every existing security test green.

Report vulnerabilities privately — see [`SECURITY.md`](SECURITY.md), not a public issue or PR.

## Style
Idiomatic modern Python, explicit types, immutable security artifacts, small public API. Public API changes
require updating `__all__` and the contract test.
