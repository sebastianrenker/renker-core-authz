# renker-core-authz

![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![CI](https://github.com/sebastianrenker/renker-core-authz/actions/workflows/ci.yml/badge.svg)
![Dependencies](https://img.shields.io/badge/runtime%20deps-zero-brightgreen)

> Deterministic capability + policy + tamper-evident audit for autonomous agent actions — the public authorization core of the Renker platform.

## Overview

An AI agent may *request* an action; this library decides whether it runs —
**outside** the model — and records every decision in a tamper-evident audit
trail. Zero runtime dependencies (standard library only), Apache-2.0.

Guardrails built *inside* an LLM can be talked around. `renker-core-authz` puts
the decision in a small, deterministic function that reads only trusted grants —
never the agent's claims. Prompt injection can change *what is requested*, not
*what is allowed*.

## Features

- `Actor` · `Capability` / `PathScope` / `CapabilityStore`
- `evaluate` → **ALLOW / DENY / REQUIRE_APPROVAL** with an explainable reason
- `AuditLog` — sha256 hash chain + head anchor + `verify()` + `query()`
- `GuardedFilesystem` — least-privilege file access behind the decision
- **Zero runtime dependencies** (standard library only)

## Architecture

Security model (honest):

- The decision uses **only** trusted grants + actor/action/target — no
  request-supplied authorization or risk.
- Capabilities are immutable; least privilege by construction (one action verb +
  one path scope).
- Scope containment is traversal-, prefix-confusion-, and case-safe
  (`resolve()` + normcase path parts).
- Audit is **tamper-evident, not immutable** (see below).

**It does NOT provide:** cryptographic authentication of actors (identity is
validated, not authenticated); protection once the host account is fully
compromised; enforcement for actions not routed through it; an externally
anchored/notarized audit; multi-process audit coordination. These are documented,
not hidden.

## Quickstart

```bash
pip install renker-core-authz            # once published to PyPI
# or from source:
pip install git+https://github.com/sebastianrenker/renker-core-authz
```

```python
from datetime import datetime, timedelta, timezone
from renker_core_authz import (
    Actor,
    Capability,
    CapabilityStore,
    PathScope,
    GuardedFilesystem,
)
from renker_core_authz.audit import AuditLog

now = datetime.now(timezone.utc)
store = CapabilityStore()
store.grant(
    Capability(
        capability="filesystem.write",
        scope=PathScope(base="~/Documents/drafts"),
        granted_to="agent:session-1",
        granted_by="human:owner",
        issued_at=now,
        expires_at=now + timedelta(hours=1),
    )
)

guard = GuardedFilesystem(store, AuditLog("audit.log"))
result = guard.write(Actor("agent", "session-1"), "~/Documents/drafts/note.txt", "hi")
print(result.decision.value, result.reason)  # ALLOW / DENY with an explainable reason
```

## Tests

```bash
pip install -e ".[dev]"
ruff format --check . && ruff check . && mypy && pytest -q
```

## Related RENKER projects
`renker-core-authz` is the public authorization core consumed across the Renker
platform — infrastructure for trusted, autonomous AI systems built around three
pillars (ACT / LEARN / SECURE) on a shared identity, capability, permission,
policy, and audit foundation (`renker-core`, currently private; this package is
its public authorization subset).

```text
RENKER — ACT (Rencora) · LEARN (Continuum) · SECURE (RenkerVault)
                         shared foundation: renker-core
```

| Pillar | Role | Repo |
| --- | --- | --- |
| Rencora | ACT — desktop agent runtime, integrates this library | https://github.com/sebastianrenker/rencora |
| Continuum | LEARN — evidence-verified autonomous research | https://github.com/sebastianrenker/continuum |
| RenkerVault | SECURE — identity & secure communication | https://github.com/sebastianrenker/renkervault |

## License

Apache-2.0 — see [`LICENSE`](LICENSE). © 2026 Sebastian Renker.
