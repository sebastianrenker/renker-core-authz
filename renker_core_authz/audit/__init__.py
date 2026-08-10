from __future__ import annotations

from renker_core_authz.audit.log import (
    CHAIN_HASH_ALGORITHM,
    GENESIS_HASH,
    AuditError,
    AuditEvent,
    AuditLog,
)

PRIMITIVE = "audit"

APPEND_ONLY = True

__all__ = [
    "PRIMITIVE",
    "APPEND_ONLY",
    "CHAIN_HASH_ALGORITHM",
    "GENESIS_HASH",
    "AuditError",
    "AuditEvent",
    "AuditLog",
]
