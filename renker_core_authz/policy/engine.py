from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from renker_core_authz.capabilities.model import Capability
from renker_core_authz.capabilities.store import CapabilityStore
from renker_core_authz.identity.actor import Actor


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    reason: str
    actor: str
    action: str
    target: str
    allowed_scope: str | None = None
    capability_id: str | None = None


def evaluate(
    *,
    actor: Actor,
    action: str,
    target: str,
    store: CapabilityStore,
    now: datetime | None = None,
) -> PolicyResult:
    candidates = store.find(actor.urn, action)
    if not candidates:
        return PolicyResult(
            decision=Decision.DENY,
            reason=f"no capability grants {action} to {actor.urn}",
            actor=actor.urn,
            action=action,
            target=target,
        )

    last_reason = "no candidate capability matched the requested target"
    last_scope: str | None = None
    last_id: str | None = None

    for cap in candidates:
        result = _evaluate_one(
            actor=actor, action=action, target=target, cap=cap, store=store, now=now
        )
        if result.decision is not Decision.DENY:
            return result
        last_reason = result.reason
        last_scope = result.allowed_scope
        last_id = result.capability_id

    return PolicyResult(
        decision=Decision.DENY,
        reason=last_reason,
        actor=actor.urn,
        action=action,
        target=target,
        allowed_scope=last_scope,
        capability_id=last_id,
    )


def _evaluate_one(
    *,
    actor: Actor,
    action: str,
    target: str,
    cap: Capability,
    store: CapabilityStore,
    now: datetime | None,
) -> PolicyResult:
    scope = cap.scope.describe()
    base = PolicyResult(
        decision=Decision.DENY,
        reason="",
        actor=actor.urn,
        action=action,
        target=target,
        allowed_scope=scope,
        capability_id=cap.capability_id,
    )

    if cap.granted_to != actor.urn:
        return _deny(
            base,
            f"capability {cap.capability_id} is granted to {cap.granted_to}, not {actor.urn}",
        )
    if not cap.permits_action(action):
        return _deny(base, f"capability permits {cap.capability}, not {action}")
    if cap.is_expired(now):
        return _deny(base, f"capability {cap.capability_id} expired at {cap.expires_at}")
    if store.is_revoked(cap.capability_id):
        return _deny(base, f"capability {cap.capability_id} has been revoked")
    if not cap.permits_target(target):
        return _deny(base, f"target is outside capability scope {scope}")

    if cap.approval_policy == "deny":
        return _deny(base, "approval policy is deny")
    if cap.approval_policy == "human":
        return _replace(
            base, Decision.REQUIRE_APPROVAL, "approval policy requires human confirmation"
        )
    return _replace(base, Decision.ALLOW, "within capability scope, action and lifetime")


def _deny(base: PolicyResult, reason: str) -> PolicyResult:
    return _replace(base, Decision.DENY, reason)


def _replace(base: PolicyResult, decision: Decision, reason: str) -> PolicyResult:
    return PolicyResult(
        decision=decision,
        reason=reason,
        actor=base.actor,
        action=base.action,
        target=base.target,
        allowed_scope=base.allowed_scope,
        capability_id=base.capability_id,
    )
