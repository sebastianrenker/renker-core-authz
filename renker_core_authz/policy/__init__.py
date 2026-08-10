from __future__ import annotations

from renker_core_authz.policy.engine import Decision, PolicyResult, evaluate

PRIMITIVE = "policy"

RISK_TIERS = ("low", "medium", "high", "critical")

DECISIONS = ("ALLOW", "DENY", "REQUIRE_APPROVAL")

__all__ = ["PRIMITIVE", "RISK_TIERS", "DECISIONS", "Decision", "PolicyResult", "evaluate"]
