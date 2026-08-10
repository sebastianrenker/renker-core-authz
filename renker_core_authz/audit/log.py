from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

CHAIN_HASH_ALGORITHM = "sha256"
GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    timestamp: str
    actor: str
    action: str
    target: str
    capability: str | None
    policy_decision: str
    reason: str
    outcome: str
    prev_hash: str
    entry_hash: str


class AuditError(Exception):
    pass


def _canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash_entry(payload: dict, prev_hash: str) -> str:
    material = _canonical(payload) + prev_hash
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _parse_timestamp(value: str) -> datetime:
    moment = datetime.fromisoformat(value)
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment


class AuditLog:
    def __init__(self, log_path: str | Path) -> None:
        self.log_path = Path(log_path)
        self.anchor_path = self.log_path.with_suffix(self.log_path.suffix + ".head")
        self._lock = threading.Lock()

    def _head(self) -> str:
        if self.anchor_path.exists():
            return self.anchor_path.read_text(encoding="utf-8").strip()
        return GENESIS_HASH

    def record(
        self,
        *,
        actor: str,
        action: str,
        target: str,
        capability: str | None,
        policy_decision: str,
        reason: str,
        outcome: str,
    ) -> AuditEvent:
        with self._lock:
            prev_hash = self._head()
            event_id = uuid.uuid4().hex
            timestamp = datetime.now(timezone.utc).isoformat()
            payload = {
                "event_id": event_id,
                "timestamp": timestamp,
                "actor": actor,
                "action": action,
                "target": target,
                "capability": capability,
                "policy_decision": policy_decision,
                "reason": reason,
                "outcome": outcome,
            }
            entry_hash = _hash_entry(payload, prev_hash)
            event = AuditEvent(
                event_id=event_id,
                timestamp=timestamp,
                actor=actor,
                action=action,
                target=target,
                capability=capability,
                policy_decision=policy_decision,
                reason=reason,
                outcome=outcome,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
            )
            self._append(event)
            return event

    def _append(self, event: AuditEvent) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.log_path, "a", encoding="utf-8") as handle:
            handle.write(_canonical(asdict(event)) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        self._write_anchor(event.entry_hash)

    def _write_anchor(self, value: str) -> None:
        tmp = self.anchor_path.with_suffix(self.anchor_path.suffix + ".tmp")
        tmp.write_text(value, encoding="utf-8")
        os.replace(tmp, self.anchor_path)

    def read_all(self) -> list[AuditEvent]:
        if not self.log_path.exists():
            return []
        events: list[AuditEvent] = []
        for index, line in enumerate(self.log_path.read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            try:
                events.append(AuditEvent(**json.loads(line)))
            except (ValueError, TypeError) as error:
                raise AuditError(f"corrupt audit entry at line {index}: {error}") from error
        return events

    def query(
        self,
        *,
        actor: str | None = None,
        action: str | None = None,
        decision: str | None = None,
        outcome: str | None = None,
        capability: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[AuditEvent]:
        results: list[AuditEvent] = []
        for event in self.read_all():
            if actor is not None and event.actor != actor:
                continue
            if action is not None and event.action != action:
                continue
            if decision is not None and event.policy_decision != decision:
                continue
            if outcome is not None and event.outcome != outcome:
                continue
            if capability is not None and event.capability != capability:
                continue
            moment = _parse_timestamp(event.timestamp)
            if since is not None and moment < since:
                continue
            if until is not None and moment >= until:
                continue
            results.append(event)
        return results

    def verify(self) -> None:
        events = self.read_all()
        prev = GENESIS_HASH
        for index, event in enumerate(events):
            payload = {
                "event_id": event.event_id,
                "timestamp": event.timestamp,
                "actor": event.actor,
                "action": event.action,
                "target": event.target,
                "capability": event.capability,
                "policy_decision": event.policy_decision,
                "reason": event.reason,
                "outcome": event.outcome,
            }
            if event.prev_hash != prev:
                raise AuditError(f"broken chain at entry {index}: prev_hash mismatch")
            expected = _hash_entry(payload, prev)
            if event.entry_hash != expected:
                raise AuditError(f"tampered entry {index}: entry_hash mismatch")
            prev = event.entry_hash
        if events:
            if prev != self._head():
                raise AuditError("head anchor mismatch: log tail was truncated or replaced")
        elif self.anchor_path.exists() and self._head() != GENESIS_HASH:
            raise AuditError("head anchor present but log is empty: entries were deleted")
