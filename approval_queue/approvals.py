"""Approval queue (policy-spec.md section 3).

Every PENDING reply is stored here as a record: tool name, full arguments exactly as the
model passed them, timestamp and status. Nothing is delivered until a human approves it.

approve() is the ONLY function in the codebase that puts mail on the wire (a test scans
the source to keep it that way). Before delivering, it runs policy.enforce.enforce()
again against the thread's current stored From header, so a record that was tampered
with, or a thread whose author changed, is refused. reject() throws the draft away: it
is never delivered and cannot be approved later. The record stays for the audit trail.

Named approval_queue/ (not queue/) so it never shadows the stdlib queue module.
"""

from __future__ import annotations

import copy
import itertools
from dataclasses import dataclass
from datetime import datetime, timezone

from policy.enforce import PENDING, enforce

STATUS_PENDING = "PENDING"
STATUS_APPROVED = "APPROVED"
STATUS_REJECTED = "REJECTED"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ApprovalError(Exception):
    pass


@dataclass
class ApprovalRecord:
    record_id: str
    tool: str
    args: object  # full arguments exactly as the model passed them (deep copy)
    thread_id: str
    to: str  # recipient fixed by the policy layer, never by the model
    body: str
    rule: str  # rule that made it PENDING (Q)
    created_at: str
    status: str = STATUS_PENDING
    decided_at: str | None = None
    decided_by: str | None = None
    note: str | None = None  # reject reason, or the rule that refused it at approve time


@dataclass(frozen=True)
class SentMail:
    record_id: str
    thread_id: str
    to: str
    body: str
    sent_at: str
    approved_by: str


class ApprovalQueue:
    """`mailbox` provides thread_from(thread_id) for the re-check and send(message) for delivery."""

    def __init__(self, mailbox, clock=utc_now):
        self._mailbox = mailbox
        self._clock = clock
        self._ids = itertools.count(1)
        self.records: dict[str, ApprovalRecord] = {}

    # Called by tools.dispatch.dispatch() for PENDING decisions only.
    def submit(self, draft, decision, call=None) -> ApprovalRecord:
        if decision.decision != PENDING:
            raise ApprovalError(f"only PENDING calls can be queued, got {decision.decision}")
        args = copy.deepcopy(call.get("args")) if isinstance(call, dict) else None
        record = ApprovalRecord(
            record_id=f"APR-{next(self._ids):04d}",
            tool=decision.tool,
            args=args,
            thread_id=draft.thread_id,
            to=draft.to,
            body=draft.body,
            rule=decision.rule,
            created_at=self._clock(),
        )
        self.records[record.record_id] = record
        return record

    def pending(self) -> list[ApprovalRecord]:
        return [r for r in self.records.values() if r.status == STATUS_PENDING]

    def _open(self, record_id: str) -> ApprovalRecord:
        record = self.records[record_id]  # KeyError for unknown ids
        if record.status != STATUS_PENDING:
            raise ApprovalError(f"{record_id} is already {record.status}")
        return record

    def approve(self, record_id: str, approver: str) -> SentMail | None:
        """The only place a queued call runs. Re-checks policy, then delivers exactly one message."""
        record = self._open(record_id)
        recheck = enforce(
            {"tool": record.tool, "args": {"thread_id": record.thread_id, "body": record.body, "to": record.to}},
            self._mailbox.thread_from(record.thread_id),
        )
        record.decided_at, record.decided_by = self._clock(), approver
        if recheck.decision != PENDING or recheck.recipient != record.to:
            record.status = STATUS_REJECTED
            record.note = f"refused at approve time: {recheck.decision} {recheck.rule}"
            return None
        sent = SentMail(record.record_id, record.thread_id, record.to, record.body, record.decided_at, approver)
        self._mailbox.send(sent)
        record.status = STATUS_APPROVED
        return sent

    def reject(self, record_id: str, reviewer: str, reason: str = "") -> ApprovalRecord:
        """Throw the draft away: never delivered, cannot be approved later."""
        record = self._open(record_id)
        record.status = STATUS_REJECTED
        record.decided_at, record.decided_by = self._clock(), reviewer
        record.note = reason or "rejected by reviewer"
        return record
