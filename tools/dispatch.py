"""The single entry point for model tool calls.

Order is fixed: look up the thread's stored From header -> policy.enforce.enforce()
-> only then a handler. BLOCKED calls never reach a handler. PENDING replies become
drafts in the approval queue. This module has no way to put mail on the wire:
delivery happens only in ApprovalQueue.approve() (approval_queue/approvals.py), which
calls enforce() again first. Every call, BLOCKED ones included, gets one CallLog entry.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from policy.enforce import ALLOWED, PENDING, Decision, enforce

# Read-only handlers. Looked up only after enforce() returned ALLOWED.
_HANDLERS = {
    "read": lambda mailbox, thread_id: mailbox.read(thread_id),
    "search": lambda mailbox, query, max_results=20: mailbox.search(query, max_results),
    "label": lambda mailbox, thread_id, label: mailbox.add_label(thread_id, label),
    "move": lambda mailbox, thread_id, folder: mailbox.move(thread_id, folder),
}


@dataclass(frozen=True)
class Draft:
    thread_id: str
    to: str  # always the thread author, set by the policy layer
    body: str


@dataclass(frozen=True)
class Outcome:
    decision: Decision
    result: Any = None


def _thread_from(call, mailbox) -> str | None:
    args = call.get("args") if isinstance(call, dict) else None
    thread_id = args.get("thread_id") if isinstance(args, dict) else None
    if not isinstance(thread_id, str):
        return None
    try:
        return mailbox.thread_from(thread_id)
    except Exception:
        return None


def dispatch(call, mailbox, approvals, log=None, context: dict | None = None) -> Outcome:
    """Run one model tool call. `mailbox` must provide thread_from/read/search/add_label/move;
    `approvals` must provide submit(draft, decision, call). `log` (a tools.call_log.CallLog)
    gets one entry per call; `context` adds fields to it (message_id, source, raw_arguments)."""
    decision = enforce(call, _thread_from(call, mailbox))
    outcome = _execute(call, decision, mailbox, approvals)
    if log is not None:
        log.record(call, decision, _log_result(outcome), context)
    return outcome


def _execute(call, decision, mailbox, approvals) -> Outcome:
    if decision.decision == ALLOWED:
        return Outcome(decision, _HANDLERS[decision.tool](mailbox, **call["args"]))

    if decision.decision == PENDING:
        args = call["args"]
        draft = Draft(thread_id=args["thread_id"], to=decision.recipient, body=args["body"])
        record = approvals.submit(draft, decision, call)
        return Outcome(decision, record if record is not None else draft)

    return Outcome(decision)  # BLOCKED: no handler, no draft


def _log_result(outcome: Outcome):
    result = outcome.result
    record_id = getattr(result, "record_id", None)
    if record_id is not None:  # PENDING: point at the approval record, nothing was delivered
        return {"approval_id": record_id, "status": result.status, "to": result.to}
    return result
