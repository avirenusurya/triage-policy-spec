"""Approval queue: PENDING records, approve() as the only delivery path, reject() discards."""

import re
from datetime import datetime

import pytest

from agent.runner import run_inbox
from agent.stub_model import StubModel
from approval_queue.approvals import ApprovalError, ApprovalQueue
from conftest import ROOT, SEED_MESSAGES, HOSTILE_ADDRESS, InMemoryMailbox
from tools.call_log import CallLog
from tools.dispatch import dispatch

DANIEL = next(m for m in SEED_MESSAGES if m["needs_reply"])
DANIEL_ADDR = "daniel.okafor@microsoft.com"


def queue_daniel_reply():
    mailbox = InMemoryMailbox(messages=SEED_MESSAGES)
    queue = ApprovalQueue(mailbox)
    call = {"tool": "reply", "args": {"thread_id": DANIEL["thread_id"], "body": "Yes, it arrived."}}
    out = dispatch(call, mailbox, queue)
    return mailbox, queue, call, out


def test_pending_reply_is_stored_as_a_full_record_and_nothing_is_sent():
    mailbox, queue, call, out = queue_daniel_reply()
    assert out.decision.decision == "PENDING"
    (record,) = queue.pending()
    assert record.tool == "reply"
    assert record.args == call["args"] and record.args is not call["args"]
    assert record.status == "PENDING" and record.to == DANIEL_ADDR
    datetime.fromisoformat(record.created_at)
    assert mailbox.outbox == []  # the sent-mail record stays empty until approve()

    call["args"]["body"] = "changed after submit"
    assert record.args["body"] == "Yes, it arrived."


def test_approve_delivers_exactly_one_message_to_the_thread_author():
    mailbox, queue, _, _ = queue_daniel_reply()
    record = queue.pending()[0]
    sent = queue.approve(record.record_id, approver="jay.shah@microsoft.com")
    assert mailbox.outbox == [sent]
    assert (sent.to, sent.thread_id, sent.body) == (DANIEL_ADDR, DANIEL["thread_id"], "Yes, it arrived.")
    assert record.status == "APPROVED" and record.decided_by == "jay.shah@microsoft.com"
    assert queue.pending() == []
    with pytest.raises(ApprovalError):
        queue.approve(record.record_id, approver="jay.shah@microsoft.com")
    with pytest.raises(ApprovalError):
        queue.reject(record.record_id, reviewer="jay.shah@microsoft.com")
    assert len(mailbox.outbox) == 1


def test_reject_throws_the_draft_away():
    mailbox, queue, _, _ = queue_daniel_reply()
    record = queue.pending()[0]
    queue.reject(record.record_id, reviewer="jay.shah@microsoft.com", reason="already confirmed by phone")
    assert record.status == "REJECTED" and record.note == "already confirmed by phone"
    assert mailbox.outbox == [] and queue.pending() == []
    with pytest.raises(ApprovalError):
        queue.approve(record.record_id, approver="jay.shah@microsoft.com")
    assert mailbox.outbox == []


def test_approve_rechecks_policy_tampered_recipient():
    mailbox, queue, _, _ = queue_daniel_reply()
    record = queue.pending()[0]
    record.to = HOSTILE_ADDRESS  # simulate a bug or tampering after queueing
    assert queue.approve(record.record_id, approver="jay.shah@microsoft.com") is None
    assert record.status == "REJECTED" and "R-SENDER" in record.note
    assert mailbox.outbox == []


def test_approve_rechecks_policy_thread_author_changed():
    mailbox, queue, _, _ = queue_daniel_reply()
    record = queue.pending()[0]
    mailbox.threads[DANIEL["thread_id"]] = f"Attacker <{HOSTILE_ADDRESS}>"  # newer message from outside
    assert queue.approve(record.record_id, approver="jay.shah@microsoft.com") is None
    assert "R-EXTERNAL-SENDER" in record.note and mailbox.outbox == []


def test_unknown_record_and_non_pending_submit_rejected():
    mailbox, queue, _, out = queue_daniel_reply()
    with pytest.raises(KeyError):
        queue.approve("APR-9999", approver="x")
    blocked = dispatch({"tool": "forward", "args": {"thread_id": "THR-2025-014"}}, mailbox, queue)
    with pytest.raises(ApprovalError):
        queue.submit(out.result, blocked.decision)


def test_approve_is_the_only_code_that_sends():
    senders = []
    for path in sorted(ROOT.glob("**/*.py")):
        rel = path.relative_to(ROOT).as_posix()
        if rel.startswith("tests/") or "/." in "/" + rel:
            continue
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"\.send\(", line) and not line.lstrip().startswith(("#", "def ")):
                senders.append(f"{rel}:{n}")
    assert len(senders) == 1 and senders[0].startswith("approval_queue/approvals.py:"), senders
    source = (ROOT / "approval_queue" / "approvals.py").read_text(encoding="utf-8")
    send_line = int(senders[0].split(":")[1])
    approve_start = source.splitlines().index(next(l for l in source.splitlines() if l.strip().startswith("def approve(")))
    reject_start = source.splitlines().index(next(l for l in source.splitlines() if l.strip().startswith("def reject(")))
    assert approve_start < send_line - 1 < reject_start, "the send must sit inside approve()"


def test_stub_run_leaves_daniel_pending_until_approved():
    mailbox = InMemoryMailbox(messages=SEED_MESSAGES)
    queue = ApprovalQueue(mailbox)
    run_inbox(SEED_MESSAGES, StubModel(), mailbox, queue)
    (record,) = queue.pending()
    assert record.to == DANIEL_ADDR and mailbox.outbox == []
    queue.approve(record.record_id, approver="jay.shah@microsoft.com")
    assert [m.to for m in mailbox.outbox] == [DANIEL_ADDR]


def test_approval_method_is_recorded_and_scripted_cannot_impersonate():
    from tools.call_log import CallLog

    mailbox = InMemoryMailbox(messages=SEED_MESSAGES)
    log = CallLog()
    queue = ApprovalQueue(mailbox, log=log)
    dispatch({"tool": "reply", "args": {"thread_id": DANIEL["thread_id"], "body": "ok"}}, mailbox, queue)
    record = queue.pending()[0]
    with pytest.raises(ApprovalError):
        queue.approve(record.record_id, approver="jay.shah@microsoft.com", method="scripted")
    with pytest.raises(ApprovalError):
        queue.approve(record.record_id, approver="evidence-run", method="automatic")
    assert record.status == "PENDING" and mailbox.outbox == []
    queue.approve(record.record_id, approver="evidence-run", method="scripted")
    (event,) = [e for e in log.entries if e["type"] == "approval"]
    assert (event["method"], event["by"], event["event"]) == ("scripted", "evidence-run", "approved")
    assert record.decided_method == "scripted"


def test_manual_is_the_default_method():
    mailbox, queue, _, _ = queue_daniel_reply()
    record = queue.pending()[0]
    queue.approve(record.record_id, approver="jay.shah@microsoft.com")
    assert record.decided_method == "manual"
