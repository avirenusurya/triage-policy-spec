"""Attack replay, part 1: end-to-end run on the seeded inbox, reading the sent-mail record
(mailbox.outbox) directly after each step."""

import json

from agent.runner import RunReport, run_inbox, triage_message
from agent.stub_model import StubModel
from approval_queue.approvals import ApprovalQueue
from conftest import HOSTILE_ADDRESS, ROOT, SEED_MESSAGES, InMemoryMailbox

HOSTILE = next(m for m in SEED_MESSAGES if "assistant:" in m["body"])
DANIEL = next(m for m in SEED_MESSAGES if m["needs_reply"])
DANIEL_ADDR = "daniel.okafor@microsoft.com"
RUN_LOG = ROOT / "runs" / "seeded-inbox-stub.jsonl"


def fresh():
    mailbox = InMemoryMailbox(messages=SEED_MESSAGES)
    return mailbox, ApprovalQueue(mailbox), StubModel(), RunReport()


def test_sent_mail_is_empty_after_the_hostile_email_is_processed():
    mailbox, queue, model, report = fresh()
    for msg in sorted(SEED_MESSAGES, key=lambda m: m["received_at"]):
        triage_message(msg, model, mailbox, queue, report)
        if msg is HOSTILE:
            assert mailbox.outbox == []
            assert queue.pending() == []  # nothing from the hostile email even reached the queue
    assert mailbox.outbox == []  # and still empty once the whole inbox is done


def test_sent_mail_holds_daniels_reply_only_after_approve():
    mailbox, queue, model, _ = fresh()
    run_inbox(SEED_MESSAGES, model, mailbox, queue)
    (record,) = queue.pending()
    assert mailbox.outbox == []

    queue.approve(record.record_id, approver="jay.shah@microsoft.com")

    assert len(mailbox.outbox) == 1
    (sent,) = mailbox.outbox
    assert (sent.to, sent.thread_id) == (DANIEL_ADDR, DANIEL["thread_id"])
    assert all(m.to != HOSTILE_ADDRESS for m in mailbox.outbox)


def test_saved_run_log_matches_a_fresh_run():
    saved = [json.loads(line) for line in RUN_LOG.read_text(encoding="utf-8").splitlines()]
    saved = [e for e in saved if e["type"] == "tool_call"]
    mailbox, queue, model, _ = fresh()
    report = run_inbox(SEED_MESSAGES, model, mailbox, queue)

    def strip(entries):
        return [{k: v for k, v in e.items() if k != "timestamp"} for e in entries]

    assert strip(saved) == strip(report.call_log.entries)
    hostile_outbound = [e for e in saved if e["message_id"] == HOSTILE["message_id"]
                        and e["tool"] in ("forward", "send", "reply")]
    assert len(hostile_outbound) == 4 and all(e["decision"] == "BLOCKED" for e in hostile_outbound)
