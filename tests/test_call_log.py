"""Call log: one structured entry per tool call, blocked calls included."""

import json

from agent.runner import RunReport, run_inbox, triage_message, OpenRouterModel
from agent.stub_model import StubModel
from approval_queue.approvals import ApprovalQueue
from conftest import SEED_MESSAGES, HOSTILE_ADDRESS, InMemoryMailbox, FINANCE_THREAD

FIELDS = {"entry_id", "timestamp", "tool", "args", "decision", "rule", "reason", "result", "message_id", "source"}
HOSTILE = next(m for m in SEED_MESSAGES if "assistant:" in m["body"])


def stub_run():
    mailbox = InMemoryMailbox(messages=SEED_MESSAGES)
    queue = ApprovalQueue(mailbox)
    report = run_inbox(SEED_MESSAGES, StubModel(), mailbox, queue)
    return report, mailbox, queue


def test_one_entry_per_tool_call_with_required_fields():
    report, _, _ = stub_run()
    entries = report.call_log.entries
    assert len(entries) == len(report.steps) > 0
    assert [e["entry_id"] for e in entries] == list(range(1, len(entries) + 1))
    for e in entries:
        assert FIELDS <= set(e)
        assert e["decision"] in {"BLOCKED", "PENDING", "ALLOWED"}


def test_blocked_calls_are_logged_with_the_models_exact_arguments():
    report, _, _ = stub_run()
    hostile = [e for e in report.call_log.entries if e["message_id"] == HOSTILE["message_id"]]
    blocked = [e for e in hostile if e["decision"] == "BLOCKED"]
    assert sorted((e["tool"], e["rule"]) for e in blocked) == [
        ("forward", "T"), ("reply", "R-EXTERNAL-SENDER"), ("reply", "R-SENDER"), ("send", "T")]
    fwd = next(e for e in blocked if e["tool"] == "forward")
    assert fwd["args"] == {"thread_id": FINANCE_THREAD, "to": HOSTILE_ADDRESS}
    assert json.loads(fwd["raw_arguments"]) == fwd["args"]  # the exact text the model sent
    assert all(e["result"] is None for e in blocked)


def test_pending_entry_points_at_the_approval_record():
    report, mailbox, queue = stub_run()
    (pending,) = [e for e in report.call_log.entries if e["decision"] == "PENDING"]
    assert pending["rule"] == "Q"
    record = queue.records[pending["result"]["approval_id"]]
    assert pending["result"] == {"approval_id": record.record_id, "status": "PENDING", "to": record.to}
    assert record.args == pending["args"]
    assert mailbox.outbox == []


def test_unparseable_arguments_are_logged_raw():
    replies = iter([
        {"choices": [{"message": {"content": None, "tool_calls": [
            {"id": "c1", "type": "function", "function": {"name": "reply", "arguments": "{not json"}}]}}]},
        {"choices": [{"message": {"content": "done", "tool_calls": []}}]},
    ])
    model = OpenRouterModel("some-provider/some-model", "test-key", post=lambda *a: next(replies))
    mailbox = InMemoryMailbox(messages=SEED_MESSAGES)
    report = RunReport()
    triage_message(HOSTILE, model, mailbox, ApprovalQueue(mailbox), report)
    entry = report.call_log.entries[0]
    assert (entry["tool"], entry["args"], entry["raw_arguments"]) == ("reply", "{not json", "{not json")
    assert (entry["decision"], entry["rule"]) == ("BLOCKED", "T")


def test_log_serialises_to_json_lines():
    report, _, _ = stub_run()
    lines = report.call_log.to_jsonl().splitlines()
    assert len(lines) == len(report.call_log.entries)
    assert [json.loads(line) for line in lines] == report.call_log.entries
