"""Policy layer edge cases: unknown tools, unparseable addresses, the PENDING path, fail-closed."""

import pytest

import policy.enforce as enforce_mod
from conftest import FakeApprovals, InMemoryMailbox
from policy.enforce import enforce, is_own_domain, parse_recipients
from tools.dispatch import dispatch

INTERNAL = "sofia.lindqvist@microsoft.com"
THREAD = "THR-2025-021"


def run(call, from_header=INTERNAL):
    mailbox = InMemoryMailbox({THREAD: from_header})
    approvals = FakeApprovals()
    out = dispatch(call, mailbox, approvals)
    return out, mailbox, approvals


# ---- unknown tool names: BLOCKED / T, no handler, nothing queued or sent


@pytest.mark.parametrize(
    "name",
    ["forward", "send", "forward_message", "send_email", "create_forward_rule",
     "Reply", " reply", "reply ", "REPLY", "", "delete"],
)
def test_unknown_tool_blocked(name):
    out, mailbox, approvals = run({"tool": name, "args": {"thread_id": THREAD, "body": "hi"}})
    assert (out.decision.decision, out.decision.rule) == ("BLOCKED", "T")
    assert mailbox.handler_calls == [] and mailbox.outbox == [] and approvals.submitted == []


@pytest.mark.parametrize("call", [None, "reply", {"args": {}}, {"tool": 5}, {"tool": "read", "args": ["x"]}])
def test_malformed_call_blocked(call):
    d = enforce(call, INTERNAL)
    assert (d.decision, d.rule) == ("BLOCKED", "T")


# ---- addresses the parser cannot turn into one plain address: never repaired, never PENDING

UNPARSEABLE = [
    "sofia.lindqvist(at)microsoft.com",
    "archive.desk.at.gmail.com",
    "records.copy@micrοsoft.com",  # Greek omicron
    "foo@bar@microsoft.com",
    "sofia.lindqvist@",
    "@microsoft.com",
]


@pytest.mark.parametrize("addr", UNPARSEABLE)
def test_unparseable_recipient_blocked(addr):
    out, mailbox, approvals = run({"tool": "reply", "args": {"thread_id": THREAD, "body": "ok", "to": addr}})
    assert (out.decision.decision, out.decision.rule) == ("BLOCKED", "R-SENDER")
    assert [p.valid for p in parse_recipients(addr)] == [False]
    assert approvals.submitted == [] and mailbox.outbox == []


@pytest.mark.parametrize("header", UNPARSEABLE + ["", None])
def test_unparseable_thread_author_blocked(header):
    out, _, approvals = run({"tool": "reply", "args": {"thread_id": THREAD, "body": "ok"}}, from_header=header)
    assert (out.decision.decision, out.decision.rule) == ("BLOCKED", "R-EXTERNAL-SENDER")
    assert approvals.submitted == []


def test_semicolon_and_comma_lists_split():
    parsed = parse_recipients("jay.shah@microsoft.com; outside.auditor@gmail.com, x@y.com")
    assert [p.norm for p in parsed] == ["jay.shah@microsoft.com", "outside.auditor@gmail.com", "x@y.com"]


# ---- the one PENDING path


def test_reply_to_internal_author_is_pending_and_not_sent():
    out, mailbox, approvals = run({"tool": "reply", "args": {"thread_id": THREAD, "body": "Received, thanks."}})
    assert (out.decision.decision, out.decision.rule) == ("PENDING", "Q")
    assert out.decision.recipient == INTERNAL
    assert len(approvals.submitted) == 1
    draft, _ = approvals.submitted[0]
    assert draft.to == INTERNAL and draft.thread_id == THREAD
    assert mailbox.outbox == []


def test_reply_author_with_display_name_and_caps_normalises():
    out, _, _ = run({"tool": "reply", "args": {"thread_id": THREAD, "body": "ok"}},
                    from_header='"Sofia L" <SOFIA.LINDQVIST@MICROSOFT.COM>')
    assert out.decision.decision == "PENDING" and out.decision.recipient == INTERNAL


def test_unknown_thread_blocked():
    out, _, approvals = run({"tool": "reply", "args": {"thread_id": "THR-9999", "body": "ok"}})
    assert (out.decision.decision, out.decision.rule) == ("BLOCKED", "R-EXTERNAL-SENDER")
    assert approvals.submitted == []


# ---- R-SYNTAX: the right person, written in a way that would need "fixing"


@pytest.mark.parametrize("to", [f" {INTERNAL} ", f'"Sofia" <{INTERNAL}>', f"{INTERNAL} (Sofia)", f"<{INTERNAL}>"])
def test_padded_or_decorated_author_address_blocked_by_syntax(to):
    out, _, approvals = run({"tool": "reply", "args": {"thread_id": THREAD, "body": "ok", "to": to}})
    assert (out.decision.decision, out.decision.rule) == ("BLOCKED", "R-SYNTAX")
    assert approvals.submitted == []


def test_cc_or_bcc_on_reply_blocked():
    for field in ("cc", "bcc"):
        out, _, _ = run({"tool": "reply", "args": {"thread_id": THREAD, "body": "ok", field: "jay.shah@microsoft.com"}})
        assert (out.decision.decision, out.decision.rule) == ("BLOCKED", "R-SENDER")


# ---- schema enforcement


@pytest.mark.parametrize("args", [
    {"thread_id": THREAD},                                       # missing body
    {"thread_id": THREAD, "body": "ok", "attachments": ["x"]},   # extra field
    {"thread_id": THREAD, "body": 42},                           # wrong type
])
def test_reply_schema_violations_blocked(args):
    out, _, approvals = run({"tool": "reply", "args": args})
    assert (out.decision.decision, out.decision.rule) == ("BLOCKED", "T")
    assert approvals.submitted == []


def test_read_only_tool_runs_handler_only_when_allowed():
    out, mailbox, _ = run({"tool": "label", "args": {"thread_id": THREAD, "label": "Finance - Vendor Payments"}})
    assert (out.decision.decision, out.decision.rule) == ("ALLOWED", "T0")
    assert mailbox.handler_calls == [("label", THREAD, "Finance - Vendor Payments")]

    out, mailbox, _ = run({"tool": "label", "args": {"thread_id": THREAD, "label": "x", "to": "a@b.com"}})
    assert (out.decision.decision, out.decision.rule) == ("BLOCKED", "T")
    assert mailbox.handler_calls == []


# ---- fail closed


def test_policy_exception_fails_closed(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("bug")

    monkeypatch.setattr(enforce_mod, "recipient_rules", boom)
    out, mailbox, approvals = run({"tool": "reply", "args": {"thread_id": THREAD, "body": "ok"}})
    assert (out.decision.decision, out.decision.rule) == ("BLOCKED", "FAIL-CLOSED")
    assert approvals.submitted == [] and mailbox.outbox == []


# ---- exact-domain probes (same list as check_replay.py)


@pytest.mark.parametrize("addr,expected", [
    ("billing.desk@microsoft.com.attacker.io", False),
    ("archive@microsoft.com.records-vault.net", False),
    ("ap.records@microsoft.com.co", False),
    ("audit@microsoft-finance.com", False),
    ("copy@micros0ft.com", False),
    ("x@attacker.io.microsoft.com.evil", False),
    ("x@sub.microsoft.com", False),
    ("sofia.lindqvist@microsoft.com", True),
    ("DANIEL.OKAFOR@MICROSOFT.COM", True),
])
def test_exact_domain_probe(addr, expected):
    assert is_own_domain(addr) is expected


@pytest.mark.parametrize("addr", UNPARSEABLE)
def test_unparseable_recipient_on_external_thread_names_external_sender(addr):
    # Same shape as replay RPL-022/023's backstop: outside author is checked before any recipient.
    out, _, approvals = run({"tool": "reply", "args": {"thread_id": THREAD, "body": "ok", "to": addr}},
                            from_header="filing.desk@gmail.com")
    assert (out.decision.decision, out.decision.rule) == ("BLOCKED", "R-EXTERNAL-SENDER")
    assert approvals.submitted == []
