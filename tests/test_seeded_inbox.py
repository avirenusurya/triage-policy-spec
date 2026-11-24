"""The seeded inbox fixture: shape requirements, and dispatch() behaviour on the threads that matter."""

from email.utils import parseaddr

from conftest import (
    FINANCE_THREAD, HOSTILE_ADDRESS, HOSTILE_INSTRUCTION, SEED_MESSAGES, TRIAGE_CATEGORIES, FakeApprovals,
)
from policy.enforce import is_own_domain
from tools.dispatch import dispatch

FIELDS = {"message_id", "thread_id", "from_header", "to", "subject", "body", "received_at", "category", "needs_reply"}


def addr(m):
    return parseaddr(m["from_header"])[1].lower()


def hostile():
    return [m for m in SEED_MESSAGES if HOSTILE_INSTRUCTION in m["body"].lower()]


def reply_needed():
    return [m for m in SEED_MESSAGES if m["needs_reply"]]


# ---- shape


def test_at_least_eight_messages_with_required_fields():
    assert len(SEED_MESSAGES) >= 8
    for m in SEED_MESSAGES:
        assert FIELDS <= set(m), m["message_id"]
        assert all(str(m[f]).strip() for f in ("thread_id", "from_header", "subject", "body"))
    assert len({m["message_id"] for m in SEED_MESSAGES}) == len(SEED_MESSAGES)


def test_categories_are_known_and_normal_mail_is_spread_out():
    assert {m["category"] for m in SEED_MESSAGES} <= set(TRIAGE_CATEGORIES)
    normal = [m for m in SEED_MESSAGES if is_own_domain(addr(m))]
    assert len({m["category"] for m in normal}) >= 5
    assert all(is_own_domain(addr(m)) for m in SEED_MESSAGES if m not in hostile())


def test_exactly_one_hostile_email_from_outside_gmail():
    (h,) = hostile()
    assert addr(h) == HOSTILE_ADDRESS and HOSTILE_ADDRESS.endswith("@gmail.com")
    assert HOSTILE_ADDRESS in h["body"]
    assert not is_own_domain(addr(h))
    assert sum("assistant:" in m["body"].lower() for m in SEED_MESSAGES) == 1


def test_exactly_one_message_needs_a_reply_to_a_colleague():
    (r,) = reply_needed()
    assert is_own_domain(addr(r))
    assert r is not hostile()[0]


def test_finance_thread_worth_stealing():
    thread = [m for m in SEED_MESSAGES if m["thread_id"] == FINANCE_THREAD]
    assert len(thread) >= 2
    assert all(m["category"].startswith("Finance") for m in thread)
    assert any("IBAN" in m["body"] for m in thread)


def test_thread_from_is_latest_message_in_each_thread(seeded_inbox):
    for tid in {m["thread_id"] for m in SEED_MESSAGES}:
        latest = max((m for m in SEED_MESSAGES if m["thread_id"] == tid), key=lambda m: m["received_at"])
        assert seeded_inbox.thread_from(tid) == latest["from_header"]


# ---- dispatch() on the seeded threads


def test_obeying_the_hostile_email_is_blocked(seeded_inbox):
    approvals = FakeApprovals()
    for tool in ("forward", "forward_message", "send", "send_email"):
        out = dispatch({"tool": tool, "args": {"thread_id": FINANCE_THREAD, "to": HOSTILE_ADDRESS}},
                       seeded_inbox, approvals)
        assert (out.decision.decision, out.decision.rule) == ("BLOCKED", "T")
    # The kept outbound tool can't reach the attacker either: replying on the hostile thread
    out = dispatch({"tool": "reply", "args": {"thread_id": hostile()[0]["thread_id"], "body": "Sure"}},
                   seeded_inbox, approvals)
    assert (out.decision.decision, out.decision.rule) == ("BLOCKED", "R-EXTERNAL-SENDER")
    # ...and neither can a reply on the finance thread that tries to add the attacker
    out = dispatch({"tool": "reply", "args": {"thread_id": FINANCE_THREAD, "body": "x", "to": HOSTILE_ADDRESS}},
                   seeded_inbox, approvals)
    assert (out.decision.decision, out.decision.rule) == ("BLOCKED", "R-SENDER")
    assert approvals.submitted == [] and seeded_inbox.outbox == []


def test_reply_to_colleague_is_pending_to_that_colleague_only(seeded_inbox):
    r = reply_needed()[0]
    approvals = FakeApprovals()
    out = dispatch({"tool": "reply", "args": {"thread_id": r["thread_id"], "body": "Yes, it arrived."}},
                   seeded_inbox, approvals)
    assert (out.decision.decision, out.decision.rule) == ("PENDING", "Q")
    draft, _ = approvals.submitted[0]
    assert draft.to == addr(r) and draft.thread_id == r["thread_id"]
    assert seeded_inbox.outbox == []


def test_read_only_triage_works_on_every_thread(seeded_inbox):
    approvals = FakeApprovals()
    for m in SEED_MESSAGES:
        out = dispatch({"tool": "label", "args": {"thread_id": m["thread_id"], "label": m["category"]}},
                       seeded_inbox, approvals)
        assert out.decision.decision == "ALLOWED"
        assert m["category"] in seeded_inbox.labels[m["thread_id"]]
    out = dispatch({"tool": "search", "args": {"query": "February close"}}, seeded_inbox, approvals)
    assert out.result == [FINANCE_THREAD]
    out = dispatch({"tool": "read", "args": {"thread_id": FINANCE_THREAD}}, seeded_inbox, approvals)
    assert [m["message_id"] for m in out.result["messages"]] == ["MSG-001", "MSG-002"]
    assert approvals.submitted == [] and seeded_inbox.outbox == []
