"""One parametrised case per row of policy-spec.md section 5 (RPL-001..RPL-033)."""

import pytest

import check_replay
from conftest import ROOT, FakeApprovals, InMemoryMailbox, load_rows, row_to_call
from policy.enforce import DECISIONS, PENDING
from tools.dispatch import dispatch

X = ("BLOCKED", "R-EXTERNAL-SENDER")

# case_id: (decision, rule, backstop) -- must equal policy-spec.md section 5
EXPECTED = {
    "RPL-001": ("BLOCKED", "T", X),
    "RPL-002": ("BLOCKED", "T", X),
    "RPL-003": ("BLOCKED", "T", X),
    "RPL-004": ("BLOCKED", "T", X),
    "RPL-005": ("BLOCKED", "T", X),
    "RPL-006": ("BLOCKED", "T", X),
    "RPL-007": ("BLOCKED", "T", X),
    "RPL-008": ("BLOCKED", "T", X),
    "RPL-009": ("BLOCKED", "T", X),
    "RPL-010": ("BLOCKED", "T", X),
    "RPL-011": ("BLOCKED", "T", X),
    "RPL-012": ("BLOCKED", "T", X),
    "RPL-013": ("BLOCKED", "T", X),
    "RPL-014": ("BLOCKED", "T", X),
    "RPL-015": ("BLOCKED", "T", X),
    "RPL-016": ("BLOCKED", "T", X),
    "RPL-017": ("BLOCKED", "T", X),
    "RPL-018": ("BLOCKED", "T", X),
    "RPL-019": ("BLOCKED", "T", X),
    "RPL-020": ("BLOCKED", "T", X),
    "RPL-021": ("BLOCKED", "T", X),
    "RPL-022": ("BLOCKED", "T", X),
    "RPL-023": ("BLOCKED", "T", X),
    "RPL-024": ("BLOCKED", "T", X),
    "RPL-025": ("BLOCKED", "T", X),
    "RPL-026": ("BLOCKED", "T", X),
    "RPL-027": ("BLOCKED", "T", X),
    "RPL-028": ("BLOCKED", "T", X),
    "RPL-029": ("BLOCKED", "R-SENDER", ("BLOCKED", "R-SENDER")),
    "RPL-030": ("BLOCKED", "R-SENDER", ("BLOCKED", "R-SENDER")),
    "RPL-031": ("ALLOWED", "T0", ("ALLOWED", "T0")),
    "RPL-032": ("BLOCKED", "T", ("BLOCKED", "R-SENDER")),
    "RPL-033": ("BLOCKED", "R-EXTERNAL-SENDER", X),
}

ROWS = load_rows()


@pytest.mark.parametrize("row", ROWS, ids=[r["case_id"] for r in ROWS])
def test_replay_row(row):
    decision, rule, backstop = EXPECTED[row["case_id"]]
    mailbox = InMemoryMailbox({row["referenced_thread_id"]: row["from_address"]})
    approvals = FakeApprovals()

    out = dispatch(row_to_call(row), mailbox, approvals)

    assert out.decision.decision in DECISIONS
    assert (out.decision.decision, out.decision.rule) == (decision, rule), out.decision.reason
    assert out.decision.backstop == backstop
    assert mailbox.outbox == [], "something was sent"
    if decision == PENDING:
        assert len(approvals.submitted) == 1
    else:
        assert approvals.submitted == [], "a draft reached the approval queue"
    if decision == "BLOCKED":
        assert mailbox.handler_calls == [], "a handler ran for a blocked call"


def test_expected_table_matches_spec():
    spec = check_replay.load_spec_table()
    ours = {cid: ((d, r), b) for cid, (d, r, b) in EXPECTED.items()}
    assert ours == spec


def test_every_replay_row_has_a_case():
    ids = [r["case_id"] for r in ROWS]
    assert len(ids) == 33 and len(set(ids)) == 33
    assert set(ids) == set(EXPECTED)
