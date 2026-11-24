"""Fixtures and replay-row loading shared by the test suite. The seeded messages and the
in-memory mailbox live in agent/sandbox.py so the agent runner can use them too."""

import csv
from pathlib import Path

import pytest

from agent.sandbox import (  # noqa: F401  (re-exported for the tests)
    FINANCE_THREAD,
    HOSTILE_ADDRESS,
    HOSTILE_INSTRUCTION,
    SEED_MESSAGES,
    TRIAGE_CATEGORIES,
    InMemoryMailbox,
    RecordingApprovals,
)

FakeApprovals = RecordingApprovals

ROOT = Path(__file__).resolve().parent.parent

# Replay sheet tool names -> what the model would call. Unregistered names stay as-is.
TOOL_ALIASES = {"draft_reply": "reply", "list_messages": "search"}


def load_rows():
    rows = []
    for name in ("replay_set.csv", "spec_cases.csv"):
        with open(ROOT / name, newline="", encoding="utf-8") as f:
            rows += list(csv.DictReader(f))
    return rows


def row_to_call(row):
    """Build the tool call an obedient model would make for this replay row."""
    tool = TOOL_ALIASES.get(row["requested_tool"], row["requested_tool"])
    if tool == "search":
        return {"tool": "search", "args": {"query": row["subject"]}}
    args = {"thread_id": row["referenced_thread_id"]}
    if tool == "reply":
        args["body"] = "Confirming receipt."
    for field, column in (("to", "target_to"), ("cc", "target_cc"), ("bcc", "target_bcc")):
        if row[column]:
            args[field] = row[column]  # raw, padding and all
    return {"tool": tool, "args": args}


@pytest.fixture
def approvals():
    return FakeApprovals()


@pytest.fixture
def seeded_inbox():
    """A fresh mailbox holding SEED_MESSAGES. dispatch() looks up the stored From through
    mailbox.thread_from(thread_id), exactly as with the replay rows."""
    return InMemoryMailbox(messages=SEED_MESSAGES)
