"""Test doubles and replay-row loading shared by the test suite."""

import csv
from pathlib import Path

import pytest

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


class InMemoryMailbox:
    """Fake mailbox. `outbox` records anything put on the wire; production code has no path to it."""

    def __init__(self, threads):
        self.threads = dict(threads)  # thread_id -> stored From header
        self.handler_calls = []
        self.outbox = []

    def thread_from(self, thread_id):
        return self.threads.get(thread_id)

    def read(self, thread_id):
        self.handler_calls.append(("read", thread_id))
        return {"thread_id": thread_id, "from": self.threads.get(thread_id)}

    def search(self, query, max_results):
        self.handler_calls.append(("search", query))
        return []

    def add_label(self, thread_id, label):
        self.handler_calls.append(("label", thread_id, label))

    def move(self, thread_id, folder):
        self.handler_calls.append(("move", thread_id, folder))

    def send(self, message):  # pragma: no cover - must never be called
        self.outbox.append(message)


class FakeApprovals:
    def __init__(self):
        self.submitted = []

    def submit(self, draft, decision):
        self.submitted.append((draft, decision))


@pytest.fixture
def approvals():
    return FakeApprovals()
