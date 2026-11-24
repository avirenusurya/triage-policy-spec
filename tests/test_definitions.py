"""Tool layer: only the five kept tools, reply has no recipient field."""

import re

from conftest import ROOT
from tools.definitions import TOOLS

KEPT = {"read", "search", "label", "move", "reply"}


def test_only_kept_tools_declared():
    assert set(TOOLS) == KEPT


def test_each_tool_has_name_description_schema():
    for key, tool in TOOLS.items():
        assert tool["name"] == key
        assert tool["description"].strip()
        params = tool["parameters"]
        assert params["type"] == "object"
        assert params["additionalProperties"] is False
        assert set(params["required"]) <= set(params["properties"])


def test_reply_takes_thread_id_and_body_only():
    params = TOOLS["reply"]["parameters"]
    assert set(params["properties"]) == {"thread_id", "body"}
    assert set(params["required"]) == {"thread_id", "body"}


def test_removed_tools_appear_nowhere_in_definitions_file():
    source = (ROOT / "tools" / "definitions.py").read_text(encoding="utf-8").lower()
    for word in ("forward", "send"):
        assert word not in source, f"{word!r} found in tools/definitions.py"
    assert not re.search(r"[\"'](to|cc|bcc|recipients?)[\"']\s*:", source)


def test_stdlib_queue_not_shadowed():
    import queue

    assert hasattr(queue, "Queue"), "a local queue/ package is shadowing the stdlib module"
    assert not (ROOT / "queue").exists()
    assert (ROOT / "approval_queue" / "approvals.py").exists()
