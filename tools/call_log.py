"""Structured call log: one entry per tool call that reaches dispatch(), whatever the outcome
(type "tool_call"), plus lifecycle events written by the approval queue and the runner
(type "approval", "sent_mail"), so a saved run shows what actually left the mailbox.

Each entry records the tool, the arguments exactly as the model passed them (and the raw
argument string when the model sent JSON text), the policy decision, the rule that fired,
the reason and the result. BLOCKED calls are logged like any other.
"""

from __future__ import annotations

import copy
import dataclasses
import json
from datetime import datetime, timezone


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _jsonable(obj):
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    return str(obj)


class CallLog:
    def __init__(self, clock=utc_now):
        self._clock = clock
        self.entries: list[dict] = []

    def record(self, call, decision, result=None, context: dict | None = None) -> dict:
        is_call = isinstance(call, dict)
        entry = {
            "entry_id": len(self.entries) + 1,
            "timestamp": self._clock(),
            "type": "tool_call",
            "tool": call.get("tool") if is_call else None,
            "args": copy.deepcopy(call.get("args")) if is_call else copy.deepcopy(call),
            "decision": decision.decision,
            "rule": decision.rule,
            "reason": decision.reason,
            "result": json.loads(json.dumps(result, default=_jsonable)),
        }
        entry.update(context or {})
        self.entries.append(entry)
        return entry

    def event(self, type_: str, **fields) -> dict:
        entry = {"entry_id": len(self.entries) + 1, "timestamp": self._clock(), "type": type_}
        entry.update(json.loads(json.dumps(fields, default=_jsonable)))
        self.entries.append(entry)
        return entry

    def tool_calls(self) -> list[dict]:
        return [e for e in self.entries if e["type"] == "tool_call"]

    def to_jsonl(self) -> str:
        return "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in self.entries)
