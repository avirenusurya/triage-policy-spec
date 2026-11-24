"""Tool definitions for the triage agent (policy-spec.md section 2).

Only the five kept tools are declared. Nothing else is registered, so the model
cannot call any other tool, whatever an email asks for.

`reply` takes `thread_id` and `body` only. It has no recipient field: the
recipient is always the author of the thread, read from the stored From header
by the policy layer (policy/enforce.py), and every reply waits in the approval
queue for a human.
"""

_THREAD_ID = {
    "type": "string",
    "description": "Mailbox thread identifier, e.g. THR-2025-014.",
}

TOOLS = {
    "read": {
        "name": "read",
        "description": "Open a thread and return its messages so it can be classified. Read-only.",
        "parameters": {
            "type": "object",
            "properties": {"thread_id": _THREAD_ID},
            "required": ["thread_id"],
            "additionalProperties": False,
        },
    },
    "search": {
        "name": "search",
        "description": "Find threads or list messages matching a query in this mailbox. Read-only.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search text, e.g. 'payroll query'."},
                "max_results": {"type": "integer", "description": "Upper bound on results (1-50)."},
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    },
    "label": {
        "name": "label",
        "description": "Add a label to a thread, e.g. 'Finance - Vendor Payments' or 'Needs human'.",
        "parameters": {
            "type": "object",
            "properties": {
                "thread_id": _THREAD_ID,
                "label": {"type": "string", "description": "Label name to add."},
            },
            "required": ["thread_id", "label"],
            "additionalProperties": False,
        },
    },
    "move": {
        "name": "move",
        "description": "Move a thread to a folder in this mailbox, e.g. 'Read later' or 'Archive'.",
        "parameters": {
            "type": "object",
            "properties": {
                "thread_id": _THREAD_ID,
                "folder": {"type": "string", "description": "Destination folder in this mailbox."},
            },
            "required": ["thread_id", "folder"],
            "additionalProperties": False,
        },
    },
    "reply": {
        "name": "reply",
        "description": (
            "Draft a short reply to the author of a thread. The recipient is fixed by the "
            "system to the thread author's address and cannot be chosen. The draft goes to "
            "the approval queue; a human approves it before anything leaves the mailbox."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "thread_id": _THREAD_ID,
                "body": {"type": "string", "description": "Plain-text reply body. No attachments."},
            },
            "required": ["thread_id", "body"],
            "additionalProperties": False,
        },
    },
}

READ_ONLY_TOOLS = frozenset({"read", "search", "label", "move"})
OUTBOUND_TOOLS = frozenset({"reply"})
