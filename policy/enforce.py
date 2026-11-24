"""Policy layer: every tool call passes through `enforce()` before any handler runs.

Implements policy-spec.md sections 2-4. Evaluation order (section 5):

    T  tool allow-list  ->  R-EXTERNAL-SENDER  ->  R-SENDER  ->  R-DOMAIN  ->  R-SYNTAX  ->  Q

Decisions are exactly one of BLOCKED, PENDING, ALLOWED.

Fail-closed choices:
- Unknown tool name (anything not declared in tools/definitions.py, compared
  exactly: "Reply", " reply" and "forward_message" are all unknown) -> BLOCKED, rule T.
  The handler table is never consulted.
- A call that is not {"tool": str, "args": dict}, or whose args break the tool's
  schema (missing/extra/wrong-typed fields) -> BLOCKED, rule T.
- An address the parser cannot turn into exactly one plain ASCII local@domain
  (e.g. "sofia.lindqvist(at)microsoft.com", "archive.desk.at.gmail.com",
  homoglyph domains) is never repaired and always ends BLOCKED. Order decides the
  rule: on a thread from an outside author R-EXTERNAL-SENDER fires first (replay
  RPL-022/023 backstop); on an internal thread the address cannot equal the author,
  so R-SENDER fires. An unparseable stored From header -> R-EXTERNAL-SENDER.
- Any unexpected exception inside the policy layer -> BLOCKED, rule FAIL-CLOSED.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from email.utils import getaddresses

from tools.definitions import OUTBOUND_TOOLS, READ_ONLY_TOOLS, TOOLS

BLOCKED = "BLOCKED"
PENDING = "PENDING"
ALLOWED = "ALLOWED"
DECISIONS = frozenset({BLOCKED, PENDING, ALLOWED})

OWN_DOMAIN = "microsoft.com"
RECIPIENT_FIELDS = ("to", "cc", "bcc")

_PLAIN_ADDR = re.compile(r"[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+")
_JSON_TYPES = {"string": str, "integer": int, "object": dict}


@dataclass(frozen=True)
class Decision:
    """Result of enforce(). `recipient` is set only for PENDING replies."""

    decision: str
    rule: str
    reason: str
    tool: str | None = None
    recipient: str | None = None
    backstop: tuple[str, str] | None = None  # what section 4 alone would decide


@dataclass(frozen=True)
class ParsedAddress:
    raw: str  # the token exactly as supplied
    display: str  # display name or comment the parser found
    addr: str  # address part the parser returned
    valid: bool  # exactly one plain ASCII local@domain

    @property
    def norm(self) -> str | None:
        return self.addr.lower() if self.valid else None

    @property
    def domain(self) -> str | None:
        return self.norm.rsplit("@", 1)[1] if self.valid else None


# --------------------------------------------------------------------------- parsing


def _split_tokens(value: str) -> list[str]:
    """Split a recipient field on ',' or ';' outside quotes, <...> and (...)."""
    tokens, buf, quoted, angle, paren = [], [], False, 0, 0
    prev = ""
    for ch in value:
        if ch == '"' and prev != "\\":
            quoted = not quoted
        elif not quoted:
            if ch == "<":
                angle += 1
            elif ch == ">":
                angle = max(0, angle - 1)
            elif ch == "(":
                paren += 1
            elif ch == ")":
                paren = max(0, paren - 1)
            elif ch in ",;" and angle == 0 and paren == 0:
                tokens.append("".join(buf))
                buf = []
                prev = ch
                continue
        buf.append(ch)
        prev = ch
    tokens.append("".join(buf))
    return [t for t in tokens if t.strip()]


def parse_address(token: str) -> ParsedAddress:
    """Parse one address with the stdlib RFC 5322 parser, then verify the result strictly."""
    if not isinstance(token, str):
        return ParsedAddress(raw=repr(token), display="", addr="", valid=False)
    pairs = getaddresses([token])  # strict parsing (Python 3.13+ default)
    if len(pairs) != 1:
        return ParsedAddress(raw=token, display="", addr="", valid=False)
    display, addr = pairs[0]
    valid = bool(addr) and addr.isascii() and addr.count("@") == 1 and bool(
        _PLAIN_ADDR.fullmatch(addr.lower())
    )
    return ParsedAddress(raw=token, display=display, addr=addr, valid=valid)


def parse_recipients(value) -> list[ParsedAddress]:
    """Parse a to/cc/bcc value (string or list of strings) into one entry per address token."""
    if value is None:
        return []
    items = [value] if isinstance(value, str) else list(value)
    out: list[ParsedAddress] = []
    for item in items:
        if not isinstance(item, str):
            out.append(parse_address(item))
            continue
        out.extend(parse_address(tok) for tok in _split_tokens(item))
    return out


def is_own_domain(address: str) -> bool:
    """Exact-domain check used by R-EXTERNAL-SENDER and R-DOMAIN: domain == microsoft.com."""
    parsed = parse_address(address)
    return parsed.valid and parsed.domain == OWN_DOMAIN


# --------------------------------------------------------------------------- schema


def _schema_error(tool: str, args: dict) -> str | None:
    schema = TOOLS[tool]["parameters"]
    props = schema.get("properties", {})
    missing = [k for k in schema.get("required", []) if k not in args]
    if missing:
        return f"missing required field(s) {missing}"
    if schema.get("additionalProperties") is False:
        extra = sorted(set(args) - set(props))
        if extra:
            return f"field(s) {extra} not in the {tool} schema"
    for key, value in args.items():
        expected = _JSON_TYPES.get(props.get(key, {}).get("type"))
        if expected and (not isinstance(value, expected) or isinstance(value, bool)):
            return f"field {key!r} must be {props[key]['type']}"
    return None


# --------------------------------------------------------------------------- recipient rules


def recipient_rules(thread_from, recipients: dict) -> tuple[str, str, str, str | None]:
    """Section 4. Returns (decision, rule, reason, recipient). `recipients` holds any
    to/cc/bcc the call tried to set; with no `to`, the recipient is the thread author."""
    sender = parse_address(thread_from) if thread_from is not None else None

    # R-EXTERNAL-SENDER: reply only exists on threads whose stored From is exactly @microsoft.com
    if sender is None or not sender.valid or sender.domain != OWN_DOMAIN:
        shown = "unknown thread" if thread_from is None else repr(thread_from)
        return BLOCKED, "R-EXTERNAL-SENDER", f"thread author {shown} is not on {OWN_DOMAIN}", None

    if "to" in recipients:
        to = parse_recipients(recipients["to"])
    else:
        to = [ParsedAddress(raw=sender.addr, display="", addr=sender.addr, valid=True)]
    cc = parse_recipients(recipients.get("cc"))
    bcc = parse_recipients(recipients.get("bcc"))

    # R-SENDER: exactly one To, equal to the thread author, no cc/bcc
    if len(to) != 1 or cc or bcc or not to[0].valid or to[0].norm != sender.norm:
        return BLOCKED, "R-SENDER", "recipients must be exactly the thread author, no cc/bcc", None

    target = to[0]
    # R-DOMAIN: re-check the final recipient's domain (defence in depth; also runs at send time)
    if target.domain != OWN_DOMAIN:
        return BLOCKED, "R-DOMAIN", f"recipient domain {target.domain!r} is not {OWN_DOMAIN}", None

    # R-SYNTAX: plain local@domain exactly as written, no padding, display name or comment
    if target.raw != target.raw.strip() or target.display or target.raw.lower() != target.norm:
        return BLOCKED, "R-SYNTAX", f"recipient {target.raw!r} is not a plain address", None

    return PENDING, "Q", "reply to thread author queued for human approval", target.norm


# --------------------------------------------------------------------------- entry point


def enforce(call, thread_from: str | None = None) -> Decision:
    """Decide a tool call before any handler runs.

    call:        {"tool": <name>, "args": {...}} as produced by the model.
    thread_from: the stored From header of the thread named by args["thread_id"],
                 looked up by the dispatcher (never taken from the model or the email body).
    """
    try:
        return _enforce(call, thread_from)
    except Exception as exc:  # never let a policy bug turn into an allow
        tool = call.get("tool") if isinstance(call, dict) else None
        return Decision(BLOCKED, "FAIL-CLOSED", f"policy error: {type(exc).__name__}", tool)


def _enforce(call, thread_from) -> Decision:
    if not isinstance(call, dict) or not isinstance(call.get("tool"), str):
        return Decision(BLOCKED, "T", "malformed tool call")
    tool = call["tool"]
    raw_args = call.get("args", {})
    if not isinstance(raw_args, dict):
        return Decision(BLOCKED, "T", "tool arguments must be an object", tool)

    args = dict(raw_args)
    recipients = {k: args.pop(k) for k in RECIPIENT_FIELDS if k in args}

    if tool in READ_ONLY_TOOLS and not recipients:
        backstop = (ALLOWED, "T0")
    else:
        b_dec, b_rule, _, _ = recipient_rules(thread_from, recipients)
        backstop = (b_dec, b_rule)

    # T: tool allow-list
    if tool not in TOOLS:
        return Decision(BLOCKED, "T", f"tool {tool!r} is not registered", tool, backstop=backstop)

    if tool in READ_ONLY_TOOLS:
        if recipients:
            return Decision(BLOCKED, "T", f"{tool} takes no recipients", tool, backstop=backstop)
        error = _schema_error(tool, args)
        if error:
            return Decision(BLOCKED, "T", error, tool, backstop=backstop)
        return Decision(ALLOWED, "T0", "read-only tool, nothing leaves the mailbox", tool, backstop=backstop)

    assert tool in OUTBOUND_TOOLS  # reply
    error = _schema_error(tool, args)
    if error:
        return Decision(BLOCKED, "T", error, tool, backstop=backstop)
    decision, rule, reason, recipient = recipient_rules(thread_from, recipients)
    return Decision(decision, rule, reason, tool, recipient=recipient, backstop=backstop)
