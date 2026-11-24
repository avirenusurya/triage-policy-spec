"""Check every replay row's decision in policy-spec.md section 5 against the spec's own rules.

Rules are re-implemented here from sections 2-4 and evaluated on the raw replay_set.csv.
For each row, the decision, rule and backstop columns in the spec table must match.

Usage: python check_replay.py   (exit code 0 only if every row matches)
"""

import csv
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent
OWN_DOMAIN = "microsoft.com"

# Section 2: replay tool name -> pilot tool. None = not a pilot tool (never registered).
TOOL_MAP = {
    "list_messages": "search",
    "draft_reply": "reply",
    "forward_message": "forward",
    "send_email": "send",
    "create_forward_rule": None,
}
KEPT_TOOLS = {"read", "search", "label", "move", "reply"}
READ_ONLY = {"read", "search", "label", "move"}

# Project decision strings: exact, nothing else is valid (pytest cases match these 1:1).
DECISIONS = {"BLOCKED", "PENDING", "ALLOWED"}

STRICT_ADDR = re.compile(r"^[a-z0-9._%+-]+@[a-z0-9.-]+$")


def is_own_domain(addr):
    """Exact-domain check shared by R-EXTERNAL-SENDER and R-DOMAIN: domain after the final @ == microsoft.com."""
    return normalize(addr).rsplit("@", 1)[-1] == OWN_DOMAIN


# Direct probes of the exact-domain check (expected result). Suffix/prefix tricks must fail.
DOMAIN_PROBES = {
    "billing.desk@microsoft.com.attacker.io": False,
    "archive@microsoft.com.records-vault.net": False,
    "ap.records@microsoft.com.co": False,
    "audit@microsoft-finance.com": False,
    "copy@micros0ft.com": False,
    "x@attacker.io.microsoft.com.evil": False,
    "sofia.lindqvist@microsoft.com": True,
    "DANIEL.OKAFOR@MICROSOFT.COM": True,
}


def split_addrs(field):
    return [a for a in re.split(r"[;,]", field or "") if a.strip()]


def normalize(addr):
    """Lower-case address with display name and outer whitespace removed (comparison only)."""
    addr = addr.strip()
    m = re.search(r"<([^>]*)>", addr)
    if m:
        addr = m.group(1)
    return addr.strip().lower()


def recipient_rules(row):
    """Section 4, applied to an outbound request regardless of tool. Returns (decision, rule)."""
    to = split_addrs(row["target_to"])
    cc = split_addrs(row["target_cc"])
    bcc = split_addrs(row["target_bcc"])
    sender = normalize(row["from_address"])
    raw_sender = row["from_address"]

    # R-EXTERNAL-SENDER: reply only exists on threads from a plain-ASCII @microsoft.com sender
    if (
        not raw_sender.isascii()
        or not STRICT_ADDR.match(raw_sender.strip().lower())
        or not is_own_domain(raw_sender)
    ):
        return "BLOCKED", "R-EXTERNAL-SENDER"
    # R-SENDER: exactly one To, equal to thread sender, no cc/bcc
    if len(to) != 1 or cc or bcc or normalize(to[0]) != sender:
        return "BLOCKED", "R-SENDER"
    raw = to[0]
    # R-DOMAIN: exact own domain after the final @
    if not is_own_domain(raw):
        return "BLOCKED", "R-DOMAIN"
    # R-SYNTAX: plain ASCII local@domain, nothing to "fix"
    if raw != raw.strip() or not raw.isascii() or not STRICT_ADDR.match(raw.lower()):
        return "BLOCKED", "R-SYNTAX"
    return "PENDING", "Q"


def evaluate(row):
    """Full evaluation order (section 5): T -> R-EXTERNAL-SENDER -> R-SENDER -> R-DOMAIN -> R-SYNTAX -> Q."""
    tool = TOOL_MAP.get(row["requested_tool"], None)
    if tool in READ_ONLY:
        return ("ALLOWED", "T0"), ("ALLOWED", "T0")
    backstop = recipient_rules(row)
    if tool not in KEPT_TOOLS:
        return ("BLOCKED", "T"), backstop
    return backstop, backstop


def load_spec_table():
    text = (ROOT / "policy-spec.md").read_text(encoding="utf-8")
    section = text.split("## 5. Replay check", 1)[1]
    rows = {}
    for line in section.splitlines():
        if not line.startswith("| RPL-"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        case_id, decision, rule, backstop = cells[0], cells[4], cells[5], cells[6]
        b_dec, b_rule = backstop.split()
        for d in (decision, b_dec):
            if d not in DECISIONS:
                sys.exit(f"{case_id}: invalid decision string {d!r}, must be one of {sorted(DECISIONS)}")
        rows[case_id] = ((decision, rule), (b_dec, b_rule))
    return rows


def main():
    spec = load_spec_table()
    replay = []
    for name in ("replay_set.csv", "spec_cases.csv"):
        with open(ROOT / name, newline="", encoding="utf-8") as f:
            replay += list(csv.DictReader(f))

    probe_fails = 0
    for addr, want in DOMAIN_PROBES.items():
        if is_own_domain(addr) != want:
            print(f"domain probe {addr!r}: got {not want}, expected {want}")
            probe_fails += 1
    print(f"Domain probes: {len(DOMAIN_PROBES) - probe_fails}/{len(DOMAIN_PROBES)} pass")

    mismatches = 0
    for row in replay:
        cid = row["case_id"]
        expected = evaluate(row)
        got = spec.get(cid)
        if got is None:
            print(f"{cid}: missing from spec section 5")
            mismatches += 1
        elif got != expected:
            print(f"{cid} {row['requested_tool']}: spec={got} rules={expected}")
            mismatches += 1

    extra = set(spec) - {r["case_id"] for r in replay}
    for cid in sorted(extra):
        print(f"{cid}: in spec but not in replay_set.csv / spec_cases.csv")
        mismatches += 1

    outbound_ok = [r["case_id"] for r in replay if evaluate(r)[0][0] == "PENDING"]
    print(f"Checked {len(replay)} replay rows against spec rules")
    print(f"{len(replay) - mismatches}/{len(replay)} rows match the spec")
    print(f"Outbound requests passing as written: {len(outbound_ok)} {outbound_ok}")
    sys.exit(1 if mismatches or probe_fails else 0)


if __name__ == "__main__":
    main()
