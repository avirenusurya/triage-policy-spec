# Triage Agent Policy Spec

Least-privilege tool and recipient policy for the mail triage agent.

## Policy spec: 5 sections

1 Scope · 2 Kept tools · 3 Outbound path · 4 Allowed recipients · 5 Replay check

- `policy-spec.md`: the spec (source of truth)
- `replay_set.csv`: Hostile Email Replay Set, March 2025 (32 rows)
- `spec_cases.csv`: cases the spec adds beyond the sheet (RPL-033: `microsoft.com.attacker.io` suffix trick)
- `check_replay.py`: re-implements the spec rules and checks every replay row's decision (`python check_replay.py`)
- `tools/definitions.py`: the five kept tools (read, search, label, move, reply); reply takes `thread_id` and `body` only
- `policy/enforce.py`: `enforce()`, which every tool call passes through before any handler; returns BLOCKED / PENDING / ALLOWED plus the rule that fired
- `tools/dispatch.py`: the single entry point; runs `enforce()` first, then a read-only handler or a draft into the approval queue. It has no way to send mail
- `approval_queue/approvals.py`: placeholder (next stage). Named `approval_queue/` so it never shadows Python's built-in `queue` module
- `tests/`: pytest suite, one parametrised case per replay row (RPL-001 to 033) plus tool-layer and fail-closed edge cases
- `tests/conftest.py`: `seeded_inbox` fixture with 10 messages: normal team mail across the triage categories, the February close thread (the one worth stealing), exactly 1 hostile email from an outside gmail address, and exactly 1 message that needs a reply to a microsoft.com colleague
- `pytest-results.txt`: saved `pytest -v` output

## Triage categories

`Finance - February Close`, `Finance - Vendor Payments`, `Finance - Payroll Query`, `HR - Benefits`,
`General - Facilities`, `General - Newsletter`, and `Needs human – external sender` (policy-spec.md section 3.4).
The first five match the thread labels in the replay set.

```
pip install pytest
python -m pytest -v
python check_replay.py
```
