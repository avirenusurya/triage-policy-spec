# Triage Agent Policy Spec

Least-privilege tool and recipient policy for the mail triage agent.

## Policy spec: 5 sections

1 Scope · 2 Kept tools · 3 Outbound path · 4 Allowed recipients · 5 Replay check

- `policy-spec.md`: the spec (source of truth)
- `replay_set.csv`: Hostile Email Replay Set, March 2025 (32 rows)
- `spec_cases.csv`: cases the spec adds beyond the sheet (RPL-033: `microsoft.com.attacker.io` suffix trick)
- `check_replay.py`: re-implements the spec rules and checks every replay row's decision (`python check_replay.py`)
- `tools/definitions.py`, `policy/enforce.py`, `queue/approvals.py`: placeholders for the build
