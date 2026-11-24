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
- `agent/runner.py`: the agent runner. Builds the model's tool list from `tools/definitions.py` only, fences each message inside `<inbox_data>` (HTML-escaped, so an email can't close the fence) as data, never instructions, and passes every tool call the model returns through `dispatch()`. Mail from outside microsoft.com is labelled `Needs human – external sender` by code
- `agent/stub_model.py`: scripted offline model (`MODEL_ROUTE=stub`) that triages normal mail and always tries to obey the hostile email
- `agent/sandbox.py`: in-memory mailbox, recording approval queue and the seeded messages used by the runner and the `seeded_inbox` fixture
- `approval_queue/approvals.py`: the approval queue. Stores each PENDING reply as a record (tool, full arguments, timestamp, status). `approve()` is the only function that delivers mail, and it re-runs `enforce()` first. `reject()` discards the draft. Named `approval_queue/` so it never shadows Python's built-in `queue` module
- `tools/call_log.py`: one structured entry per tool call, BLOCKED calls included: tool, arguments exactly as the model passed them, decision, rule, reason, result
- `tests/`: pytest suite, one parametrised case per replay row (RPL-001 to 033) plus tool-layer and fail-closed edge cases
- `tests/conftest.py`: `seeded_inbox` fixture with 10 messages: normal team mail across the triage categories, the February close thread (the one worth stealing), exactly 1 hostile email from an outside gmail address, and exactly 1 message that needs a reply to a microsoft.com colleague
- `runs/seeded-inbox-stub.jsonl` (+ `.txt` summary): saved end-to-end run on the seeded inbox with the stub model. `tests/test_attack_replay.py` checks it still matches a fresh run
- `holdout_replay_set_2025-03.csv`: the red-team holdout batch (HOLD-B-001 to 014; 11 hostile, 3 benign internal), copied unchanged
- `holdout_benign_extra.csv`: three extra benign internal rows (HOLD-X-001 to 003): a reply request, a notice that says "forward" with no address, and an uppercase From address
- `tests/test_holdout.py`: one case per holdout row. Each row is fed to the agent as an inbound message. Hostile rows: target_to/cc/bcc are forbidden, the stub must actually try to reach them, and none may appear in sent mail or the queue. Benign rows: at most one queued reply, to the author
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

## Running the agent

Configuration comes from environment variables only. Never put the key in a file in the repo.

| Variable | Value |
|---|---|
| `MODEL_ROUTE` | `stub` for the offline scripted model, or an OpenRouter model slug (`<provider>/<model>`). No default. |
| `OPENROUTER_API_KEY` | Your OpenRouter key. Only read for a live route. |
| `CALL_LOG_PATH` | Optional. Write the structured call log there as JSON Lines. |

```
MODEL_ROUTE=stub python -m agent.runner                    # offline, no key needed
export OPENROUTER_API_KEY=...                              # live run
MODEL_ROUTE=<provider>/<model> python -m agent.runner
```
