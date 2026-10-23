# Request reports and optional controls

Daily startup and `codex-api usage` are unchanged. Reports, output tools and offline risk scans make no model request. Existing installations gain no new hard ceilings until their owner reviews them. Token limits alone do not cap dollars or prove complimentary eligibility.

## Understand usage

Run `codex-api report`, or `!codex-api report` inside Codex. Add `--json` for structured data. The report separates confirmed tokens, current reservations, prior uncertain holds, UTC overlap, the starting baseline and the safety margin. Shared reports show member usage and the project/organization constraints on the remaining balance; another member's request records are not returned.

Recent records contain requested model/tier, complete input count, terminal input/output/cache/reasoning counters when available, request phase, run ID and sanitized correlation identifiers. Reasoning is part of output, not an extra charge. Missing historical or optional counters are unavailable, never invented zeroes. Reported model/tier fields describe provider metadata, not proof of backend execution. Repeated tool fingerprints are a review hint, not a finding that the task has failed.

Observations use additive tables in the existing witnessed ledger. They store no prompt, tool arguments, tool output, raw provider errors or credentials. Reporting is read-only and does not repair state. Currency reports use integer micro-USD: 1,000,000 micro-USD is one dollar. They describe reviewed upper-bound accounting, not the provider's final invoice.

## Review controls once

The private installation directory is printed by setup. Create a draft there, outside the shared project:

```sh
codex-api controls draft /absolute/private/installation/controls-draft.json
codex-api controls inspect /absolute/private/installation/controls-draft.json
codex-api controls apply /absolute/private/installation/controls-draft.json --digest FULL_DIGEST --reviewed
```

Edit the private draft before inspection. The setup agent may perform the exact digest step within the owner's authorization; the hash alone does not require another question. Changes require a stopped API session/coordinator. Repeating the same apply after an interruption preserves recorded usage. Direct edits, deletion or policy mismatch stop requests. After a model policy change, review a matching controls draft again.

Fields:

| Field | Meaning |
| --- | --- |
| `version` | `1` |
| `policy_digest` | Exact current model-policy digest; generated in the draft |
| `session_tokens` | Optional full input + maximum output ceiling for a wrapper run; `null` leaves it off |
| `session_requests` | Optional count of attempted requests, including failed counting; `null` leaves it off |
| `consecutive_errors` | Same-error pause threshold, `0`–`32`; draft recommends `3` |
| `minimum_free_bytes` | Private host-volume free-space floor; draft recommends `134217728`; `0` disables it |
| `spending` | Optional reviewed USD policy; `null` leaves it off |

A normal launch creates a host run ID. `resume` retains the last wrapper run ID; native Codex session IDs are different. Starting explicitly new work creates a new run, but never resets daily tokens, unknown holds or USD budgets. Run ceilings do not prove a semantic task made progress. Identical tool calls can be legitimate, so their detection is advisory. Quota, cancellation and UTC-transition errors do not trigger the repeated-error pause.

The host-storage floor checks admission; it neither imposes a VM disk quota nor continuously limits a running local program. No cleanup deletes project files, history, ledgers or unrelated Docker data. A model pause does not kill useful local jobs.

## Recover after a stop

```sh
codex-api session list
codex-api session handoff
codex-api session native
codex-api resume --last
```

`list` shows wrapper runs. `native` reads only bounded session metadata inside this API sandbox and lists actual Codex IDs, including files absent from a native picker. It does not read subscription history, change an index or decompress archives. It skips unsupported/compressed records explicitly. Resume a selected native ID with `codex-api resume SESSION_ID`.

`handoff` is a mechanical accounting/status summary, with no extra model call. It cannot reconstruct an unwritten task goal or guarantee the model remembers work after compaction. Review project progress before asking it to continue.

After inspecting a repeated error, exit the API session and acknowledge its exact run:

```sh
codex-api session continue RUN_ID --reviewed
```

The coordinator owner uses `--member MEMBER` with the coordinator stopped. Members cannot clear an owner pause through HTTP. This acknowledgement changes no ceiling or usage. For a stopped operation that never reached generation and has no provider request reservation, `session resolve OPERATION_ID --reviewed` closes its observation; a possible counting charge stays recorded. Dispatched unknown usage still needs the existing `reconcile` evidence workflow.

## Optional USD budgets

Use only after the owner explicitly chooses paid API use and verifies upper-bound pricing. The token policy and free-only eligibility gate remain independent. USD controls require exact counting and the daily token guard. They do not enable payment, recharge, sharing or a different tier.

The `spending` object requires:

- `daily_micro_usd` and `monthly_micro_usd`: positive integer ceilings or `null`, at least one enabled.
- `baselines`: verified prior use for the current enabled UTC day/month, including explicit zero. Existing baseline values cannot be rewritten. Future periods start at zero only for tracked traffic; uncertain prior calls remain held.
- `valid_until`: Unix seconds when the reviewed prices expire. Expiry blocks even counting.
- `count_request_max_micro_usd`: verified upper price for one exact-count call. Unknown pricing cannot be represented as a free assumption. A count attempt reserves this before dispatch.
- `prices`: one row for every selected model. Each row has the selected `tier`, `input_micro_usd_per_million`, `output_micro_usd_per_million` and an official `reference` URL. Rates must cover the worst applicable input length and any relevant price band. The harness validates the schema, not the truth of an operator's price evidence.

Before generation, full input and maximum output are reserved using those prices. Cached input uses the full input upper rate; reasoning is included in output. Unknown/disconnected usage keeps its upper hold across periods. A total-only reconciliation cannot reconstruct the price split, so it conservatively retains the full USD hold as completed consumption; confirmed no-model-use evidence retains only a possible count charge. Near-boundary and late completion overlap also constrain the next period. No automatic provider/model/tier switch or recharge occurs.

Changing controls requires resolving unfinished requests first, including requests from older releases that have no cost observations. Replaying the identical reviewed controls remains possible. This prevents a price change from understating an existing uncertain hold.

Shared USD ceilings are coordinator-wide across all members/projects, with member-scoped run limits. Per-project/member USD allocations are not a new transfer system; the existing token allocations remain the member controls. The coordinator owner sets pricing and prior-use baselines. Traffic outside this coordinator is not controlled.

If actual counters imply a cost above the reservation, its confirmed amount is retained and a durable stop blocks later requests. Review prices and unresolved calls, then use `controls resume --reviewed` while stopped. It refuses unknown calls or an already-exhausted current spending ceiling. It does not erase the discrepancy, reset balances or remove the token safety stop. No local estimate guarantees the provider's final bill or a refund.

## Optional command output filtering

Inside Codex, use `!codex-api output run -- COMMAND ARG...`; the same command is available from the host terminal through the owned sandbox's native permissions. It does not execute a host shell command. For example:

```sh
codex-api output run -- python3 -m pytest -q
codex-api output show RECORD_ID
codex-api output show RECORD_ID --full
codex-api output remove RECORD_ID
```

The command's exit status is retained. Success output is summarized; failures retain a larger tail. Terminal controls are removed from displayed output. Private guest temporary storage (`/tmp/codex-api-output`) retains up to 8 MiB of the combined stdout/stderr tail. Truncation is explicit. At most 16 records are accepted; removal is deliberate. These records may contain secrets and stay inside the VM; they are not a general backup and are not included in managed history capture. Sandbox reset or temporary-directory cleanup can remove them. Do not publish them.

No command is transparently rewritten, no hook is installed, and API history is not compressed or rerouted. Less command output does not imply the same percentage reduction in tokens or dollars. On a failed command, mentioned unapproved domains are hints only; `codex-api explain network` lists approved dependency sources without granting a new one.

## Explicit project undo

Checkpoints are optional private copies for selected text files, not the sensitive-file protection mechanism or a synchronized workspace. They do not change Git history. Keep real secrets outside the project first; name/content checks cannot identify every secret.

```sh
codex-api checkpoint create src/app.py tests/test_app.py
codex-api checkpoint preview CHECKPOINT_ID
codex-api checkpoint restore CHECKPOINT_ID --digest CURRENT_PREVIEW_DIGEST --reviewed
codex-api checkpoint list
codex-api checkpoint remove CHECKPOINT_ID
```

Use workspace-relative paths. API sessions must be stopped. Each snapshot permits 1–64 explicit UTF-8 files, 2 MiB per file, 16 MiB total and at most 16 snapshots. Credential paths, owner-protected paths, Git/agent config, dependencies, links and binary files are refused. Checksums detect accidental snapshot changes. File permission bits are captured; privileged mode bits are not restored. New parent directories are not created.

Restore requires a fresh preview of current content and modes. It rechecks files, uses no-follow directory descriptors and atomic file replacement, and stops on a conflict. Keep external editors/watchers quiet: ordinary filesystems do not offer a content-hash compare-and-swap against an uncooperative editor racing the final rename. A multi-file restore is not one filesystem transaction.

An interrupted restore leaves a private pre-restore journal and blocks ordinary startup. Inspect `checkpoint recover`, then `checkpoint recover --reviewed` to restore pre-restore content. Unexpected later edits stop recovery without overwriting them; the private journal remains for deliberate resolution. Checkpoints cannot undo API charges, secret disclosure or remote side effects. They never restore keys, quotas, policy or the subscription environment.
