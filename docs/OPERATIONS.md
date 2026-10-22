# Operations

## Everyday commands

| Need | Command |
|---|---|
| Start | `codex-api` |
| Resume last API session | `codex-api resume --last` |
| Remaining A/B tokens | `codex-api usage` or `!codex-api usage` inside Codex |
| Machine-readable usage | `codex-api usage --json` |
| Local diagnosis | `codex-api doctor` |
| Redacted local diagnostic file | `codex-api doctor --bundle` |
| Explain an error | `codex-api explain CODE` |
| Stop from another terminal | `codex-api stop` |
| Block new requests | `codex-api pause` |
| Private key-file location | `codex-api credentials` |
| Stage a replacement project key | `codex-api credentials stage` |
| Activate the locally filled key | `codex-api credentials activate` |
| Review managed skills | `codex-api extensions list` |
| Hide additional exact project paths | `codex-api protect add RELATIVE_PATH ...` |
| Owner: shared allocation overview | `codex-api team allocations` |
| Member: ask for more tokens | `codex-api team request --group B --tokens 100000` |

Use the host terminal for maintenance. The guest helper supports usage, the managed skill list and a member quota request; it cannot approve, transfer, upgrade or administer. `pause` does not erase usage. Exit/relaunch to resume normal admission. A native resume suggestion may say `codex resume`; use `codex-api resume` for this environment.

## Common messages

| Code or check | What to do |
|---|---|
| `daily_token_limit` | Full input/output reservation cannot fit. Choose a model in the other group, shorten/new conversation, or wait until UTC rollover. |
| `provider_disabled` / free eligibility | Free-only is blocked. Do not mark eligibility verified without evidence. Explicitly allow charges only if intended. |
| `organization_usage_unknown` | Other organization callers are present or unconfirmed. Stop and review the shared-pool assumption. |
| `workspace_policy_failed` | Move the named sensitive item outside the project; do not paste its content into chat. |
| `input_count_unavailable` | No generation was sent. Resolve the counting failure before retrying. |
| `utc_day_transition` | Retry at 00:00:15 UTC. No model inference was sent; an earlier count may have occurred. |
| `provider_clock_unverified` / `provider_clock_mismatch` | No inference was sent. Check automatic date/time and the count response; counting may already have occurred. |
| `invalid_api_key` | Update the private key file for the same project/account. No subscription login. |
| `credit_balance_exhausted` / `insufficient_quota` | Review account Billing; local token balance is separate. No automatic recharge occurs. |
| `rate_limit_exceeded` | Retry manually later. No fallback model/provider is used. |
| `quota_reconciliation_required` | Inspect `codex-api reconcile`; do not delete the database or witness. |
| Installation/runtime integrity | A pinned file or executable changed. Review the update; do not disable the check. |
| Shared Docker policy | Review the exact conflict. Do not reset other people's sandboxes or broad global settings. |
| `team_unavailable` | Keep the owner Mac awake and its coordinator running; verify the encrypted connection. No independent quota or provider fallback exists. |
| `team_auth_failed` / `team_identity_changed` | Verify the private invitation with the owner; do not bypass host-key or identity checks. |
| `duplicate_operation` | The explicit request ID already exists. Inspect the original before intentionally submitting new work. |
| `terminal_usage_invalid` / `terminal_usage_conflict` | Malformed usage was rejected; the conservative reservation remains held. |
| `upgrade_recovery_required` | Run `codex-api upgrade recover`; do not edit the activation journal or reset usage. |

If a key was exposed, revoke it in the provider account first. Editing a local file does not revoke an old key. Key replacement must keep the same account binding; a different account requires a separate installation and ledger.

## Uncertain usage

`codex-api reconcile` is read-only by default. It does not query provider billing or make model calls. For a specific unresolved request:

```sh
codex-api reconcile --template REQUEST_ID
```

Fill the generated private receipt using completed-request evidence, then exit the API session:

```sh
codex-api reconcile --apply PRIVATE_RECEIPT_PATH
```

Record actual usage, confirm no usage, or conservatively keep the full consumed reservation. Receipts are owner-only and outside the workspace; replay is idempotent. Evidence is the operator's responsibility. Missing/unfinished/placeholder evidence is rejected. A discrepancy safety stop is not automatically cleared.

## Updates and removal

This release refuses unreviewed code/runtime drift. Use the [reviewed update workflow](UPDATES.md); no background updater runs. Activation switches a complete code generation and fences its manifest. An interrupted activation requires recovery. Rollback stages old code with today's managed policy and preserves credentials, account binding, the whole ledger and witness. Never rerun setup with a new directory to get extra quota for the same organization.

`codex-api reset` explicitly removes the recorded owned sandbox, preserving the project, keys and ledger. Recreate with `codex-api prepare`. A deliberate reset removes sandbox-only history unless a prior managed-rebuild backup exists. Normal extension/policy/update rebuilds automatically preserve selected API history and preferences; a failed capture stops replacement. Backups live privately outside the project and may contain sensitive conversation content.

In shared mode, `codex-api stop` closes only that client's environment. Stop `codex-api team serve` in its owner terminal to stop the coordinator and its dedicated tunnel service. Member revocation blocks new admissions and does not refund already dispatched usage. Recovery for shared usage is `codex-api team reconcile`, with the coordinator stopped before applying evidence.

`codex-api retire` additionally moves the private installation to a timestamped sibling archive. The launcher remains but cannot run the archived installation. Archives contain credentials: keep them private, revoke unused keys, and remove them deliberately when no longer needed. This does not remove the source checkout, project, shared builder cache, Docker login or global settings. It never calls global Docker reset/prune/logout/daemon-stop.

To remove a launcher, first check that it is the generated harness launcher and points to the retired directory. Do not delete a different command that later reused the same name.
