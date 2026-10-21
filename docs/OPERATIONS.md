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

Use the host terminal for maintenance; the guest helper only supports usage. `pause` does not erase usage. Exit/relaunch to resume normal admission. A native resume suggestion may say `codex resume`; use `codex-api resume` for this environment.

## Common messages

| Code or check | What to do |
|---|---|
| `daily_token_limit` | Full input/output reservation cannot fit. Choose a model in the other group, shorten/new conversation, or wait until UTC rollover. |
| `provider_disabled` / free eligibility | Free-only is blocked. Do not mark eligibility verified without evidence. Explicitly allow charges only if intended. |
| `organization_usage_unknown` | Other organization callers are present or unconfirmed. Stop and review the shared-pool assumption. |
| `workspace_policy_failed` | Move the named sensitive item outside the project; do not paste its content into chat. |
| `input_count_unavailable` | No generation was sent. Resolve the counting failure before retrying. |
| `invalid_api_key` | Update the private key file for the same project/account. No subscription login. |
| `credit_balance_exhausted` / `insufficient_quota` | Review account Billing; local token balance is separate. No automatic recharge occurs. |
| `rate_limit_exceeded` | Retry manually later. No fallback model/provider is used. |
| `quota_reconciliation_required` | Inspect `codex-api reconcile`; do not delete the database or witness. |
| Installation/runtime integrity | A pinned file or executable changed. Review the update; do not disable the check. |
| Shared Docker policy | Review the exact conflict. Do not reset other people's sandboxes or broad global settings. |

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

This release refuses in-place code/runtime drift. There is no automatic updater. A reviewed upgrade must retain credentials, account binding, the whole ledger and witness, and native preferences. Never rerun setup with a new directory to get extra quota for the same organization.

`codex-api reset` removes only the recorded owned sandbox, preserving the project, keys and ledger. Recreate and rerun acceptance with `codex-api prepare`. Sandbox-only CLI history/preferences are removed by reset.

`codex-api retire` additionally moves the private installation to a timestamped sibling archive. The launcher remains but cannot run the archived installation. Archives contain credentials: keep them private, revoke unused keys, and remove them deliberately when no longer needed. This does not remove the source checkout, project, shared builder cache, Docker login or global settings. It never calls global Docker reset/prune/logout/daemon-stop.

To remove a launcher, first check that it is the generated harness launcher and points to the retired directory. Do not delete a different command that later reused the same name.
