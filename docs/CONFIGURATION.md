# Models, quotas and speed

An installation's owner-approved policy lives in `verification.json` under `openai.policy`, outside the project. Credentials and account binding remain separate. A generated, read-only guest copy contains no key or account ID. Every model menu, request check, usage line and shared invitation derives from this contract.

New installs contain an empty policy and cannot send model requests. Defaults are suggestions, not inherited personal choices. Existing pre-0.3 installs retain their original five models, two groups, output cap, Standard tier, daily limits and billing gates through a read-only legacy adapter. An upgrade does not rewrite their verification file or reset usage.

## First setup

```sh
codex-api policy template
codex-api policy check /ABSOLUTE/PRIVATE/INSTALL/policy-draft.json
```

The first command creates a private draft without overwriting anything. Its example allowance is **not your free allowance**. The setup agent edits it after learning your preferences, actual account allowances and model capabilities. `policy check` validates local consistency and returns a review digest; it makes no API call and does not certify account access.

A policy has these fields:

- `version`: `1`.
- `reset`: `daily_utc`. Only daily UTC counters are supported. A monthly allowance cannot be presented as a daily free pool; choose a separately justified daily budget instead.
- `safety_margin_percent`: integer 0–50; recommendation 5.
- `warning_percent`: integer 1–99; recommendation 90. At most one notice per UTC day/pool, including after a threshold change.
- `pools`: 1–8 stable identifiers, each with a printable English `label` and a positive integer `daily_tokens` allowance. Usable capacity is `floor(daily_tokens × (100 − margin) / 100)`.
- `models`: 1–32 approved model IDs. Each declares its `pool`, `context_window`, `max_output_tokens`, supported `reasoning_efforts`, supported `service_tiers`, and official capability `reference` URL. Every pool must have a model. Metadata must be verified for Responses API and the local tool protocol; a `/models` listing alone proves neither. Additional owner-reviewed model IDs do not require editing Python source.
- `defaults`: selected `model`, compatible `reasoning_effort`, `service_tier`, `output_token_cap`, and `request_deadline_seconds` (30–900). The output reservation cap must fit every selected model. The template suggests 16,384; choose a smaller value when appropriate.

Saved model/reasoning choices are retained when compatible. A model switch uses a supported reasoning default when the old preference no longer fits; an explicitly incompatible override is rejected before launch.

The template is readable JSON. All fields are validated; unknown fields, duplicate JSON keys, unsafe files, booleans/fractions in integer fields, unsupported periods, unknown tiers and incompatible model/default combinations fail closed. Policy files must be owner-only ordinary files (0600). No project configuration or skill may widen the contract.

To explicitly choose the previous setup:

```sh
codex-api policy template --preset legacy-five
```

This proposes five models, Standard, A/B reference pools of 250,000 / 2,500,000 and a 5% margin. It is not a universal free-use entitlement. The legacy initial `--baseline-a`/`--baseline-b` pair is retained as an explicit opt-in to this preset, never an automatic install default.

## Service tiers

One fixed tier is selected per installation policy. Every selected model must support it. Per-request switching and `/fast`/`/ultrafast` toggles cannot bypass the owner choice. Use a reviewed policy change to select a different tier.

| Choice | Wire value | Boundary |
| --- | --- | --- |
| Standard, recommended initial choice | `default` | Standard pricing/performance; not inherently free |
| Fast | `fast` | Higher per-token price; `priority` is normalized to `fast` |
| Flex | `flex` | Lower price, longer waits and possible resource unavailability; recommend a 900-second total deadline |
| Ultrafast | `ultrafast` | Supported model/account combinations only; higher price and separate rate limits |

`auto` is rejected. The harness sends the selected tier explicitly, so an account's default cannot silently select a faster, more expensive tier. It does not retry, switch models, or fall back from Flex to Standard. A provider may apply its documented downgrade behavior; token reservations remain conservative, and the local token ledger is not an exact money ledger. The HTTP path stays behind the same gateway; enabling a tier does not enable WebSockets or hosted tools.

Account access and project allowed-tier settings must be checked separately by the owner. Free-only does not assume complimentary eligibility for non-Standard tiers and will not send such requests. Changing tier does not authorize API charges. API error codes remain visible if a model or tier is unavailable.

Sources: [Responses API](https://developers.openai.com/api/reference/resources/responses/methods/create), [Fast](https://developers.openai.com/api/docs/guides/fast-mode), [Flex](https://developers.openai.com/api/docs/guides/flex-processing), [Ultrafast](https://developers.openai.com/api/docs/guides/ultrafast-mode), [project tier restrictions](https://developers.openai.com/api/docs/guides/error-codes).

## Changing an existing policy

Exit the API session. Review a private copy of the desired policy, then:

```sh
codex-api policy check /ABSOLUTE/PRIVATE/POLICY.json
codex-api policy apply /ABSOLUTE/PRIVATE/POLICY.json --reviewed-digest EXACT_SHA256
```

For each newly introduced pool, add `--baseline POOL=TODAYS_PRIOR_TOKENS`. Existing baselines cannot be supplied again or reset. Initial account binding uses `configure --policy FILE --reviewed-policy-digest SHA256 --baseline POOL=TOKENS`; see SETUP.md.

Changes preserve account binding, keys, safe session history, ledger identity, request rows, used tokens and unresolved reservations. Limits cannot be lowered beneath current consumption, pools cannot be removed/renamed, and models with recorded history cannot be reassigned to another pool. Removing a model does not forget its historical pool binding. Uncertain requests must be reconciled before policy changes. Free-use evidence is invalidated; a change never grants free eligibility.

A durable fence covers the accounting update, verification file and generated guest files. If interrupted, requests stop. Repeat the **same reviewed apply command** to finish; do not delete its fence, reset a baseline, or restore an old database. If only guest rendering was interrupted during preparation, rerun `prepare`. Tampered files stop recovery instead of being accepted.

The host command prepares the owned sandbox automatically after a successful apply. The original project remains live; only this API environment's selected history/preferences are preserved. Daily use is still `codex-api`.

## Shared policies

Choose the policy before coordinator initialization. Organization, project and member counters support the same pool identifiers and ceilings. Use named `--baseline POOL=N` and `--tokens POOL=N` arguments; A/B flags remain compatible with the legacy profile only.

Invitations include the policy and its digest. A member inspects the sanitized policy with `team join --invite FILE --inspect`, then joins with `--reviewed-policy-digest SHA256`. The member does not provide an OpenAI key or independently guess quotas. Every connection checks the coordinator identity and policy digest; a mismatch stops requests. Local usage is never used as a fallback.

This release pins an initialized coordinator's model/pool/tier policy. Policy replacement requires a future reviewed migration; it is deliberately refused rather than resetting shared accounting. Normal member/project allocation changes, transfers and quota requests remain available. Existing shared ledgers gain normalized per-pool allocation tables without deleting legacy tables, usage or invitations.
