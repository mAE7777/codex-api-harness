# Reviewed updates and rollback

Daily use stays the same: enter the project and run `codex-api`. Updating is a separate, stopped-session action. The updater never downloads or executes a candidate automatically.

Version 0.4 adds request observations without resetting token usage. Optional controls, run identity and checkpoints remain permanent private state and are included in update preservation checks. Once request controls are approved, rollback to code older than 0.4 is refused because that code cannot enforce them. Removing the controls file does not bypass the ledger's recorded approval. An interrupted controls apply can be completed by replaying its exact reviewed command.

Version 0.5 adds the bundled MCP and optional free tool policy. Existing search flags are not converted into a new approval. External tools remain closed until reviewed; configuration, keys, sessions and usage stay in place. The retained bundled MCP kit requires a guard at least 0.5; older rollback is refused rather than stripping guest protections. Tool approvals are also recorded in the ledger, so deleting the policy file cannot bypass them. Tool budgets never roll back.

Installations created with version 0.2 or later keep credentials, settings, and the complete ledger at permanent paths. Versioned application code lives under `releases/`. One atomic `current` pointer selects a generation. The generated Docker kit follows the current protected paths and approved skills. Updates and rollbacks never restore an old ledger, witness, key, account binding, or extension registry.

## Update

1. Exit API Codex and stop any team coordinator using this installation. Keep the source checkout outside the agent workspace.
2. Run `codex-api upgrade stage /absolute/path/to/source`. This copies a bounded source inventory, validates metadata, compiles Python without executing it, and prints a full source digest and review directory.
3. Review those exact files and their changes. An optional `--source-pin COMMIT_SHA` is a recorded label; the actual staged tree digest binds the bytes. Neither a digest nor passing tests establishes publisher identity or proves code safe.
4. Run `codex-api upgrade activate --reviewed-digest FULL_DIGEST`. This explicitly trusts that staged host code. The updater runs its regression checks, then uses that candidate's policy renderer in a separate process with a temporary home and bounded path-only input. Credentials, account settings and ledgers are not passed to the renderer. It checks that permanent state and current policy stayed unchanged before selecting the complete new code generation.
5. The command prepares and verifies only the owned sandbox, then reports `API sandbox ready`. Project files, credentials, and accounting remain in place. If preparation fails, requests stay blocked. Run `codex-api prepare` to retry; a successful update needs no extra preparation command.

Candidate verification is reviewed **host code**; environment cleanup does not make arbitrary host code safe. Review the complete candidate, including its tests. The harness does not claim that static scanning can certify an update. Check output is stored privately under `upgrades/checks/`; it is not uploaded.

The updater requires the existing layout and updater ABI, and preserves the declared Docker Sandboxes, Codex and Playwright runtime pins. A runtime or layout migration requires a separate review. Direct version downgrades are refused. Existing 0.1 installations are not silently converted, copied, reinitialized or reset; the updater refuses them until a separate migration is reviewed.

## Roll back code

Use `codex-api upgrade list` to find a retained generation, then run `codex-api upgrade rollback RELEASE_ID`.

Rollback verifies the retained source, runs its checks, and builds a new host code generation. It retains the complete current manifest-verified guest kit, including native policy, feature pins, guest wrappers, and approved skills. Older templates cannot replace those protections. Rollback does not restore private state. The command prepares the sandbox automatically. Keep retained generations private because their generated policy may contain local project paths and approved private skills.

On launch, the manifest still authenticates every policy byte. A separate semantic check requires the exact current workspace and protected-path masks, including descendants; extra denials, newer constraints and formatting changes remain valid. Changing protected paths edits only the two path-mask sections and preserves every other current policy value. Built-in and unrecognized additional denials survive removal of an owner path. An unfamiliar section format is refused before changing settings. The updater supports rollback within its declared ABI and runtime pins. An older generation unable to validate the retained policy refuses to start; ABI compatibility does not bypass policy checks.

## Interrupted activation

Code selection is atomic. Switching the code pointer and replacing the installation manifest are two separate filesystem operations, fenced by a durable `upgrade-pending.json` journal. An interruption blocks new sessions and policy changes.

- `codex-api upgrade recover` selects the verified previous generation.
- `codex-api upgrade recover --finish` finishes selecting the already reviewed candidate.

Recovery validates the selected code and permanent policy, preserves the current ledger, and requires native preparation again. A damaged candidate can be discarded while recovering verified old code. Changed policy, unexpected manifest contents or damaged selected code stop recovery for investigation; no usage is guessed, refunded or restored.

If a candidate prevents the normal command from opening, run `python3 setup.py recover --home "/absolute/private/installation"` from a trusted source checkout. Add `--finish` only to finish the reviewed candidate. This uses the same stopped-session checks and leaves the current ledger in place.

The host owner can deliberately modify both code and local records. Local hashes and journals detect mistakes and incomplete updates; they are not protection against a malicious host owner or simultaneous restoration of every authority file.

## Policy compatibility

Version 0.3 uses a generalized model/quota/tier contract and normalized shared allocation tables. Code older than 0.3 cannot enforce those states; rollback to it is refused when a modern policy or coordinator is present. A personal pre-0.3 installation kept on its untouched legacy policy can still select a compatible retained old generation. No rollback restores an old usage database or credential file. Finish a pending policy change before staging activation.
