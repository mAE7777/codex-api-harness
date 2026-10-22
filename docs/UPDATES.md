# Reviewed updates and rollback

Daily use stays the same: enter the project and run `codex-api`. Updating is a separate, stopped-session action. The updater never downloads or executes a candidate automatically.

Fresh 0.2 installations keep credentials, settings and the complete ledger at permanent paths. Versioned application code lives under `releases/`; one atomic `current` pointer selects a generation. The generated Docker kit follows the current protected paths and approved skills. Updating and rolling back never restore an old ledger, witness, key, account binding, or extension registry.

## Update

1. Exit API Codex and stop any team coordinator using this installation. Keep the source checkout outside the agent workspace.
2. Run `codex-api upgrade stage /absolute/path/to/source`. This copies a bounded source inventory, validates metadata, compiles Python without executing it, and prints a full source digest and review directory.
3. Review those exact files and their changes. An optional `--source-pin COMMIT_SHA` is a recorded label; the actual staged tree digest binds the bytes. Neither a digest nor passing tests establishes publisher identity or proves code safe.
4. Run `codex-api upgrade activate --reviewed-digest FULL_DIGEST`. This explicitly trusts that staged host code. The updater runs its regression checks, then uses that candidate's policy renderer in a separate process with a temporary home and bounded path-only input. Credentials, account settings and ledgers are not passed to the renderer. It checks that permanent state and current policy stayed unchanged before selecting the complete new code generation.
5. The command rebuilds and verifies only the owned sandbox before the next session. Project files, credentials and accounting remain in place. If native preparation fails, requests stay blocked until it succeeds.

Candidate verification is reviewed **host code**; environment cleanup does not make arbitrary host code safe. Review the complete candidate, including its tests. The harness does not claim that static scanning can certify an update. Check output is stored privately under `upgrades/checks/`; it is not uploaded.

The updater requires the existing layout and updater ABI, and preserves the declared Docker Sandboxes, Codex and Playwright runtime pins. A runtime or layout migration requires a separate review. Direct version downgrades are refused. Existing 0.1 installations are not silently converted, copied, reinitialized or reset; the updater refuses them until a separate migration is reviewed.

## Roll back code

Use `codex-api upgrade list` to find a retained generation, then run `codex-api upgrade rollback RELEASE_ID`.

Rollback verifies the retained pristine source, runs its checks, and builds a **new** host code generation. It retains the complete current manifest-verified guest kit, including native policy, feature pins, guest wrappers and approved skills. This prevents older templates from weakening current guest protections. It does not restore private state. Native sandbox preparation is required again. Keep retained generations private: their generated policy may contain local project paths and approved private skills.

On launch, the manifest still authenticates every policy byte. A separate semantic check requires the exact current workspace and protected-path masks, including descendants; extra denials, newer constraints and formatting changes remain valid. Changing protected paths edits only the two path-mask sections and preserves every other current policy value. Built-in and unrecognized additional denials survive removal of an owner path. An unfamiliar section format is refused before changing settings. The updater supports rollback within its declared ABI and runtime pins. An older generation unable to validate the retained policy refuses to start; ABI compatibility does not bypass policy checks.

## Interrupted activation

Code selection is atomic. Switching the code pointer and replacing the installation manifest are two separate filesystem operations, fenced by a durable `upgrade-pending.json` journal. An interruption blocks new sessions and policy changes.

- `codex-api upgrade recover` selects the verified previous generation.
- `codex-api upgrade recover --finish` finishes selecting the already reviewed candidate.

Recovery validates the selected code and permanent policy, preserves the current ledger, and requires native preparation again. A damaged candidate can be discarded while recovering verified old code. Changed policy, unexpected manifest contents or damaged selected code stop recovery for investigation; no usage is guessed, refunded or restored.

If a candidate prevents the normal command from opening, run `python3 setup.py recover --home "/absolute/private/installation"` from a trusted source checkout. Add `--finish` only to finish the reviewed candidate. This uses the same stopped-session checks and leaves the current ledger in place.

The host owner can deliberately modify both code and local records. Local hashes and journals detect mistakes and incomplete updates; they are not protection against a malicious host owner or simultaneous restoration of every authority file.
