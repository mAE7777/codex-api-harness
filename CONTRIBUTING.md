# Contributing

Use Python 3.11.8+ and the standard library. Run:

```sh
python3 scripts/check.py
python3 scripts/check_public.py
```

Tests use fake providers and temporary loopback listeners. A test must not use a developer's API key, change their subscription configuration, or call a paid model/search service. Platform integration changes also need fresh sandbox acceptance on a supported Mac; passing Linux unit tests is not proof of VM isolation.

`kit/` contains templates. The installer renders workspace/port bindings and generates the managed requirements inside the private installation. Build and accept that rendered kit through `codex-api prepare`; do not mount a personal project into the source templates directly.

Before publishing, stage only source, documentation and tests. Scan the full Git history with a secret scanner. Never copy an installed directory, existing Git history, account-derived model prompts, or a personal acceptance report into this repository.

Preserve: five-model and endpoint allowlists, explicit billing opt-in, complete pre-dispatch reservations, witness/history integrity, unknown-use retention, UTC/concurrent behavior, two-line English usage, the 5% reference margin, once-per-group/day notices, account separation, scoped lifecycle ownership and no subscription fallback.

New tool/provider access needs tests for costs, credentials, input validation, network rules, cancellation and failures. Do not widen package domains or add a silent retry/fallback. Keep setup explanations short and request choices only when they are needed.

Pin and review third-party tool/runtime updates. Do not vendor downloaded binaries or change the ledger identity to resolve migration problems. Update README/SETUP/boundary documentation when behavior changes.
