# Contributing

Use Python 3.11.8+ and the standard library. Run:

```sh
python3 scripts/check.py
python3 scripts/check_public.py
```

Tests use fake providers and temporary loopback listeners. Never use a real API key, change subscription configuration, or call a model or search service in a test. If your execution sandbox blocks local listeners, run the suite in an authorized local test environment. Do not skip those tests and report a pass. Platform integration changes also need fresh sandbox acceptance on a supported Mac. Passing Linux unit tests does not prove VM isolation.

`kit/` contains templates. The installer renders workspace/port bindings and generates the managed requirements inside the private installation. Build and accept that rendered kit through `codex-api prepare`; do not mount a personal project into the source templates directly.

Before publishing, stage only source, documentation, and tests. `check_public.py` checks that exact index and refuses unstaged tracked changes. Scan the full Git history with a secret scanner. Never copy an installed directory, unrelated Git history, account-derived model prompts, or a personal acceptance report into this repository.

Preserve the owner-approved model and endpoint limits, explicit billing choice, full reservations before dispatch, ledger integrity, and uncertain-usage holds. Keep UTC rollover and concurrent requests safe. Usage has one English line per configured pool. The recommended margin is 5%, and warnings occur at most once per UTC day per pool. Preserve existing owner choices, including legacy A/B output. Never import subscription credentials or control an unowned sandbox.

New tool/provider access needs tests for costs, credentials, input validation, network rules, cancellation and failures. Do not widen package domains or add a silent retry/fallback. Keep setup explanations short and request choices only when they are needed.

Pin and review third-party tool/runtime updates. Do not vendor downloaded binaries or change the ledger identity to resolve migration problems. Update README/SETUP/boundary documentation when behavior changes.
