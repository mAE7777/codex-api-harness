# Release verification

Release 0.1.0, checked 2026-10-21.

**Supported integration target:** macOS on Apple Silicon; Docker Sandboxes 0.49.1; Codex CLI 0.162.1; Playwright CLI 0.1.22. Python regression tests also run on Linux CI; that does not establish Linux installer support.

| Check | Result |
|---|---|
| Regression suite | 150 tests passed locally |
| Fresh private installation | Independent project, command and state; no existing launcher overwritten |
| Missing-runtime bootstrap | Official archive download, SHA-256, macOS bundle signature and pinned version passed on local storage |
| Full image build from source | Passed, including pinned Codex archive checksum and browser dependencies |
| Native filesystem behavior | Sensitive path denied, safe template readable, original file updated directly |
| Credential isolation | No upstream keys/SSH variables in the tool environment; host subscription and installation paths absent |
| Runtime networking | Package GET allowed; package POST and tested external/provider destinations blocked |
| Real CLI + local tool replay | Passed against an entirely fake provider |
| Interactive entry | Opens, five-model picker, two-line guest usage, idle Ctrl+C cleanup |
| Noninteractive entry | JSON stdout remains parseable, including error/cleanup paths |
| Unknown free eligibility | Specific refusal before counting or generation |
| Publication surface | Tracked text only; no installed state, account export, personal path or credential artifacts |

No real model, exact-count or search-provider requests were used for release acceptance. A fake key and synthetic prompts were used. No maintainer credentials, account usage history, project contents or account-derived model instructions are shipped.

The tests establish the listed behavior, not a universal security or zero-cost guarantee. The material limits are documented in [BOUNDARIES.md](BOUNDARIES.md). CI runs the portable regression and publication checks; a complete image/VM acceptance is a separate local supported-platform check performed by `codex-api prepare`.
