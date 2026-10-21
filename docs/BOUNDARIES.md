# Boundaries

## Billing and accounting

The gateway permits only `api.openai.com` Responses inference and its exact-input-count endpoint. Hosted tool declarations, unknown fields, paid service tiers, server-side storage, external file URLs and media endpoints are rejected. Locally supplied image data for model input is permitted; media generation is disabled. Text-only use is not proof of free inference.

Free-only mode requires a current, complete eligibility record and expires closed. The installer does not manufacture that record. In particular, it does not assume exact counting is free or that local-tool reasoning qualifies for complimentary tokens. `--allow-api-charges` explicitly bypasses the free-eligibility claim, **not** the daily reservation guard. Account payment/recharge controls are separate and must be checked in the provider's account UI.

Factory budgets: group A 237,500; group B 2,375,000 tokens per UTC day. These are conservative starter limits, 95% of reference pools of 250,000 / 2,500,000. They are not live account discovery or a universal entitlement. The owner must check current [pricing](https://developers.openai.com/api/docs/pricing) and model/project availability. The model catalog is pinned metadata, not an account access check.

Before each generation, the gateway counts complete replayed input, instructions and tool definitions, then durably reserves input plus up to 16,384 output tokens. Reasoning is included in provider output usage. A request that cannot fit is rejected before generation. Counting may already have occurred; its financial treatment is not assumed. Requests with no complete usage retain their reservation; they are never silently refunded, retried, or rerouted.

One gateway owns the ledger. A session lock prevents duplicate launch/maintenance races. SQLite transactions and a separate witness detect inconsistent state; they are not tamper-proof against the host owner, malicious host software, or a simultaneous rollback of both files. Do not delete/restore state to regain quota. A changing clock or inconsistent ledger can stop requests for investigation.

The owner supplies today's prior A/B usage and confirms other organization clients are stopped. Unmanaged organization traffic cannot be predicted. This release does not coordinate multiple machines, projects or people. If another client starts using the organization, pause this harness before relying on the remaining-free-pool estimate.

New UTC days establish new budgets automatically. In-flight/unknown prior-day reservations carry conservatively; terminal cross-day usage is not discarded. A 90% notice uses actual plus reserved tokens and is claimed at most once per group/day across restarts. A crash after claiming can prevent display. Notice delivery failure does not loosen admission. Noninteractive notices use stderr after the command; usage itself remains two lines.

Cancel/timeout closes connections where possible, but cannot prove the upstream stopped computing. Unsent permits are voided; potentially dispatched requests retain their reservation. Under-reserved actual usage creates a safety stop. Reconciliation requires explicit completed-request evidence and preserves history; it is not an account billing query or automatic refund.

## Files and processes

The VM receives the selected project through a live direct mount. Changes, deletion and Git operations affect the original project. All allowed project contents and Git history may be read by the agent and sent as model input. `.gitignore`, `.dockerignore`, project instructions and hidden filenames are not security boundaries.

The host API key and ledger stay outside the mount. The guest receives only a random local gateway token. That token permits requests within this gateway's policy; it is not the upstream API key. It is visible to in-guest tools, so do not describe it as inaccessible to the agent. Host subscription state, skills, plugins, browser profiles, SSH agent and other projects are not imported.

Additional native masks deny common environment/credential paths. Host checks run before counting and again before dispatch. Four exact `.env` template names accept only reviewed placeholder-like values. Known public CA bundle names get a content check; standard venv interpreter aliases target the guest runtime. External/broken symlinks and hard-linked files fail preflight.

**Linux deny-glob matches are a per-tool-process-start snapshot, scanned to depth 16.** A running watcher, shell or server can read a matching file created later if its other permissions permit it. Starting a new tool process rescans; continuing the old process does not. Request-time checks cannot undo a secret already copied to a log, memory or another filename. There is no continuous secret-content filter or filtered live filesystem mount. [Official permissions documentation](https://learn.chatgpt.com/docs/permissions#deny-reads-with-exact-paths-or-globs).

Inside the VM, Docker provides a private Docker engine and privileged development facilities. Native tool masks are defense in depth for ordinary execution, not an independent security boundary against malicious code with in-VM privileges. **Keep actual secrets outside every shared project.** Docker's VM boundary and the absence of host mounts remain the host isolation boundary. [Docker isolation model](https://docs.docker.com/ai/sandboxes/security/isolation/).

## Network and local tools

Runtime permits the authenticated localhost gateway and HTTPS GET/HEAD to `registry.npmjs.org:443`, `pypi.org:443`, `files.pythonhosted.org:443`. Other direct destinations, including OpenAI and GitHub, remain blocked. Global allows could widen runtime access, so preparation and startup reject them rather than silently replacing global policies. Docker organization governance and broader existing configurations require separate review.

Allowed hosts are still network access: query strings and paths can carry data, and package code can execute lifecycle/build scripts. This is not universal exfiltration prevention. npm audit/fund/update prompts are off; TLS certificate validation remains on. Package dependencies needing other registries, GitHub or CDN binaries will fail. Initial trusted image builds use broader build-time downloads; build access is not the runtime allowlist.

Playwright is installed for local pages. Installation does not grant arbitrary web browsing or authenticated host-browser access. Hosted execution, paid search, remote MCP and media tools do not become available because a local package is installed. Unknown tools fail closed. Supported local function/custom-tool names and request formats are tied to the pinned CLI release.

Only the fixed managed quota-notice hooks execute. They discard hook input and return a UI-only message. Project/user/plugin hooks are skipped. Enabling a new skill/plugin/tool requires a separate review of filesystem access, network destinations, credentials, request shapes and pricing. Source instructions can still influence the agent; this harness does not solve prompt injection.

## Privacy, storage and removal

The gateway does not log prompts, queries, tool outputs or raw provider error bodies. The ledger stores request hashes and accounting metadata. Private CLI conversation history remains inside the persistent sandbox. Selected project paths, account IDs, configuration hashes and diagnostics are local private state; do not publish that directory or its archives.

Provider request storage is disabled with `store=false`. This does not override provider retention, logging, training/data-sharing choices or legal policies. The harness never opts into account data sharing automatically.

`stop` is reversible. `reset` removes only the sandbox whose recorded ID and workspace still match. `retire` resets that sandbox and archives private state, including credentials and usage; it is not secure erasure. Project files remain. Shared builder cache, daemon, Docker login and global settings are left alone. Deleting the source checkout does not revoke keys or erase installed state.

The host owner, host malware, upstream provider, selected project and third-party dependencies remain in the trust model. No sandbox can protect secrets the owner explicitly pastes into a model prompt.
