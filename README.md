# Codex API Harness

Run Codex CLI with your own API key, an isolated project folder, and a durable token budget. Keep subscription Codex separate.

**macOS · Apple Silicon · local Docker Sandboxes · Python 3.11.8+**

## Set up with Codex or ChatGPT Work

Open this repository in a local session and say:

> Read SETUP.md and set this up for me. Inspect my environment first, recommend suitable defaults, and ask only for choices you need. Use my own models, limits and account permissions. Keep credentials out of chat and leave my existing Codex setup alone.

The agent checks your machine, helps choose one project and an account-specific policy, creates a private credential file, and verifies the sandbox with a fake provider. No real API test call is required. A cloud-only session needs to move to the target Mac with local terminal/filesystem access.

New installations have **no selected models or assumed allowance**. The draft recommends Standard, medium reasoning, a 5% safety margin and one daily 90% warning per pool. Its example model and token allowance are proposals to review, not account entitlements. The original five-model/A–B setup is an optional `legacy-five` preset. [Configuration](docs/CONFIGURATION.md) · [Manual or agent-guided setup](SETUP.md).

## Daily use

```sh
cd ~/Projects/codex-workspace
codex-api
```

Use `/model`, `codex-api resume --last`, and supported reasoning/appearance preferences normally. `/model` contains only the installation's approved models. Ctrl+C cancels a task; when idle, Ctrl+C or `/quit` exits and stops the dedicated gateway and sandbox.

```sh
codex-api usage
```

Example for a user-approved 100,000-token daily allowance with a 5% margin:

```text
Daily (Selected models): 95,000 / 95,000 tokens remaining
```

Inside Codex, use `!codex-api usage`. It makes no provider call. Output is one English line per configured pool. The first number is remaining capacity; the second is the usable ceiling **after** the safety margin. Existing A/B installations retain their two English lines. Budgets reset at **00:00 UTC**, not local midnight, and do not accumulate. Unknown requests and near-midnight usage may conservatively reduce the next day's balance. `usage --json` includes the accounting date, reset time, baseline and reservations.

## What it includes

- **One policy.** Approved models, model-to-pool mapping, actual daily allowances, margin, warning threshold, reasoning, output cap and service tier feed the gateway, native catalog, preferences and shared clients together. Standard, Fast, Flex and Ultrafast must pass the same compatibility checks. `auto` and silent paid fallback are disabled.
- **Separate API environment.** Private `CODEX_HOME`, host-side provider key and authenticated gateway. No subscription login, fallback or imported host credentials.
- **Request-time budgets.** Exact input count, full input plus maximum output reserved before generation, actual usage settled afterward. Unknown usage retains its reservation across restarts and UTC rollover.
- **Local coding tools.** Shell, patches and pinned Playwright CLI. Runtime dependency downloads are limited to approved npm/PyPI hosts and HTTPS GET/HEAD.
- **Hosted tools blocked.** OpenAI web/file search, hosted execution, remote MCP, storage and unknown tool types are rejected. Image/video generation, transcription and speech output remain disabled.
- **Optional shared organization.** One owner-Mac coordinator enforces organization, project and member allocations. Invitations bind the same model/quota/tier policy; mismatches stop requests. [Shared setup](docs/SHARED.md).
- **Reviewed extensions.** Stage local skills or skill-only plugin bundles, inspect them, then approve the exact digest. Native plugins, MCP and plugin hooks remain disabled. [Extensions](docs/EXTENSIONS.md).
- **State-preserving maintenance.** Specific errors, local diagnostics, reconciliation, reviewed upgrades, key rotation and additional protected paths. Interrupted changes stop new requests; recovery never restores an old usage ledger. [Operations](docs/OPERATIONS.md) · [Updates](docs/UPDATES.md).

## Costs and boundaries

**A token budget is not a guarantee of free API use or a dollar spending cap.** Free-only is the default and blocks requests while complimentary eligibility is unverified. Standard does not mean free. Faster tiers can cost more; Flex has different latency and availability. Model metadata and a valid policy do not prove account access, project tier permissions or free-pool eligibility. Setup never changes payment, recharge, billing limits or data sharing. [Configuration and tiers](docs/CONFIGURATION.md) · [Accounting boundaries](docs/BOUNDARIES.md#billing-and-accounting).

The original project is mounted live; edits and deletions affect it immediately. Keep real secrets outside it. Sensitive-path masks are additional protection: Linux masks do not refresh inside an already-running process when a matching file is created later. File contents, Git history and renamed secrets are not universally scanned. [Filesystem boundaries](docs/BOUNDARIES.md#files-and-processes).

Docker has machine-wide settings. Setup reports conflicts and stops; initialization requires an informed choice on a fresh sandbox host. Removal never prunes other sandboxes or deletes the project. Runtime versions and platform support remain pinned; a policy cannot enable unreviewed tools, providers or operating systems.

Shared mode requires every organization caller to participate. Unrelated keys, Playground and other programs cannot be fenced by this harness. The owner can see forwarded requests, must be trusted, and must keep the Mac awake and reachable. Search adapters remain disabled pending separate account verification; search stays disabled in shared mode.

## Maintenance

```sh
codex-api doctor                 # local checks; no provider call
codex-api policy show            # selected models, tier and safe limits
codex-api policy template        # private draft; never overwrites an existing draft
codex-api policy check FILE      # schema, compatibility and review digest
codex-api explain permissions
codex-api reconcile              # inspect uncertain usage; no automatic refund
codex-api extensions list
codex-api protect list
codex-api stop                   # recovery if the original terminal disappeared
codex-api reset                  # owned sandbox only; preserve keys and usage
codex-api retire                 # remove that sandbox and archive private state
```

Policy changes require a stopped session and exact review, preserve existing usage and baselines, and rebuild the owned sandbox automatically. Coordinator policy is pinned after initialization in this release; live allocation changes remain available. [Policy changes and recovery](docs/CONFIGURATION.md#changing-an-existing-policy).

```sh
python3 scripts/check.py         # regression tests; fake providers only
python3 scripts/check_public.py  # publication surface check
```

MIT licensed. Downloaded tools keep their own licenses and terms. Not affiliated with OpenAI or Docker.
