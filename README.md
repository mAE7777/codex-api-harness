# Codex API Harness

Run Codex CLI with your own API key, one shared project folder, and a durable daily token budget. Keep your subscription Codex separate.

**macOS · Apple Silicon · local Docker Sandboxes · Python 3.11.8+**

## Set up with Codex or ChatGPT Work

Open this repository in a local session and say:

> Read SETUP.md and set this up for me. Inspect my environment first, explain each decision briefly, and ask only when you need my choice. Keep credentials out of chat and leave my existing Codex setup alone.

The setup guide checks your machine, asks where you want to work, creates a private key file, and tests the sandbox with a fake model. It does not make a paid API test call. Work needs local terminal/filesystem access; a cloud-only session cannot install this on your Mac.

For manual setup, follow [SETUP.md](SETUP.md). No remote install script, subscription login, or search-provider key is required.

## Daily use

```sh
cd ~/Projects/codex-workspace
codex-api
```

Use `/model` normally. Model, reasoning and supported appearance preferences persist privately. `codex-api resume --last` restores an API session. Ctrl+C cancels a task; when idle, Ctrl+C or `/quit` exits and stops the dedicated gateway and sandbox.

```sh
codex-api usage
```

```text
A (6.1 Sol / 6 Astra / 6 Luna): 237,500 / 237,500 tokens remaining
B (5.6 Terra / 5.6 Luna): 2,375,000 / 2,375,000 tokens remaining
```

Inside Codex, use `!codex-api usage`. It makes no model call and still prints only those two English lines. Each group gets one 90% warning per UTC day. The starter budgets leave 5% below reference pools of 250,000 and 2,500,000 tokens; **those reference pools are not a promise of your account's free allowance**.

## What it includes

- **Separate API environment.** Private `CODEX_HOME`, host-side API key, local authenticated gateway, no subscription fallback or imported host credentials.
- **Request-time budgets.** Exact input-count request, full input plus maximum output reserved before generation, actual usage settled afterward. Unknown usage keeps its reservation across restarts and UTC rollover.
- **Five allowed models.** A: `gpt-6.1-sol`, `gpt-6-astra`, `gpt-6-luna`. B: `gpt-5.6-terra`, `gpt-5.6-luna`. Availability still depends on your API project.
- **Local coding tools.** Shell, patches and installed Playwright CLI. npm/PyPI downloads are limited to three hosts and HTTPS GET/HEAD.
- **Hosted tools blocked.** OpenAI web/file search, hosted execution, remote MCP, storage and unknown tool types are rejected. Image/video generation, transcription and speech output stay disabled.
- **Useful failures.** Specific English errors, `doctor`, permission explanations and explicit reconciliation for uncertain usage. No automatic retries, model switch or quota reset.
- **Optional shared organization.** One coordinator enforces organization, project and member budgets together. Fixed daily allocations, temporary transfers, quota requests, revocation and private invitations work across computers. [Shared setup](docs/SHARED.md).
- **Reviewed skills.** Stage local skill bytes, inspect the report, then approve their exact digest. Skill-only plugin bundles are supported; native plugins, MCP and plugin hooks stay disabled. [Extensions](docs/EXTENSIONS.md).
- **Safe maintenance.** Reviewed code generations, explicit crash recovery, code-only rollback, private key rotation, and additional exact protected paths. Rebuilds preserve this API environment's selected history and preferences. [Updates](docs/UPDATES.md).

## Costs and safety boundaries

**This is a token-budget guard, not a guarantee of free API use or a dollar spending cap.** Free-only is the default and blocks requests when eligibility is unverified. Exact-count pricing and complimentary eligibility for local-tool reasoning are not assumed. To allow API charges while retaining the token guard, explicitly choose that mode during setup or run `codex-api billing --allow-api-charges`. Nothing changes your account's payment, recharge, spending-limit or data-sharing settings. [Details](docs/BOUNDARIES.md#billing-and-accounting).

Only your chosen project is mounted, and edits affect the original files immediately. Keep real secrets outside it. Sensitive-path masks and request-time checks are additional protection; Linux masks do not refresh inside an already-running tool process when a matching file is created later. File contents, Git history, logs and renamed files are not universal secret-scanned. [Filesystem boundaries](docs/BOUNDARIES.md#files-and-processes).

Docker has some machine-wide settings. Setup reports unsafe shared settings and stops. Initial host configuration requires an explicit step, is allowed only on a fresh sandbox host, and is never a global reset. Removing this harness never prunes other sandboxes, stops the shared daemon, or removes your project.

Personal mode remains the default. Shared mode uses the owner's Mac and a restricted encrypted tunnel; it adds no hosted dashboard or paid server requirement. The coordinator owner can see requests while forwarding them. Every caller using that organization must participate: unrelated keys, Playground and other programs cannot be fenced by this harness. Coordinator loss stops requests. Exa/Tavily adapters remain disabled pending separate account verification; Brave has no active adapter. Search providers stay disabled in shared mode.

## Maintenance

```sh
codex-api doctor                 # local checks; no provider call
codex-api explain permissions
codex-api reconcile              # inspect uncertain usage; no automatic refund
codex-api team allocations       # owner: today's shared allocations
codex-api extensions list        # reviewed skill catalog
codex-api protect list           # additional owner-selected protected paths
codex-api credentials stage      # create a private replacement-key file
codex-api stop                   # recovery if the original terminal disappeared
codex-api reset                  # remove only the owned sandbox; preserve usage and keys
codex-api retire                 # remove that sandbox and archive private state
```

The installer refuses to overwrite another command or altered installation. Runtime versions are pinned. Upgrades stage reviewed code before an atomic generation switch; credentials and accounting are permanent state and never roll back. See [capabilities](docs/CAPABILITIES.md), [verification](docs/VERIFICATION.md), [operations](docs/OPERATIONS.md), [security](SECURITY.md) and [contributing](CONTRIBUTING.md).

```sh
python3 scripts/check.py         # regression tests; fake providers only
python3 scripts/check_public.py  # check the tracked publication surface
```

MIT licensed. Codex, Docker Sandboxes and other downloaded tools keep their own licenses and service terms. This project is not affiliated with OpenAI or Docker.
