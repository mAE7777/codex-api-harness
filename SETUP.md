# Agent-guided local setup

Follow these steps in order. Automate the work between decisions. Use the owner's language, short explanations, and one small group of questions at a time. Never collect a secret in chat.

## 1. Inspect before asking

Run from this checkout:

```sh
python3 setup.py inspect --json
```

This reads OS/architecture, Python and sandbox versions, command conflicts, PATH membership, and whether an existing subscription config or harness exists. It does not read auth files, environment values, repository contents, or credentials. To locate missing tools, use command lookup and version checks; do not dump the shell environment or scan the user's whole disk.

Supported release: macOS on Apple Silicon, Python 3.11.8+, Docker Sandboxes 0.49.1. On an unsupported OS, cloud executor, or machine without local access, stop and explain how to open the repository on the target Mac. Do not silently switch to a normal Docker container or host Codex.

If an existing harness is detected, preserve it. For an authorized upgrade, follow [UPDATES.md](docs/UPDATES.md); do not replace its owner policy with a new draft. A second account or project needs a separate installation/launcher. Never delete private state to make installation pass.

If Python is missing/old, explain the prerequisite and ask before installing it. If Homebrew already exists, recommend its maintained Python package. Do not bootstrap a package manager with an unreviewed remote script. If `sbx` is missing, the installer can download the pinned official archive privately with `--bootstrap-sbx`; it checks SHA-256 and the macOS signature. No Docker PAT needs to be pasted into chat.

Explain the harness in three sentences:

> This gives you a separate API Codex, with access to one project folder. A local gateway keeps your API key outside the sandbox and reserves tokens before each request. It does not guarantee free API use; we will choose the billing policy before enabling requests.

## 2. Choose the project and installation

Ask for the absolute project path. Recommend `~/Projects/codex-workspace`, created empty, unless the user already chose a path. Explain that the original folder is shared live: changes and deletions are real. Existing Git history is readable. No project copy or manual sync is used.

Do not propose mounting the home directory, Downloads, Documents, a credential folder, or the entire Projects parent. Do not import private repositories automatically. If the selected existing folder contains sensitive files, report paths only and let the owner move them outside the workspace. Do not open their contents or move them silently.

The private installation defaults to `~/Library/Application Support/CodexAPIHarness`; its key and ledger are outside the project. The launcher defaults to `~/.local/bin/codex-api`. If another `codex-api` exists, keep it and ask for another command name, then pass `--launcher` with that path. Never overwrite the subscription's `codex` command.

Keep the private installation on local storage, outside sync/file-provider folders. Such folders can attach Finder metadata that invalidates application-bundle verification. Use the default local Library location; never strip quarantine or disable signature checks to continue.

Run:

```sh
python3 setup.py install --workspace ABSOLUTE_PROJECT_PATH
```

Add `--bootstrap-sbx` only when the runtime is missing and the user agreed. An existing compatible executable can be selected with `--sbx ABSOLUTE_EXECUTABLE_PATH`. The installer checks its version and records its hash. `--home` and `--port` allow a separate installation when necessary; port defaults to 49188. Use a free port rather than stopping another service. Paths are arguments, not shell fragments: quote them safely.

If `~/.local/bin` is absent from PATH, show the exact launcher path immediately. Ask before editing a shell startup file; make a narrowly scoped PATH addition only if needed. Do not replace that file or `source` it in the setup agent. Otherwise no shell configuration change is needed.

The installer is resumable: rerunning with the same settings verifies and preserves existing state. It refuses unexpected changes rather than resetting anything. Do not delete the private directory to get around a failure.

## 3. Choose mode and the account-specific policy

First ask whether this is **personal mode**, **coordinator owner**, or **joining a shared organization**. Personal mode is the simplest default. For shared mode, follow [SHARED.md](docs/SHARED.md) now, then return to sandbox preparation and handover below. A joining member does not need an OpenAI key or a personal account configuration. Never request an unnecessary key just because the installer created a blank file.

### Personal mode or coordinator owner: choose the policy first

Create a private draft with `codex-api policy template`. Do not apply it unchanged. It proposes one model, a sample daily allowance, Standard, medium reasoning, 5% safety margin and 90% warning. No allowance or model is installed automatically. The optional `--preset legacy-five` is only for an owner who deliberately chooses that setup and confirms their own entitlement.

Ask one short group of questions, with recommended choices first:

- Which models should be available? Offer one suitable model first, then alternatives. Verify each exact model's Responses/local-tool support, context/output bounds, reasoning efforts and service tiers using current official documentation. An owner-reviewed additional model ID needs no source edit. A key's `/models` list does not prove tool compatibility or free eligibility; do not call it merely to avoid asking the owner, or enable a model from that list alone.
- What are the actual shared allowance pools and today's prior input plus output usage? Never assume the sample allowance is free. Assign models that share one allowance to the same pool. Support 1–8 pools, not a mandatory A/B pair. Only daily UTC reset is supported; explain if their allowance uses another period and choose a separately justified conservative daily budget.
- Which speed tier? Recommend Standard initially. Offer Fast, Flex or Ultrafast only when supported by every selected model and permitted by their API project. Explain the cost/availability consequence. Flex recommends a 900-second deadline; other defaults use 600. There is one fixed selected tier per installation; auto and automatic tier fallback stay disabled.

Edit only the private draft using the owner's choices and verified metadata. Keep its English pool labels short. Set an output reservation cap that fits every selected model. Run `codex-api policy check ABSOLUTE_DRAFT_PATH`; explain the selected models, tier, effective ceilings after the margin, and 00:00 UTC reset in a few sentences. The digest is local consistency/review evidence, not an API entitlement check. The setup agent may pass the exact digest after the owner has already authorized those choices; do not add a second approval just for the hash.

For a coordinator owner, apply this reviewed policy with one explicit `--baseline POOL=TOKENS` per pool before `team init`; no OpenAI key or client VM is needed for this policy selection. Coordinator initialization requires the actual full organization baselines again, including any earlier personal traffic. Its policy is then pinned in this release. Allocation changes remain available; policy replacement is refused instead of resetting a shared ledger. Use named pools in SHARED.md.

Joining members skip independent model/budget choices. Inspect and review the coordinator invitation policy instead, using the branch below. No API key is needed.

### Shared mode branch

The coordinator installation is a host service. Initialize its organization, project keys and members using SHARED.md, with the owner's actual prior usage and all other organization callers stopped. Once initialized, that installation cannot run a second independent personal gateway. Do not convert or overwrite an existing personal installation.

Create a separate client installation for the owner, with its own private home, launcher and unused local gateway port. Keep its project binding explicit. When the coordinator is running, join using the owner's private invite:

```sh
codex-api-client team join --invite PRIVATE_OWNER_INVITE --inspect
codex-api-client team join --invite PRIVATE_OWNER_INVITE --local --reviewed-policy-digest SHA256
```

Here `codex-api-client` means the exact separate launcher selected during installation. `--local` uses the coordinator on the same Mac and needs no SSH key. The client account remains unconfigured locally; its upstream project key belongs only to the coordinator.

For a remote member, automate the following on that member's computer:

1. Install a normal isolated client without configuring a personal OpenAI account or asking for an OpenAI key.
2. Run `codex-api team keygen`. Give the owner only the reported `.pub` file; never the adjacent private key. The owner registers it and configures `team share` before sending the refreshed private invitation.
3. Let the member save that invitation locally. Give that exact file owner-only permissions, without printing or committing it. Verify the owner supplied it through a trusted channel.
4. Run `codex-api team join --invite ABSOLUTE_PRIVATE_INVITE_PATH --inspect`. Review only its sanitized models, tier and budgets; do not print the invitation file or token. Then run `codex-api team join --invite ABSOLUTE_PRIVATE_INVITE_PATH --reviewed-policy-digest SHA256`. The invitation supplies the restricted tunnel address, port and pinned host key. The dedicated client key is selected automatically. No system SSH login or host-key prompt should be bypassed.
5. If the invitation's private address is unreachable, ask for the reachable private LAN/VPN address. Do not open public HTTP, configure router forwarding, accept a new host key, or fall back to another account. The owner's Mac must be awake with `team serve` running.

For a renewed token from the same coordinator/member, use `team join --invite FILE --replace-member-credential --reviewed-policy-digest SHA256`. A new coordinator or member identity requires a separate installation. After successful pairing, skip personal steps 3–4 and proceed to sandbox preparation below. `codex-api`, `/model`, resume and one English usage line per approved pool remain the daily interface.

### Personal mode credentials, only now

The installer creates `openai-key.env` inside the private installation, mode 0600. Tell the owner the exact absolute path from the install result. Ask them to fill `OPENAI_API_KEY=` locally and reply when saved. They may use their editor; never ask them to paste the key into the conversation or a command argument. Check readiness using `codex-api doctor`; do not read or print the key yourself.

Explain that they need their own OpenAI API project and a restricted key, with Responses, exact input counting and the owner-selected models permitted. Subscription access and API billing are separate. The harness does not enable account data sharing or alter billing. If complimentary usage requires data sharing, the owner must review that consequence in their account. Do not make that decision for them.

Request the organization ID and project ID; these identify the account binding, not the secret key. Prefer local entry if the owner does not want them in chat. Do not copy them from someone else's installation.

Skip Brave, Exa and Tavily keys. They are not prerequisites. When the owner later requests search, explain the disabled adapters and the need for fresh account-level free-limit/payment verification first. Never enable a search provider from a key alone.

## 4. Choose billing and accounting assumptions

Ask:

- **Free-only (recommended when avoiding all charges):** leave model requests blocked while complimentary eligibility or count-endpoint pricing is uncertain.
- **Allow API charges with token protection:** explicitly permit OpenAI API charges; the daily token guard and blocked hosted tools remain. This is not a dollar spending cap.

Then establish whether all other clients using the same OpenAI organization are stopped. Quotas can be organization-wide; separate projects do not prove separate pools. Recommend using a dedicated organization/account usage context. If other traffic is present or unknown, do not pass `--exclusive-organization`; requests will remain blocked. Multiple participating people/computers must use the optional coordinator instead of independent personal ledgers.

Ask for today's already-used **input plus output** tokens for each approved pool, including other clients. Zero is appropriate only when the owner confirms no usage today. If usage cannot be established, wait for the next UTC day with other callers stopped, rather than guessing or clearing the ledger.

Configure once, with the actual IDs and baselines:

```sh
codex-api configure --organization ORG_ID --project PROJECT_ID \
  --policy ABSOLUTE_PRIVATE_DRAFT_PATH --reviewed-policy-digest SHA256 \
  --exclusive-organization --baseline Daily=TOKENS
```

Append `--allow-api-charges` only after explicit owner approval of that choice. No real API request is made. This command creates the initial budgets, binds the account, and refuses rebinding or baseline resets. Repeat `--baseline POOL=TOKENS` once for every configured pool. The actual models, caps, tier, warning and margin come from the reviewed draft; verify the account permits them. A valid local policy does not prove model access or free eligibility. Do not fabricate a successful entitlement check.

Later billing changes preserve all usage:

```sh
codex-api billing --allow-api-charges
codex-api billing --free-only
```

Free-only is intentionally blocked until actual free eligibility is established. Do not set verification booleans to true just to make the CLI work. If the user requires guaranteed zero charges and eligibility remains unconfirmed, leave requests disabled and clearly explain that outcome.

## 5. Prepare and verify the sandbox

```sh
codex-api prepare
```

The first build downloads pinned Codex, Playwright and browser components. Runtime package downloads are limited to npm and PyPI; build-time downloads have a separate, broader scope. No upstream model or search call is used for acceptance.

If Docker login is needed, guide the user through `codex-api login` in their own terminal, then retry preparation. Docker credentials stay in Docker's credential mechanism; do not request a PAT in chat or create a project-local token file.

Some isolation controls are machine-wide Docker settings. If setup reports unsafe settings, explain their effect before proceeding: host browser/SSH forwarding and clipboard images must be off, the network preset must be Locked Down, and the MCP catalog must be empty. On a **fresh host with no sandboxes or custom global policy**, and only after the owner agrees:

```sh
codex-api prepare --configure-sandbox-host
```

This initializes Docker's shared settings. It refuses if any existing sandbox or custom global rule would be affected. For an existing shared Docker setup, show the conflict and stop for a deliberate review; never call global reset, prune, logout, or daemon stop to get around it. Other organization governance requires separate review.

Preparation verifies the native file masks, direct write-through, credential absence, blocked destinations, permitted package downloads, pinned tool versions, and a real CLI/local-tool replay against a fake provider using the selected model and tier. A rejected CLI tier or incompatible request leaves readiness false; do not downgrade silently. Failed checks leave the environment unready. Never hand-edit readiness records or copy another person's PASS report.

## 6. Hand over a working entry point

Run `codex-api doctor` and `codex-api usage`. Explain any WARN, especially unverified free eligibility. Normal usage must contain exactly one English line per configured pool. Existing A/B installations keep two lines. Both numbers are usable tokens after the safety margin; the daily balance resets at 00:00 UTC, not local midnight, and does not accumulate. `usage --json` exposes the accounting period, next reset, baselines and reservations without a provider call.

Open the real CLI, query `!codex-api usage`, and exit when idle with Ctrl+C. Do not submit a real model prompt without the owner's explicit request. Verify cleanup. In free-only mode, make clear that the interface can open but model requests remain blocked.

Finish with only:

1. The exact `cd …` and launcher commands.
2. How to see usage and exit.
3. Whether requests are enabled, whether API charges are allowed, and any unresolved blocker.
4. One reminder: real secrets belong outside the shared project.

Do not ask the user to keep doing maintenance commands. Point to `docs/OPERATIONS.md` only if they need recovery or removal.

## Optional capabilities, only when requested

For a skill or skill-only plugin, use [EXTENSIONS.md](docs/EXTENSIONS.md). Inspect the requested local folder only, read every staged file, explain code/network references briefly, and approve the exact digest only after review. Do not import all personal skills, execute remote installers, grant new destinations, or turn on native plugins. Review is not a proof against malicious instructions.

Use [UPDATES.md](docs/UPDATES.md) for a version change. Stage without executing candidate code; review its digest before running its candidate checks. Never overwrite an installed app or restore an old ledger to upgrade. An interrupted activation blocks new sessions until explicit recovery.

If additional project paths should be hidden, use `codex-api protect add RELATIVE_PATH ...`. Exact paths are private host settings. The command rebuilds only the owned sandbox and preserves selected API history/preferences automatically; the project is still shared live. Explain the native per-process snapshot limit from BOUNDARIES.md; no continuous DLP claim is permitted.
