# Codex API Harness

Use Codex CLI with your own OpenAI API key, access to one project folder, and a daily token budget. Docker Sandboxes isolates the API environment from your subscription Codex setup.

macOS on Apple Silicon · Docker Sandboxes 0.49.1 · Python 3.11.8+

## Set up with Codex or ChatGPT Work

Open this repository in a local session and say:

> Read SETUP.md and set this up for me. Inspect my environment first, recommend suitable defaults, and ask for the choices you need. Use my models, limits, and account permissions. Keep credentials out of chat and leave my existing Codex setup alone.

The agent inspects your machine, helps you choose one project and a model policy, and creates a private credential file. It verifies the sandbox with a fake provider. Setup needs local access to the target Mac. A cloud-only session cannot install it there.

New installations have no selected models or assumed allowance. The setup draft recommends Standard, medium reasoning, a 5% safety margin, and a daily 90% warning per pool. Review its example model and budget for your account. The original five-model setup is an optional `legacy-five` preset.

Follow [SETUP.md](SETUP.md) for installation or [Configuration](docs/CONFIGURATION.md) for models, budgets, and speed tiers.

## Use it

Enter the project folder you selected during setup. For example:

```sh
cd ~/Projects/codex-workspace
codex-api
```

No subscription login is needed. `/model` lists only approved models. Supported reasoning and appearance preferences remain saved. Use `codex-api resume --last` to resume an API session. Ctrl+C cancels a task. When idle, Ctrl+C or `/quit` exits and stops the dedicated gateway and sandbox.

Check the remaining budget with `codex-api usage`, or `!codex-api usage` inside Codex. The command makes no provider call. For an approved 100,000-token daily budget with a 5% margin:

```text
Daily (Selected models): 95,000 / 95,000 tokens remaining
```

The first number is the remaining capacity. The second is the ceiling after the margin. Output has one English line per pool. Existing A/B installations keep two lines.

Budgets reset at 00:00 UTC and do not accumulate. Uncertain requests and usage near midnight can reduce the next day's balance. `codex-api usage --json` shows the accounting date, reset time, baseline, and reservations.

## Included controls

- One reviewed policy sets models, quota pools, limits, reasoning, output caps, warnings, and a fixed service tier. Standard, Fast, Flex, and Ultrafast require compatible models and account permissions. Automatic tier selection and paid fallback are disabled.
- Provider keys stay on the host. The API environment has its own `CODEX_HOME` and authenticated gateway. It inherits no subscription login or host credentials.
- The gateway counts input and reserves input plus maximum output before generation. It settles confirmed usage afterward. Uncertain usage retains its reservation across restarts and UTC rollover.
- Local shell, patches, and pinned Playwright CLI are available. Runtime dependency downloads permit HTTPS GET and HEAD only to approved npm and PyPI hosts.
- OpenAI hosted search, execution, remote MCP, storage, and unknown tool types are blocked. Image and video generation, transcription, and speech output are disabled.

Optional [shared mode](docs/SHARED.md) adds one coordinator on the owner's Mac with organization, project, and member allocations. [Reviewed skills](docs/EXTENSIONS.md) use immutable snapshots and exact approval digests. Native plugins, MCP, and plugin hooks remain disabled.

## Costs and limits

A token budget does not guarantee free API use or cap dollar spending. New installations default to free-only and block requests while complimentary eligibility is unverified. Standard does not mean free. Setup never changes payment, recharge, billing limits, or data sharing. Read [billing and accounting](docs/BOUNDARIES.md#billing-and-accounting) before enabling requests.

The project is mounted live. Edits and deletions affect the original files. Keep real secrets outside it. Sensitive-path masks cannot protect a matching file created after a long-running process starts. They also do not remove secrets from Git history or renamed copies. See [files and processes](docs/BOUNDARIES.md#files-and-processes).

Docker has machine-wide settings. Setup stops on conflicts. It changes those settings only with an informed choice on a fresh sandbox host. Removal leaves other sandboxes and your project in place.

Shared mode requires every organization caller to use the coordinator. It cannot control unrelated keys or Playground traffic. The coordinator owner can see forwarded requests and must keep the Mac awake and reachable. Search adapters require separate account verification and stay disabled in shared mode.

## Diagnose, update, or remove

```sh
codex-api doctor                 # local checks; no provider call
codex-api policy show            # models, limits, and selected tier
codex-api explain CODE           # reason and next step for a rejection
codex-api reconcile              # inspect uncertain usage
codex-api stop                   # stop after the original terminal disappears
codex-api retire                 # remove the owned sandbox and archive private state
```

[Operations](docs/OPERATIONS.md) covers recovery, key rotation, protected paths, and removal. [Updates](docs/UPDATES.md) preserves current credentials and usage through reviewed code changes. Policy changes require a stopped session. An initialized coordinator permits allocation changes, but whole-policy replacement is not supported in this release.

[Capability reference](docs/CAPABILITIES.md) · [Release verification](docs/VERIFICATION.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

MIT licensed. Downloaded tools retain their own licenses and terms. Not affiliated with OpenAI or Docker.
