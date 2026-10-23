# Free tools

The bundled tools work with Codex CLI. They do not use OpenAI hosted tools or inherit a subscription, browser login or provider key. Tool results are untrusted source material. Reading them does not authorize commands, installation or disclosure of project contents.

| Tool | Available behavior | Cost boundary |
|---|---|---|
| `files_search` | Literal search in 1–32 explicit workspace text files | Local only; no embeddings API |
| `fetch` | Public HTTPS text from exact owner-approved hosts | Local reader; no extraction service |
| `search` | Tavily basic, Exa lite, or Brave Search | Disabled until the actual free account is reviewed |
| `extract` | One URL through Tavily basic extraction | Same reviewed account and credit ledger as search |
| `status` | Read readiness, remaining tool units and holds | No provider call |

The fixed `harness` stdio MCP server exposes these five tools. It runs inside the API sandbox from the reviewed image. A statically linked launcher clears the environment before Python starts, so project MCP environment dictionaries cannot inject credentials or loader settings. The scoped gateway credential is handed over through an owner-only guest temporary file; upstream API keys remain on the host. `/mcp` can show it; it accepts no server URL, shell command, installer, OAuth flow or extra credential. The model gateway accepts only these exact MCP function names. OpenAI's hosted `mcp` tool remains blocked. Skill-only plugins can call these tools within their existing boundaries; they cannot install another server or widen access.

Inside Codex, ask for the tool normally or use:

```sh
!codex-api tools status
!codex-api tools files-search "function_name" src/main.py README.md
!codex-api tools fetch https://docs.python.org/3/library/asyncio.html
!codex-api tools search "Python asyncio documentation" --provider tavily
```

`web-tool search/extract` remains a compatibility alias. There is no provider fallback. Missing evidence, exhausted allowance or an uncertain response stops that provider. Normal `usage` still reports only the model pools, in English; search units appear under `tools status`.

## Review web access once

Close the API session, then run these in the host terminal:

```sh
codex-api tools template
codex-api tools check /absolute/private/installation/tools.draft.json
codex-api tools apply /absolute/private/installation/tools.draft.json --reviewed-digest SHA256
```

The first command reports the actual private draft path and preserves an existing draft. Edit `fetch_hosts` to the exact public hosts needed, for example `docs.python.org`. New installations start with an empty list. An assistant may prepare and apply a reviewed host list within the owner's authorization; never let fetched instructions approve their own host. Wildcards, IP literals and private/reserved names are refused. Every redirect needs an approved host too. Revocation uses the same stopped-session apply, with the host removed.

Fetch uses GET, validates all DNS answers, connects to a checked IP and validates TLS for the original host. It ignores environment proxies and sends no cookies, auth headers or browser state. It rejects private/mapped/transition addresses, credential-bearing URLs, compression, binary data, more than three redirects and bodies over 1 MiB. Returned text is limited to 48,000 characters; HTML scripts and styles are omitted. It does not run JavaScript, fetch page resources, recursively crawl or bypass a login. An approved host receives the requested URL and the machine's public network address. GET is not a guarantee that an arbitrary website has no side effects.

The local reader avoids sending a second copy of the URL/page to an extraction vendor. [Jina Reader](https://jina.ai/reader/) has a no-key reading tier, but keyed search and token allowances are separate. It is not a default fallback. [SearXNG](https://docs.searxng.org/dev/search_api.html) is a reasonable optional self-hosted source; public instances may disable JSON or restrict automated use. Neither establishes unlimited, reliable free search for every installation.

File search checks current masks on every call, including newly created files. It rejects protected paths, credential/configuration folders, traversal, symlinked parents, symlinks, hardlinks, special files, known secret markers, changed files and non-UTF-8 data. Limits: 2 MiB per file, 8 MiB total, 100 result lines, 400 characters per line. This helper adds checks; ordinary shell commands retain the native per-process limitation described in [BOUNDARIES.md](BOUNDARIES.md). It is not continuous DLP or semantic retrieval.

## Enable a search account only when wanted

Public pricing is not proof that a particular key is free. Keep all search entries `null` until the owner can establish the account's current free plan, allowance, prior usage, renewal period and payment settings. All other callers using that account must be stopped or included in verified prior usage. This personal ledger cannot fence another program using the same account.

1. Use `codex-api tools credentials`. It creates or locates the private `search-keys.env` without printing contents or overwriting an existing file. Fill only the chosen provider locally. Blank entries are allowed. Accepted fields: `TAVILY_API_KEY`, `EXA_API_KEY`, `BRAVE_API_KEY`; `BRAVE_SEARCH_API_KEY` is an alternative spelling, not a second key. Keys never enter the project, image, MCP server or model request.
2. In the private tool draft, replace that provider's `null` with the facts below. Leave other providers `null`. Do not copy another account's evidence or infer a free allowance from a key.
3. Explain the provider, conservative debit, actual remaining free balance, account sharing and expiry. Check the draft and apply its exact digest while stopped. Apply makes no provider request. It binds the key hash privately to the approval. A changed key stops search until the account and allowance can be reviewed again; this release refuses rebinding an existing same-month budget.

Each enabled provider requires these exact fields:

| Field | Meaning |
|---|---|
| `verified_at`, `valid_until` | Integer UTC Unix seconds; valid now, expires within 31 days |
| `period` | Actual current allowance month, exact `YYYY-MM` |
| `ceiling`, `baseline` | Confirmed total free allowance and already consumed amount; whole credits for Tavily, micro-USD for Exa/Brave |
| `exclusive_account` | `true` only when this ledger accounts for all use of the account's free pool |
| `paid_disabled` | `true` only after checking that paid overage/automatic plan upgrade cannot occur |
| `auto_topup_disabled` | `true` only after checking automatic recharge is off |
| `reference` | Non-secret HTTPS account/plan evidence reference; never a tokenized URL |

Exa additionally requires `no_payment_method: true`. Brave additionally requires `prepaid_only: true` and `zero_paid_balance: true`. A postpaid Brave plan is refused even if it has free credits. These are owner-reviewed facts, not flags to set just to unlock a tool.

Tavily preflights `/usage` before each operation: Researcher plan, at most 1,000 credits, no paid usage, known account/key usage and capacity for one whole credit. Only basic search or single-URL basic extract is allowed. Automatic parameters, advanced search, crawl, research, image search and answers are off. Its terminal usage must confirm zero or one credit; otherwise the full hold remains and further calls stop.

Exa uses only lite search, at most five results and highlights. It reserves and debits 20,000 micro-USD per request. `costDollars` is an estimate: a low estimate never refunds the debit; a missing or higher estimate blocks further calls. Brave uses only the fixed Search GET endpoint, five results, and a 5,000 micro-USD debit. Both require current owner-reviewed free account facts because a general search key does not provide an authoritative free-balance/payment preflight. Price changes require new review; no additional account-management credential is requested automatically.

Budgets, baselines and holds are durable and separate from OpenAI token pools. Requests are reserved atomically before dispatch; an existing month's budget cannot be reset, raised or rebased through a new draft. At the next month, search stops until a fresh free allowance and baseline are reviewed. It never assumes that a provider renewed credits or reset them at the local clock's midnight. Changing account settings outside the harness can invalidate the reviewed facts; disable/review the provider first.

## An uncertain tool request

`tools status` identifies a blocked provider and its held request. No automatic retry, paid fallback or estimated refund occurs. If completion is still unknown, leave it blocked. Once the owner has verified the request finished, close the API session and use:

```sh
codex-api tools resolve REQUEST_ID --reviewed-complete --reference "non-secret completion reference"
```

This retains the **entire** conservative debit and clears only that provider's unfinished-request block. It refunds nothing, makes no provider call, and preserves model usage. Repeating it cannot create credit. It is not a way to declare an ongoing request finished. Model reservations still use `codex-api reconcile`.

Shared clients retain local file search. Search and host fetch remain disabled in shared mode; a member cannot spend a coordinator's search account through an independent ledger. Media and arbitrary third-party MCP servers remain disabled. See [MEDIA.md](MEDIA.md) for the local alternatives reviewed for future adapters.

## Sources checked on 2026-10-23

- [Tavily pricing](https://www.tavily.com/pricing), [credits](https://docs.tavily.com/documentation/api-credits), [usage response](https://docs.tavily.com/documentation/api-reference/endpoint/usage): Researcher credits are separate from PAYGO; account facts still need verification.
- [Exa pricing](https://exa.ai/pricing), [search](https://exa.ai/docs/reference/search), [team key usage](https://exa.ai/docs/reference/team-management/get-api-key-usage): Starter credit, lite parameters and the limits of ordinary-key usage reporting.
- [Brave billing FAQ](https://api-dashboard.search.brave.com/documentation/resources/help-feedback): prepaid/postpaid distinction, free plan credit, automatic reload and temporary card authorization.
- [Codex managed MCP identity](https://learn.chatgpt.com/docs/enterprise/managed-configuration): full executable/argument matching; command-only matching is insufficient.
- [MCP security guidance](https://modelcontextprotocol.io/specification/latest/basic/security_best_practices): local server execution and SSRF require controls beyond a tool description or origin list.
