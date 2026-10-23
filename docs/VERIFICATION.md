# Release verification

Release 0.4.0, checked 2026-10-23. Supported integration target: macOS Apple Silicon, Python 3.11.8+, Docker Sandboxes 0.49.1, Codex CLI 0.162.1, and Playwright CLI 0.1.22. Portable Linux tests do not establish native Linux installation support.

| Check | Scope |
| --- | --- |
| Portable regression | 431 tests passed for this release; `python3 scripts/check.py` uses fake providers and loopback only |
| Request observations | Content-free input/cache/output/reasoning records; explicit missing counters; read-only pool decomposition; member-scoped reports |
| Optional controls | Full-request run reservations, same-error acknowledgement, storage floor, expiring integer USD prices, atomic concurrent reservations, prior-use baselines, unknown cross-period holds and cost discrepancy stops |
| Control changes | Unfinished requests prevent changed controls; deleted approvals cannot bypass enforcement or permit rollback to an unaware guard |
| Local recovery | Named-pool reconciliation, retained count charges, native API session inventory without index repair, checksummed text checkpoints, modes, conflicts and interrupted-restore recovery |
| Reviewed skills | Offline content-free source/rule-bound findings and acknowledgement; no cloud scan or capability expansion |
| Native helpers | Host output run/show/remove; failure exit status and retained tail; host/guest report round trip; native session listing and two English guest usage lines |
| Maintenance preferences | Sandboxed helper commands construct protected policy without rewriting saved interface preferences |
| Shared shutdown | Owned-child fallback when its process group is missing; bounded explicit failure; coordinator ledger closes even if tunnel cleanup fails |
| Patch regression | Unsupported compatibility efforts, all ASCII control characters in pool labels, mixed shared baseline flags, allocation diagnostics, host rejection codes, subscription baseline warnings, and successful/failed upgrade preparation |
| Account-specific policy | Empty new installs; one or three pools; owner-reviewed model IDs; limits above the old reference caps; margin and warning validation |
| Unified validation | Model, reasoning, context/output cap and tier checked together; catalog/defaults/guest contract agree; unknown fields, tiers and mismatched capabilities rejected |
| Native speed tiers | Actual pinned CLI completed local tool calls through the gateway with Standard, Fast, Flex and Ultrafast using one selected model and a fake provider; selected wire tier checked |
| Native isolation | Pinned image rebuild; filesystem masks, write-through, absent host credentials, blocked destinations and permitted dependency sources |
| State-preserving changes | Ledger identity, baselines, spent tokens and request rows preserved; active sessions, uncertain usage, pool removal and historical model reassignment rejected |
| Interrupted changes | Failure after budget commit and during partial guest rendering; exact replay preserves usage and restores consistent policy; changed inputs fail closed |
| Shared policy | Arbitrary named pools enforce organization/project/member caps together; normalized defaults, transfers, requests and digest-bound invitations |
| Shared transport | Actual restricted SSH pairing/relay, credential rotation, cancellation and rejection of shell/SFTP/other TCP/reverse/Unix-socket forwarding |
| UTC accounting | Configured lifetime-plus-15-second overlap, late/unknown settlement, provider clock evidence and 00:00:15 admission guard |
| Recovery and rollback | Reconciliation uses the selected pools/deadline; old code cannot ignore a generalized policy or shared state; no old ledger restoration |
| Legacy compatibility | Read-only interpretation of pre-0.3 model/group/tier settings; two English usage lines retained; legacy launchers recognize the new policy command without replacement |
| Publication | Exact staged surface and Git history scanned; empty source policy required; installed policy/keys/runtime artifacts excluded |

The four-tier native checks were run for 0.3.0 using a separate temporary installation, workspace, port, and owned sandbox. Version 0.4.0 also completed an independent native rebuild and the helper checks above, then removed its owned temporary sandbox. Keys and accounts were synthetic. Preparation repeats isolation and offline protocol acceptance, including output-storage writability and read-only API session inventory. No real model, exact-count, or search request is required. A fake-provider pass establishes the local CLI and gateway protocol. It does not prove actual model access, project tier permission, pricing, or complimentary eligibility.

The compatibility effort subset was checked against the official model pages for [6 Astra](https://developers.openai.com/api/docs/models/gpt-6-astra), [6.1 Sol](https://developers.openai.com/api/docs/models/gpt-6.1-sol), [6 Luna](https://developers.openai.com/api/docs/models/gpt-6-luna), [5.6 Terra](https://developers.openai.com/api/docs/models/gpt-5.6-terra), and [5.6 Luna](https://developers.openai.com/api/docs/models/gpt-5.6-luna). Runtime pins and catalog entries do not establish an account's entitlement.

The earlier 0.2 integration also verified native reviewed skills, adversarial project configuration, original-session resume and idle Ctrl+C cleanup. Those regressions remain covered by the suite; release upgrades still run local preparation before a user resumes work.

Free-only eligibility remains unconfirmed and requests stay blocked by default. The harness cannot fence unrelated organization callers, guarantee arbitrary extension behavior, or defend against a hostile guest root. See [BOUNDARIES.md](BOUNDARIES.md). CI runs portable tests/publication checks; `codex-api prepare` performs the supported-platform image and local-tool acceptance.
