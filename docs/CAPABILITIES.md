# Capability contract

This release supports macOS Apple Silicon, Python 3.11.8+, Docker Sandboxes 0.49.1, Codex CLI 0.162.1 and Playwright CLI 0.1.22. A new native runtime requires separate compatibility review.

| Capability | Status | Boundary |
|---|---|---|
| Five-model picker, reasoning/UI preferences, API resume | Supported | Protected policy overrides preferences |
| Shell, patches, Code Mode and local Playwright | Supported | One original project mount; restricted runtime network |
| Exact count, input + maximum output reservation | Supported | Unknown terminal usage keeps the full hold |
| Two-line English usage; 90% daily group notice | Supported | Warnings do not authorize requests |
| Multiple members in one project or different projects | Optional | One authoritative organization coordinator |
| Shared project cap, member cap, temporary transfer | Optional | Atomic accounting; used/reserved tokens cannot transfer |
| Quota request and owner approval | Optional | No automatic budget increase; repeated approval is idempotent |
| Restricted encrypted member tunnel | Optional | Dedicated host-side service; no shell/subsystem/other forwarding |
| Reviewed standalone skills and skill-only plugin bundles | Optional | Exact digest; explicit invocation by default; scripts need review |
| Native plugin marketplace, MCP, apps and plugin hooks | Blocked | Bundle capabilities require dedicated adapters |
| Native multi-agent delegation | Blocked | Feature stays pinned off; shared mode supports separate human members |
| Existing subscription/home credentials, browser, host skills | Blocked | Never inherited or imported |
| OpenAI hosted search/execution/storage/MCP | Blocked | Both client configuration and request schema reject them |
| Image/video generation, speech/transcription | Blocked | No endpoint, credential or fallback supplied |
| Brave search | Unsupported | No active adapter |
| Exa/Tavily | Disabled by default | Personal-only adapters require fresh account/payment evidence |
| Universal free API entitlement | Unconfirmed | Free-only blocks count/inference until proven |
| Native CLI transparent retry deduplication | Unconfirmed | Explicit operation IDs supported; no prompt-hash deduplication |
| Real-time authoritative OpenAI Usage/Costs reconciliation | Unsupported | Aggregated account data cannot authorize the next request |
| Continuous secret filtering / hostile in-VM root defense | Unsupported | Keep actual secrets outside the project |
| Code updates and rollback | Supported | Reviewed generation switch; permanent usage never rolls back |
| Full Linux/Windows installation | Unsupported | Portable tests do not establish native integration |

Unknown routes, tool types, service tiers and request fields fail closed. Errors identify the reason; `codex-api explain CODE` gives a next step. A blocked capability is never enabled by a skill instruction or a request parameter.

## Design references

OpenAI's [spending-controller guidance](https://developers.openai.com/cookbook/articles/per_run_spending_controller_responses_api) supports atomic shared reservation and conservative uncertain usage. Its [organization Usage API](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/usage/methods/completions) provides grouped account reporting, not an admission completeness guarantee. These are independent of complimentary eligibility.

[Cycles](https://github.com/runcycles/cycles-protocol) informed hierarchical atomic budgets and explicit operation identity. [OCTG](https://github.com/yohi/octg) informed conservative accounting/recovery; [Prodex](https://github.com/christiandoxa/prodex) informed diagnostics and capability boundaries. These are references, not runtime dependencies or security certifications. No third-party code from those projects is bundled.
