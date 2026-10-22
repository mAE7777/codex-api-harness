# Release verification

Release 0.2.0, checked 2026-10-22.

**Supported integration target:** macOS on Apple Silicon; Docker Sandboxes 0.49.1; Codex CLI 0.162.1; Playwright CLI 0.1.22. Python regression tests also run on Linux CI; that does not establish Linux installer support.

| Check | Result |
|---|---|
| Complete frozen distribution | 354 tests passed from the exact read-only staged candidate |
| Atomic shared admission | Organization, project and member ceilings; concurrent requests, restart, allocations, transfers and repeated approval covered |
| UTC accounting | 615-second conservative overlap, rejected attempts, late settlement, manual reconciliation and 15-second reset guard covered |
| Clock evidence | Missing, malformed, stale and future count-response dates stop inference; no extra provider call |
| Streaming accounting | Terminal success waits for consistent usage and clean EOF; conflict/cancellation/truncation preserve holds; evidence-bound recovery covered |
| Real restricted SSH | Native forwarding works; shell, SFTP, other TCP destinations, reverse TCP, Unix sockets, reverse Unix sockets and changed host keys rejected |
| Remote client | Actual local SSH pairing and relay with fake provider; owned ephemeral tunnels, busy-port protection, credential rotation and cancellation covered |
| Reviewed skills | Immutable snapshots, unsupported plugin capabilities, links, modifications, digest approval and session leases covered |
| Native managed skill | Actual pinned CLI loaded the reviewed catalog and read its skill through a local tool against a fake provider |
| Final native rebuild and resume | Passed: selected API history restored automatically; actual CLI resumed the original thread and included its earlier synthetic prompt |
| Native baseline isolation | Full pinned image rebuild and fake CLI/local-tool acceptance passed, including filesystem, credential and network checks |
| Daily interactive use | Real launcher opened; picker showed exactly five models; guest usage printed two English lines; idle Ctrl+C exited and stopped the dedicated environment |
| Adversarial native project config | Passed: provider/model/catalog, developer instructions, skill discovery, feature, MCP, hook and notification overrides failed; actual local tool could not read a new sensitive-file canary |
| Updates and recovery | Candidate renderer, clean environment, retained guest policy, mask-only edits, interrupted activation, rollback and unchanged private accounting covered |
| Publication surface and history | 66 public text files passed the staged-surface check; independent source and Git-history credential scans found no matches |

The native tests use a separate temporary installation, launcher, port, workspace and sandbox. Existing subscription configuration and the maintainer's installed personal API environment are preserved. Provider keys, conversations and account IDs in acceptance fixtures are synthetic. No real model, exact-count or search-provider requests are used for release acceptance.

Free-only eligibility remains unconfirmed and requests stay blocked by default. The suite does not prove a universal complimentary allowance, prevent independent organization callers, or certify arbitrary skill/code behavior. The material limits are documented in [BOUNDARIES.md](BOUNDARIES.md). CI runs portable regression and publication checks; the complete image/VM acceptance is a separate supported-platform check performed by `codex-api prepare`.
