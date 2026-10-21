# Third-party tools

This repository contains harness source, minimal model metadata, and build recipes. It does not redistribute Docker/Codex binaries, browser bundles, account exports or server-provided model instructions.

Downloaded at setup/build time:

| Component | Pinned version | Upstream |
|---|---|---|
| Docker Sandboxes | 0.49.1 | https://github.com/docker/sbx-releases |
| Codex CLI | 0.162.1 | https://github.com/openai/codex |
| Playwright CLI | 0.1.22 | https://github.com/microsoft/playwright-cli |
| Base images | Digests in the Dockerfile | https://dhi.io |

Each component retains its own license, notices and terms. The MIT license here covers this harness, not vendor services or their usage fees. The model catalog uses the public pinned Codex schema; it does not establish current availability or entitlement. Distribution archives are checksum-verified before extraction. The macOS bootstrap also checks its signature.

OS packages and the browser installed by Playwright have their own dependency trees. Base image digests and CLI versions are pinned; distribution package repositories remain build-time update sources, so builds are not byte-for-byte reproducible. Runtime package access is narrower than build-time access. Maintain security updates deliberately.
