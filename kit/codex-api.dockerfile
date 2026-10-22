FROM dhi.io/debian-base:trixie-dev@sha256:9b025768946856e44f9775005eb199f2e1820484ea27bb5c8bcbb187b80464dc AS codex
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates
RUN set -eu; \
    release=https://github.com/openai/codex/releases/download/rust-v0.162.1; \
    asset=codex-package-aarch64-unknown-linux-musl.tar.gz; \
    mkdir -p /tmp/release /out/opt/codex /out/usr/local/bin; \
    cd /tmp/release; \
    curl -fsSLO "$release/$asset"; \
    curl -fsSLO "$release/codex-package_SHA256SUMS"; \
    grep "  $asset\$" codex-package_SHA256SUMS | sha256sum -c -; \
    tar -xzf "$asset" -C /out/opt/codex; \
    ln -s /opt/codex/bin/codex /out/usr/local/bin/codex; \
    chown -R 0:0 /out; \
    grep -q '"version": "0.162.1"' /out/opt/codex/codex-package.json

FROM dhi.io/sbx-templates:codex-docker@sha256:a5cefde0c07f0834e77c733436e611e8984b4f7a65803ea10a5024c25587d128
RUN npm uninstall -g --no-fund --no-audit @openai/codex \
    && npm install -g --no-fund --no-audit @playwright/cli@0.1.22
USER root
COPY --from=codex /out/ /
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && test "$(command -v codex)" = /usr/local/bin/codex \
    && scratch=$(mktemp -d) \
    && CODEX_HOME="$scratch" codex --version | grep -q '0.162.1' \
    && rm -rf "$scratch" \
    && pwcli=$(node -e 'process.stdout.write(require.resolve("playwright/package.json",{paths:["/usr/local/share/npm-global/lib/node_modules/@playwright/cli"]}).replace(/package\.json$/, "cli.js"))') \
    && node "$pwcli" install-deps chromium
USER agent
RUN pwcli=$(node -e 'process.stdout.write(require.resolve("playwright/package.json",{paths:["/usr/local/share/npm-global/lib/node_modules/@playwright/cli"]}).replace(/package\.json$/, "cli.js"))') \
    && node "$pwcli" install chromium \
    && playwright-cli --version | grep -q '0.1.22'
USER root
COPY config.toml models.json runtime-policy.json /etc/codex-api/
COPY preferences.py /etc/codex-api/preferences.py
COPY extensions /etc/codex-api/extensions/
COPY requirements.toml /etc/codex/requirements.toml
COPY quota-notice.py npmrc /etc/codex-api/
COPY workspace /etc/codex-api/workspace
COPY quota-client.py /usr/local/bin/codex-api
COPY entrypoint.sh /usr/local/bin/codex-api-entrypoint
COPY web-tool.py /usr/local/bin/web-tool
RUN find /etc/codex-api -maxdepth 1 -type f -exec chmod 0644 {} + \
    && chmod 0644 /etc/codex/requirements.toml \
    && find /etc/codex-api/extensions -type d -exec chmod 0755 {} + \
    && find /etc/codex-api/extensions -type f -exec chmod 0444 {} + \
    && chmod 0755 /usr/local/bin/codex-api-entrypoint /usr/local/bin/web-tool /usr/local/bin/codex-api
USER agent
ENV IS_SANDBOX=1 CODEX_HOME=/home/agent/.codex-api GIT_TERMINAL_PROMPT=0
WORKDIR /home/agent/workspace
ENTRYPOINT ["/usr/local/bin/codex-api-entrypoint"]
