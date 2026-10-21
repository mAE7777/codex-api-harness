#!/bin/sh
set -eu
umask 077
test "${IS_SANDBOX:-}" = 1 || { echo 'API Codex requires the dedicated sandbox.' >&2; exit 1; }
test -n "${CODEX_GATEWAY_TOKEN:-}" || { echo 'Gateway credential missing; startup stopped.' >&2; exit 1; }
test "${CODEX_HOME:-}" = /home/agent/.codex-api || exit 1
test -n "${WORKSPACE_DIR:-}" || { echo 'Workspace binding missing.' >&2; exit 1; }
test "$(realpath "$WORKSPACE_DIR")" = __WORKSPACE_SHELL__ || { echo 'Unexpected workspace binding.' >&2; exit 1; }
test ! -e "$CODEX_HOME/auth.json" || { echo 'Unexpected login state; startup stopped.' >&2; exit 1; }
mkdir -p "$CODEX_HOME"
cd "$WORKSPACE_DIR"
exec env -i HOME=/home/agent USER=agent LOGNAME=agent \
  PATH="$PATH" TERM="${TERM:-xterm-256color}" LANG=C.UTF-8 \
  IS_SANDBOX=1 CODEX_HOME="$CODEX_HOME" WORKSPACE_DIR="$WORKSPACE_DIR" \
  CODEX_GATEWAY_TOKEN="$CODEX_GATEWAY_TOKEN" GIT_TERMINAL_PROMPT=0 \
  HTTP_PROXY="${HTTP_PROXY:-}" HTTPS_PROXY="${HTTPS_PROXY:-}" ALL_PROXY="${ALL_PROXY:-}" \
  NO_PROXY="${NO_PROXY:-}" SSL_CERT_FILE="${SSL_CERT_FILE:-/etc/ssl/certs/ca-certificates.crt}" \
  NODE_EXTRA_CA_CERTS="${NODE_EXTRA_CA_CERTS:-/etc/ssl/certs/ca-certificates.crt}" \
  NPM_CONFIG_USERCONFIG=/etc/codex-api/npmrc \
  NPM_CONFIG_REGISTRY=https://registry.npmjs.org/ NPM_CONFIG_AUDIT=false \
  NPM_CONFIG_FUND=false NPM_CONFIG_UPDATE_NOTIFIER=false \
  NPM_CONFIG_CACHE=/tmp/codex-api-cache/npm \
  PIP_CONFIG_FILE=/dev/null PIP_INDEX_URL=https://pypi.org/simple \
  PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1 \
  PIP_CERT="${SSL_CERT_FILE:-/etc/ssl/certs/ca-certificates.crt}" \
  REQUESTS_CA_BUNDLE="${SSL_CERT_FILE:-/etc/ssl/certs/ca-certificates.crt}" \
  PIP_CACHE_DIR=/tmp/codex-api-cache/pip \
  UV_DEFAULT_INDEX=https://pypi.org/simple UV_PYTHON_DOWNLOADS=never \
  UV_CACHE_DIR=/tmp/codex-api-cache/uv \
  python3 -I /etc/codex-api/preferences.py "$@"
