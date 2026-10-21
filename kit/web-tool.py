#!/usr/bin/env python3
"""Guest-side helper: no provider credentials or arbitrary destinations."""
import argparse
import json
import os
import urllib.request
import urllib.error

parser = argparse.ArgumentParser()
parser.add_argument("operation", choices=["search", "extract"])
parser.add_argument("value")
parser.add_argument("--provider", choices=["tavily", "exa"], default="tavily")
args = parser.parse_args()
token = os.environ.get("CODEX_GATEWAY_TOKEN", "")
if not token: raise SystemExit("Gateway credential unavailable; request stopped")
payload = {"provider": args.provider, "query" if args.operation == "search" else "url": args.value}
request = urllib.request.Request(
    "http://host.docker.internal:49187/tools/" + args.operation,
    data=json.dumps(payload).encode(),
    headers={"Content-Type": "application/json", "Authorization": "Bearer " + token},
    method="POST")
try:
    with urllib.request.urlopen(request, timeout=45) as response:
        print(response.read(512_001).decode())
except urllib.error.HTTPError as error:
    print(error.read(4096).decode())
    raise SystemExit(1)
