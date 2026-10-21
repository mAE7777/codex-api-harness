#!/usr/bin/env python3
"""Guest read-only command. No provider keys, model calls, or lifecycle access."""
import json
import os
import sys
import urllib.error
import urllib.request


def main(args):
    if args not in ([], ['usage'], ['usage','--json'], ['help'], ['--help']):
        print('Guest command supports: codex-api usage [--json]. Use the host terminal for maintenance.', file=sys.stderr)
        return 2
    if args in (['help'], ['--help']):
        print('codex-api usage [--json] — read local daily quota without a model request.')
        return 0
    token = os.environ.get('CODEX_GATEWAY_TOKEN', '')
    if not token:
        print('API Codex quota: gateway credential is unavailable.', file=sys.stderr); return 1
    request = urllib.request.Request('http://host.docker.internal:49187/v1/quota', headers={'Authorization':'Bearer '+token})
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=3) as response:
            data = response.read(32769)
        if len(data) > 32768: raise ValueError()
        result = json.loads(data)
        lines = result['usage_lines']
        if len(lines) != 2 or not all(isinstance(line,str) and line.isascii() and '\n' not in line and '\r' not in line for line in lines): raise ValueError()
        if not lines[0].startswith('A (') or not lines[1].startswith('B ('): raise ValueError()
        print(json.dumps(result, indent=2) if '--json' in args else '\n'.join(lines))
        return 0
    except (OSError, ValueError, KeyError, TypeError, urllib.error.URLError):
        print('API Codex quota: local gateway is unavailable; check codex-api doctor in the host terminal.', file=sys.stderr)
        return 1


if __name__ == '__main__': raise SystemExit(main(sys.argv[1:]))
