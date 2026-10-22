#!/usr/bin/env python3
"""Managed UI-only notice. Discard hook input; send no prompt or tool data."""
import json
import os
import sys
import urllib.request


def main():
    # Drain the input pipe, without logging, persisting, or forwarding its data.
    total=0
    while True:
        chunk=sys.stdin.buffer.read(65536)
        if not chunk:break
        total+=len(chunk)
        if total>16_000_000:return 0
    token=os.environ.get('CODEX_GATEWAY_TOKEN','')
    # codex exec --json currently discards informational hook warnings. Leave
    # those pending for the host launcher's stderr or the next interactive UI.
    if not token or os.environ.get('CODEX_API_INTERACTIVE')!='1':return 0
    request=urllib.request.Request('http://host.docker.internal:49187/v1/notices/claim',data=b'{}',
        headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'},method='POST')
    try:
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request,timeout=.6) as response:data=response.read(16385)
        if len(data)>16384:return 0
        notices=json.loads(data).get('notices',[])
        if not isinstance(notices,list) or len(notices)>8:return 0
        messages=[n.get('message') for n in notices if isinstance(n,dict)]
        if len(messages)!=len(notices) or not all(isinstance(m,str) and m.isascii() and len(m)<=512 and m.startswith('API quota warning - Group ') and not any(ord(c)<32 for c in m) for m in messages):return 0
        if messages:print(json.dumps({'systemMessage':'\n'.join(messages)}),flush=True)
    except (OSError,ValueError,TypeError,AttributeError):pass
    # Informational only: failures never gate startup, tools, or model inference.
    return 0


if __name__=='__main__':raise SystemExit(main())
