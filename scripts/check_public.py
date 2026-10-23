#!/usr/bin/env python3
"""Check the exact tracked release surface without opening any private key file."""
from pathlib import Path
import re
import json
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
FORBIDDEN_NAMES={'settings.json','verification.json','readiness.json','installation.json','gateway.token','auth.json','openai-key.env','search-keys.env','docker-login.env',
                 'controls.json','controls-draft.json','controls-stop.json','active-run.json','checkpoint-pending.json',
                 'policy-draft.json','policy-pending.json','policy-render-pending.json','policy.json','team-policy.json','runtime-acceptance.json','protocol-acceptance.json','team-client.json','protected-paths.json','ledger-witness.json','upgrade-pending.json','last-key-rotation.json','authorized_keys','sshd_config'}
PATTERNS={
    'host home path':rb'/(?:Users|home)/[A-Za-z0-9_.-]+/',
    'OpenAI key':rb'\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{28,}',
    'GitHub token':rb'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})',
    'Tavily key':rb'\btvly-[A-Za-z0-9_-]{24,}',
    'private key':rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    'account identifier':rb'\b(?:org-|proj_)[A-Za-z0-9]{16,}',
    'email address':rb'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
}


def check(paths,blobs=None):
    failures=[]
    for path in paths:
        relative=path.relative_to(ROOT)
        if path.is_symlink() or path.name in FORBIDDEN_NAMES or path.name.startswith(('team-known-hosts','team-tunnel.key')) or path.suffix in {'.log','.env','.sqlite3','.pem','.p12','.pfx','.key','.sock'} or any(p in {'state','backups','vendor','__pycache__','team','guest-state','extensions','releases','upgrades','checkpoints'} for p in relative.parts):
            failures.append((str(relative),'runtime, private, binary or linked artifact'));continue
        data=blobs[str(relative)] if blobs is not None else path.read_bytes()
        if str(relative)=='kit/runtime-policy.json':
            try:
                empty=json.loads(data)
                if empty!={'version':1,'reset':'daily_utc','safety_margin_percent':5,'warning_percent':90,'pools':{},'models':{},'defaults':{}}:failures.append((str(relative),'installed owner policy in public template'))
            except (ValueError,UnicodeError):failures.append((str(relative),'invalid empty policy template'))
        if b'\x00' in data:failures.append((str(relative),'binary artifact'));continue
        # /home/agent is the public fixed guest home, not a host identity.
        scanned=data.replace(b'/home/agent/',b'/guest/')
        for label,pattern in PATTERNS.items():
            matches=list(re.finditer(pattern,scanned))
            if label=='email address':
                matches=[m for m in matches if m.group().rsplit(b'@',1)[1] not in {b'example.com',b'example.org',b'example.invalid'}]
            if matches:failures.append((str(relative),label))
    return failures


if __name__=='__main__':
    if subprocess.run(['git','diff','--quiet'],cwd=ROOT).returncode:
        raise SystemExit('Unstaged tracked changes exist. Stage the exact intended source before scanning.')
    listing=subprocess.check_output(['git','ls-files','--stage','-z'],cwd=ROOT).decode().split('\0')
    paths=[];blobs={}
    for record in listing:
        if not record:continue
        info,name=record.split('\t',1);mode,sha,stage=info.split()
        if stage!='0' or mode not in {'100644','100755'}:raise SystemExit('Unsupported linked or conflicted index entry: '+name)
        paths.append(ROOT/name)
        blobs[name]=subprocess.check_output(['git','cat-file','blob',sha],cwd=ROOT)
    if not paths:raise SystemExit('No tracked files; stage the intended public files first.')
    failures=check(paths,blobs)
    for name,kind in failures:print(name+': '+kind,file=sys.stderr)
    if failures:raise SystemExit(1)
    print('Public surface checked: '+str(len(paths))+' text files; no matching credential, account, email, host-path or runtime artifacts.')
