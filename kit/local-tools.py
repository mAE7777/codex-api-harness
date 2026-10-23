#!/usr/bin/env python3
"""Optional guest-only output filtering. No hooks or model traffic rewriting."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

MAX_BYTES=8*1024*1024
MAX_FILES=16


def location():
    if os.environ.get('IS_SANDBOX')!='1' or os.environ.get('CODEX_HOME')!='/home/agent/.codex-api':raise ValueError('Output tools run only in the dedicated API sandbox.')
    # Native workspace permissions intentionally keep CODEX_HOME read-only.
    # Optional tool records belong in the guest's writable temporary storage.
    path=Path('/tmp/codex-api-output')
    if path.is_symlink():raise ValueError('Output storage must not be linked.')
    path.mkdir(mode=0o700,parents=True,exist_ok=True)
    info=path.stat()
    if info.st_uid!=os.getuid() or info.st_mode&0o077:raise ValueError('Output storage must be owner-only.')
    return path


def clean_text(raw):
    text=raw.decode('utf-8',errors='replace')
    # Remove terminal control sequences before showing command-controlled text.
    text=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',text)
    text=''.join(c for c in text if c in '\n\t' or 32<=ord(c)<127 or ord(c)>=160)
    return text


def summarize(raw,code,truncated=False):
    text=clean_text(raw)
    lines=text.splitlines()
    if len(lines)<=80:return text
    if code:
        chosen=lines[-160:]
    else:
        important=[line for line in lines if re.search(r'(?i)error|fail|warn|passed|tests?\b|summary',line)]
        chosen=important[:20]+lines[-40:]
    return ('[Output summarized; use output show for the retained original.]\n'+
            ('[Original exceeded 8 MiB; only its tail was retained.]\n' if truncated else '')+'\n'.join(chosen))


def native_sessions():
    if os.environ.get('IS_SANDBOX')!='1' or os.environ.get('CODEX_HOME')!='/home/agent/.codex-api':raise ValueError('Native session inspection requires the API sandbox.')
    home=Path(os.environ['CODEX_HOME']);found={};visited=0;skipped=0
    if home.is_symlink():raise ValueError('API session home must not be linked.')
    pending=[(home/name,0) for name in ('sessions','archived_sessions') if (home/name).exists()]
    while pending:
        folder,depth=pending.pop()
        if folder.is_symlink():raise ValueError('Session directories must not be linked.')
        if depth>8:skipped+=1;continue
        with os.scandir(folder) as entries:
            for entry in entries:
                visited+=1
                if visited>4096:raise ValueError('API session inventory exceeds 4096 entries; no index was repaired.')
                if entry.is_symlink():skipped+=1;continue
                if entry.is_dir(follow_symlinks=False):pending.append((Path(entry.path),depth+1));continue
                if not entry.name.endswith('.jsonl'):skipped+=1;continue
                fd=os.open(entry.path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                with os.fdopen(fd,'rb') as src:
                    import stat
                    info=os.fstat(src.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise ValueError('Unsafe API session file.')
                    first=src.readline(65537)
                if len(first)>65536:skipped+=1;continue
                try:
                    record=json.loads(first);payload=record.get('payload',{});identity=payload.get('id')
                    if record.get('type')!='session_meta' or not isinstance(identity,str) or not re.fullmatch(r'[a-f0-9-]{36}',identity):raise ValueError()
                    found[identity]={'session_id':identity,'modified_at':info.st_mtime}
                except (ValueError,TypeError,AttributeError):skipped+=1
    return {'sessions':sorted(found.values(),key=lambda r:r['modified_at'],reverse=True)[:40],
            'skipped_or_compressed':skipped,'provider_requests':0,'index_modified':False,
            'next_step':'Resume a listed session with codex-api resume SESSION_ID in the host terminal. Wrapper run IDs are different.'}


def main(args):
    parser=argparse.ArgumentParser(prog='codex-api output')
    sub=parser.add_subparsers(dest='action',required=True)
    run=sub.add_parser('run');run.add_argument('command',nargs=argparse.REMAINDER)
    for name in ('show','remove'):
        p=sub.add_parser(name);p.add_argument('id')
        if name=='show':p.add_argument('--full',action='store_true')
    options=parser.parse_args(args);root=location()
    if options.action!='run':
        if not re.fullmatch(r'[a-f0-9]{32}',options.id):raise ValueError('Use a complete output record ID.')
        path=root/(options.id+'.bin')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as src:
            import stat
            info=os.fstat(src.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>MAX_BYTES:raise ValueError('Unsafe output record.')
            data=src.read(MAX_BYTES+1)
        if options.action=='remove':path.unlink();print('Owned output record removed.');return 0
        print(clean_text(data) if options.full else '\n'.join(clean_text(data).splitlines()[-160:]))
        if not options.full:print('Showing the retained tail; use --full for the complete retained record.')
        return 0
    command=options.command[1:] if options.command[:1]==['--'] else options.command
    if not command:parser.error('Provide a command after --.')
    if len(list(root.iterdir()))>=MAX_FILES:raise ValueError('Output storage has 16 records. Remove an owned record explicitly before recording more.')
    identity=uuid.uuid4().hex;path=root/(identity+'.bin')
    code=1;tail=bytearray();truncated=False
    child=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env=os.environ.copy())
    try:
        while True:
            block=child.stdout.read(65536)
            if not block:break
            tail.extend(block)
            if len(tail)>MAX_BYTES:del tail[:-MAX_BYTES];truncated=True
        code=child.wait()
    except BaseException:
        child.terminate()
        try:child.wait(timeout=3)
        except subprocess.TimeoutExpired:child.kill();child.wait()
        raise
    finally:
        child.stdout.close()
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as dest:dest.write(tail)
    print(summarize(tail,code,truncated));print('Exit: '+str(code)+' | retained output: '+identity)
    if code:
        hosts=set(re.findall(r'https?://(?:[^/@\s]+@)?([A-Za-z0-9.-]+)',tail.decode('utf-8',errors='replace')))
        unapproved=sorted(hosts-{'registry.npmjs.org','pypi.org','files.pythonhosted.org','localhost','127.0.0.1','host.docker.internal'})[:10]
        if unapproved:print('Unapproved hosts mentioned: '+', '.join(unapproved)+'. Runtime dependency sources are npm and PyPI only; host credentials were not imported.')
    return code if code>=0 else 128-code


if __name__=='__main__':
    try:raise SystemExit(main(sys.argv[2:] if sys.argv[1:2]==['output'] else sys.argv[1:]))
    except (ValueError,OSError) as error:print(str(error),file=sys.stderr);raise SystemExit(1)
