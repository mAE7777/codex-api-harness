"""Explicit bounded text-file undo. Never touch Git or restore API accounting."""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

from guard import Denied, atomic_json, canonical
from policy import read_json
from workspace_policy import protected_name, protected_paths, validate_protected_paths
from extensions import _directory, SECRET

MAX_FILE=2*1024*1024
MAX_TOTAL=16*1024*1024


def fail(message):raise Denied(message,code='checkpoint_review_required')
def digest(data):return hashlib.sha256(data).hexdigest() if data is not None else None


def mode(workspace,parts):
    parent=_directory(Path(workspace).joinpath(*parts[:-1]))
    try:
        try:info=os.stat(parts[-1],dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError:return None
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:fail('File permissions cannot be read safely.')
        return stat.S_IMODE(info.st_mode)&0o777
    finally:os.close(parent)


def relative(root, value):
    validate_protected_paths([value])
    parts=value.split('/')
    if any(protected_name(p) or p.lower() in {'.git','.codex','.agents','.claude','node_modules'} for p in parts):fail('Credential, configuration and dependency paths cannot be checkpointed.')
    if any(value==p or value.startswith(p+'/') for p in protected_paths(root)):fail('Owner-protected paths cannot be checkpointed.')
    return parts


def read(workspace, parts):
    parent=_directory(Path(workspace).joinpath(*parts[:-1]))
    try:
        try:fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        except FileNotFoundError:return None
        with os.fdopen(fd,'rb') as source:
            before=os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>MAX_FILE:fail('Checkpoint files must be ordinary unlinked text files of at most 2 MiB.')
            data=source.read(MAX_FILE+1);after=os.fstat(source.fileno())
            if (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns) or len(data)>MAX_FILE:fail('A file changed during checkpoint inspection.')
        try:text=data.decode('utf-8')
        except UnicodeError:fail('Checkpoint supports explicit UTF-8 text files only.')
        if '\x00' in text or SECRET.search(text) or re.search(r'\b(?:tvly-|ghp_)[A-Za-z0-9_-]{20,}',text):fail('Possible secret detected; no file contents were printed or copied.')
        return data
    finally:os.close(parent)


def directory(root):
    path=Path(root)/'checkpoints'
    if path.is_symlink():fail('Unsafe private checkpoint storage.')
    path.mkdir(mode=0o700,exist_ok=True)
    if path.stat().st_mode&0o077:fail('Checkpoint storage must be owner-only.')
    return path


def create(root,workspace,paths):
    if not 1<=len(paths)<=64 or len(set(paths))!=len(paths):fail('Choose one to 64 distinct explicit file paths.')
    target=directory(root)
    if len(list(target.glob('*.json')))>=16:fail('Checkpoint storage has 16 snapshots. Remove one explicitly before creating another.')
    files={};modes={};total=0
    for path in paths:
        data=read(workspace,relative(root,path))
        if data is None:fail('A selected file is missing; nothing was checkpointed.')
        total+=len(data)
        if total>MAX_TOTAL:fail('Checkpoint exceeds its 16 MiB total limit.')
        files[path]=base64.b64encode(data).decode()
        modes[path]=mode(workspace,relative(root,path))
    identity=uuid.uuid4().hex
    value={'version':1,'workspace':str(Path(workspace).resolve()),'files':files,'modes':modes}
    value['checksum']=digest(canonical(value));atomic_json(target/(identity+'.json'),value)
    return {'id':identity,'files':list(files),'warning':'Explicit private copies; not continuous backup or secret-content certification.'}


def load(root,workspace,identity):
    if not re.fullmatch(r'[a-f0-9]{32}',identity):fail('Use a complete checkpoint ID.')
    row=read_json(directory(root)/(identity+'.json'),private=True,maximum=24*1024*1024)
    if not isinstance(row,dict) or set(row)!={'version','workspace','files','modes','checksum'} or row['version']!=1 or row['workspace']!=str(Path(workspace).resolve()) or not isinstance(row['files'],dict) or not 1<=len(row['files'])<=64:fail('Checkpoint identity or workspace binding changed.')
    if row['checksum']!=digest(canonical({k:v for k,v in row.items() if k!='checksum'})):fail('Checkpoint checksum changed.')
    if not isinstance(row['modes'],dict) or set(row['modes'])!=set(row['files']) or any(type(m) is not int or not 0<=m<=0o777 for m in row['modes'].values()):fail('Invalid checkpoint permissions.')
    total=0
    for path,content in row['files'].items():
        relative(root,path)
        try:data=base64.b64decode(content,validate=True)
        except (ValueError,TypeError):fail('Invalid checkpoint encoding.')
        total+=len(data)
        if len(data)>MAX_FILE or total>MAX_TOTAL:fail('Checkpoint size limit exceeded.')
        # Validate stored content too; a modified private snapshot cannot bypass
        # the sensitive-path checks at restore time.
        try:text=data.decode('utf-8')
        except UnicodeError:fail('Invalid checkpoint text.')
        if '\x00' in text or SECRET.search(text):fail('Unsafe checkpoint content.')
    return row


def preview(root,workspace,identity):
    row=load(root,workspace,identity);changes=[]
    for path,content in row['files'].items():
        current=read(workspace,relative(root,path));saved=base64.b64decode(content)
        changes.append({'path':path,'current_sha256':digest(current),'restore_sha256':digest(saved),'current_mode':mode(workspace,relative(root,path)),'restore_mode':row['modes'][path]})
    plan={'checkpoint':identity,'changes':changes}
    return {**plan,'review_digest':digest(canonical(plan))}


def write(workspace,parts,data,expected,permissions=0o600,expected_mode=None):
    # Parent directory descriptors and O_NOFOLLOW prevent path-link escapes.
    # Content checks detect edits since preview; they are not a filesystem CAS
    # against an uncooperative editor racing the final rename.
    if digest(read(workspace,parts))!=expected:fail('A file changed after review. Restore stopped; preview again.')
    if expected_mode is not None and mode(workspace,parts)!=expected_mode:fail('File permissions changed after review.')
    parent=_directory(Path(workspace).joinpath(*parts[:-1]));temporary='.codex-restore-'+uuid.uuid4().hex
    try:
        if data is None:
            os.unlink(parts[-1],dir_fd=parent);os.fsync(parent);return
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        with os.fdopen(fd,'wb') as dest:dest.write(data);os.fchmod(dest.fileno(),permissions);dest.flush();os.fsync(dest.fileno())
        if digest(read(workspace,parts))!=expected:fail('A file changed during restore. It was not overwritten.')
        if expected is None:
            # Never overwrite a file created after preview.
            os.link(temporary,parts[-1],src_dir_fd=parent,dst_dir_fd=parent,follow_symlinks=False)
            os.unlink(temporary,dir_fd=parent)
        else:os.replace(temporary,parts[-1],src_dir_fd=parent,dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        try:os.unlink(temporary,dir_fd=parent)
        except FileNotFoundError:pass
        os.close(parent)


def restore(root,workspace,identity,review_digest):
    view=preview(root,workspace,identity)
    if review_digest!=view['review_digest']:fail('Preview changed. Approve the current restore digest.')
    snapshot=load(root,workspace,identity);journal=[]
    for change in view['changes']:
        path=change['path'];before=read(workspace,relative(root,path))
        if digest(before)!=change['current_sha256']:fail('A file changed after preview.')
        journal.append({'path':path,'before':base64.b64encode(before).decode() if before is not None else None,'after':snapshot['files'][path],'before_mode':change['current_mode'],'after_mode':change['restore_mode']})
    pending=Path(root)/'checkpoint-pending.json'
    atomic_json(pending,{'version':1,'workspace':str(Path(workspace).resolve()),'files':journal})
    for change,row in zip(view['changes'],journal):write(workspace,relative(root,row['path']),base64.b64decode(row['after']),change['current_sha256'],row['after_mode'],row['before_mode'])
    pending.unlink()
    return {'restored':len(journal),'accounting_changed':False}


def recover(root,workspace,*,reviewed=False):
    pending=Path(root)/'checkpoint-pending.json'
    row=read_json(pending,private=True,maximum=48*1024*1024)
    if not isinstance(row,dict) or row.get('version')!=1 or row.get('workspace')!=str(Path(workspace).resolve()) or not isinstance(row.get('files'),list) or not 1<=len(row['files'])<=64:fail('Interrupted restore metadata is invalid.')
    actions=[];seen=set();total=0
    for item in row['files']:
        if not isinstance(item,dict) or set(item)!={'path','before','after','before_mode','after_mode'} or not isinstance(item['path'],str) or item['path'] in seen:fail('Invalid interrupted restore entry.')
        seen.add(item['path'])
        parts=relative(root,item['path']);current=read(workspace,parts)
        try:
            before=base64.b64decode(item['before'],validate=True) if item['before'] is not None else None
            after=base64.b64decode(item['after'],validate=True)
        except (ValueError,TypeError):fail('Invalid interrupted restore encoding.')
        if len(after)>MAX_FILE or before is not None and len(before)>MAX_FILE:fail('Interrupted restore exceeds file bounds.')
        total+=len(after)+(len(before) if before is not None else 0)
        if total>2*MAX_TOTAL:fail('Interrupted restore exceeds total size bounds.')
        if type(item['after_mode']) is not int or not 0<=item['after_mode']<=0o777:fail('Invalid interrupted file permissions.')
        if current not in (before,after):fail('A file changed outside the interrupted restore. Private recovery data was retained; no overwrite was attempted.')
        permissions=item['before_mode'] if before is not None else 0o600
        if type(permissions) is not int or not 0<=permissions<=0o777:fail('Invalid interrupted file permissions.')
        if current!=before or before is not None and mode(workspace,parts)!=permissions:actions.append((parts,before,digest(current),permissions,mode(workspace,parts)))
    if not reviewed:return {'files_to_restore':[ '/'.join(a[0]) for a in actions],'next_step':'Review, then repeat checkpoint recover --reviewed. This restores pre-restore files.'}
    for parts,data,expected,permissions,expected_mode in actions:write(workspace,parts,data,expected,permissions,expected_mode)
    pending.unlink();return {'recovered':len(actions),'accounting_changed':False}


def command(root,workspace,args):
    from maintenance import stopped
    parser=argparse.ArgumentParser(prog='codex-api checkpoint')
    sub=parser.add_subparsers(dest='action',required=True)
    create_parser=sub.add_parser('create');create_parser.add_argument('paths',nargs='+')
    for action in ('preview','restore','remove'):
        p=sub.add_parser(action);p.add_argument('id')
        if action=='restore':p.add_argument('--digest',required=True);p.add_argument('--reviewed',action='store_true')
    p=sub.add_parser('recover');p.add_argument('--reviewed',action='store_true')
    sub.add_parser('list');options=parser.parse_args(args)
    with stopped(root):
        if (Path(root)/'checkpoint-pending.json').exists() and options.action!='recover':fail('Finish checkpoint recover before another checkpoint operation.')
        if options.action=='create':result=create(root,workspace,options.paths)
        elif options.action=='preview':result=preview(root,workspace,options.id)
        elif options.action=='restore':
            if not options.reviewed:fail('Restore requires an exact digest and --reviewed.')
            result=restore(root,workspace,options.id,options.digest)
        elif options.action=='recover':result=recover(root,workspace,reviewed=options.reviewed)
        elif options.action=='remove':load(root,workspace,options.id);(directory(root)/(options.id+'.json')).unlink();result={'removed':options.id}
        else:result={'checkpoints':[p.stem for p in sorted(directory(root).glob('*.json'))]}
    print(json.dumps(result,indent=2));return result
