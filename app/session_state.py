"""Bounded preservation of this guest's JSONL history and safe preferences.

No subscription state, credentials, hooks, plugins, skills, or databases are
copied. A failed capture stops replacement before the original VM is removed.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import threading
import time

from guard import Denied, atomic_json, canonical

MAX_FILES = 4096
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_ENCODED_BYTES = 192 * 1024 * 1024
TIMEOUT = 90
SAFE_PATH = re.compile(r'(?:history\.jsonl|session_index\.jsonl|preferences\.json|(?:sessions|archived_sessions)/(?:[A-Za-z0-9_.-]+/){0,8}[A-Za-z0-9_.-]+\.jsonl(?:\.zst)?)\Z')
IDENTITY = re.compile(r'[A-Za-z0-9_-]{1,128}\Z')

# Pure, dependency-free allowlist shared verbatim with the guest transport.
PREFERENCE_FILTER = '''
def clean_preferences(data):
 out={}
 if not isinstance(data,dict):return out
 enums={'model':{'gpt-6-astra','gpt-6.1-sol','gpt-6-luna','gpt-5.6-terra','gpt-5.6-luna'},'model_reasoning_effort':{'low','medium','high','xhigh','max','ultra'},'model_reasoning_summary':{'auto','concise','detailed','none'},'model_verbosity':{'low','medium','high'}}
 for key,allowed in enums.items():
  if isinstance(data.get(key),str) and data[key] in allowed:out[key]=data[key]
 if out.get('model') in {'gpt-6-luna','gpt-5.6-luna'} and out.get('model_reasoning_effort')=='ultra':out['model_reasoning_effort']='max'
 tui=data.get('tui',{})
 if isinstance(tui,dict):
  safe={}
  if isinstance(tui.get('theme'),str) and re.fullmatch(r'[a-zA-Z0-9_-]{1,64}',tui['theme']):safe['theme']=tui['theme']
  for key in ('animations','status_line_use_colors'):
   if type(tui.get(key)) is bool:safe[key]=tui[key]
  status=tui.get('status_line')
  if isinstance(status,list) and len(status)<=24 and all(isinstance(x,str) and re.fullmatch(r'[a-z0-9_-]{1,64}',x) for x in status):safe['status_line']=status
  if safe:out['tui']=safe
 return out
'''
_filter_namespace = {'re': re}
exec(PREFERENCE_FILTER, _filter_namespace)
clean_preferences = _filter_namespace['clean_preferences']

EXPORT = '''import base64,hashlib,json,os,re,stat,tomllib
MAX_FILES=4096;MAX_FILE=67108864;MAX_TOTAL=134217728
HOME='/home/agent/.codex-api'
''' + PREFERENCE_FILTER + '''
files=[];total=0
try:root=os.open(HOME,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
except FileNotFoundError:print(json.dumps({'version':1,'files':[]}));raise SystemExit(0)
def read(fd,name):
 before=os.stat(name,dir_fd=fd,follow_symlinks=False)
 if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>MAX_FILE:raise ValueError('unsafe session file')
 source=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
 try:
  opened=os.fstat(source)
  if (opened.st_dev,opened.st_ino,opened.st_nlink)!=(before.st_dev,before.st_ino,1):raise ValueError('changed session file')
  chunks=[];length=0
  while length<=MAX_FILE:
   part=os.read(source,min(65536,MAX_FILE+1-length))
   if not part:break
   chunks.append(part);length+=len(part)
  after=os.fstat(source)
  if length>MAX_FILE or (opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise ValueError('changed session file')
  data=b''.join(chunks)
  if name.endswith('.jsonl.zst'):
   if not data.startswith(b'\\x28\\xb5\\x2f\\xfd'):raise ValueError('unsupported compressed session format')
  else:
   data.decode('utf-8')
   if b'\\0' in data:raise ValueError('non-text session file')
  return data
 finally:os.close(source)
def add(path,data):
 global total
 total+=len(data)
 if len(files)>=MAX_FILES or total>MAX_TOTAL:raise ValueError('session history exceeds safe capture limit')
 files.append({'path':path,'sha256':hashlib.sha256(data).hexdigest(),'data':base64.b64encode(data).decode('ascii')})
def walk(fd,prefix,depth=0):
 if depth>8:raise ValueError('session nesting exceeds limit')
 entries=os.listdir(fd)
 if len(entries)>MAX_FILES:raise ValueError('too many session entries')
 for name in sorted(entries):
  if not re.fullmatch(r'[A-Za-z0-9_.-]+',name) or name in {'.','..'}:raise ValueError('unsafe session name')
  mode=os.stat(name,dir_fd=fd,follow_symlinks=False).st_mode
  if stat.S_ISDIR(mode):
   child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
   try:walk(child,prefix+name+'/',depth+1)
   finally:os.close(child)
  elif stat.S_ISREG(mode) and name.endswith(('.jsonl','.jsonl.zst')):add(prefix+name,read(fd,name))
  elif stat.S_ISREG(mode) and name.endswith('.lock'):continue
  else:raise ValueError('unsupported, linked, special, or in-progress session entry')
try:
 for folder in ('sessions','archived_sessions'):
  try:child=os.open(folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root)
  except FileNotFoundError:continue
  try:walk(child,folder+'/')
  finally:os.close(child)
 for name in ('history.jsonl','session_index.jsonl'):
  try:data=read(root,name)
  except FileNotFoundError:continue
  add(name,data)
 preferences={}
 for name in ('preferences.json','config.toml'):
  try:data=read(root,name)
  except FileNotFoundError:continue
  if len(data)>1000000:raise ValueError('preference file exceeds limit')
  try:parsed=json.loads(data) if name.endswith('.json') else tomllib.loads(data.decode())
  except (ValueError,UnicodeError):continue
  preferences.update(clean_preferences(parsed))
 if preferences:add('preferences.json',json.dumps(preferences,sort_keys=True,separators=(',',':')).encode())
 print(json.dumps({'version':1,'files':files},sort_keys=True,separators=(',',':')))
finally:os.close(root)
'''

RESTORE = '''import base64,hashlib,json,os,re,stat,sys,uuid
MAX_ENCODED=201326592;MAX_FILE=67108864;MAX_TOTAL=134217728
payload=sys.stdin.buffer.read(MAX_ENCODED+1)
if len(payload)>MAX_ENCODED:raise ValueError('restore input exceeds limit')
data=json.loads(payload)
if set(data)!={'version','files'} or data['version']!=1 or not isinstance(data['files'],list) or len(data['files'])>4096:raise ValueError('invalid restore envelope')
pattern=re.compile(r'(?:history\\.jsonl|session_index\\.jsonl|preferences\\.json|(?:sessions|archived_sessions)/(?:[A-Za-z0-9_.-]+/){0,8}[A-Za-z0-9_.-]+\\.jsonl(?:\\.zst)?)\\Z')
checked=[];seen=set();total=0
for entry in data['files']:
 if not isinstance(entry,dict) or set(entry)!={'path','sha256','data'} or not isinstance(entry['path'],str) or not pattern.fullmatch(entry['path']) or any(x in {'.','..'} for x in entry['path'].split('/')) or entry['path'] in seen:raise ValueError('unsafe restore path')
 seen.add(entry['path']);raw=base64.b64decode(entry['data'],validate=True);total+=len(raw)
 if len(raw)>MAX_FILE or total>MAX_TOTAL or hashlib.sha256(raw).hexdigest()!=entry['sha256']:raise ValueError('invalid restore bytes')
 if entry['path'].endswith('.jsonl.zst'):
  if not raw.startswith(b'\\x28\\xb5\\x2f\\xfd'):raise ValueError('unsupported compressed session format')
 else:
  raw.decode('utf-8')
  if b'\\0' in raw:raise ValueError('non-text restore bytes')
 checked.append((entry['path'],raw))
os.umask(0o077)
home='/home/agent/.codex-api';os.makedirs(home,mode=0o700,exist_ok=True)
root=os.open(home,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
 if os.path.lexists(home+'/auth.json'):raise ValueError('unexpected guest login state')
 for path,raw in checked:
  parts=path.split('/');folder=os.dup(root)
  try:
   for part in parts[:-1]:
    try:os.mkdir(part,mode=0o700,dir_fd=folder)
    except FileExistsError:pass
    child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=folder);os.close(folder);folder=child
   name=parts[-1]
   try:mode=os.stat(name,dir_fd=folder,follow_symlinks=False)
   except FileNotFoundError:mode=None
   if mode is not None:
    if not stat.S_ISREG(mode.st_mode) or mode.st_nlink!=1:raise ValueError('unsafe restore destination')
    old=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=folder)
    try:
     chunks=[];length=0
     while length<=MAX_FILE:
      part=os.read(old,min(65536,MAX_FILE+1-length))
      if not part:break
      chunks.append(part);length+=len(part)
     olddata=b''.join(chunks)
     if olddata!=raw:raise ValueError('restore would overwrite different guest history')
    finally:os.close(old)
    continue
   temporary='.harness-restore-'+uuid.uuid4().hex
   output=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=folder)
   try:
    with os.fdopen(output,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    os.rename(temporary,name,src_dir_fd=folder,dst_dir_fd=folder)
   finally:
    try:os.unlink(temporary,dir_fd=folder)
    except FileNotFoundError:pass
  finally:os.close(folder)
 print(json.dumps({'restored':len(checked)}))
finally:os.close(root)
'''


def _fail(message):
    raise Denied(message, code='guest_state_preservation_failed')


def _exchange(sbx, name, script, *, env, data=None, maximum=MAX_ENCODED_BYTES):
    """Never let an untrusted guest fill an unbounded stdout or host file."""
    process=None
    writer=None
    error=[]
    try:
        command=[str(sbx),'exec']+(['-i'] if data is not None else [])+[name,'python3','-I','-c',script]
        process=subprocess.Popen(command,stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                                 stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=env,start_new_session=True,bufsize=0)
        if data is not None:
            def write():
                try:
                    view=memoryview(data)
                    while view:
                        written=process.stdin.write(view)
                        if not written:raise OSError('restore pipe closed')
                        view=view[written:]
                    process.stdin.close()
                except (OSError,ValueError):error.append(True)
            writer=threading.Thread(target=write,daemon=True);writer.start()
        result=bytearray();deadline=time.monotonic()+TIMEOUT
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout,selectors.EVENT_READ)
            while True:
                if time.monotonic()>deadline:_fail('Guest state preservation timed out. The private backup was kept; no project, credentials, or usage state was reset.')
                if not selector.select(min(.2,max(0,deadline-time.monotonic()))):continue
                part=os.read(process.stdout.fileno(),65536)
                if not part:break
                result.extend(part)
                if len(result)>maximum:_fail('Guest state exceeds the safe preservation limit. The existing sandbox was not replaced.')
        if process.wait(timeout=5)!=0 or error:_fail('Guest history could not be preserved or restored safely. Existing history and the private backup were left in place.')
        return bytes(result)
    except (OSError,subprocess.SubprocessError):
        _fail('Guest history transport failed. The private backup was kept; retry preparation after checking Docker Sandboxes.')
    finally:
        if process is not None:
            if process.poll() is None:
                try:os.killpg(process.pid,signal.SIGTERM);process.wait(timeout=2)
                except (OSError,subprocess.TimeoutExpired):
                    try:os.killpg(process.pid,signal.SIGKILL)
                    except OSError:pass
            if process.stdout is not None:process.stdout.close()
            if process.stdin is not None:
                try:process.stdin.close()
                except (OSError,ValueError):pass
        if writer is not None:writer.join(timeout=1)


def validate_payload(value):
    if not isinstance(value,dict) or set(value)!={'version','files'} or value['version']!=1 or not isinstance(value['files'],list) or len(value['files'])>MAX_FILES:
        _fail('Guest history export has an unsupported format.')
    seen=set();total=0
    for entry in value['files']:
        if not isinstance(entry,dict) or set(entry)!={'path','sha256','data'} or not isinstance(entry['path'],str) or not SAFE_PATH.fullmatch(entry['path']) or any(part in {'.','..'} for part in entry['path'].split('/')) or entry['path'] in seen:
            _fail('Guest history export contains an unsafe path or duplicate entry.')
        seen.add(entry['path'])
        if not isinstance(entry['data'],str) or len(entry['data'])>((MAX_FILE_BYTES+2)//3)*4 or not isinstance(entry['sha256'],str):_fail('Guest history export exceeds its file limit.')
        try:raw=base64.b64decode(entry['data'],validate=True)
        except (ValueError,UnicodeError):_fail('Guest history export contains invalid text or encoding.')
        total+=len(raw)
        if len(raw)>MAX_FILE_BYTES or total>MAX_TOTAL_BYTES or hashlib.sha256(raw).hexdigest()!=entry['sha256']:
            _fail('Guest history export failed size or integrity validation.')
        if entry['path'].endswith('.jsonl.zst'):
            if not raw.startswith(b'\x28\xb5\x2f\xfd'):_fail('Guest history export contains an unsupported compressed format.')
        else:
            try:text=raw.decode('utf-8')
            except UnicodeError:_fail('Guest history export contains invalid text.')
            if '\x00' in text:_fail('Guest history export contains invalid text.')
        if entry['path']=='preferences.json':
            try:preferences=json.loads(raw)
            except ValueError:_fail('Guest preferences are invalid.')
            if clean_preferences(preferences)!=preferences:_fail('Guest state export tried to include policy or credentials in preferences.')
    return value


def _storage(root):
    path=Path(root)/'guest-state'
    if path.is_symlink():_fail('Private guest history storage must not be a symlink.')
    path.mkdir(mode=0o700,exist_ok=True)
    if path.stat().st_mode&0o077:_fail('Private guest history storage must be accessible only to its owner.')
    return path


def _pending(root):
    path=Path(root)/'guest-state/pending.json'
    if not path.exists():
        if path.is_symlink():_fail('Private history backup must not be linked.')
        return None
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink!=1 or path.stat().st_mode&0o077 or path.stat().st_size>MAX_ENCODED_BYTES:
        _fail('Private history backup failed ownership, path, or size checks.')
    try:data=json.loads(path.read_bytes())
    except (ValueError,OSError):_fail('Private history backup is unreadable; it was not reset.')
    if not isinstance(data,dict) or set(data)!={'version','source_id','restored_to','payload','checksum'} or data['version']!=1 or not isinstance(data['source_id'],str) or not IDENTITY.fullmatch(data['source_id']) or data['restored_to'] is not None and (not isinstance(data['restored_to'],str) or not IDENTITY.fullmatch(data['restored_to'])):
        _fail('Private history backup metadata is invalid.')
    validate_payload(data['payload'])
    if hashlib.sha256(canonical(data['payload'])).hexdigest()!=data['checksum']:_fail('Private history backup checksum changed. No old backup was substituted.')
    return data


def capture(root, sbx, name, sandbox_id, *, env):
    """Call only after VM identity verification and while holding session.lock."""
    if not isinstance(sandbox_id,str) or not IDENTITY.fullmatch(sandbox_id):_fail('Cannot preserve history without an owned sandbox identity.')
    directory=_storage(root);previous=_pending(root)
    if previous and sandbox_id not in {previous['source_id'],previous['restored_to']}:
        return {'pending':True,'files':len(previous['payload']['files'])}  # Keep original across a failed replacement.
    raw=_exchange(sbx,name,EXPORT,env=env)
    try:payload=validate_payload(json.loads(raw))
    except ValueError:_fail('Guest history export is unreadable. The original VM was not removed.')
    record={'version':1,'source_id':sandbox_id,'restored_to':None,'payload':payload,'checksum':hashlib.sha256(canonical(payload)).hexdigest()}
    atomic_json(directory/'pending.json',record)
    return {'pending':True,'files':len(payload['files'])}


def restore(root, sbx, name, sandbox_id, *, env):
    """Idempotent across interrupted preparation; never overwrite different data."""
    if not isinstance(sandbox_id,str) or not IDENTITY.fullmatch(sandbox_id):_fail('Cannot restore history without an owned sandbox identity.')
    _storage(root);record=_pending(root)
    if record is None:return {'restored':0}
    if record['restored_to']==sandbox_id:return {'restored':len(record['payload']['files'])}
    if record['source_id']==sandbox_id:return {'restored':0}  # Original VM has not yet been replaced.
    raw=_exchange(sbx,name,RESTORE,env=env,data=canonical(record['payload']),maximum=8192)
    try:result=json.loads(raw)
    except ValueError:_fail('Guest history restore confirmation was invalid. The private backup was kept.')
    if result!={'restored':len(record['payload']['files'])}:_fail('Guest history restore confirmation did not match the private backup.')
    record['restored_to']=sandbox_id;atomic_json(Path(root)/'guest-state/pending.json',record)
    return result


def complete(root, sandbox_id):
    """Retain the most recent private backup after native acceptance succeeds."""
    record=_pending(root)
    if record is None:return
    if record['restored_to']!=sandbox_id and record['source_id']!=sandbox_id:_fail('Guest history activation has not been confirmed for this sandbox.')
    directory=_storage(root)
    os.replace(directory/'pending.json',directory/'last.json')
    descriptor=os.open(directory,os.O_RDONLY)
    try:os.fsync(descriptor)
    finally:os.close(descriptor)
