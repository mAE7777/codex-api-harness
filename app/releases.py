"""Reviewed code generations with permanent credentials and accounting state.

The current code pointer is atomic. Its manifest uses a durable activation fence;
an interruption requires explicit recovery before another session can start.
"""
from __future__ import annotations
import argparse
import ast
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

from guard import Denied, atomic_json, canonical

LAYOUT_VERSION = 2
UPDATER_ABI = 1
DIGEST = re.compile(r'[0-9a-f]{64}')
RELEASE_ID = re.compile(r'[a-z0-9][a-z0-9-]{7,95}')
IMAGE_KEYS = ('image_built','filesystem_tested','network_tested','host_integrations_absent','codex_protocol_tested')
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_POLICY_INPUT = 128 * 1024
MAX_POLICY_OUTPUT = 4 * 1024 * 1024


def fail(message):
    raise Denied(message, code='upgrade_review_required')


def _json(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_size > MAX_SOURCE_BYTES:
        fail('Release metadata is missing, linked, or exceeds its size limit.')
    try: return json.loads(path.read_text())
    except (OSError, ValueError): fail('Release metadata cannot be read safely.')


def _sync(directory):
    fd = os.open(directory, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)


def _relative(value):
    if not isinstance(value, str) or '\\' in value or any(ord(c) < 32 for c in value): fail('Invalid release file path.')
    p = Path(value)
    if p.is_absolute() or not p.parts or any(x in {'','.','..'} for x in value.split('/')):
        fail('Invalid release file path.')
    return p


def _tree(directory, *, maximum_files=512, maximum_bytes=MAX_SOURCE_BYTES):
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir(): fail('A release tree is missing or linked.')
    files = {}
    total = 0
    for path in sorted(directory.rglob('*')):
        relative = path.relative_to(directory)
        if '__pycache__' in relative.parts: continue
        if path.is_symlink(): fail('Release trees must not contain symbolic links.')
        if path.is_dir(): continue
        if not path.is_file() or path.stat().st_nlink != 1: fail('Release trees must contain ordinary, unlinked files.')
        if len(files) >= maximum_files or path.stat().st_size > 2 * 1024 * 1024: fail('The release tree exceeds its file limits.')
        data = path.read_bytes(); total += len(data)
        if total > maximum_bytes: fail('The release tree exceeds its size limit.')
        files[str(relative)] = hashlib.sha256(data).hexdigest()
    return files


def _payload_tree(payload, name):
    # Approved skills may have up to 32 separate 2 MiB snapshots. The base
    # source review stays much smaller; generated assets have a separate bound.
    return _tree(Path(payload)/name,maximum_files=10000,maximum_bytes=96*1024*1024) if name=='kit' else _tree(Path(payload)/name)


def _metadata(source):
    path = Path(source)/'setup.py'
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 256 * 1024: fail('Choose a complete harness source checkout.')
    try: tree = ast.parse(path.read_text())
    except (SyntaxError, UnicodeError): fail('The candidate installer is not valid Python source.')
    wanted = {'VERSION','SBX_VERSION','CODEX_VERSION','PLAYWRIGHT_VERSION','INSTALL_LAYOUT_VERSION','UPDATER_ABI','APP_FILES','KIT_FILES'}
    values = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in wanted:
                    try: values[target.id] = ast.literal_eval(node.value)
                    except (ValueError, TypeError): fail('Release metadata must use literal constants.')
    if set(values) != wanted or type(values['INSTALL_LAYOUT_VERSION']) is not int or values['INSTALL_LAYOUT_VERSION'] != LAYOUT_VERSION or type(values['UPDATER_ABI']) is not int or values['UPDATER_ABI'] != UPDATER_ABI:
        fail('This candidate does not support the installed code-generation layout. No code or usage was changed.')
    if not isinstance(values['VERSION'], str) or not re.fullmatch(r'\d+\.\d+\.\d+', values['VERSION']): fail('Use a numbered harness release.')
    for key in ('APP_FILES','KIT_FILES'):
        names = values[key]
        if not isinstance(names, tuple) or not names or not all(isinstance(n,str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',n) for n in names) or len(names) != len(set(names)):
            fail('The candidate has an unsupported source-file inventory.')
    required = {'settings.py','controller.py','guard.py','gateway.py','releases.py'}
    if not required <= set(values['APP_FILES']): fail('The candidate is missing required accounting and release modules.')
    return values


def _source_files(source):
    source = Path(source)
    if source.is_symlink() or not source.is_dir(): fail('Choose a real harness source directory.')
    meta = _metadata(source)
    selected = ['setup.py','scripts/check.py']
    selected += ['app/'+n for n in meta['APP_FILES']]
    selected += ['kit/'+n for n in meta['KIT_FILES']]
    tests = source/'tests'
    if tests.is_symlink() or not tests.is_dir(): fail('The candidate regression tests are missing.')
    selected += [str(p.relative_to(source)) for p in sorted(tests.glob('*.py')) if p.name=='__init__.py' or re.fullmatch(r'test_[A-Za-z0-9_]+\.py',p.name)]
    if not any(p.startswith('tests/test_') for p in selected): fail('The candidate has no regression suite.')
    files = {}; total = 0
    for relative in selected:
        path = source/_relative(relative)
        if any(parent.is_symlink() for parent in path.parents if parent != source.parent): fail('Candidate source paths must not contain symbolic links.')
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_size > 2 * 1024 * 1024:
            fail('A required candidate source file is missing, linked, or too large.')
        data = path.read_bytes(); total += len(data)
        if total > MAX_SOURCE_BYTES: fail('The candidate source exceeds the review size limit.')
        if relative.endswith('.py'):
            try: compile(data, relative, 'exec')
            except (SyntaxError, ValueError): fail('A candidate Python source file does not compile.')
        files[relative] = data
    return meta, files


def _report(meta, files, source_pin=None):
    if source_pin is not None and (not isinstance(source_pin,str) or not re.fullmatch(r'[0-9a-f]{40}',source_pin)):
        fail('An optional source pin must be a complete lowercase Git commit SHA. The tree digest remains authoritative.')
    return {'version':1,'layout_version':LAYOUT_VERSION,'updater_abi':UPDATER_ABI,
            'harness_version':meta['VERSION'],'sbx_version':meta['SBX_VERSION'],
            'codex_version':meta['CODEX_VERSION'],'playwright_cli_version':meta['PLAYWRIGHT_VERSION'],
            'source_pin':source_pin,'files':{name:hashlib.sha256(data).hexdigest() for name,data in sorted(files.items())}}


def _copy_files(files, destination):
    destination = Path(destination); destination.mkdir(mode=0o700,parents=True)
    for relative, data in files.items():
        path = destination/_relative(relative); path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as out: out.write(data); out.flush(); os.fsync(out.fileno())
    for directory in sorted((p for p in destination.rglob('*') if p.is_dir()),key=lambda p:len(p.parts),reverse=True): _sync(directory)
    _sync(destination)


def _freeze(directory):
    directory = Path(directory)
    for path in sorted(directory.rglob('*'),key=lambda p:len(p.parts),reverse=True): path.chmod(0o500 if path.is_dir() else 0o400)
    directory.chmod(0o500)


def _write_descriptor(payload, root, report, digest, *, kind):
    atomic_json(payload/'.installation-root',{'version':LAYOUT_VERSION,'root':str(Path(root).resolve())})
    atomic_json(payload/'release.json',{'version':1,'layout_version':LAYOUT_VERSION,'updater_abi':UPDATER_ABI,
                'harness_version':report['harness_version'],'source_digest':digest,'kind':kind,
                'app_files':_tree(payload/'app')})
    (payload/'.installation-root').chmod(0o400);(payload/'release.json').chmod(0o400)
    _freeze(payload/'app');_freeze(payload/'source')
    _sync(payload)


def initialize_layout(stage, final_root, *, source, version):
    """Create a fresh layout; never migrates or copies an existing ledger."""
    stage, final_root = Path(stage), Path(final_root)
    meta, files = _source_files(source)
    if meta['VERSION']!=version:fail('The installer version and source metadata differ.')
    report = _report(meta,files); digest = hashlib.sha256(canonical(report)).hexdigest()
    release_id = 'initial-'+digest[:24]
    releases = stage/'releases';releases.mkdir(mode=0o700)
    payload = releases/release_id;payload.mkdir(mode=0o700)
    (stage/'app').rename(payload/'app');(stage/'kit').rename(payload/'kit')
    _copy_files(files,payload/'source');atomic_json(payload/'source-report.json',report)
    _write_descriptor(payload,final_root,report,digest,kind='initial')
    os.symlink('releases/'+release_id,stage/'current')
    os.symlink('current/app',stage/'app');os.symlink('current/kit',stage/'kit')
    _sync(stage)
    return {'layout_version':LAYOUT_VERSION,'active_release':release_id,'source_digest':digest}


def active_payload(root):
    root = Path(root)
    current = root/'current'
    if not current.is_symlink(): fail('This installation has no reviewed code-generation layout. Legacy installations require a separate migration review; no personal state was changed.')
    target = current.readlink()
    if target.is_absolute() or len(target.parts)!=2 or target.parts[0]!='releases' or not RELEASE_ID.fullmatch(target.parts[1]): fail('The active release pointer is invalid.')
    releases = root/'releases'
    if root.is_symlink() or releases.is_symlink() or not releases.is_dir(): fail('Release storage must be a real private directory.')
    payload = root/target
    if payload.is_symlink() or not payload.is_dir(): fail('The selected code generation is missing or linked.')
    if _json(payload/'.installation-root') != {'version':LAYOUT_VERSION,'root':str(root.resolve())}: fail('The selected release belongs to another installation.')
    for name in ('app','kit'):
        alias = root/name
        if not alias.is_symlink() or alias.readlink()!=Path('current')/name: fail('The managed code aliases changed; no unreviewed directory was used.')
        if (payload/name).is_symlink() or not (payload/name).is_dir(): fail('A release payload directory is invalid.')
    return payload


def resolve_payload(root, name):
    if name not in {'app','kit'}: fail('Unknown release payload directory.')
    root = Path(root)
    if not (root/'current').exists() and not (root/'current').is_symlink():
        target = root/name
        if target.is_symlink() or not target.is_dir(): fail('The private payload directory is unavailable or linked.')
        return target
    return active_payload(root)/name


def validate_layout(root):
    payload = active_payload(root)
    descriptor = _json(payload/'release.json')
    if descriptor.get('layout_version')!=LAYOUT_VERSION or descriptor.get('updater_abi')!=UPDATER_ABI or descriptor.get('app_files')!=_tree(payload/'app'):
        fail('The active application differs from its reviewed code generation.')
    return payload


@contextlib.contextmanager
def _stopped(root, *, allow_pending=False):
    root = Path(root)
    if root.is_symlink() or not root.is_dir(): fail('Use the existing private harness installation.')
    for name in ('state','team'):
        if (root/name).is_symlink():fail('Private accounting directories must not be linked.')
    locks=[]
    try:
        names=['session.lock','upgrade.lock','state/process.lock']
        if (root/'team/state/process.lock').exists():names.append('team/state/process.lock')
        for name in names:
            path=root/name
            if path.is_symlink() or name.startswith('state/') and not path.is_file(): fail('A required release/accounting lease is unavailable.')
            fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600);locks.append(fd)
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:fail('Exit the API session and stop its gateway before changing code. Active accounting and sessions were left unchanged.')
        if (root/'gateway-process.json').exists() or not (root/'paused').exists(): fail('Stop this API environment before changing code.')
        if (root/'upgrade-pending.json').exists() and not allow_pending: fail('A release activation was interrupted. Run codex-api upgrade recover before another code change.')
        yield
    finally:
        for fd in reversed(locks):os.close(fd)


def _store(root):
    directory=Path(root)/'upgrades'
    if directory.is_symlink():fail('Upgrade storage must not be a symlink.')
    directory.mkdir(mode=0o700,exist_ok=True)
    for name in ('candidates','checks','history'):
        path=directory/name
        if path.is_symlink():fail('Upgrade storage must not contain symlinks.')
        path.mkdir(mode=0o700,exist_ok=True)
    return directory


def _candidate(root,digest):
    if not isinstance(digest,str) or not DIGEST.fullmatch(digest):fail('Use the complete source digest printed by upgrade stage.')
    directory=_store(root)/'candidates'/digest
    if directory.is_symlink():fail('A staged candidate must not be linked.')
    report=_json(directory/'report.json')
    if not isinstance(report,dict) or hashlib.sha256(canonical(report)).hexdigest()!=digest or report.get('files')!=_tree(directory/'source'):
        fail('The staged source changed after review. Stage the intended source again.')
    meta,files=_source_files(directory/'source')
    if _report(meta,files,report.get('source_pin'))!=report:fail('The staged source inventory changed after review.')
    return directory,report,meta,files


def _verify_manifest(root,manifest,payload=None):
    root=Path(root)
    if not isinstance(manifest,dict) or not isinstance(manifest.get('files'),dict):fail('The installation integrity manifest is unavailable.')
    for relative,digest in manifest['files'].items():
        parts=_relative(relative).parts
        path=(payload/parts[0]/Path(*parts[1:]) if payload is not None and parts[0] in {'app','kit'} else root/relative)
        if not isinstance(digest,str) or not DIGEST.fullmatch(digest) or path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            fail('An installation file changed. Review the integrity failure before updating; no quota was reset.')


def _policy_digest(root):
    root=Path(root);parts={}
    for name in ('settings.json','protected-paths.json','extensions/registry.json'):
        path=root/name
        if path.exists():
            if path.is_symlink():fail('Managed policy must not be linked.')
            parts[name]=hashlib.sha256(path.read_bytes()).hexdigest()
    from extensions import verify
    parts['approved_extensions']=verify(root)
    return hashlib.sha256(canonical(parts)).hexdigest()


def _permanent_fingerprint(root):
    """Detect test-written private state without backing up or restoring it."""
    root=Path(root);files={}
    for name in ('openai-key.env','openai-key.next.env','search-keys.env','gateway.token','verification.json','team-client.json'):
        path=root/name
        if path.exists():
            if path.is_symlink() or not path.is_file():fail('A private state file is unsafe.')
            files[name]=hashlib.sha256(path.read_bytes()).hexdigest()
    for name in ('state','team/state'):
        path=root/name
        if path.exists():
            if path.is_symlink() or not path.is_dir():fail('Private accounting storage is unsafe.')
            values={}
            for item in sorted(path.rglob('*')):
                if item.is_symlink():fail('Private accounting storage contains a linked file.')
                if item.is_dir():continue
                if not item.is_file() or item.stat().st_nlink!=1:fail('Private accounting storage contains an invalid file.')
                digest=hashlib.sha256()
                with item.open('rb') as source:
                    for block in iter(lambda:source.read(1024*1024),b''):digest.update(block)
                values[str(item.relative_to(path))]=digest.hexdigest()
            files[name]=values
    return hashlib.sha256(canonical(files)).hexdigest()


def stage(root,source,*,source_pin=None):
    root=Path(root);source=Path(source).expanduser()
    with _stopped(root):
        validate_layout(root)
        manifest=_json(root/'installation.json');_verify_manifest(root,manifest)
        workspace=Path(_json(root/'settings.json')['workspace'])
        if source.is_relative_to(workspace) or source.resolve().is_relative_to(workspace.resolve()):fail('Keep reviewed harness source outside the agent workspace.')
        meta,files=_source_files(source);report=_report(meta,files,source_pin);digest=hashlib.sha256(canonical(report)).hexdigest()
        store=_store(root);destination=store/'candidates'/digest
        if destination.exists():_candidate(root,digest)
        else:
            with tempfile.TemporaryDirectory(prefix='.stage-',dir=store) as temporary:
                output=Path(temporary)/'candidate';output.mkdir(mode=0o700)
                _copy_files(files,output/'source');atomic_json(output/'report.json',report)
                _freeze(output/'source');(output/'report.json').chmod(0o400)
                output.rename(destination);_sync(destination.parent)
        return {'digest':digest,'harness_version':report['harness_version'],'source_pin':source_pin,
                'review_directory':str(destination/'source'),'files':len(files),
                'status':'staged; no candidate code was executed or activated'}


def _run_checks(root,candidate,digest):
    log=_store(root)/'checks'/(digest+'.log')
    fd=os.open(log,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    environment={k:v for k,v in os.environ.items() if k in {'HOME','TMPDIR','LANG','LC_ALL'}}
    environment['PATH']=os.defpath
    try:
        with os.fdopen(fd,'wb') as output:
            result=subprocess.run([sys.executable,'-I',str(candidate/'source/scripts/check.py')],cwd=candidate/'source',env=environment,stdout=output,stderr=subprocess.STDOUT,timeout=300)
    except (OSError,subprocess.SubprocessError):fail('The reviewed candidate checks did not finish. The active code and usage were preserved; inspect the private upgrade check log.')
    if result.returncode:fail('The reviewed candidate regression checks failed. Active code and usage were preserved; inspect the private upgrade check log.')
    return hashlib.sha256(log.read_bytes()).hexdigest()


def _version(value):
    if not isinstance(value,str) or not re.fullmatch(r'\d+\.\d+\.\d+',value):fail('The installed version cannot be compared safely.')
    return tuple(map(int,value.split('.')))


def _compatible(manifest,report,*,rollback=False):
    if manifest.get('layout_version')!=LAYOUT_VERSION or report.get('updater_abi')!=UPDATER_ABI:fail('This upgrade requires a separately reviewed layout migration.')
    if not rollback and _version(report['harness_version'])<_version(manifest['harness_version']):fail('Direct downgrades are disabled. Use upgrade rollback for a retained, reviewed source generation.')
    for key in ('sbx_version','codex_version','playwright_cli_version'):
        if report.get(key)!=manifest.get(key):fail('Runtime pins changed. This updater preserves the tested runtime; review that runtime migration separately.')


def _render_requirements(payload, workspace, protected):
    """Use the reviewed candidate renderer, not the still-imported old module.

    The renderer is explicitly reviewed host code, not an untrusted-code
    sandbox. Give it only bounded path data and a clean, temporary home; never
    pass account configuration, credentials, environment secrets, or ledgers.
    """
    from workspace_policy import validate_protected_paths, validate_managed_requirements
    workspace=Path(workspace)
    if not workspace.is_absolute():fail('The candidate policy workspace must be absolute.')
    data=canonical({'workspace':str(workspace),'protected':validate_protected_paths(list(protected))})
    if len(data)>MAX_POLICY_INPUT:fail('The candidate policy input exceeds its bounded path-only format.')
    code='''import json,sys
from pathlib import Path
raw=sys.stdin.buffer.read(131073)
if len(raw)>131072:raise ValueError('policy input too large')
data=json.loads(raw)
if not isinstance(data,dict) or set(data)!={'workspace','protected'} or not isinstance(data['workspace'],str) or not Path(data['workspace']).is_absolute():raise ValueError('invalid policy input')
sys.path.insert(0,sys.argv[1])
from workspace_policy import managed_requirements,validate_protected_paths
result=managed_requirements(Path(data['workspace']),validate_protected_paths(data['protected']))
if not isinstance(result,str):raise ValueError('invalid policy output')
sys.stdout.buffer.write(result.encode('utf-8'))
'''
    process=None
    try:
        with tempfile.TemporaryDirectory(prefix='.policy-home-',dir=payload) as temporary:
            environment={'HOME':temporary,'TMPDIR':temporary,'PATH':os.defpath,'LANG':'C.UTF-8'}
            process=subprocess.Popen([sys.executable,'-I','-c',code,str(Path(payload)/'app')],cwd=payload,
                env=environment,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                start_new_session=True,bufsize=0)
            os.set_blocking(process.stdin.fileno(),False);os.set_blocking(process.stdout.fileno(),False)
            result=bytearray();pending=memoryview(data);deadline=time.monotonic()+30
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdin,selectors.EVENT_WRITE,'input')
                selector.register(process.stdout,selectors.EVENT_READ,'output')
                while selector.get_map():
                    if time.monotonic()>deadline:fail('The reviewed candidate policy renderer timed out. No code generation was activated.')
                    for key,_ in selector.select(min(.2,max(0,deadline-time.monotonic()))):
                        if key.data=='input':
                            try:written=os.write(key.fd,pending[:65536])
                            except BlockingIOError:continue
                            except BrokenPipeError:written=0
                            if not written:pending=memoryview(b'')
                            else:pending=pending[written:]
                            if not pending:selector.unregister(process.stdin);process.stdin.close()
                        else:
                            try:part=os.read(key.fd,65536)
                            except BlockingIOError:continue
                            if not part:selector.unregister(process.stdout);continue
                            result.extend(part)
                            if len(result)>MAX_POLICY_OUTPUT:fail('The reviewed candidate policy renderer exceeded its output limit. No code generation was activated.')
            if process.wait(timeout=3)!=0:fail('The reviewed candidate policy renderer failed. No code generation was activated.')
            value=bytes(result)
            validate_managed_requirements(value,workspace,protected)
            return value
    except (OSError,subprocess.SubprocessError):
        fail('The reviewed candidate policy renderer could not complete. Existing code, policy, and usage were preserved.')
    finally:
        if process is not None:
            if process.poll() is None:
                try:os.killpg(process.pid,signal.SIGTERM);process.wait(timeout=2)
                except (OSError,subprocess.TimeoutExpired):
                    try:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=2)
                    except (OSError,subprocess.TimeoutExpired):pass
            if process.stdin is not None:process.stdin.close()
            if process.stdout is not None:process.stdout.close()


def _generation(root,report,meta,files,*,kind):
    root=Path(root);release_id=kind+'-'+uuid.uuid4().hex
    directory=root/'releases'/release_id
    directory.mkdir(mode=0o700)
    app=directory/'app';app.mkdir(mode=0o700)
    kit=directory/'kit';kit.mkdir(mode=0o700)
    for name in meta['APP_FILES']:(app/name).write_bytes(files['app/'+name])
    settings=_json(root/'settings.json');workspace=Path(settings['workspace'])
    if kind=='rollback':
        # Revert host code while retaining every current guest protection and
        # approved extension byte. Never reactivate the historical guest kit.
        current=resolve_payload(root,'kit');manifest=_json(root/'installation.json')
        expected={name[len('kit/'):]:digest for name,digest in manifest['files'].items() if name.startswith('kit/')}
        if _payload_tree(active_payload(root),'kit')!=expected:fail('Current guest kit contains unverified files; rollback did not copy them.')
        for name in expected:
            path=kit/_relative(name);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            path.write_bytes((current/name).read_bytes());path.chmod(0o600)
    else:
        import shlex
        for name in meta['KIT_FILES']:
            data=files['kit/'+name].decode('utf-8')
            data=data.replace('__WORKSPACE_SHELL__',shlex.quote(str(workspace))).replace('__WORKSPACE_TOML__',json.dumps(str(workspace))).replace('49187',str(settings['gateway_port']))
            (kit/name).write_text(data)
        (kit/'workspace').write_text(str(workspace)+'\n')
        from workspace_policy import protected_paths
        (kit/'requirements.toml').write_bytes(_render_requirements(directory,workspace,protected_paths(root)))
        from extensions import render_build
        render_build(root,kit_directory=kit)
    # A renderer is reviewed code but its output cannot silently replace the
    # exact reviewed application source or an unchanged base guest template.
    if _tree(app)!={name:hashlib.sha256(files['app/'+name]).hexdigest() for name in meta['APP_FILES']}:
        fail('The candidate renderer changed its reviewed application source. No generation was activated.')
    _copy_files(files,directory/'source');atomic_json(directory/'source-report.json',report)
    _write_descriptor(directory,root,report,hashlib.sha256(canonical(report)).hexdigest(),kind=kind)
    _sync(directory.parent)
    return release_id,directory


def _new_manifest(root,old,payload,release_id,report):
    manifest=dict(old)
    files={p:d for p,d in old['files'].items() if _relative(p).parts[0] not in {'app','kit'}}
    for name in ('app','kit'):
        files.update({name+'/'+p:d for p,d in _payload_tree(payload,name).items()})
    manifest.update(harness_version=report['harness_version'],files=files,layout_version=LAYOUT_VERSION,
                    active_release=release_id,source_digest=hashlib.sha256(canonical(report)).hexdigest())
    return manifest


def _invalidate(root):
    ready=_json(Path(root)/'readiness.json')
    for key in IMAGE_KEYS:ready[key]=False
    atomic_json(Path(root)/'readiness.json',ready)


def _switch(root,release_id):
    if not isinstance(release_id,str) or not RELEASE_ID.fullmatch(release_id):fail('Invalid code generation identity.')
    root=Path(root);temporary=root/('.current-'+uuid.uuid4().hex)
    os.symlink('releases/'+release_id,temporary)
    try:os.replace(temporary,root/'current');_sync(root)
    finally:temporary.unlink(missing_ok=True)


def _commit(root,journal):
    root=Path(root)
    _switch(root,journal['new_release'])
    atomic_json(root/'installation.json',journal['new_manifest'])
    atomic_json(_store(root)/'history'/(journal['transaction_id']+'.json'),journal)
    (root/'upgrade-pending.json').unlink();_sync(root)


def activate(root,digest,*,reviewed_digest,rollback=False):
    root=Path(root)
    if reviewed_digest!=digest:fail('Review the exact staged source, then pass its full digest with --reviewed-digest. Staging never executes candidate code.')
    with _stopped(root):
        previous=validate_layout(root);old=_json(root/'installation.json');_verify_manifest(root,old)
        candidate,report,meta,files=_candidate(root,digest);_compatible(old,report,rollback=rollback)
        policy=_policy_digest(root);private_state=_permanent_fingerprint(root)
        checked=_run_checks(root,candidate,digest)
        # A candidate test is reviewed host code. Revalidate all permanent facts
        # after it finishes; never accept test-written policy or quota resets.
        if _json(root/'installation.json')!=old:fail('Installation metadata changed during candidate verification. No generation was activated.')
        _verify_manifest(root,old)
        if _policy_digest(root)!=policy or _permanent_fingerprint(root)!=private_state:
            fail('Managed policy, credentials, or accounting changed during candidate verification. No code was activated and no private state was restored. Investigate before continuing.')
        _candidate(root,digest)
        release_id,payload=_generation(root,report,meta,files,kind='rollback' if rollback else 'upgrade')
        if _json(root/'installation.json')!=old:fail('Installation metadata changed while rendering candidate policy. No generation was activated.')
        _verify_manifest(root,old)
        if _policy_digest(root)!=policy or _permanent_fingerprint(root)!=private_state:
            fail('Managed policy, credentials, or accounting changed while rendering candidate policy. No code was activated and no private state was restored.')
        _candidate(root,digest)
        new=_new_manifest(root,old,payload,release_id,report);_verify_manifest(root,new,payload)
        journal={'version':1,'transaction_id':uuid.uuid4().hex,'at':time.time(),
                 'old_release':previous.name,'new_release':release_id,
                 'old_manifest':old,'new_manifest':new,'policy_digest':policy,
                 'checks_digest':checked,'source_digest':digest}
        _invalidate(root)
        atomic_json(root/'upgrade-pending.json',journal)
        _commit(root,journal)
        return {'active_release':release_id,'harness_version':report['harness_version'],
                'source_digest':digest,'usage_preserved':True,'native_prepare_required':True}


def _journal(root):
    journal=_json(Path(root)/'upgrade-pending.json')
    keys={'version','transaction_id','at','old_release','new_release','old_manifest','new_manifest','policy_digest','checks_digest','source_digest'}
    if not isinstance(journal,dict) or set(journal)!=keys or journal['version']!=1 or not re.fullmatch(r'[a-f0-9]{32}',journal.get('transaction_id','')):
        fail('The interrupted activation journal is invalid; no state was guessed.')
    for key in ('old_release','new_release'):
        if not isinstance(journal[key],str) or not RELEASE_ID.fullmatch(journal[key]):fail('The interrupted activation identity is invalid.')
    for key in ('policy_digest','checks_digest','source_digest'):
        if not isinstance(journal[key],str) or not DIGEST.fullmatch(journal[key]):fail('The interrupted activation proof is invalid.')
    return journal


def recover(root,*,finish=False):
    root=Path(root)
    with _stopped(root,allow_pending=True):
        journal=_journal(root)
        for name in ('app','kit'):
            alias=root/name
            if not alias.is_symlink() or alias.readlink()!=Path('current')/name:fail('Managed code aliases changed. Recovery stopped without following an unreviewed directory.')
        if _policy_digest(root)!=journal['policy_digest']:fail('Managed policy changed during an interrupted activation. Recovery stopped without restoring stale permissions.')
        current=_json(root/'installation.json')
        if current not in (journal['old_manifest'],journal['new_manifest']):fail('The current manifest differs from both recorded generations. Recovery stopped without guessing.')
        chosen='new' if finish else 'old'
        payload=root/'releases'/journal[chosen+'_release']
        if payload.is_symlink() or _json(payload/'.installation-root')!={'version':LAYOUT_VERSION,'root':str(root.resolve())}:fail('The selected recovery generation belongs to another installation.')
        _verify_manifest(root,journal[chosen+'_manifest'],payload)
        _invalidate(root);_switch(root,journal[chosen+'_release'])
        atomic_json(root/'installation.json',journal[chosen+'_manifest'])
        atomic_json(_store(root)/'history'/(journal['transaction_id']+'-recovered.json'),{**journal,'recovered_to':chosen})
        (root/'upgrade-pending.json').unlink();_sync(root)
        return {'recovered_to':chosen,'usage_preserved':True,'native_prepare_required':True}


def rollback(root,release_id):
    root=Path(root)
    if not isinstance(release_id,str) or not RELEASE_ID.fullmatch(release_id):fail('Choose an installed generation from upgrade list.')
    # A historical generated kit is never reactivated. Its retained pristine
    # source is staged, checked, and rendered with today's managed policy.
    payload=root/'releases'/release_id
    if payload.is_symlink() or _json(payload/'.installation-root')!={'version':LAYOUT_VERSION,'root':str(root.resolve())}:fail('The historical generation does not belong to this installation.')
    report=_json(payload/'source-report.json')
    digest=hashlib.sha256(canonical(report)).hexdigest()
    if report.get('files')!=_tree(payload/'source'):fail('The retained source changed; rollback was refused.')
    staged=stage(root,payload/'source',source_pin=report.get('source_pin'))
    if staged['digest']!=digest:fail('The retained source no longer matches its reviewed inventory.')
    return activate(root,digest,reviewed_digest=digest,rollback=True)


def inventory(root):
    root=Path(root);current=active_payload(root).name;rows=[]
    for payload in sorted((root/'releases').iterdir()):
        if payload.is_symlink() or not payload.is_dir() or not RELEASE_ID.fullmatch(payload.name):continue
        try:descriptor=_json(payload/'release.json')
        except Denied:
            rows.append({'release':payload.name,'active':payload.name==current,'status':'incomplete; not selected'})
            continue
        rows.append({'release':payload.name,'harness_version':descriptor.get('harness_version'),
                     'source_digest':descriptor.get('source_digest'),'active':payload.name==current})
    return {'active_release':current,'activation_pending':(root/'upgrade-pending.json').exists(),'releases':rows}


def command(root,args):
    parser=argparse.ArgumentParser(prog='codex-api upgrade',description='Stage and review code without rolling back keys, policies, or usage.')
    sub=parser.add_subparsers(dest='action',required=True)
    sub.add_parser('list')
    source=sub.add_parser('stage');source.add_argument('source',type=Path);source.add_argument('--source-pin')
    select=sub.add_parser('activate');select.add_argument('--reviewed-digest',required=True)
    restore=sub.add_parser('rollback');restore.add_argument('release')
    repair=sub.add_parser('recover');repair.add_argument('--finish',action='store_true')
    options=parser.parse_args(args)
    if options.action=='list':result=inventory(root)
    elif options.action=='stage':result=stage(root,options.source,source_pin=options.source_pin)
    elif options.action=='activate':result=activate(root,options.reviewed_digest,reviewed_digest=options.reviewed_digest)
    elif options.action=='rollback':result=rollback(root,options.release)
    else:result=recover(root,finish=options.finish)
    print(json.dumps(result,indent=2))
    if result.get('native_prepare_required'):print('Run codex-api prepare before the next session. Existing project files, credentials, and the ledger remain in place.')
    return result
