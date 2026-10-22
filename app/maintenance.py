"""Explicit host-only credential rotation and additional protected paths."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import time
import uuid

from guard import Denied, atomic_json


@contextlib.contextmanager
def stopped(root):
    root=Path(root)
    if (root/'upgrade-pending.json').exists():raise Denied('Complete codex-api upgrade recover before changing credentials or filesystem policy.',code='upgrade_recovery_required')
    with (root/'session.lock').open('a+b') as lease:
        try:fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise Denied('Exit the API session before changing this setting. The running session was left unchanged.')
        if (root/'gateway-process.json').exists():raise Denied('Stop the API gateway before changing this setting.')
        yield


def rotation(root,args):
    root=Path(root)
    parser=argparse.ArgumentParser(prog='codex-api credentials')
    parser.add_argument('action',choices=['stage','activate'])
    options=parser.parse_args(args)
    with stopped(root):
        if (root/'team-client.json').exists():raise Denied('This client has no OpenAI key. Rotate its member credential at the coordinator instead.')
        staging=root/'openai-key.next.env'
        if options.action=='stage':
            if not staging.exists():
                fd=os.open(staging,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'w') as out:out.write('# New key for the SAME organization and project; fill locally.\nOPENAI_API_KEY=\n')
            elif staging.is_symlink() or staging.stat().st_mode&0o077:
                raise Denied('The staged key file is unsafe; it was not changed.')
            print('Fill the new key locally: '+str(staging))
            print('Keep the same organization and project, then run codex-api credentials activate. No key is sent to a provider for validation.')
            return
        from gateway import credentials
        values=credentials(staging)
        key=values.get('OPENAI_API_KEY')
        if set(values)!={'OPENAI_API_KEY'} or not isinstance(key,str) or len(key)<20 or not key.isascii():
            raise Denied('The staged key is missing or malformed. The current key was preserved.')
        profile=json.loads((root/'verification.json').read_text()).get('openai',{})
        if not profile.get('account_configured'):raise Denied('Configure the account binding before rotating its key.')
        current=root/'openai-key.env'
        if current.is_symlink() or current.stat().st_mode&0o077:raise Denied('The current key file is unsafe.')
        # No old key backup; ledger and account binding remain at their original paths.
        os.replace(staging,current)
        descriptor=os.open(root,os.O_RDONLY)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
        atomic_json(root/'last-key-rotation.json',{'version':1,'at':time.time(),'provider_requests':0,'account_binding_preserved':True})
    print('Key rotated locally. Organization, project, usage, and billing policy were preserved. Account access is checked by OpenAI on the next authorized request.')


def protect(root,args):
    root=Path(root)
    parser=argparse.ArgumentParser(prog='codex-api protect')
    parser.add_argument('action',choices=['list','add','remove'])
    parser.add_argument('paths',nargs='*')
    options=parser.parse_args(args)
    from workspace_policy import protected_paths, validate_protected_paths, update_managed_path_masks
    current=protected_paths(root)
    if options.action=='list':
        if options.paths:parser.error('list accepts no paths')
        print('\n'.join(current) if current else 'No additional protected paths. Built-in credential protections remain enabled.')
        return False
    if not options.paths:parser.error('Choose at least one workspace-relative path')
    chosen=validate_protected_paths(options.paths)
    with stopped(root):
        # Re-read while holding the session lease.
        current=protected_paths(root)
        updated=sorted(set(current)|set(chosen)) if options.action=='add' else sorted(set(current)-set(chosen))
        if updated==current:print('Protected paths are unchanged.');return False
        settings=json.loads((root/'settings.json').read_text())
        manifest=json.loads((root/'installation.json').read_text())
        target=root/'kit/requirements.toml'
        content=target.read_bytes() if not target.is_symlink() else b''
        if target.is_symlink() or hashlib.sha256(content).hexdigest()!=manifest['files'].get('kit/requirements.toml'):
            raise Denied('Managed filesystem policy integrity failed; no setting was changed.')
        data=update_managed_path_masks(content,Path(settings['workspace']),current,updated)
        # Every intermediate crash is fail-closed: readiness or the manifest differs.
        ready=json.loads((root/'readiness.json').read_text())
        for field in ('image_built','filesystem_tested','network_tested','host_integrations_absent','codex_protocol_tested'):ready[field]=False
        atomic_json(root/'readiness.json',ready)
        atomic_json(root/'protected-paths.json',updated)
        temporary=target.with_name(target.name+'.'+uuid.uuid4().hex)
        temporary.write_bytes(data);temporary.chmod(0o600);os.replace(temporary,target)
        manifest['files']['kit/requirements.toml']=hashlib.sha256(data).hexdigest()
        atomic_json(root/'installation.json',manifest)
    print('Protected paths updated. Rebuilding the owned sandbox applies the new native file masks; project files and usage are preserved.')
    return True
