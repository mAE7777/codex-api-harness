#!/usr/bin/env python3
"""Private, resumable local installation. Python standard library only."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

SOURCE = Path(__file__).resolve().parent
sys.path.insert(0, str(SOURCE/'app'))
from guard import Denied, Ledger, atomic_json
from workspace_policy import check_workspace, managed_requirements

VERSION = '0.4.0'
INSTALL_LAYOUT_VERSION = 2
UPDATER_ABI = 1
SBX_VERSION = '0.49.1'
CODEX_VERSION = '0.162.1'
PLAYWRIGHT_VERSION = '0.1.22'
SBX_URL = 'https://github.com/docker/sbx-releases/releases/download/v0.49.1/DockerSandboxes-darwin.tar.gz'
SBX_SHA256 = 'e797bd6ed882cdfbd415318f44f2569d7238d14763fe2c445773099e2e613385'
DEFAULT_HOME = Path.home()/'Library/Application Support/CodexAPIHarness'
APP_FILES = ('settings.py','guard.py','gateway.py','controller.py','diagnostics.py',
             'recovery.py','transport_control.py','workspace_policy.py','onboarding.py','provision.py',
             'team_client.py','shared.py','extensions.py','maintenance.py','releases.py',
             'session_state.py','team_ssh.py','policy.py','configuration.py','runtime_controls.py','activity.py','checkpoints.py','extension_risks.py')
KIT_FILES = ('codex-api.yaml','codex-api.dockerfile','config.toml','models.json',
             'model-template.json','runtime-policy.json','entrypoint.sh','preferences.py','quota-client.py','quota-notice.py','web-tool.py','npmrc','local-tools.py')


def default_sbx():
    command = shutil.which('sbx')
    if command: return Path(command).resolve()
    for name in ('Sbx.app','Docker Sandboxes.app'):
        p=Path('/Applications')/name/'Contents/MacOS/sbx'
        if p.is_file(): return p
    return None


def inspect_context():
    """Inventory only. Never enumerate repositories, env values, or auth files."""
    sbx=default_sbx()
    version=None
    if sbx:
        try:
            r=subprocess.run([str(sbx),'version'],capture_output=True,text=True,timeout=10)
            found=re.search(r'v?(0\.\d+\.\d+)\b',r.stdout)
            version=found.group(1) if r.returncode==0 and found else 'unavailable'
        except (OSError,subprocess.TimeoutExpired): version='unavailable'
    wrapper=Path.home()/'.local/bin/codex-api'
    return {'os':platform.system(),'architecture':platform.machine(),
            'python_version':platform.python_version(),
            'supported':platform.system()=='Darwin' and platform.machine()=='arm64' and sys.version_info>=(3,11,8),
            'sandbox_cli_found':sbx is not None,'sandbox_cli_version':version,
            'python_requirement':'3.11.8+','sandbox_requirement':SBX_VERSION,
            'existing_subscription_config':(Path.home()/'.codex/config.toml').exists(),
            'existing_launcher':wrapper.exists() or wrapper.is_symlink(),
            'existing_harness':(DEFAULT_HOME/'installation.json').is_file(),
            'install_directory':str(DEFAULT_HOME),'launcher_directory':str(wrapper.parent),
            'launcher_on_path':str(wrapper.parent) in os.environ.get('PATH','').split(os.pathsep),
            'provider_requests':0,'secret_contents_read':False}


def validate_locations(root, workspace, launcher):
    if not root.is_absolute() or not workspace.is_absolute() or not launcher.is_absolute():
        raise ValueError('Installation, workspace, and launcher paths must be absolute.')
    for target in (root,workspace,launcher):
        if target.is_symlink() or any(p.is_symlink() for p in target.parents):
            # macOS /var -> /private/var is canonicalized by the caller first.
            raise ValueError('Use real directories without symlinked path components.')
        if any(ord(c)<32 for c in str(target)): raise ValueError('Control characters are not allowed in paths.')
    forbidden={Path('/'),Path.home(),Path.home()/'Projects',Path.home()/'Documents',Path.home()/'Downloads',Path.home()/'.codex',Path.home()/'Library'}
    if workspace in forbidden or workspace.is_relative_to(Path.home()/'.codex'):
        raise ValueError('Choose a dedicated project directory, not your home, Downloads, Documents, or subscription directory.')
    if root.is_relative_to(workspace) or workspace.is_relative_to(root):
        raise ValueError('The private installation and shared workspace must be separate.')
    if SOURCE.is_relative_to(workspace) or workspace==SOURCE:
        raise ValueError('Keep this source checkout outside the shared workspace.')
    check_workspace(workspace) if workspace.exists() else None


def launcher_text(root):
    code='import sys;from pathlib import Path;sys.path.insert(0,str(Path('+repr(str(root/'app'))+').resolve(strict=True)));from controller import main;sys.exit(main())'
    prefix='exec '+shlex.quote(str(Path(sys.executable).resolve()))+' -I -c '+shlex.quote(code)
    return ('#!/bin/sh\n# codex-api-harness launcher; subscription Codex is never invoked.\n'
            'case "${1-}" in\n'
            "  '') set -- start ;;\n"
            '  start|status|usage|doctor|explain|reconcile|stop|pause|login|prepare|reset|retire|configure|credentials|billing|policy|team|extensions|protect|upgrade|help) ;;\n'
            '  -h|--help) set -- help ;;\n'
            '  *) set -- start "$@" ;;\n'
            'esac\n'+prefix+' "$@"\n')


def bootstrap_sbx(stage):
    print('Downloading the pinned Docker Sandboxes CLI; checking SHA-256 before extraction.',flush=True)
    directory=stage/'vendor';directory.mkdir(mode=0o700)
    archive=directory/'sbx.tar.gz'
    with urllib.request.urlopen(SBX_URL,timeout=60) as response,archive.open('wb') as out:
        shutil.copyfileobj(response,out)
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=SBX_SHA256:
        raise ValueError('Docker Sandboxes archive checksum mismatch. Nothing was executed.')
    with tarfile.open(archive,'r:gz') as source:source.extractall(directory,filter='data')
    archive.unlink()
    candidates=list(directory.glob('**/Sbx.app/Contents/MacOS/sbx'))
    if len(candidates)!=1:raise ValueError('Unexpected Docker Sandboxes archive layout.')
    binary=candidates[0];app=binary.parents[2]
    subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(app)],check=True,capture_output=True)
    return binary.relative_to(stage)


def install(root,workspace,sbx=None,*,bootstrap=False,port=49188,launcher=None):
    """Creates only this installation. Never updates existing files or clears state."""
    os.umask(0o077)
    raw_root=Path(root).expanduser();raw_workspace=Path(workspace).expanduser()
    if raw_root.is_symlink() or raw_workspace.is_symlink():raise ValueError('Installation and workspace must not be symlinks.')
    root=raw_root.resolve();workspace=raw_workspace.resolve()
    launcher=Path(launcher or Path.home()/'.local/bin/codex-api').expanduser().absolute()
    validate_locations(root,workspace,launcher)
    if type(port) is not int or not 1024<=port<=65535:raise ValueError('Gateway port must be 1024..65535.')
    sbx=Path(sbx).expanduser().resolve() if sbx else default_sbx()
    if root.exists():
        manifest_path=root/'installation.json'
        if root.is_symlink() or not manifest_path.is_file():raise ValueError('The installation directory already exists without an owned manifest. It was left unchanged.')
        manifest=json.loads(manifest_path.read_text())
        if (root/'upgrade-pending.json').exists():
            raise ValueError('A code activation was interrupted. Run codex-api upgrade recover; no private state was overwritten.')
        settings=json.loads((root/'settings.json').read_text())
        if manifest.get('harness_version')!=VERSION:
            raise ValueError('The installed harness version differs. Use a reviewed state-preserving upgrade; nothing was overwritten.')
        if sbx is not None and settings['sbx_path']!=str(sbx):
            raise ValueError('The installed runtime binding differs. No executable or state was replaced.')
        if settings['workspace']!=str(workspace) or settings['gateway_port']!=port:
            raise ValueError('Existing settings differ. No credentials, workspace binding, or quota were overwritten.')
        for relative,expected in manifest['files'].items():
            path=root/relative
            if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=expected:raise ValueError('Existing installation integrity failed. No repair or quota reset was attempted.')
        if manifest.get('layout_version')==INSTALL_LAYOUT_VERSION:
            from releases import validate_layout
            validate_layout(root)
        if launcher.is_symlink() or not launcher.is_file() or launcher.read_text()!=launcher_text(root):
            raise ValueError('The launcher differs or is missing. It was not overwritten.')
        return {'installed':True,'resumed':True,'root':str(root),'workspace':str(workspace),'provider_requests':0}
    if launcher.exists() or launcher.is_symlink():
        raise ValueError('A codex-api command already exists. It was left unchanged; use --launcher with another command name.')
    if not sbx and not bootstrap:raise ValueError('Docker Sandboxes is missing. Use --bootstrap-sbx to install the verified CLI privately, or install it from Docker.')
    if sbx:
        r=subprocess.run([str(sbx),'version'],capture_output=True,text=True,timeout=15)
        if r.returncode or not re.search(r'(?<![0-9.])v?'+re.escape(SBX_VERSION)+r'\b',r.stdout):raise ValueError('This release requires Docker Sandboxes '+SBX_VERSION+'. No runtime was replaced.')
    root.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.codex-api-install-',dir=root.parent) as temporary:
        stage=Path(temporary)/'installation';stage.mkdir(mode=0o700)
        for subdir in ('app','kit','bin'): (stage/subdir).mkdir(mode=0o700)
        if not sbx:
            relative=bootstrap_sbx(stage);sbx=root/relative
        name='codex-api-'+hashlib.sha256(str(root).encode()).hexdigest()[:10]
        settings={'workspace':str(workspace),'sbx_path':str(sbx),'sandbox_name':name,'gateway_port':port}
        atomic_json(stage/'settings.json',settings)
        for name in APP_FILES:(stage/'app'/name).write_bytes((SOURCE/'app'/name).read_bytes())
        for name in KIT_FILES:
            data=(SOURCE/'kit'/name).read_text()
            data=data.replace('__WORKSPACE_SHELL__',shlex.quote(str(workspace))).replace('__WORKSPACE_TOML__',json.dumps(str(workspace)))
            data=data.replace('49187',str(port))
            (stage/'kit'/name).write_text(data)
        (stage/'kit/workspace').write_text(str(workspace)+'\n')
        (stage/'kit/requirements.toml').write_text(managed_requirements(workspace))
        atomic_json(stage/'protected-paths.json',[])
        from extensions import render_build
        render_build(stage)
        wrapper=launcher_text(root)
        (stage/'bin/codex-api').write_text(wrapper);(stage/'bin/codex-api').chmod(0o700)
        # Blank private key file. The setup agent asks the owner to fill it locally.
        (stage/'openai-key.env').write_text('# Private host file; never mount or commit.\nOPENAI_API_KEY=\n')
        (stage/'gateway.token').write_text(secrets.token_urlsafe(48)+'\n')
        (stage/'paused').touch(mode=0o600)
        ledger=Ledger(stage/'state',initialize=True);ledger.close()
        atomic_json(stage/'verification.json',{'openai':{'enabled':False,'verified':False,'billing_policy':'free_only',
                    'account_configured':False,'quota_guard':True,'org_exclusive':False,
                    'policy':__import__('policy').empty()},
                    'tavily':{'enabled':False},'exa':{'enabled':False},'brave':{'enabled':False}})
        atomic_json(stage/'readiness.json',{k:False for k in ('docker_authenticated','image_built','filesystem_tested','network_tested','host_integrations_absent','codex_protocol_tested','openai_free_verified')})
        subscription=Path.home()/'.codex/config.toml'
        if subscription.is_symlink():raise ValueError('Subscription configuration is a symlink. Installation stopped without reading it.')
        baseline=hashlib.sha256(subscription.read_bytes()).hexdigest() if subscription.is_file() else None
        from releases import initialize_layout
        layout=initialize_layout(stage,root,source=SOURCE,version=VERSION)
        files={str(p.relative_to(stage)):hashlib.sha256(p.read_bytes()).hexdigest()
               for subdir in ('app','kit','bin') for p in (stage/subdir).rglob('*') if p.is_file()}
        files['settings.json']=hashlib.sha256((stage/'settings.json').read_bytes()).hexdigest()
        if sbx.is_relative_to(root):
            relative=str(sbx.relative_to(root));files[relative]=hashlib.sha256((stage/relative).read_bytes()).hexdigest()
        external_digest=hashlib.sha256(sbx.read_bytes()).hexdigest() if not sbx.is_relative_to(root) else None
        atomic_json(stage/'installation.json',{'version':1,'harness_version':VERSION,'files':files,'external_sbx_sha256':external_digest,**layout,
                    'subscription_config_sha256':baseline,'workspace':str(workspace),'owned_sandbox_name':settings['sandbox_name'],
                    'sbx_version':SBX_VERSION,'codex_version':CODEX_VERSION,'playwright_cli_version':PLAYWRIGHT_VERSION})
        if not workspace.exists():workspace.mkdir(mode=0o700,parents=True)
        stage.rename(root)
    launcher.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd=os.open(launcher,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700)
    with os.fdopen(fd,'w') as out:out.write(wrapper)
    return {'installed':True,'resumed':False,'root':str(root),'workspace':str(workspace),'launcher':str(launcher),'provider_requests':0}


def main(argv=None):
    parser=argparse.ArgumentParser(description='Install isolated API Codex. No provider requests or subscription changes.')
    parser.add_argument('action',nargs='?',choices=['inspect','install','recover'],default='install')
    parser.add_argument('--json',action='store_true')
    parser.add_argument('--workspace',type=Path)
    parser.add_argument('--home',type=Path,default=DEFAULT_HOME)
    parser.add_argument('--launcher',type=Path)
    parser.add_argument('--sbx',type=Path)
    parser.add_argument('--bootstrap-sbx',action='store_true')
    parser.add_argument('--port',type=int,default=49188)
    parser.add_argument('--finish',action='store_true',help='Finish an interrupted reviewed activation instead of selecting old code; recover only.')
    args=parser.parse_args(argv)
    try:
        if args.action=='inspect':print(json.dumps(inspect_context(),indent=2));return 0
        if args.finish and args.action!='recover':parser.error('--finish applies only to recover')
        if args.action=='recover':
            from releases import recover
            result=recover(args.home.expanduser().resolve(),finish=args.finish)
            print(json.dumps(result,indent=2))
            print('Recovery preserved private state. Run codex-api prepare before the next session.')
            return 0
        if platform.system()!='Darwin' or platform.machine()!='arm64' or sys.version_info<(3,11,8):
            raise ValueError('Supported: macOS on Apple Silicon, Python 3.11.8+. Nothing was installed.')
        if not args.workspace:
            if not sys.stdin.isatty():raise ValueError('Choose the dedicated project directory with --workspace PATH. Run inspect first; see SETUP.md.')
            print('This keeps API Codex separate, shares one project folder, and checks each request against a daily token budget.')
            value=input('Project folder [~/Projects/codex-workspace]: ').strip() or '~/Projects/codex-workspace'
            args.workspace=Path(value)
        result=install(args.home,args.workspace,args.sbx,bootstrap=args.bootstrap_sbx,port=args.port,launcher=args.launcher)
        print(json.dumps(result,indent=2) if args.json else 'Installed privately. No model request was made.\nKey file: '+str(Path(result['root'])/'openai-key.env')+'\nNext: follow SETUP.md to bind your account, prepare the sandbox, and choose whether API charges are allowed.')
        return 0
    except (Denied,OSError,ValueError,subprocess.SubprocessError,tarfile.TarError):
        # Do not echo subprocess argv, key-file content, or arbitrary provider output.
        error=sys.exc_info()[1]
        detail=str(error) if isinstance(error,(Denied,ValueError)) else 'a local operation failed; existing credentials and usage were not reset.'
        if isinstance(error,subprocess.CalledProcessError) and error.cmd and error.cmd[0]=='/usr/bin/codesign':
            detail='The Docker archive passed its checksum but failed macOS bundle verification. No downloaded executable was run. If using a sync or file-provider folder, retry with the default local installation directory. Do not bypass verification.'
        print('Setup stopped: '+detail,file=sys.stderr)
        return 1


if __name__=='__main__':raise SystemExit(main())
