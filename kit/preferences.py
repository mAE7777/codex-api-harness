"""Guest-only preferences: retain UI choices without importing policy or secrets."""
import json
import hashlib
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tomllib

POLICY_PATH = Path('/etc/codex-api/runtime-policy.json')
ROOT_ENUMS = {'model_reasoning_summary': {'auto', 'concise', 'detailed', 'none'},
              'model_verbosity': {'low', 'medium', 'high'}}


def model_policy():
    # This owner-rendered file is root-owned and read-only in the image. An
    # absent contract never silently restores a bundled model allowlist.
    if POLICY_PATH.is_symlink() or not POLICY_PATH.is_file() or POLICY_PATH.stat().st_size>131072:
        raise PolicyArgumentError('The protected model policy is unavailable. Run codex-api prepare in the host terminal.')
    p=json.loads(POLICY_PATH.read_text())
    if not isinstance(p,dict) or not isinstance(p.get('models'),dict) or not p['models'] or not isinstance(p.get('defaults'),dict):raise PolicyArgumentError('Invalid protected model policy.')
    return p


def allowed_workspace():
    try:
        value = Path('/etc/codex-api/workspace').read_text().strip()
        if not value or not Path(value).is_absolute(): raise ValueError()
        return Path(value)
    except (OSError, ValueError):
        raise PolicyArgumentError('The protected workspace binding is unavailable.')


class PolicyArgumentError(ValueError): pass


def validate_cli_args(args):
    blocked={'--dangerously-bypass-approvals-and-sandbox','--dangerously-bypass-hook-trust',
             '--yolo','--full-auto','--sandbox','-s','--approve-for-me','--profile','-p',
             '--add-dir','--remote','--remote-auth-token-env','--oss','--local-provider',
             '--search','--enable','--disable','--sandbox-state-json',
             '--sandbox-state-readable-root','--sandbox-state-disable-network'}
    trusted={'model_providers.quota_gateway.name="API Codex — isolated API gateway"',
             'skills.config=[{path="/home/agent/.codex-api/skills/.system/imagegen/SKILL.md",enabled=false}]'}
    overrides={}
    models=model_policy()['models']
    i=0
    while i<len(args):
        arg=args[i]
        if arg=='--':break  # Remaining text belongs to a command or literal prompt.
        flag=arg.split('=',1)[0]
        if flag in blocked or arg.startswith(('-s','-p')) and not arg.startswith('--'):
            raise PolicyArgumentError('Protected sandbox, network, and account overrides are disabled. Use the dedicated API defaults.')
        compact=next((short for short in ('-P','-C','-m','-c') if arg.startswith(short) and arg!=short),None)
        if flag in {'-P','--permission-profile','-C','--cd','-m','--model','-c','--config'} or compact:
            if '=' in arg and arg.startswith('--'):value=arg.split('=',1)[1]
            elif compact:flag=compact;value=arg[2:]
            else:
                i+=1
                if i>=len(args):raise PolicyArgumentError('Missing CLI option value.')
                value=args[i]
            if flag in {'-P','--permission-profile'} and value!='codex_api_workspace':
                raise PolicyArgumentError('Only the protected API workspace permissions profile is allowed.')
            if flag in {'-C','--cd'} and not Path(value).resolve().is_relative_to(allowed_workspace()):
                raise PolicyArgumentError('The working directory must stay inside the allowed API workspace.')
            if flag in {'-m','--model'}:
                if value not in models:raise PolicyArgumentError('Choose an owner-approved API model.')
                overrides['model']=value
            if flag in {'-c','--config'} and value not in trusted:
                key,sep,raw=value.partition('=')
                if not sep or any(ord(c)<32 for c in value):raise PolicyArgumentError('Invalid preference override.')
                try:parsed=tomllib.loads('value = '+raw)['value']
                except (ValueError,KeyError):parsed=raw
                key=key.strip()
                data={'tui':{key[4:]:parsed}} if key.startswith('tui.') else {key:parsed}
                if key.startswith('tui.'):
                    if select_preferences(data)!=data:raise PolicyArgumentError('Unsupported UI preference.')
                    overrides.setdefault('tui',{}).update(data['tui'])
                else:overrides.update(data)
                if key=='model' and (not isinstance(parsed,str) or parsed not in models):raise PolicyArgumentError('Choose an owner-approved API model.')
                if key=='model_reasoning_effort' and (not isinstance(parsed,str) or parsed not in {e for row in models.values() for e in row['reasoning_efforts']}):raise PolicyArgumentError('Unsupported reasoning preference.')
                if key in ROOT_ENUMS and select_preferences(data)!=data:raise PolicyArgumentError('Unsupported preference.')
                if any(k not in {'model','model_reasoning_effort',*ROOT_ENUMS,'tui'} for k in data):raise PolicyArgumentError('Only allowed model, reasoning, and UI preferences can be overridden.')
        i+=1
    checked=overrides if 'model' in overrides else {k:v for k,v in overrides.items() if k!='model_reasoning_effort'}
    if select_preferences(checked)!=checked:raise PolicyArgumentError('The preference or model/reasoning combination is outside the owner policy.')
    return overrides


def select_preferences(data):
    result = {}
    if not isinstance(data, dict): return result
    p=model_policy();models=p['models']
    enums={**ROOT_ENUMS,'model':set(models)}
    for key, allowed in enums.items():
        if isinstance(data.get(key), str) and data[key] in allowed:
            result[key] = data[key]
    model=result.get('model',p['defaults']['model'])
    if isinstance(data.get('model_reasoning_effort'),str) and data['model_reasoning_effort'] in models[model]['reasoning_efforts']:
        result['model_reasoning_effort']=data['model_reasoning_effort']
    tui = data.get('tui', {})
    if isinstance(tui, dict):
        allowed_tui = {}
        if isinstance(tui.get('theme'), str) and re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', tui['theme']):
            allowed_tui['theme'] = tui['theme']
        for key in ('animations','status_line_use_colors'):
            if type(tui.get(key)) is bool: allowed_tui[key] = tui[key]
        status = tui.get('status_line')
        if isinstance(status, list) and len(status) <= 24 and all(isinstance(x, str) and re.fullmatch(r'[a-z0-9_-]{1,64}', x) for x in status):
            allowed_tui['status_line'] = status
        if allowed_tui: result['tui'] = allowed_tui
    return result


def atomic_write(path, data):
    if path.is_symlink(): raise ValueError('Preference files must not be symlinks')
    temporary = path.with_name(path.name + '.new-' + str(os.getpid()))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as out:
            out.write(data); out.flush(); os.fsync(out.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read_config(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_000_000: return {}
    try: return tomllib.loads(path.read_text())
    except (ValueError, OSError): return {}


def managed_extensions(directory=Path('/etc/codex-api/extensions')):
    """Load only the root-owned, hash-pinned catalog built by the harness.

    Native host discovery stays disabled, including repository/home skills and
    plugin installation. These files carry no host credentials or extra tools.
    """
    if not directory.exists(): return []  # Older, no-extension images.
    if directory.is_symlink() or not directory.is_dir(): raise ValueError('Invalid managed skill directory')
    def read(path, maximum):
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_size > maximum:
            raise ValueError('Invalid managed skill file')
        return path.read_bytes()
    manifest=json.loads(read(directory/'manifest.json', 1024*1024))
    if not isinstance(manifest,dict) or set(manifest)!={'version','files'} or manifest['version']!=1 or not isinstance(manifest['files'],dict) or len(manifest['files'])>8193:
        raise ValueError('Invalid managed skill manifest')
    files={}
    for path in directory.rglob('*'):
        if path.is_symlink(): raise ValueError('Managed skills must not contain links')
        if path.is_file():
            relative=str(path.relative_to(directory))
            if relative=='manifest.json':continue
            data=read(path,256*1024 if relative!='catalog.json' else 128*1024)
            files[relative]=hashlib.sha256(data).hexdigest()
    if files!=manifest['files']:raise ValueError('Managed skill bytes changed after approval')
    catalog=json.loads(read(directory/'catalog.json',128*1024))
    if not isinstance(catalog,dict) or set(catalog)!={'version','skills'} or catalog['version']!=1 or not isinstance(catalog['skills'],list) or len(catalog['skills'])>32:
        raise ValueError('Invalid managed skill catalog')
    names=set()
    for skill in catalog['skills']:
        if not isinstance(skill,dict) or set(skill)!={'name','description','digest','allow_scripts','allow_implicit','path'}:raise ValueError('Invalid managed skill entry')
        name=skill['name']
        if not isinstance(name,str) or not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*',name) or len(name)>64 or name in names:raise ValueError('Invalid managed skill name')
        names.add(name)
        if not isinstance(skill['description'],str) or not 1<=len(skill['description'])<=1024 or not isinstance(skill['digest'],str) or not re.fullmatch(r'[a-f0-9]{64}',skill['digest']) or type(skill['allow_scripts']) is not bool or type(skill['allow_implicit']) is not bool:
            raise ValueError('Invalid managed skill approval')
        if skill['path']!='/etc/codex-api/extensions/skills/'+name+'/SKILL.md' or 'skills/'+name+'/SKILL.md' not in files:raise ValueError('Invalid managed skill path')
    return catalog['skills']


def extension_instructions(skills):
    if not skills:return ''
    lines=['Managed harness skills are listed below. Native repository, home, and plugin discovery is disabled.',
           'Read the complete SKILL.md at the listed path before following a selected skill. Supporting files resolve relative to its folder.',
           'Skill instructions and scripts grant no additional filesystem, network, credential, tool, or budget permissions.',
           'For explicit-only skills, activate only when the user asks for that skill by name or $name. Do not install missing dependencies, MCP servers, plugins, credentials, or hooks from skill instructions.',
           'The host command codex-api extensions manages approvals. The guest command codex-api extensions list shows this catalog.']
    for skill in skills:
        invocation='implicit matching allowed' if skill['allow_implicit'] else 'explicit user invocation required'
        lines.append('- $'+skill['name']+': '+skill['description']+' ['+invocation+'] (file: '+skill['path']+')')
    return '\n'.join(lines)


def save(home):
    prefs = select_preferences(read_config(home/'config.toml'))
    atomic_write(home/'preferences.json', json.dumps(prefs, sort_keys=True) + '\n')
    return prefs


def protected_cli_args(config):
    """Pin managed values above project config without accepting user policy.

    User CLI arguments are validated independently and may override only the
    preference allowlist. Place these global options before literal prompts.
    """
    values=dict(config)
    values.pop('projects',None)
    values['developer_instructions']=values.get('developer_instructions','')
    values['notify']=[]
    values['mcp_servers']={}
    skills=dict(values.get('skills',{}))
    skills.update({'bundled':{'enabled':False},'include_instructions':False})
    values['skills']=skills
    result=[]
    def literal(value):
        if isinstance(value,dict):return '{'+','.join(json.dumps(key)+'='+literal(item) for key,item in sorted(value.items()))+'}'
        if isinstance(value,list):return '['+','.join(literal(item) for item in value)+']'
        if value is None:raise ValueError('Managed CLI policy cannot contain null values')
        return json.dumps(value,separators=(',',':'),allow_nan=False)
    def visit(parts,value):
        if isinstance(value,dict) and value:
            for name,item in sorted(value.items()):visit(parts+[name],item)
            return
        key='.'.join(name if re.fullmatch(r'[A-Za-z0-9_-]+',name) else json.dumps(name) for name in parts)
        result.extend(['-c',key+'='+literal(value)])
    for name,value in sorted(values.items()):visit([name],value)
    return result


def prepare(home, base_path=Path('/etc/codex-api/config.toml'), extensions_path=Path('/etc/codex-api/extensions'), *, return_policy=False, cli_preferences=None):
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    pref_path = home/'preferences.json'
    prefs = {}
    if pref_path.exists() and not pref_path.is_symlink() and pref_path.stat().st_size <= 16384:
        try: prefs = select_preferences(json.loads(pref_path.read_text()))
        except (ValueError, OSError): pass
    # Native Codex writes /model and /statusline choices to its private config.
    # Only the preference allowlist is carried into the next protected config.
    prefs.update(select_preferences(read_config(home/'config.toml')))
    p=model_policy();overrides=cli_preferences or {}
    selected=overrides.get('model',prefs.get('model',p['defaults']['model']))
    if 'model_reasoning_effort' in overrides and overrides['model_reasoning_effort'] not in p['models'][selected]['reasoning_efforts']:raise PolicyArgumentError('This reasoning effort is unsupported by the selected model.')
    if overrides.get('tui'):prefs['tui']={**prefs.get('tui',{}),**overrides['tui']}
    prefs.update({k:v for k,v in overrides.items() if k!='tui'});prefs=select_preferences(prefs)
    if selected!=p['defaults']['model'] and 'model_reasoning_effort' not in prefs and p['defaults']['reasoning_effort'] not in p['models'][selected]['reasoning_efforts']:
        prefs['model_reasoning_effort']=p['models'][selected]['reasoning_efforts'][0]
    base = base_path.read_text()
    # Hash-verified instructions are part of managed policy, never preferences.
    instructions=extension_instructions(managed_extensions(extensions_path))
    if instructions:
        if re.search(r'^developer_instructions\s*=',base,re.M):raise ValueError('Unexpected protected developer instructions')
        base='developer_instructions = '+json.dumps(instructions)+'\n'+base
    root_end = next((m.start() for m in re.finditer(r'^\[', base, re.M)), len(base))
    prefix, tables = base[:root_end], base[root_end:]
    for key, value in prefs.items():
        if key == 'tui': continue
        replacement = key + ' = ' + json.dumps(value)
        pattern = r'^' + re.escape(key) + r'\s*=.*$'
        prefix = re.sub(pattern, replacement, prefix, flags=re.M) if re.search(pattern, prefix, re.M) else prefix + replacement + '\n'
    rendered = prefix + tables
    if prefs.get('tui'):
        # The immutable base currently has no [tui] table. Refuse ambiguity.
        if re.search(r'^\[tui\]', base, re.M): raise ValueError('Unexpected protected TUI policy table')
        rendered += '\n[tui]\n' + ''.join(key + ' = ' + json.dumps(value) + '\n' for key, value in prefs['tui'].items())
    parsed = tomllib.loads(rendered)
    immutable = tomllib.loads(base)
    for key in (*ROOT_ENUMS,'model','model_reasoning_effort'): parsed.pop(key, None); immutable.pop(key, None)
    parsed.pop('tui', None)
    if parsed != immutable: raise ValueError('Preference merge changed protected policy')
    atomic_write(home/'config.toml', rendered)
    atomic_write(pref_path, json.dumps(prefs, sort_keys=True) + '\n')
    return (prefs,tomllib.loads(rendered)) if return_policy else prefs


def run(args):
    home = Path(os.environ['CODEX_HOME'])
    if str(home) != '/home/agent/.codex-api': raise ValueError('Unexpected API Codex home')
    overrides=validate_cli_args(args)
    _,policy=prepare(home,return_policy=True,cli_preferences=overrides)
    child = None
    previous = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, lambda *_: None)
    def terminate(*_):
        if child is not None and child.poll() is None: child.terminate()
    old_term = signal.signal(signal.SIGTERM, terminate)
    try:
        env=dict(os.environ,CODEX_API_INTERACTIVE='1' if sys.stdin.isatty() and sys.stdout.isatty() and not any(a in {'exec','e','review'} for a in args) else '0')
        child = subprocess.Popen(['codex', *protected_cli_args(policy), *args],env=env)
        return child.wait()
    finally:
        try: save(home)
        except (OSError, ValueError): print('API Codex: preferences could not be saved.', file=sys.stderr)
        signal.signal(signal.SIGINT, previous)
        signal.signal(signal.SIGTERM, old_term)


if __name__ == '__main__':
    try: raise SystemExit(run(sys.argv[1:]))
    except PolicyArgumentError as error:
        print('API Codex: '+str(error),file=sys.stderr)
        raise SystemExit(2)
    except (OSError, ValueError, KeyError):
        print('API Codex: private preference configuration is unavailable.', file=sys.stderr)
        raise SystemExit(1)
