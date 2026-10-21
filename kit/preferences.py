"""Guest-only preferences: retain UI choices without importing policy or secrets."""
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tomllib

MODELS = {'gpt-6-astra', 'gpt-6.1-sol', 'gpt-6-luna', 'gpt-5.6-terra', 'gpt-5.6-luna'}
EFFORTS = {'low', 'medium', 'high', 'xhigh', 'max', 'ultra'}
ROOT_ENUMS = {'model': MODELS, 'model_reasoning_effort': EFFORTS,
              'model_reasoning_summary': {'auto', 'concise', 'detailed', 'none'},
              'model_verbosity': {'low', 'medium', 'high'}}


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
            if flag in {'-m','--model'} and value not in MODELS:
                raise PolicyArgumentError('Choose one of the five allowed API models.')
            if flag in {'-c','--config'} and value not in trusted:
                key,sep,raw=value.partition('=')
                if not sep or any(ord(c)<32 for c in value):raise PolicyArgumentError('Invalid preference override.')
                try:parsed=tomllib.loads('value = '+raw)['value']
                except (ValueError,KeyError):parsed=raw
                key=key.strip()
                data={'tui':{key[4:]:parsed}} if key.startswith('tui.') else {key:parsed}
                if select_preferences(data)!=data:raise PolicyArgumentError('Only allowed model, reasoning, and UI preferences can be overridden.')
        i+=1


def select_preferences(data):
    result = {}
    if not isinstance(data, dict): return result
    for key, allowed in ROOT_ENUMS.items():
        if isinstance(data.get(key), str) and data[key] in allowed:
            result[key] = data[key]
    if result.get('model') in {'gpt-6-luna', 'gpt-5.6-luna'} and result.get('model_reasoning_effort') == 'ultra':
        result['model_reasoning_effort'] = 'max'
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


def save(home):
    prefs = select_preferences(read_config(home/'config.toml'))
    atomic_write(home/'preferences.json', json.dumps(prefs, sort_keys=True) + '\n')
    return prefs


def prepare(home, base_path=Path('/etc/codex-api/config.toml')):
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    pref_path = home/'preferences.json'
    prefs = {}
    if pref_path.exists() and not pref_path.is_symlink() and pref_path.stat().st_size <= 16384:
        try: prefs = select_preferences(json.loads(pref_path.read_text()))
        except (ValueError, OSError): pass
    # Native Codex writes /model and /statusline choices to its private config.
    # Only the preference allowlist is carried into the next protected config.
    prefs.update(select_preferences(read_config(home/'config.toml')))
    base = base_path.read_text()
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
    for key in ROOT_ENUMS: parsed.pop(key, None); immutable.pop(key, None)
    parsed.pop('tui', None)
    if parsed != immutable: raise ValueError('Preference merge changed protected policy')
    atomic_write(home/'config.toml', rendered)
    atomic_write(pref_path, json.dumps(prefs, sort_keys=True) + '\n')
    return prefs


def run(args):
    home = Path(os.environ['CODEX_HOME'])
    if str(home) != '/home/agent/.codex-api': raise ValueError('Unexpected API Codex home')
    validate_cli_args(args)
    prepare(home)
    child = None
    previous = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, lambda *_: None)
    def terminate(*_):
        if child is not None and child.poll() is None: child.terminate()
    old_term = signal.signal(signal.SIGTERM, terminate)
    try:
        env=dict(os.environ,CODEX_API_INTERACTIVE='1' if sys.stdin.isatty() and sys.stdout.isatty() and not any(a in {'exec','e','review'} for a in args) else '0')
        child = subprocess.Popen(['codex', *args],env=env)
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
