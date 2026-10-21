"""Shared host preflight and matching native rules. No project copies or secret logging."""
import json
from pathlib import Path
import re
import urllib.parse

from guard import Denied

from settings import WORKSPACE
TEMPLATES = frozenset({'.env.example', '.env.sample', '.env.template', '.env.dist'})
PRIVATE_NAMES = frozenset({'search-keys.env','openai-key.env','docker-login.env','auth.json',
                           'id_rsa','id_ed25519','.npmrc','.netrc','.pypirc'})
PRIVATE_DIRS = frozenset({'.ssh','.aws','.gnupg'})
PRIVATE_EXTENSIONS = ('.pem','.p12','.pfx')
PUBLIC_CA_NAMES = frozenset({'cacert.pem','ca-bundle.pem'})


def public_ca_bundle(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size>3_000_000:return False
    try:data=path.read_text('utf-8')
    except (OSError,UnicodeError):return False
    if any(marker in data.lower() for marker in ('private key','sk-proj-','tvly-','github_pat_')):return False
    blocks=re.findall(r'-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----',data)
    if not blocks:return False
    import ssl
    try:
        if not all(ssl.PEM_cert_to_DER_cert(block) for block in blocks):return False
    except (ValueError,TypeError):return False
    remaining=re.sub(r'-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----','',data)
    return all(not line.strip() or line.lstrip().startswith('#') for line in remaining.splitlines())


def guest_venv_interpreter_link(path,root):
    """Standard venv aliases target the guest Python runtime, never a host mount."""
    if path.parent.name!='bin':return False
    venv=path.parent.parent;cfg=venv/'pyvenv.cfg'
    if not venv.is_relative_to(root) or cfg.is_symlink() or not cfg.is_file():return False
    current=path
    for _ in range(8):
        try:target=current.readlink()
        except OSError:return False
        if target.is_absolute():return bool(re.fullmatch(r'/usr/(?:local/)?bin/python(?:3(?:\.\d{1,2})?)?',str(target)))
        if str(target) in {'','.','..'} or '/' in str(target) or '\\' in str(target) or any(ord(c)<32 for c in str(target)):return False
        current=current.parent/target
        if not current.is_symlink():return False
    return False


def protected_name(name):
    name = name.lower()
    return (name in PRIVATE_NAMES or name in PRIVATE_DIRS or name == '.env'
            or name.startswith('.env.') and name not in TEMPLATES or name.endswith(PRIVATE_EXTENSIONS))


def safe_template(path):
    """Only empty values, explicit placeholders and small public examples qualify."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 32768: return False
    try: data = path.read_text()
    except (OSError, UnicodeError): return False
    for line in data.splitlines():
        line = line.strip()
        if not line or line.startswith('#'): continue
        if line.startswith('export '): line = line[7:]
        key, sep, value = line.partition('=')
        if not sep or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',key.strip()): return False
        value = value.strip()
        if value[:1] in {'"', "'"}:
            if len(value)<2 or value[-1]!=value[0]: return False
            value=value[1:-1]
        else: value=value.split(' #',1)[0].rstrip()
        if any(marker in value.lower() for marker in ('sk-proj-','tvly-','ghp_','github_pat_','begin private key','$(','`')): return False
        low=value.lower()
        if not value or re.fullmatch(r'\d{1,6}',value) or low in {'true','false','null','none','localhost','development','production','test','example','dummy','placeholder','changeme','replace_me'}: continue
        if re.fullmatch(r'(?:your|replace|example|dummy|placeholder|change)[ _-][A-Za-z0-9 _<>.-]{1,100}',value,re.I): continue
        if re.fullmatch(r'<[A-Za-z0-9 _-]{1,80}>',value): continue
        try:
            parsed=urllib.parse.urlsplit(value)
            if parsed.scheme in {'http','https'} and parsed.hostname and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment and (parsed.hostname in {'localhost','127.0.0.1','example.com','example.org'} or parsed.hostname.endswith(('.example.com','.example.org'))): continue
        except ValueError: pass
        return False
    return True


def check_workspace(workspace=WORKSPACE):
    import os
    workspace=Path(workspace)
    if workspace.is_symlink() or not workspace.is_dir(): raise Denied('Allowed workspace is missing or is a symlink',code='workspace_policy_failed')
    root=workspace.resolve()
    for directory,names,files in os.walk(root,followlinks=False):
        for name in names+files:
            path=Path(directory)/name
            if protected_name(name):
                empty_anchor=name.lower() in PRIVATE_DIRS and not path.is_symlink() and path.is_dir() and not any(path.iterdir())
                if not empty_anchor and (name.lower() not in PUBLIC_CA_NAMES or not public_ca_bundle(path)):
                    raise Denied('Credential-like file found in the shared workspace: '+json.dumps(str(path.relative_to(root)),ensure_ascii=True)+'; move real credentials outside the workspace before continuing.',code='workspace_policy_failed')
            if path.is_symlink():
                if not guest_venv_interpreter_link(path,root):
                    try:path.resolve(strict=True).relative_to(root)
                    except (ValueError,FileNotFoundError,RuntimeError):raise Denied('External or broken workspace symlink denied: '+json.dumps(str(path.relative_to(root)),ensure_ascii=True),code='workspace_policy_failed')
            elif path.is_file() and path.stat().st_nlink>1:
                raise Denied('Hard-linked workspace file denied',code='workspace_policy_failed')
            if name.lower() in TEMPLATES and not safe_template(path):
                raise Denied('Environment template contains unreviewed values: '+json.dumps(str(path.relative_to(root)),ensure_ascii=True)+'; keep only empty values or clear placeholders, and store real credentials outside the workspace.',code='workspace_policy_failed')


def fold_literal(value):
    return ''.join('['+c.lower()+c.upper()+']' if c.isascii() and c.isalpha() else c for c in value)


def native_deny_globs():
    # Native deny globs cannot be overridden by a positive template exception.
    # Compile the complement of four exact placeholder-template names instead.
    def complement(start,end,allowed):
        result=[]
        def visit(prefix,words):
            base='**/'+fold_literal(start+prefix);suffix=fold_literal(end)
            if '' not in words:result.append(base+suffix)
            children=sorted({w[0] for w in words if w})
            if children:
                excluded=''.join(c.lower()+c.upper() if c.isalpha() else c for c in children)
                result.append(base+'[!'+excluded+']*'+suffix)
                for char in children:visit(prefix+char,[w[1:] for w in words if w.startswith(char)])
            else:result.append(base+'?*'+suffix)
        visit('',sorted(allowed))
        return result
    patterns=['**/'+fold_literal('.env')]
    patterns+=complement('.env.','',[x[len('.env.'):] for x in TEMPLATES])
    patterns += ['**/'+fold_literal(n) for n in sorted(PRIVATE_NAMES)]
    for name in sorted(PRIVATE_DIRS):patterns += ['**/'+fold_literal(name),'**/'+fold_literal(name)+'/**']
    patterns += complement('','.pem',[x[:-4] for x in PUBLIC_CA_NAMES])
    patterns += ['**/*'+fold_literal(n) for n in PRIVATE_EXTENSIONS if n!='.pem']
    return patterns


def managed_requirements(workspace=WORKSPACE):
    lines=['default_permissions = "codex_api_workspace"','allow_managed_hooks_only = true',
           '[allowed_permission_profiles]','codex_api_workspace = true',
           '[permissions.codex_api_workspace]','extends = ":workspace"',
           'description = "API workspace with sensitive files denied"',
           '[permissions.codex_api_workspace.filesystem]','glob_scan_max_depth = 16',
           '[permissions.codex_api_workspace.filesystem.":workspace_roots"]']
    lines += [json.dumps(pattern)+' = "deny"' for pattern in native_deny_globs()]
    lines += ['[permissions.filesystem]','deny_read = [']
    lines += ['  '+json.dumps(str(workspace)+'/'+pattern)+',' for pattern in native_deny_globs()]
    lines += [']','[permissions.codex_api_workspace.network]','enabled = true',
              '[features]','hooks = true','plugin_hooks = false',
              '[hooks]','managed_dir = "/etc/codex-api"']
    for event in ('SessionStart','PreToolUse','PostToolUse','Stop','Interrupt'):
        lines += ['[[hooks.'+event+']]','[[hooks.'+event+'.hooks]]','type = "command"',
                  'command = "python3 -I /etc/codex-api/quota-notice.py"','timeout = 2']
    return '\n'.join(lines)+'\n'


if __name__=='__main__':print(managed_requirements(),end='')
