"""Shared host preflight and matching native rules. No project copies or secret logging."""
import json
from pathlib import Path
import re
import tomllib
import urllib.parse

from guard import Denied

from settings import ROOT, WORKSPACE
TEMPLATES = frozenset({'.env.example', '.env.sample', '.env.template', '.env.dist'})
PRIVATE_NAMES = frozenset({'search-keys.env','openai-key.env','docker-login.env','auth.json',
                           'id_rsa','id_ed25519','.npmrc','.netrc','.pypirc'})
PRIVATE_DIRS = frozenset({'.ssh','.aws','.gnupg'})
PRIVATE_EXTENSIONS = ('.pem','.p12','.pfx')
PUBLIC_CA_NAMES = frozenset({'cacert.pem','ca-bundle.pem'})
OWNER_MASK_MARKER = '# codex-api-owner-mask-keys: '


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


def validate_protected_paths(paths):
    if not isinstance(paths,list) or len(paths)>128:
        raise Denied('Protected paths must be a list of at most 128 exact relative paths.',code='protected_paths_invalid')
    result=[]
    for item in paths:
        if not isinstance(item,str) or len(item)>512 or not item or item.startswith('/') or any(c in item for c in '\\*?[]{}') or any(ord(c)<32 for c in item) or any(p in {'','.','..'} for p in item.split('/')):
            raise Denied('Use exact workspace-relative paths without traversal, wildcards, or control characters.',code='protected_paths_invalid')
        if item not in result:result.append(item)
    return sorted(result)


def protected_paths(root=ROOT):
    path=Path(root)/'protected-paths.json'
    if not path.exists():return []
    if path.is_symlink() or path.stat().st_mode & 0o077 or path.stat().st_size>65536:
        raise Denied('Protected-path settings are unsafe.',code='protected_paths_invalid')
    return validate_protected_paths(json.loads(path.read_text()))


def check_workspace(workspace=WORKSPACE, *, protected=None):
    import os
    workspace=Path(workspace)
    if workspace.is_symlink() or not workspace.is_dir(): raise Denied('Allowed workspace is missing or is a symlink',code='workspace_policy_failed')
    root=workspace.resolve()
    protected=validate_protected_paths(protected if protected is not None else protected_paths() if workspace==WORKSPACE else [])
    def excluded(path):
        relative=path.relative_to(root).as_posix()
        return any(relative==p or relative.startswith(p+'/') for p in protected)
    for directory,names,files in os.walk(root,followlinks=False):
        # Owner-declared paths are masked by native rules. Do not inspect contents.
        names[:]=[name for name in names if not excluded(Path(directory)/name)]
        files=[name for name in files if not excluded(Path(directory)/name)]
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


def native_deny_globs(protected=()):
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
    for path in validate_protected_paths(list(protected)):
        patterns += [path,path+'/**']
    return patterns


def managed_requirements(workspace=WORKSPACE, protected=()):
    lines=['default_permissions = "codex_api_workspace"','allow_managed_hooks_only = true',
           'mcp_servers = {}','allowed_web_search_modes = ["disabled"]',
           'allowed_approval_policies = ["never"]','allowed_login_methods = ["api"]',
           'model_catalog_json = "/etc/codex-api/models.json"','allow_login_shell = false',
           '[allowed_permission_profiles]','codex_api_workspace = true',
           '[permissions.codex_api_workspace]','extends = ":workspace"',
           'description = "API workspace with sensitive files denied"',
           '[permissions.codex_api_workspace.filesystem]','glob_scan_max_depth = 16',
           '[permissions.codex_api_workspace.filesystem.":workspace_roots"]']
    owner_masks=sorted(set(native_deny_globs(protected))-set(native_deny_globs()))
    lines += [OWNER_MASK_MARKER+json.dumps(owner_masks)]
    lines += [json.dumps(pattern)+' = "deny"' for pattern in native_deny_globs(protected)]
    lines += ['[permissions.filesystem]','deny_read = [']
    lines += ['  '+json.dumps(str(workspace)+'/'+pattern)+',' for pattern in native_deny_globs(protected)]
    lines += [']','[permissions.codex_api_workspace.network]','enabled = true','[features]']
    # Pin the same canonical feature keys as the shipped base. Project/user
    # configuration and native config commands cannot widen these values.
    base=Path(__file__).resolve().parent.parent/'kit/config.toml'
    features=tomllib.loads(base.read_text())['features']
    if not isinstance(features,dict) or any(type(value) is not bool for value in features.values()):raise Denied('Managed feature policy is invalid.')
    lines += [key+' = '+str(value).lower() for key,value in sorted(features.items())]
    lines += ['[hooks]','managed_dir = "/etc/codex-api"']
    for event in ('SessionStart','PreToolUse','PostToolUse','Stop','Interrupt'):
        lines += ['[[hooks.'+event+']]','[[hooks.'+event+'.hooks]]','type = "command"',
                  'command = "python3 -I /etc/codex-api/quota-notice.py"','timeout = 2']
    return '\n'.join(lines)+'\n'


def validate_managed_requirements(content, workspace=WORKSPACE, protected=()):
    """Check required deny semantics without downgrading a newer reviewed kit.

    The installation manifest separately authenticates every policy byte. This
    check binds its masks to today's exact workspace and protected-path list;
    it intentionally permits additional denies, feature pins, and formatting.
    Required glob entries are compared conservatively rather than guessing
    whether an arbitrary different glob language is equivalent.
    """
    protected=validate_protected_paths(list(protected))
    try:
        if isinstance(content,bytes):content=content.decode('utf-8')
        if not isinstance(content,str) or len(content.encode('utf-8'))>4*1024*1024:raise ValueError()
        policy=tomllib.loads(content)
        profiles=policy['allowed_permission_profiles']
        native=policy['permissions']['codex_api_workspace']['filesystem'][':workspace_roots']
        absolute=policy['permissions']['filesystem']['deny_read']
        if policy.get('default_permissions')!='codex_api_workspace' or not isinstance(profiles,dict) or profiles.get('codex_api_workspace') is not True or any(value is not False for name,value in profiles.items() if name!='codex_api_workspace'):
            raise ValueError()
        if not isinstance(native,dict) or not isinstance(absolute,list) or not all(isinstance(item,str) for item in absolute):raise ValueError()
        required=set(native_deny_globs(protected))
        if not all(native.get(pattern)=='deny' for pattern in required):raise ValueError()
        if not {str(workspace)+'/'+pattern for pattern in required}<=set(absolute):raise ValueError()
    except (KeyError,TypeError,ValueError,UnicodeError):
        raise Denied('The native filesystem policy does not cover the required workspace and exact protected paths. No environment was started.',code='protected_paths_invalid')
    return True


def update_managed_path_masks(content, workspace, current, updated):
    """Change only canonical path masks, keeping newer reviewed constraints.

    Unknown denials survive. Explicit origin metadata distinguishes removable
    owner masks from built-ins introduced by a newer renderer. Unexpected TOML
    layouts fail closed instead of falling back to an older full renderer.
    """
    current=validate_protected_paths(list(current));updated=validate_protected_paths(list(updated))
    if isinstance(content,bytes):
        try:content=content.decode('utf-8')
        except UnicodeError:raise Denied('Native path policy is not valid UTF-8.',code='protected_paths_invalid')
    validate_managed_requirements(content,workspace,current)
    before=tomllib.loads(content)
    lines=content.splitlines(keepends=True)
    def section(header):
        indices=[i for i,line in enumerate(lines) if line.rstrip('\r\n')==header]
        if len(indices)!=1:raise ValueError('noncanonical section')
        start=indices[0];end=next((i for i in range(start+1,len(lines)) if lines[i].lstrip().startswith('[')),len(lines))
        return start,end
    try:
        start,end=section('[permissions.codex_api_workspace.filesystem.":workspace_roots"]')
        native=before['permissions']['codex_api_workspace']['filesystem'][':workspace_roots']
        parsed={};owners=None;comments=[]
        decoder=json.JSONDecoder()
        for line in lines[start+1:end]:
            value=line.strip()
            if value.startswith(OWNER_MASK_MARKER):
                if owners is not None:raise ValueError('duplicate origin marker')
                owners=json.loads(value[len(OWNER_MASK_MARKER):])
            elif not value or value.startswith('#'):comments.append(line)
            else:
                key,offset=decoder.raw_decode(value)
                if not isinstance(key,str) or value[offset:].strip()!='= "deny"':raise ValueError('noncanonical deny')
                parsed[key]='deny'
        if parsed!=native:raise ValueError('unexpected native policy')
        builtins=set(native_deny_globs());old_required=set(native_deny_globs(current));required=native_deny_globs(updated)
        old_owner={mask for path in current for mask in (path,path+'/**')}-builtins
        if owners is None:
            if set(current)-set(updated):raise ValueError('older policy lacks owner origin metadata')
            owners=[]
        if not isinstance(owners,list) or any(not isinstance(key,str) for key in owners) or len(set(owners))!=len(owners) or not set(owners)<=old_owner or not all(native.get(key)=='deny' for key in owners):
            raise ValueError('invalid owner mask metadata')
        removed=(old_required-set(required))&set(owners)
        keep={key:value for key,value in native.items() if key not in removed}
        new_owners=(set(owners)-removed)|{key for key in required if key not in native and key not in builtins}
        for key in required:keep[key]='deny'
        replacement=[lines[start],*comments,OWNER_MASK_MARKER+json.dumps(sorted(new_owners))+'\n']
        replacement += [json.dumps(key)+' = "deny"\n' for key in keep]
        native_range=(start,end,replacement)

        absolute_start,absolute_end=section('[permissions.filesystem]')
        begins=[i for i in range(absolute_start+1,absolute_end) if lines[i].rstrip('\r\n')=='deny_read = [']
        if len(begins)!=1:raise ValueError('noncanonical absolute masks')
        first=begins[0];last=next((i for i in range(first+1,absolute_end) if lines[i].rstrip('\r\n')==']'),None)
        if last is None:raise ValueError('unterminated absolute masks')
        absolute=[]
        for line in lines[first+1:last]:
            value=line.strip()
            if not value.endswith(','):raise ValueError('noncanonical absolute deny')
            item=json.loads(value[:-1])
            if not isinstance(item,str):raise ValueError('invalid absolute deny')
            absolute.append(item)
        if absolute!=before['permissions']['filesystem']['deny_read']:raise ValueError('unexpected absolute policy')
        for key in removed:
            item=str(workspace)+'/'+key
            if item not in absolute:raise ValueError('missing owner absolute mask')
            absolute.remove(item)
        for key in required:
            item=str(workspace)+'/'+key
            if item not in absolute:absolute.append(item)
        absolute_range=(first,last+1,['deny_read = [\n',*['  '+json.dumps(item)+',\n' for item in absolute],']\n'])
        for first,last,replacement in sorted((native_range,absolute_range),reverse=True):lines[first:last]=replacement
        result=''.join(lines)
        validate_managed_requirements(result,workspace,updated)
        after=tomllib.loads(result)
        # Every value outside the two masks must remain identical, including
        # unknown newer fields in the same filesystem table.
        import copy
        baseline=copy.deepcopy(before)
        baseline['permissions']['codex_api_workspace']['filesystem'][':workspace_roots']=after['permissions']['codex_api_workspace']['filesystem'][':workspace_roots']
        baseline['permissions']['filesystem']['deny_read']=after['permissions']['filesystem']['deny_read']
        if baseline!=after:raise ValueError('unrelated policy changed')
        return result.encode('utf-8')
    except (KeyError,TypeError,ValueError,UnicodeError):
        raise Denied('The current native policy cannot safely update only its path masks. No setting was changed; use a reviewed compatible upgrade rather than replacing newer policy.',code='protected_paths_invalid')


if __name__=='__main__':print(managed_requirements(),end='')
