"""Reviewed, immutable skill snapshots. Never execute an installation script.

This catalog deliberately does not enable native plugin or host skill discovery.
Approval records a person's review of exact bytes, not a claim that static
analysis can prove arbitrary instructions or code safe.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
import uuid

from guard import Denied, atomic_json, canonical

VERSION = 1
MAX_FILES = 256
MAX_BYTES = 2 * 1024 * 1024
MAX_FILE_BYTES = 256 * 1024
MAX_DEPTH = 10
MAX_ACTIVE_SKILLS = 32
NAME = re.compile(r'[a-z0-9]+(?:-[a-z0-9]+)*\Z')
DIGEST = re.compile(r'[a-f0-9]{64}\Z')
TEXT_SUFFIXES = {'.md', '.txt', '.rst', '.json', '.yaml', '.yml', '.toml', '.csv', '.tsv',
                 '.py', '.sh', '.bash', '.js', '.mjs', '.cjs', '.ts', '.sql', '.css'}
CODE_SUFFIXES = {'.py', '.sh', '.bash', '.js', '.mjs', '.cjs', '.ts', '.sql', '.css'}
PLUGIN_FIELDS = {'name', 'version', 'description', 'author', 'homepage', 'repository',
                 'license', 'keywords', 'skills'}
SECRET = re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----|\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}'
                    r'|\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})')
DEPENDENCY = re.compile(r'^\s*(?:dependencies|mcp_servers|mcpServers|hooks|userConfig|credentials)\s*:', re.M)
ENV_SECRET = re.compile(r'(?:getenv\s*\(|environ\s*(?:\[|\.get\s*\()|process\.env\.)\s*[\'\"]?'
                        r'[A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD)\b')
FORBIDDEN_PARTS = {'.git', '.codex', '.agents', '.claude', '.claude-plugin', 'node_modules',
                   '__pycache__', 'hooks', 'credentials', 'secrets'}
IMAGE_KEYS = ('image_built', 'filesystem_tested', 'network_tested', 'host_integrations_absent',
              'codex_protocol_tested')


def fail(message):
    raise Denied(message, code='extension_review_required')


def _directory(path):
    """Open every path component without following a symlink."""
    path = Path(path).absolute()
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            if part in ('', '.', '..'): fail('Extension paths must be absolute and contain no parent traversal.')
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = following
        return fd
    except BaseException:
        os.close(fd); raise


def _read_tree(path):
    """Read a bounded text bundle with descriptor-relative, no-follow I/O."""
    result, seen = {}, set()
    total = 0
    try:root_fd = _directory(path)
    except OSError:fail('Extension folder is unavailable or linked. Choose a stable local folder without symlinks.')
    def walk(fd, prefix='', depth=0):
        nonlocal total
        if depth > MAX_DEPTH: fail('Extension folder is too deeply nested.')
        entries = sorted(os.listdir(fd))
        if len(entries) + len(result) > MAX_FILES * 2: fail('Extension folder contains too many entries.')
        for name in entries:
            if len(seen)>=MAX_FILES*2:fail('Extension folder contains too many files or directories.')
            if not re.fullmatch(r'[A-Za-z0-9_.][A-Za-z0-9_. -]{0,127}', name):
                fail('Extension contains an unsupported filename; use plain local text files.')
            if name.casefold() in FORBIDDEN_PARTS or name.casefold().startswith('.env') or name.casefold() in {'.mcp.json', 'auth.json'}:
                fail('Extension contains credentials, an unreviewed configuration, or a dependency directory.')
            relative = prefix + name
            folded = relative.casefold()
            if folded in seen: fail('Extension contains filenames that collide on a case-insensitive filesystem.')
            seen.add(folded)
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(before.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    opened=os.fstat(child)
                    if (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino):fail('Extension folder changed while being read; stage a stable folder again.')
                    walk(child, relative + '/', depth + 1)
                finally: os.close(child)
                continue
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                fail('Extension symlinks, hardlinks, devices, and special files are not accepted.')
            if before.st_size > MAX_FILE_BYTES: fail('An extension file exceeds the 256 KiB limit.')
            suffix = Path(name).suffix.lower()
            if suffix not in TEXT_SUFFIXES and name not in {'LICENSE', 'NOTICE'}:
                fail('Extension includes a binary or unsupported file type. Only reviewed text resources and scripts are supported.')
            file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                opened = os.fstat(file_fd)
                if (opened.st_dev, opened.st_ino, opened.st_nlink) != (before.st_dev, before.st_ino, 1):
                    fail('Extension changed while being read; stage it again from a stable folder.')
                data = bytearray()
                while len(data) <= MAX_FILE_BYTES:
                    chunk = os.read(file_fd, min(65536, MAX_FILE_BYTES + 1 - len(data)))
                    if not chunk: break
                    data.extend(chunk)
                after = os.fstat(file_fd)
                if len(data) > MAX_FILE_BYTES or (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns):
                    fail('Extension changed while being read; stage it again from a stable folder.')
            finally: os.close(file_fd)
            try: text = bytes(data).decode('utf-8')
            except UnicodeError: fail('Binary extension files are not supported.')
            if any(ord(c) < 32 and c not in '\n\r\t' for c in text) or '\x7f' in text:
                fail('Extension text contains unsupported control characters.')
            if SECRET.search(text): fail('Possible secret found in the extension. Remove it locally; its value was not printed or staged.')
            if suffix in {'.json', '.yaml', '.yml'} and DEPENDENCY.search(text):
                fail('Extension-declared credentials, MCP, hooks, or dependencies are not supported.')
            if suffix == '.json':
                try: structured = json.loads(text)
                except ValueError: fail('Extension JSON metadata must be valid JSON.')
                def declared_capability(value):
                    if isinstance(value, dict):
                        return any(key in {'dependencies', 'mcp_servers', 'mcpServers', 'hooks', 'userConfig', 'credentials'} or declared_capability(item) for key, item in value.items())
                    return isinstance(value, list) and any(declared_capability(item) for item in value)
                if declared_capability(structured): fail('Extension-declared credentials, MCP, hooks, or dependencies are not supported.')
            if ENV_SECRET.search(text):
                fail('Extension code requests a secret environment variable. Use a separately reviewed host adapter instead.')
            result[relative] = bytes(data)
            total += len(data)
            if len(result) > MAX_FILES or total > MAX_BYTES: fail('Extension exceeds 256 files or 2 MiB.')
    try: walk(root_fd)
    except OSError:fail('Extension files changed, became unavailable, or could not be read without following links. Stage a stable local folder again.')
    finally: os.close(root_fd)
    if not result: fail('Extension folder is empty.')
    return result


def _frontmatter(data):
    text = data.decode('utf-8')
    match = re.match(r'\A---\r?\n(.*?)\r?\n---(?:\r?\n|\Z)', text, re.S)
    if not match: fail('Every skill needs SKILL.md with name and description front matter.')
    fields = {}
    lines = match[1].splitlines()
    current = None
    for line in lines:
        if not line.strip() or line.lstrip().startswith('#'): continue
        if line[0].isspace():
            if current not in fields: fail('Unsupported skill front matter.')
            fields[current] += '\n' + line.strip()
            continue
        found = re.fullmatch(r'([a-z][a-z_-]*):\s*(.*)', line)
        if not found or found[1] in fields: fail('Unsupported or duplicate skill front matter field.')
        current = found[1]; fields[current] = found[2]
    if set(fields) - {'name', 'description', 'license', 'compatibility', 'metadata'}:
        fail('Skill front matter declares unsupported capabilities. Keep name, description, and inert metadata only.')
    def scalar(value):
        if value.startswith(('>', '|')): value = '\n'.join(value.splitlines()[1:])
        if value.startswith('"'):
            try: value = json.loads(value)
            except ValueError: fail('Use a plain or valid quoted skill description.')
        elif value.startswith("'") and value.endswith("'"): value = value[1:-1].replace("''", "'")
        return ' '.join(value.split())
    name = scalar(fields.get('name', ''))
    description = scalar(fields.get('description', ''))
    if not NAME.fullmatch(name) or len(name) > 64 or not description or len(description) > 1024:
        fail('Skill name must be lowercase words separated by hyphens; description must be 1–1024 characters.')
    return {'name': name, 'description': description}


def _describe(files):
    manifest = '.codex-plugin/plugin.json'
    kind = 'skill'
    roots = ['']
    if manifest in files:
        kind = 'skill-only plugin'
        try: plugin = json.loads(files[manifest])
        except ValueError: fail('Plugin manifest is not valid JSON.')
        if not isinstance(plugin, dict) or set(plugin) - PLUGIN_FIELDS or 'skills' not in plugin:
            fail('Only skill-only plugins are supported. MCP, hooks, apps, dependencies, and unknown manifest fields are rejected.')
        declared = plugin['skills']
        if isinstance(declared, str): declared = [declared]
        if not isinstance(declared, list) or not declared or len(declared) > 32: fail('Plugin must explicitly declare its local skill directories.')
        roots = []
        for item in declared:
            if not isinstance(item, str) or not item.startswith('./') or '\\' in item or '..' in PurePosixPath(item).parts:
                fail('Plugin skill paths must start with ./ and stay inside the staged bundle.')
            path = str(PurePosixPath(item[2:])).strip('/')
            if path in ('', '.'): fail('Plugin skill paths cannot refer to its root.')
            candidates = [path + '/'] if path + '/SKILL.md' in files else sorted({str(PurePosixPath(p).parent) + '/' for p in files if p.startswith(path + '/') and p.endswith('/SKILL.md')})
            if not candidates: fail('Declared plugin skill directory has no SKILL.md.')
            roots.extend(candidates)
        roots = sorted(set(roots))
        for file in files:
            if file == manifest or any(file.startswith(root) for root in roots): continue
            if '/' in file or Path(file).suffix.lower() not in {'.md', '.txt', '.rst'} and file not in {'LICENSE', 'NOTICE'}:
                fail('Plugin includes undeclared code or configuration outside its skill directories.')
    skills = []
    names = set()
    for root in roots:
        entry = root + 'SKILL.md'
        if entry not in files: fail('Choose a skill folder containing SKILL.md, or a supported skill-only plugin root.')
        if any(p.endswith('/SKILL.md') and p != entry and p.startswith(root) for p in files):
            fail('Nested skills are not supported; stage each skill separately or declare them in a plugin.')
        skill = _frontmatter(files[entry]); skill['path'] = root.rstrip('/')
        if skill['name'] in names: fail('Skill names must be unique within a bundle.')
        names.add(skill['name']); skills.append(skill)
    scripts = sorted(path for path, data in files.items() if Path(path).suffix.lower() in CODE_SUFFIXES or data.startswith(b'#!'))
    hosts = sorted(set(re.findall(r'https?://([A-Za-z0-9.-]+)', '\n'.join(v.decode() for v in files.values()))))
    return {'version': VERSION, 'kind': kind, 'skills': skills, 'scripts': scripts,
            'network_references': hosts, 'files': {p: {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)} for p, data in sorted(files.items())}}


def _json_file(path, *, maximum=1024 * 1024):
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_size > maximum:
        fail('Extension metadata is missing, linked, or exceeds its limit.')
    try: return json.loads(path.read_text())
    except (ValueError, OSError): fail('Extension metadata is unreadable; no unreviewed content was activated.')


def _registry(root):
    path = Path(root)/'extensions/registry.json'
    if not path.exists():
        if path.is_symlink(): fail('Extension registry must not be a symlink.')
        return {'version': VERSION, 'revision': 0, 'approved': {}}
    data = _json_file(path)
    if not isinstance(data, dict) or set(data) != {'version', 'revision', 'approved'} or data['version'] != VERSION or type(data['revision']) is not int or data['revision'] < 0 or not isinstance(data['approved'], dict) or len(data['approved']) > MAX_ACTIVE_SKILLS:
        fail('Extension registry has an unsupported schema.')
    for name, record in data['approved'].items():
        if not NAME.fullmatch(name) or not isinstance(record, dict) or set(record) != {'digest', 'skill_path', 'allow_scripts', 'allow_implicit'} or not DIGEST.fullmatch(record.get('digest', '')) or type(record['allow_scripts']) is not bool or type(record['allow_implicit']) is not bool:
            fail('Extension approval is invalid.')
    return data


@contextlib.contextmanager
def _mutation(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir(): fail('Use the installed harness private directory.')
    for name in ('session.lock', 'extensions.lock'):
        if (root/name).is_symlink(): fail('Extension maintenance locks must not be symlinks.')
    with (root/'session.lock').open('a+b') as lease, (root/'extensions.lock').open('a+b') as lock:
        try:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: fail('Exit the API session before reviewing or changing extensions. The running session was left unchanged.')
        if not (root/'paused').exists() or (root/'gateway-process.json').exists():
            fail('Stop the API environment before changing extensions.')
        if (root/'upgrade-pending.json').exists() or (root/'upgrade-pending.json').is_symlink():
            fail('Finish or roll back the pending harness update before changing extensions.')
        directory = root/'extensions'
        if directory.is_symlink(): fail('Extension storage must not be a symlink.')
        directory.mkdir(mode=0o700, exist_ok=True)
        yield


def stage(root, source):
    root = Path(root)
    with _mutation(root):
        files = _read_tree(source)
        report = _describe(files)
        digest = hashlib.sha256(canonical(report)).hexdigest()
        directory = root/'extensions'
        for subdir in ('candidates', 'snapshots'):
            path = directory/subdir
            if path.is_symlink(): fail('Extension storage must not be a symlink.')
            path.mkdir(mode=0o700, exist_ok=True)
        snapshot = directory/'snapshots'/digest
        candidate = directory/'candidates'/(digest + '.json')
        if snapshot.exists():
            if not candidate.exists():
                if _describe(_read_tree(snapshot)) != report: fail('An interrupted snapshot differs from this source; no extension was activated.')
                atomic_json(candidate, report)
            _candidate(root, digest)
        else:
            with tempfile.TemporaryDirectory(prefix='.stage-', dir=directory) as temporary:
                destination = Path(temporary)/'snapshot'; destination.mkdir(mode=0o700)
                for relative, data in files.items():
                    path = destination/relative; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
                    with os.fdopen(fd, 'wb') as out: out.write(data); out.flush(); os.fsync(out.fileno())
                destination.rename(snapshot)
                for path in sorted(snapshot.rglob('*'), key=lambda p: len(p.parts), reverse=True):
                    if path.is_dir(): path.chmod(0o500)
                snapshot.chmod(0o500)
            atomic_json(candidate, report)
        return {'digest': digest, **report, 'status': 'staged; not enabled',
                'review_directory': str(snapshot), 'warning': 'Read every staged file before approving. Static checks do not prove instructions or code safe.'}


def _candidate(root, digest):
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest): fail('Use the complete 64-character digest printed by stage.')
    directory = Path(root)/'extensions'
    for path in (directory, directory/'candidates', directory/'snapshots'):
        if path.is_symlink(): fail('Extension storage must not contain symlinks.')
    report = _json_file(directory/'candidates'/(digest + '.json'))
    if hashlib.sha256(canonical(report)).hexdigest() != digest: fail('The staged review report changed; stage the original source again.')
    files = _read_tree(directory/'snapshots'/digest)
    if _describe(files) != report: fail('Staged extension bytes changed after review. No extension was activated.')
    return report, files


def verify(root):
    registry = _registry(root)
    checked = {}
    skills = []
    for name, approval in sorted(registry['approved'].items()):
        digest = approval['digest']
        if digest not in checked: checked[digest] = _candidate(root, digest)
        report, _ = checked[digest]
        skill = next((item for item in report['skills'] if item['name'] == name and item['path'] == approval['skill_path']), None)
        if not skill or report['scripts'] and not approval['allow_scripts']: fail('Extension approval no longer matches its exact skill and capability review.')
        skills.append({**skill, **approval})
    return {'version': VERSION, 'revision': registry['revision'], 'skills': skills}


def _invalidate(root):
    root = Path(root)
    path = root/'readiness.json'
    if path.exists():
        ready = _json_file(path)
        for key in IMAGE_KEYS: ready[key] = False
        atomic_json(path, ready)


def _refresh_integrity(root):
    path = Path(root)/'installation.json'
    if not path.exists(): return
    manifest = _json_file(path, maximum=4 * 1024 * 1024)
    files = manifest.get('files')
    if not isinstance(files, dict): fail('Installation integrity manifest is unavailable.')
    # Only generated extension assets are mutable through this review workflow.
    files = {p: digest for p, digest in files.items() if not p.startswith('kit/extensions/')}
    for file in sorted((Path(root)/'kit/extensions').rglob('*')):
        if file.is_symlink(): fail('Generated extension assets must not be symlinks.')
        if file.is_file(): files[str(file.relative_to(root))] = hashlib.sha256(file.read_bytes()).hexdigest()
    manifest['files'] = files
    atomic_json(path, manifest)


def _kit(root):
    try:
        from releases import resolve_payload
    except ImportError:
        path=Path(root)/'kit'
        if path.is_symlink() or not path.is_dir(): fail('The private build kit is unavailable.')
        return path
    return resolve_payload(root, 'kit')


def approve(root, digest, *, reviewed=False, allow_scripts=False, allow_implicit=False, replace=False):
    root = Path(root)
    if not reviewed: fail('Read all staged files, then approve their exact digest with --reviewed. No installation script is run.')
    with _mutation(root):
        report, _ = _candidate(root, digest)
        if report['scripts'] and not allow_scripts:
            fail('This bundle includes code. Review every script and explicitly add --allow-scripts; existing network, credential, and budget restrictions still apply.')
        registry = _registry(root)
        for skill in report['skills']:
            previous = registry['approved'].get(skill['name'])
            if previous and previous['digest'] != digest and not replace:
                fail('A skill with this name is already approved. Review the new digest and use --replace to select it.')
        changed = False
        for skill in report['skills']:
            approval = {'digest': digest, 'skill_path': skill['path'], 'allow_scripts': bool(allow_scripts), 'allow_implicit': bool(allow_implicit)}
            if registry['approved'].get(skill['name']) != approval:
                registry['approved'][skill['name']] = approval; changed = True
        if len(registry['approved']) > MAX_ACTIVE_SKILLS: fail('At most 32 managed skills may be active; remove unused skills first.')
        if changed:
            registry['revision'] += 1
            atomic_json(root/'extensions/registry.json', registry)
            _invalidate(root)
        render_build(root)
        _refresh_integrity(root)
        return {'approved': [skill['name'] for skill in report['skills']], 'digest': digest,
                'changed': changed,
                'activation': 'The host command applies this reviewed selection automatically. Only the owned sandbox is rebuilt; credentials, ledger, and project remain in place.'}


def remove(root, name):
    if not isinstance(name, str) or not NAME.fullmatch(name): fail('Use an approved skill name from extensions list.')
    root = Path(root)
    with _mutation(root):
        registry = _registry(root)
        if name not in registry['approved']: fail('That skill is not approved in this installation.')
        del registry['approved'][name]; registry['revision'] += 1
        atomic_json(root/'extensions/registry.json', registry)
        _invalidate(root); render_build(root); _refresh_integrity(root)
        return {'removed': name, 'changed': True, 'activation': 'The host command applies this removal automatically. Old guest extension files cannot be reused.'}


def render_build(root, *, kit_directory=None):
    """Materialize only approved skill bytes into the private Docker build kit."""
    root = Path(root)
    catalog = verify(root)
    kit = _kit(root) if kit_directory is None else Path(kit_directory)
    if kit.is_symlink() or not kit.is_dir(): fail('The private build kit is unavailable.')
    target = kit/'extensions'
    if target.is_symlink(): fail('Generated extension assets must not be symlinks.')
    with tempfile.TemporaryDirectory(prefix='.extensions-', dir=kit) as temporary:
        output = Path(temporary)/'output'; output.mkdir(mode=0o700)
        (output/'skills').mkdir(mode=0o700)
        rows = []
        contents = {}
        for skill in catalog['skills']:
            _, files = _candidate(root, skill['digest'])
            prefix = skill['path'] + '/' if skill['path'] else ''
            for relative, data in files.items():
                if not relative.startswith(prefix): continue
                local = 'skills/' + skill['name'] + '/' + relative[len(prefix):]
                path = output/local; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                path.write_bytes(data); path.chmod(0o444)
                contents[local] = hashlib.sha256(data).hexdigest()
            rows.append({'name': skill['name'], 'description': skill['description'], 'digest': skill['digest'],
                         'allow_scripts': skill['allow_scripts'], 'allow_implicit': skill['allow_implicit'],
                         'path': '/etc/codex-api/extensions/skills/' + skill['name'] + '/SKILL.md'})
        public = {'version': VERSION, 'skills': rows}
        atomic_json(output/'catalog.json', public)
        contents['catalog.json'] = hashlib.sha256((output/'catalog.json').read_bytes()).hexdigest()
        atomic_json(output/'manifest.json', {'version': VERSION, 'files': contents})
        backup = kit/('.extensions-previous-' + uuid.uuid4().hex)
        if target.exists(): target.rename(backup)
        try: output.rename(target)
        finally:
            if backup.exists(): shutil.rmtree(backup)
    return hashlib.sha256(canonical(public)).hexdigest()


def verify_build(root):
    """Compare the build payload to approvals, including unexpected extra files."""
    root = Path(root)
    catalog = verify(root)
    target = _kit(root)/'extensions'
    if not target.exists():
        if catalog['skills']: fail('Approved extensions have not been rendered into the build kit.')
        return None  # Older no-extension installations remain usable.
    manifest = _json_file(target/'manifest.json')
    if set(manifest) != {'version', 'files'} or manifest['version'] != VERSION or not isinstance(manifest['files'], dict):
        fail('Extension build manifest is invalid.')
    actual = {}
    for path in target.rglob('*'):
        if path.is_symlink(): fail('Extension build payload contains an unreviewed symlink.')
        if path.is_file():
            if path.stat().st_nlink != 1: fail('Extension build payload contains an unreviewed hardlink.')
            actual[str(path.relative_to(target))] = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual.pop('manifest.json', None) is None or actual != manifest['files']:
        fail('Extension build payload changed after approval.')
    public = _json_file(target/'catalog.json')
    expected_rows = [{'name': skill['name'], 'description': skill['description'], 'digest': skill['digest'],
                      'allow_scripts': skill['allow_scripts'], 'allow_implicit': skill['allow_implicit'],
                      'path': '/etc/codex-api/extensions/skills/' + skill['name'] + '/SKILL.md'} for skill in catalog['skills']]
    if public != {'version': VERSION, 'skills': expected_rows}: fail('Extension build catalog differs from the approved selection.')
    expected_files = {'catalog.json': hashlib.sha256(canonical(public)).hexdigest()}
    for skill in catalog['skills']:
        _, files = _candidate(root, skill['digest'])
        prefix = skill['path'] + '/' if skill['path'] else ''
        for relative, data in files.items():
            if relative.startswith(prefix): expected_files['skills/' + skill['name'] + '/' + relative[len(prefix):]] = hashlib.sha256(data).hexdigest()
    if actual != expected_files: fail('Extension build includes bytes outside the approved snapshots.')
    return hashlib.sha256(canonical(public)).hexdigest()


def command(root, args):
    parser = argparse.ArgumentParser(prog='codex-api extensions', description='Review exact local skill bytes without running installers. Native plugins, MCP, and hooks stay disabled.')
    sub = parser.add_subparsers(dest='action', required=True)
    stage_parser = sub.add_parser('stage'); stage_parser.add_argument('folder', type=Path)
    inspect_parser = sub.add_parser('inspect'); inspect_parser.add_argument('digest')
    approve_parser = sub.add_parser('approve'); approve_parser.add_argument('--digest', required=True)
    approve_parser.add_argument('--reviewed', action='store_true'); approve_parser.add_argument('--allow-scripts', action='store_true')
    approve_parser.add_argument('--allow-implicit', action='store_true'); approve_parser.add_argument('--replace', action='store_true')
    listing = sub.add_parser('list'); listing.add_argument('--json', action='store_true')
    remove_parser = sub.add_parser('remove'); remove_parser.add_argument('name')
    sub.add_parser('verify')
    options = parser.parse_args(args)
    if options.action == 'stage': result = stage(root, options.folder)
    elif options.action == 'inspect':
        report, _ = _candidate(root, options.digest)
        result = {'digest': options.digest, **report, 'review_directory': str(Path(root)/'extensions/snapshots'/options.digest),
                  'warning': 'Read every file in this directory. No file has been executed or enabled.'}
    elif options.action == 'approve': result = approve(root, options.digest, reviewed=options.reviewed, allow_scripts=options.allow_scripts, allow_implicit=options.allow_implicit, replace=options.replace)
    elif options.action == 'remove': result = remove(root, options.name)
    elif options.action == 'verify': result = {'verified': True, 'build_digest': verify_build(root), **verify(root)}
    else:
        result = verify(root)
        if not options.json:
            if not result['skills']: print('No managed skills are approved.')
            for skill in result['skills']: print(skill['name'] + ' | ' + skill['digest'][:12] + ' | ' + ('reviewed code' if skill['allow_scripts'] else 'instructions') + ' | ' + ('implicit enabled' if skill['allow_implicit'] else 'explicit $' + skill['name']))
            return result
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return result
