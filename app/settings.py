"""Installation-local settings; never inherit subscription or provider environment."""
import json
from pathlib import Path

PAYLOAD = Path(__file__).resolve().parent.parent
anchor = PAYLOAD / '.installation-root'
if anchor.exists() or anchor.is_symlink():
    if anchor.is_symlink() or not anchor.is_file() or anchor.stat().st_nlink != 1 or anchor.stat().st_size > 8192:
        raise ValueError('The code generation installation anchor is unsafe')
    binding = json.loads(anchor.read_text())
    if not isinstance(binding,dict) or set(binding)!={'version','root'} or binding['version']!=2 or not isinstance(binding['root'],str):
        raise ValueError('The code generation installation anchor is invalid')
    ROOT = Path(binding['root'])
    if not ROOT.is_absolute() or ROOT.is_symlink() or ROOT.resolve()!=ROOT:
        raise ValueError('The permanent installation root is invalid')
else:
    ROOT = PAYLOAD  # Source checkout or a legacy, separately reviewed install.
DEFAULT_HOME = Path.home() / 'Library/Application Support/CodexAPIHarness'
path = ROOT / 'settings.json'
if path.is_symlink():
    raise ValueError('Installation settings must not be a symlink')
SETTINGS = json.loads(path.read_text()) if path.is_file() else {}
WORKSPACE = Path(SETTINGS.get('workspace', str(Path.home() / 'Projects/codex-workspace')))
SBX = Path(SETTINGS.get('sbx_path', '/Applications/Docker Sandboxes.app/Contents/MacOS/sbx'))
NAME = SETTINGS.get('sandbox_name', 'codex-api-harness')
PORT = SETTINGS.get('gateway_port', 49188)
if not WORKSPACE.is_absolute() or not SBX.is_absolute() or type(PORT) is not int or not 1024 <= PORT <= 65535:
    raise ValueError('Invalid installation settings')
