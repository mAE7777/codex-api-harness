"""Installation-local settings; never inherit subscription or provider environment."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
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
