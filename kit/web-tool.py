#!/usr/bin/env python3
"""Compatibility alias for the reviewed sandbox tool client."""
import runpy
import sys

if __name__ == '__main__':
    value=runpy.run_path('/etc/codex-api/tool-client.py')
    try:raise SystemExit(value['main'](sys.argv[1:]))
    except (ValueError,OSError) as error:
        print('['+getattr(error,'code','tool_local_error')+'] '+(str(error) if hasattr(error,'code') else 'Tool unavailable; inspect tools status.'),file=sys.stderr)
        raise SystemExit(1)
