#!/usr/bin/env python3
"""Run portable regression tests. Providers are fake; only loopback is used."""
from pathlib import Path
import contextlib
import io
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'app'),str(ROOT/'tests')]
suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'))
captured=io.StringIO()
with contextlib.redirect_stdout(captured):
    result=unittest.TextTestRunner(verbosity=1).run(suite)
if not result.wasSuccessful():print(captured.getvalue(),file=sys.stderr)
raise SystemExit(0 if result.wasSuccessful() else 1)
