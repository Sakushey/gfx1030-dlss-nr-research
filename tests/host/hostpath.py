"""Put every `src/*` directory on sys.path for the host test suite.

The host tooling is one flat import namespace spread over directories, so
the tests need the same view of it that `conftest.py` gives pytest.
"""
from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SRC = os.path.join(_ROOT, "src")

if os.path.isdir(_SRC):
    for _name in sorted(os.listdir(_SRC)):
        _d = os.path.join(_SRC, _name)
        if os.path.isdir(_d) and _d not in sys.path:
            sys.path.insert(0, _d)

    # `src` itself goes on the path too, APPENDED rather than inserted, so it
    # cannot shadow anything the flat directories already resolve. This is what
    # makes the `qualification` package importable as a package (`from
    # qualification import ...`) while the older flat modules (`import emu`)
    # keep working unchanged.
    if _SRC not in sys.path:
        sys.path.append(_SRC)

REPO_ROOT = _ROOT
