"""Shared import namespace for the extracted host-side modules.

The host tooling was developed as one flat import namespace spread over
several directories. This file puts every `src/*` directory on `sys.path`
so intra-namespace imports resolve (`import emu`, `import p14d_kd`, ...)
when the code is driven by pytest.

Plain `python` does not load this file automatically. Set `PYTHONPATH` when
running a script or direct import outside pytest:

    src/emulator;src/isa;src/oracle        (Windows)
    src/emulator:src/isa:src/oracle        (POSIX)
"""
from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(_ROOT, "src")

if os.path.isdir(_SRC):
    for _name in sorted(os.listdir(_SRC)):
        _d = os.path.join(_SRC, _name)
        if os.path.isdir(_d) and _d not in sys.path:
            sys.path.insert(0, _d)
