"""Make `erdl_expr` importable from a directory whose name is not an identifier.

The package lives under `conformance/erdl-expression-v1/`, which cannot be an
import path segment, so the suite is rooted here rather than at the repository
root and adds this directory to `sys.path`.
"""

from __future__ import annotations

import sys
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))
