"""Local coverage for the clean-room verifier's import guard."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_clean_room_verifier_refuses_when_concordia_is_importable() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    script = repo_root / "scripts" / "claims" / "clean_room_verify.py"
    interop_root = repo_root / "docs" / "interop"

    env = os.environ.copy()
    env["PYTHONPATH"] = (
        str(repo_root)
        if not env.get("PYTHONPATH")
        else str(repo_root) + os.pathsep + env["PYTHONPATH"]
    )

    result = subprocess.run(
        [sys.executable, str(script), str(interop_root)],
        cwd=repo_root,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "clean-room verifier requires concordia to be absent" in (
        result.stdout + result.stderr
    )
