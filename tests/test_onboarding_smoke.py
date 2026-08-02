"""Local wrapper for the installed-package onboarding smoke."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "onboarding_smoke.py"


def _current_install_probe() -> tuple[Path, str | None] | None:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import importlib.metadata as metadata, json, pathlib; "
                "import concordia; "
                "dist = metadata.distribution('concordia-protocol'); "
                "print(json.dumps({"
                "'package_path': str(pathlib.Path(concordia.__file__).resolve()), "
                "'direct_url': dist.read_text('direct_url.json')"
                "}))"
            ),
        ],
        cwd="/tmp",
        env=env,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if probe.returncode != 0:
        return None
    payload = json.loads(probe.stdout)
    return (Path(payload["package_path"]), payload["direct_url"])


def _direct_url_source_path(direct_url_text: str | None) -> Path | None:
    if not direct_url_text:
        return None
    direct_url = json.loads(direct_url_text)
    url = direct_url.get("url")
    if not isinstance(url, str):
        return None
    parsed = urlparse(url)
    if parsed.scheme != "file":
        return None
    return Path(unquote(parsed.path)).resolve()


def test_onboarding_smoke_script_against_current_install() -> None:
    install_probe = _current_install_probe()
    if install_probe is None:
        pytest.skip(
            "concordia is not installed in the current environment; "
            "install non-editable to run scripts/onboarding_smoke.py"
        )
    package_path, direct_url_text = install_probe
    if package_path.is_relative_to(REPO_ROOT):
        pytest.skip(
            "concordia is editable-installed from this source tree; "
            "scripts/onboarding_smoke.py requires a non-editable install"
        )
    if _direct_url_source_path(direct_url_text) != REPO_ROOT:
        pytest.skip(
            "concordia is installed from a different artifact; "
            "install this worktree non-editably to run scripts/onboarding_smoke.py"
        )

    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd="/tmp",
        env=env,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert result.returncode == 0, result.stdout + result.stderr
