from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path


def test_wheel_contains_py_typed_marker(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parent.parent
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(tmp_path),
            str(root),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    wheel = next(tmp_path.glob("concordia_protocol-*.whl"))

    with zipfile.ZipFile(wheel) as archive:
        assert "concordia/py.typed" in archive.namelist()


def test_tiny_type_consumer_sees_concordia_as_typed(tmp_path: Path) -> None:
    consumer = tmp_path / "consumer.py"
    consumer.write_text(
        "from concordia import KeyPair\n"
        "kp: KeyPair = KeyPair.generate()\n",
        encoding="utf-8",
    )

    subprocess.run(
        [sys.executable, "-m", "mypy", "--strict", str(consumer)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
