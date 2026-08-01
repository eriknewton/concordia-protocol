"""Regression test for generated public conformance output."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def load_conformance_generator():
    repo_root = Path(__file__).resolve().parent.parent
    module_path = repo_root / "scripts" / "claims" / "generate_conformance.py"
    spec = importlib.util.spec_from_file_location(
        "claims_generate_conformance_for_tests", module_path
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


conformance_generator = load_conformance_generator()


def test_conformance_document_matches_generator() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    expected = conformance_generator.render_conformance()
    actual = (repo_root / "docs" / "CONFORMANCE.md").read_text(encoding="utf-8")

    assert actual == expected
