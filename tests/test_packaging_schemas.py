"""Regression tests for schema packaging.

Background: ``schemas/`` lived only at the repo root, but the wheel packaged
only ``concordia/``. So ``schema_validator`` (which resolved
``parent.parent/schemas``) and the import-time a2cn adapter raised
FileNotFoundError for every pip user, while passing in dev (where the repo-root
tree exists). These tests lock the fix:

1. the build config force-includes ``schemas`` into the package, and
2. every schema the validators reference actually loads.

The end-to-end proof (build a wheel, install in a clean venv, load a schema
from outside the source tree) lives in CI as the ``wheel-install-smoke`` job,
because building a wheel inside a unit test is slow and environment-fragile.
This module is the fast in-repo guard against the config silently drifting.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

import concordia.schema_validator as sv

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - 3.10 fallback
    tomllib = None

_REPO_ROOT = Path(__file__).resolve().parent.parent

# The schemas the Python validators load by name. Keep in sync with the
# _load_schema(...) call sites in concordia/schema_validator.py.
_REFERENCED_SCHEMAS = (
    "attestation.schema.json",
    "approval_receipt.schema.json",
    "fulfillment_attestation.schema.json",
    "receipt_bundle.schema.json",
    "reference.schema.json",
    "revocation_record.schema.json",
    "predicate.json",
)


def test_every_referenced_schema_loads() -> None:
    """All schemas the validators reference resolve and parse as objects."""
    for name in _REFERENCED_SCHEMAS:
        schema = sv._load_schema(name)
        assert isinstance(schema, dict) and schema, name


def test_a2cn_dispute_schema_is_loaded_at_import() -> None:
    """The a2cn adapter loads its schema at import time; it must resolve."""
    from concordia.adapters.a2cn import dispute_resolved as dr

    assert isinstance(dr.DISPUTE_RESOLVED_SCHEMA, dict)
    assert dr.DISPUTE_RESOLVED_SCHEMA


@pytest.mark.skipif(tomllib is None, reason="tomllib requires Python 3.11+")
def test_wheel_force_includes_schemas_into_package() -> None:
    """pyproject must ship the schemas inside the package, not just at repo root.

    This is the config-drift guard: if someone removes the force-include entry,
    the wheel stops shipping schemas and pip users break again — but every
    source-tree test would still pass. This test fails loudly instead.
    """
    with (_REPO_ROOT / "pyproject.toml").open("rb") as fp:
        cfg = tomllib.load(fp)
    wheel_cfg = cfg["tool"]["hatch"]["build"]["targets"]["wheel"]
    force_include = wheel_cfg.get("force-include", {})
    assert force_include.get("schemas") == "concordia/schemas", (
        "pyproject must force-include the repo-root 'schemas' tree into "
        "'concordia/schemas' so schema-backed validators work in an installed "
        "wheel"
    )


def test_repo_root_schemas_tree_is_complete() -> None:
    """The source tree carries every referenced schema (build input exists)."""
    schemas_dir = _REPO_ROOT / "schemas"
    for name in _REFERENCED_SCHEMAS:
        assert (schemas_dir / name).is_file(), name
    assert (schemas_dir / "a2cn" / "dispute_resolved.schema.json").is_file()
