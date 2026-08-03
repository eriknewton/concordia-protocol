from __future__ import annotations

import builtins
import importlib
import pathlib
import re
import sys

try:
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[import-not-found]


def _pyproject() -> dict:
    path = pathlib.Path(__file__).resolve().parent.parent / "pyproject.toml"
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _mcp_requirements(specs: list[str]) -> list[str]:
    """Every requirement string in ``specs`` whose distribution name is ``mcp``.

    Matched on the distribution name rather than on an exact requirement string,
    so tightening or loosening the version specifier (adding an upper cap, for
    example) does not fail a test that is about WHERE the dependency lives.
    """
    names = (re.match(r"\s*([A-Za-z0-9._-]+)", s) for s in specs)
    return [
        s for s, m in zip(specs, names) if m is not None and m.group(1).lower() == "mcp"
    ]


def test_core_dependencies_do_not_include_mcp() -> None:
    """A library-only install does not pull MCP server dependencies."""
    project = _pyproject()["project"]

    assert _mcp_requirements(project["dependencies"]) == []


def test_server_extra_carries_mcp() -> None:
    """The `server` extra carries the FastMCP runtime dependency."""
    extras = _pyproject()["project"]["optional-dependencies"]

    assert "server" in extras
    mcp_specs = _mcp_requirements(extras["server"])
    assert len(mcp_specs) == 1, f"expected exactly one mcp requirement, got {mcp_specs}"
    assert ">=1.0" in mcp_specs[0], f"mcp floor must remain >=1.0, got {mcp_specs[0]!r}"
    assert "<2" in mcp_specs[0], f"mcp must remain capped below 2.x, got {mcp_specs[0]!r}"


def test_console_entrypoint_missing_mcp_reports_server_extra_hint(monkeypatch) -> None:
    def block_mcp(name: str, *args, **kwargs):
        if name.endswith("mcp_server"):
            raise ModuleNotFoundError("No module named 'mcp'", name="mcp")
        return real_import(name, *args, **kwargs)

    real_import = builtins.__import__
    main_module = importlib.import_module("concordia.__main__")
    monkeypatch.setattr("builtins.__import__", block_mcp)
    monkeypatch.setattr(sys, "argv", ["concordia-mcp-server"])

    try:
        main_module.main()
    except SystemExit as exc:
        message = str(exc)
        assert "server extra" in message
        assert "concordia-protocol[server]" in message
    else:
        raise AssertionError("missing server extra must exit with install hint")
