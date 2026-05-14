from __future__ import annotations

import importlib
import builtins
import pathlib
import sys
import tomllib


def _pyproject() -> dict:
    path = pathlib.Path(__file__).resolve().parent.parent / "pyproject.toml"
    return tomllib.loads(path.read_text(encoding="utf-8"))


def test_core_dependencies_do_not_include_mcp() -> None:
    project = _pyproject()["project"]

    assert "mcp>=1.0" not in project["dependencies"]


def test_server_extra_declares_mcp() -> None:
    extras = _pyproject()["project"]["optional-dependencies"]

    assert "mcp>=1.0" in extras["server"]


def test_console_entrypoint_import_defers_mcp(monkeypatch) -> None:
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
        assert "concordia-protocol[server]" in str(exc)
    else:
        raise AssertionError("missing server extra must exit with install hint")
