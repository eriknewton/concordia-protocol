"""Tests for the Concordia module entrypoint."""

from __future__ import annotations

import importlib.metadata
import json
import sys
import types

import pytest

from concordia import __main__ as main_module


def test_predicate_cli_requires_file_argument(monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["concordia", "predicate", "verify"])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert "predicate verify <file>" in str(exc.value)


def test_predicate_cli_prints_verification_result(monkeypatch, tmp_path, capsys) -> None:
    predicate_file = tmp_path / "predicate.json"
    predicate_file.write_text('{"predicate_id":"pred-123"}', encoding="utf-8")

    class _Result:
        def to_dict(self) -> dict:
            return {"valid": True, "predicate_id": "pred-123"}

    def fake_verify(predicate: dict) -> _Result:
        assert predicate == {"predicate_id": "pred-123"}
        return _Result()

    monkeypatch.setattr("concordia.predicate.verify_predicate", fake_verify)
    monkeypatch.setattr(
        sys,
        "argv",
        ["concordia", "predicate", "verify", str(predicate_file)],
    )

    main_module.main()

    assert json.loads(capsys.readouterr().out) == {
        "predicate_id": "pred-123",
        "valid": True,
    }


def test_version_falls_back_when_package_metadata_missing(monkeypatch, capsys) -> None:
    def missing_distribution(name: str) -> str:
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", missing_distribution)
    monkeypatch.setattr(sys, "argv", ["concordia-mcp-server", "--version"])

    main_module.main()

    assert capsys.readouterr().out == "concordia-protocol 0.1.0\n"


def test_main_dispatches_requested_transport(monkeypatch) -> None:
    calls = []

    class _Mcp:
        def run(self, *, transport: str) -> None:
            calls.append(transport)

    fake_module = types.ModuleType("concordia.mcp_server")
    fake_module.mcp = _Mcp()
    monkeypatch.setitem(sys.modules, "concordia.mcp_server", fake_module)
    monkeypatch.setattr(sys, "argv", ["concordia-mcp-server", "--transport", "sse"])

    main_module.main()

    assert calls == ["sse"]


def test_main_uses_stdio_when_transport_value_missing(monkeypatch) -> None:
    calls = []

    class _Mcp:
        def run(self, *, transport: str) -> None:
            calls.append(transport)

    fake_module = types.ModuleType("concordia.mcp_server")
    fake_module.mcp = _Mcp()
    monkeypatch.setitem(sys.modules, "concordia.mcp_server", fake_module)
    monkeypatch.setattr(sys, "argv", ["concordia-mcp-server", "--transport"])

    main_module.main()

    assert calls == ["stdio"]
