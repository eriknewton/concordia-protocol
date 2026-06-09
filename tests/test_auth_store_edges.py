from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from concordia import auth as auth_module
from concordia.auth import AuthTokenStore


def test_reissuing_agent_token_revokes_old_reverse_lookup() -> None:
    store = AuthTokenStore(autoload=False)

    first = store.register_agent_token("agent-a")
    second = store.register_agent_token("agent-a")

    assert first != second
    assert store.get_agent_id_for_token(first) is None
    assert store.get_agent_id_for_token(second) == "agent-a"
    assert not store.validate_agent_token("agent-a", first)
    assert store.validate_agent_token("agent-a", second)


def test_revoke_agent_token_is_idempotent_and_clears_reverse_lookup() -> None:
    store = AuthTokenStore(autoload=False)
    token = store.register_agent_token("agent-a")

    store.revoke_agent_token("agent-a")
    store.revoke_agent_token("agent-a")

    assert not store.validate_agent_token("agent-a", token)
    assert store.get_agent_id_for_token(token) is None


@pytest.mark.parametrize(
    ("alias", "canonical"),
    [
        ("SELLER", "initiator"),
        ("proposer", "initiator"),
        ("Buyer", "responder"),
        ("receiver", "responder"),
    ],
)
def test_session_role_aliases_validate_against_canonical_roles(
    tmp_path: Path, alias: str, canonical: str,
) -> None:
    store = AuthTokenStore(persist_path=tmp_path / "sessions.json", autoload=False)
    initiator_token, responder_token = store.register_session_tokens("session-a", "a", "b")
    token = initiator_token if canonical == "initiator" else responder_token

    assert store.validate_session_token("session-a", alias, token)


def test_get_any_session_role_drops_expired_tokens_without_persisting(
    tmp_path: Path,
) -> None:
    store = AuthTokenStore(
        persist_path=tmp_path / "sessions.json",
        ttl_seconds=0,
        autoload=False,
    )
    initiator_token, _ = store.register_session_tokens("session-a", "a", "b")
    time.sleep(0.01)

    assert store.get_any_session_role("session-a", initiator_token) is None
    assert not store.validate_session_token("session-a", "initiator", initiator_token)


def test_persist_returns_when_parent_directory_cannot_be_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = AuthTokenStore(persist_path=tmp_path / "nested" / "sessions.json", autoload=False)

    def fail_mkdir(*args: object, **kwargs: object) -> None:
        raise OSError("no directory")

    monkeypatch.setattr(Path, "mkdir", fail_mkdir)

    store.register_session_tokens("session-a", "a", "b")

    assert not store._persist_path.exists()


def test_persist_cleans_temporary_file_when_replace_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = AuthTokenStore(persist_path=tmp_path / "sessions.json", autoload=False)

    def fail_replace(src: str, dst: str) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr(os, "replace", fail_replace)

    store.register_session_tokens("session-a", "a", "b")

    assert list(tmp_path.glob(".sessions-*.json.tmp")) == []
    assert not store._persist_path.exists()


def test_persist_ignores_chmod_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = AuthTokenStore(persist_path=tmp_path / "sessions.json", autoload=False)

    def fail_chmod(path: str | Path, mode: int) -> None:
        raise OSError("chmod failed")

    monkeypatch.setattr(os, "chmod", fail_chmod)

    store.register_session_tokens("session-a", "a", "b")

    assert json.loads(store._persist_path.read_text())["sessions"]


def test_autoload_ignores_missing_corrupt_and_incomplete_session_entries(
    tmp_path: Path,
) -> None:
    missing = AuthTokenStore(persist_path=tmp_path / "missing.json")
    assert missing.get_any_session_role("session-a", "token") is None

    corrupt_path = tmp_path / "corrupt.json"
    corrupt_path.write_text("{not json")
    corrupt = AuthTokenStore(persist_path=corrupt_path)
    assert corrupt.get_any_session_role("session-a", "token") is None

    partial_path = tmp_path / "partial.json"
    partial_path.write_text(
        json.dumps(
            {
                "sessions": [
                    {"session_id": "missing-role", "token": "a"},
                    {"role": "initiator", "token": "b"},
                    {"session_id": "missing-token", "role": "responder"},
                    {
                        "session_id": "valid",
                        "role": "initiator",
                        "token": "c" * 64,
                        "expires_at": time.time() + 60,
                    },
                ]
            }
        )
    )
    partial = AuthTokenStore(persist_path=partial_path)

    assert partial.get_any_session_role("missing-role", "a") is None
    assert partial.get_any_session_role("valid", "c" * 64) == "initiator"


def test_autoload_rewrites_file_without_expired_entries(tmp_path: Path) -> None:
    store_file = tmp_path / "sessions.json"
    store_file.write_text(
        json.dumps(
            {
                "sessions": [
                    {
                        "session_id": "expired",
                        "role": "initiator",
                        "token": "a" * 64,
                        "expires_at": time.time() - 60,
                    },
                    {
                        "session_id": "active",
                        "role": "responder",
                        "token": "b" * 64,
                        "expires_at": time.time() + 60,
                    },
                ]
            }
        )
    )

    store = AuthTokenStore(persist_path=store_file)

    assert store.get_any_session_role("expired", "a" * 64) is None
    assert store.get_any_session_role("active", "b" * 64) == "responder"
    payload = json.loads(store_file.read_text())
    assert [(entry["session_id"], entry["role"]) for entry in payload["sessions"]] == [
        ("active", "responder")
    ]


def test_constructor_swallows_loader_exceptions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_load(self: AuthTokenStore) -> None:
        raise RuntimeError("loader failed")

    monkeypatch.setattr(auth_module.AuthTokenStore, "_load_session_tokens", fail_load)

    store = AuthTokenStore(persist_path=tmp_path / "sessions.json")

    assert store.get_any_session_role("session-a", "token") is None
