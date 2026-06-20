from __future__ import annotations

import json
import os
import stat
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


# ---------------------------------------------------------------------------
# Credential-file mode: the session store holds bearer tokens and must stay
# owner-only (0o600). auth.py persists with os.chmod(path, 0o600); these pin
# that invariant so a regression to a world-readable mode fails CI.
# ---------------------------------------------------------------------------


def test_session_store_is_owner_only_0o600_after_persist(tmp_path: Path) -> None:
    store_file = tmp_path / "sessions.json"
    store = AuthTokenStore(persist_path=store_file, autoload=False)

    store.register_session_tokens("session-a", "a", "b")

    mode = stat.S_IMODE(os.stat(store_file).st_mode)
    assert mode == 0o600


def test_persist_narrows_preexisting_world_readable_file_to_0o600(
    tmp_path: Path,
) -> None:
    store_file = tmp_path / "sessions.json"
    # Pre-seed a world-readable credential file on the persist path. A persist
    # must never inherit/leave a widened mode; it must end up owner-only.
    store_file.write_text("{}")
    os.chmod(store_file, 0o644)
    assert stat.S_IMODE(os.stat(store_file).st_mode) == 0o644

    store = AuthTokenStore(persist_path=store_file, autoload=False)
    store.register_session_tokens("session-a", "a", "b")

    mode = stat.S_IMODE(os.stat(store_file).st_mode)
    assert mode == 0o600


# ---------------------------------------------------------------------------
# Agent tokens are NEVER persisted. The replaced test_phase_e assertion was
# vacuous (a tautology that could never fail); these capture the real returned
# agent token string and assert it appears nowhere in the on-disk file, and
# that every persisted session token is a session token (not an agent token).
# ---------------------------------------------------------------------------


def test_agent_token_string_is_absent_from_persisted_file(tmp_path: Path) -> None:
    store_file = tmp_path / "sessions.json"
    store = AuthTokenStore(persist_path=store_file, autoload=False)

    agent_token = store.register_agent_token("agent-alice")
    store.register_session_tokens("session-1", "agent-alice", "bob")

    raw = store_file.read_text()
    # The concrete agent-token string must not be serialized anywhere.
    assert agent_token not in raw
    assert "agents" not in json.loads(raw)


def test_every_persisted_session_token_is_a_session_token_not_agent(
    tmp_path: Path,
) -> None:
    store_file = tmp_path / "sessions.json"
    store = AuthTokenStore(persist_path=store_file, autoload=False)

    agent_token = store.register_agent_token("agent-alice")
    init_token, resp_token = store.register_session_tokens(
        "session-1", "agent-alice", "bob",
    )

    payload = json.loads(store_file.read_text())
    persisted_tokens = {entry["token"] for entry in payload["sessions"]}

    # Exactly the two session tokens land on disk, and the agent token is not
    # masquerading as one of them.
    assert persisted_tokens == {init_token, resp_token}
    assert agent_token not in persisted_tokens


# ---------------------------------------------------------------------------
# TTL expiry is fail-closed AT the boundary. _is_expired uses time.time() >=
# expiry, so an exactly-expired token (expires_at == now) must be REJECTED and
# a token with one second of life left (expires_at == now + 1) must VALIDATE.
# ---------------------------------------------------------------------------


def test_session_token_rejected_exactly_at_expiry_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixed_t = 1_000_000.0
    monkeypatch.setattr(auth_module.time, "time", lambda: fixed_t)

    # ttl=0 means expiry == issue time == fixed_t, i.e. exactly at the boundary.
    store = AuthTokenStore(
        persist_path=tmp_path / "sessions.json", ttl_seconds=0, autoload=False,
    )
    init_token, _ = store.register_session_tokens("session-a", "a", "b")

    assert not store.validate_session_token("session-a", "initiator", init_token)


def test_session_token_valid_one_second_before_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixed_t = 1_000_000.0
    monkeypatch.setattr(auth_module.time, "time", lambda: fixed_t)

    # ttl=1 means expiry == fixed_t + 1; at fixed_t the token is still live.
    store = AuthTokenStore(
        persist_path=tmp_path / "sessions.json", ttl_seconds=1, autoload=False,
    )
    init_token, _ = store.register_session_tokens("session-a", "a", "b")

    assert store.validate_session_token("session-a", "initiator", init_token)


# ---------------------------------------------------------------------------
# An expired session token is scrubbed from disk on validation, so it cannot
# be resurrected by a server restart that reloads the file.
# ---------------------------------------------------------------------------


def test_expired_session_token_is_scrubbed_from_disk_on_validation(
    tmp_path: Path,
) -> None:
    store_file = tmp_path / "sessions.json"
    store = AuthTokenStore(
        persist_path=store_file, ttl_seconds=0, autoload=False,
    )
    init_token, _ = store.register_session_tokens("session-a", "a", "b")

    # The entry is on disk immediately after issue.
    before = json.loads(store_file.read_text())
    assert any(
        entry["session_id"] == "session-a" and entry["role"] == "initiator"
        for entry in before["sessions"]
    )

    time.sleep(0.01)
    assert not store.validate_session_token("session-a", "initiator", init_token)

    # Validation of an expired token must rewrite the file without that entry,
    # so a restart cannot resurrect it.
    after = json.loads(store_file.read_text())
    assert not any(
        entry["session_id"] == "session-a" and entry["role"] == "initiator"
        for entry in after["sessions"]
    )


# ---------------------------------------------------------------------------
# A type-poisoned expires_at on disk must never be coerced into a live token.
# float("not-a-number") raises inside the loader; autoload swallows the error
# (best-effort load) and the token is simply not admitted (fail closed).
# ---------------------------------------------------------------------------


def test_type_poisoned_expires_at_through_loader_does_not_admit_token(
    tmp_path: Path,
) -> None:
    store_file = tmp_path / "sessions.json"
    token = "c" * 64
    store_file.write_text(
        json.dumps(
            {
                "sessions": [
                    {
                        "session_id": "poisoned",
                        "role": "initiator",
                        "token": token,
                        "expires_at": "not-a-number",
                    }
                ]
            }
        )
    )

    store = AuthTokenStore(persist_path=store_file)

    assert store.get_any_session_role("poisoned", token) is None
    assert not store.validate_session_token("poisoned", "initiator", token)
