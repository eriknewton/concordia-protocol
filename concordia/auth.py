"""Caller authentication for Concordia MCP tools.

Implements bearer-token authentication as specified in REMEDIATION_PLAN CP-05.
Tokens are 256-bit random hex strings issued at two scopes:

1. **Agent auth token (long-lived)** — identifies/authenticates a Concordia
   agent itself across sessions. Issued by ``concordia_register_agent``.
   Required for registry, relay, want/have, and attestation operations
   referencing that agent. Lives for the lifetime of the agent registration
   (until explicitly revoked via deregister). Treat like an API key for the
   agent identity.
2. **Session token (short-lived, per-session)** — grants a specific role
   (initiator or responder) access to a specific negotiation session.
   Issued by ``concordia_open_session``, one per role. Required for all
   negotiation tool calls within that session. Persisted to disk under
   ``~/.concordia/sessions.json`` with a 24h TTL so responder clients can
   reconnect across server restarts. The responder token in particular is
   the credential a responder web UI submits to sign off on an offer.

These two token types are distinct: losing a session token only affects one
negotiation; losing an agent auth token compromises the agent identity
across every session and registry interaction it touches.

This is transport-level authentication, not cryptographic identity
verification. It prevents trivial impersonation from a second MCP client
but does not prove the caller possesses a specific Ed25519 private key.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import tempfile
import time
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Disk-persistence configuration
# ---------------------------------------------------------------------------

# Default session token TTL: 24 hours.
SESSION_TOKEN_TTL_SECONDS = 24 * 60 * 60

# Default path for persisted session tokens.  Overridable via env var for
# tests and sandboxed deployments.
_DEFAULT_SESSION_STORE_PATH = Path(
    os.environ.get(
        "CONCORDIA_SESSION_STORE",
        str(Path.home() / ".concordia" / "sessions.json"),
    )
)


def generate_token() -> str:
    """Generate a 256-bit cryptographically random hex token."""
    return secrets.token_hex(32)


class AuthTokenStore:
    """Manages bearer tokens for agent and session scopes.

    Thread-safety: this class is designed for single-threaded use within
    the MCP server event loop — no locking is provided.
    """

    def __init__(
        self,
        *,
        persist_path: Path | None = None,
        ttl_seconds: int = SESSION_TOKEN_TTL_SECONDS,
        autoload: bool = True,
    ) -> None:
        # agent_id -> token
        self._agent_tokens: dict[str, str] = {}
        # (session_id, role_canonical) -> token
        self._session_tokens: dict[tuple[str, str], str] = {}
        # (session_id, role_canonical) -> unix-epoch expiry
        self._session_expiry: dict[tuple[str, str], float] = {}
        # token -> agent_id  (reverse lookup for agent tokens)
        self._token_to_agent: dict[str, str] = {}

        # Persistence config
        self._persist_path: Path = persist_path or _DEFAULT_SESSION_STORE_PATH
        self._ttl_seconds: int = ttl_seconds

        if autoload:
            try:
                self._load_session_tokens()
            except Exception:
                # Persistence is best-effort; a corrupt file must not block
                # server startup.
                pass

    # ----- Agent-scoped tokens -----

    def register_agent_token(self, agent_id: str) -> str:
        """Issue a new token for an agent.  Replaces any existing token."""
        token = generate_token()
        # Revoke old token if present
        old_token = self._agent_tokens.get(agent_id)
        if old_token is not None:
            self._token_to_agent.pop(old_token, None)
        self._agent_tokens[agent_id] = token
        self._token_to_agent[token] = agent_id
        return token

    def revoke_agent_token(self, agent_id: str) -> None:
        """Revoke the token for an agent (e.g. on deregistration)."""
        old_token = self._agent_tokens.pop(agent_id, None)
        if old_token is not None:
            self._token_to_agent.pop(old_token, None)

    def validate_agent_token(self, agent_id: str, token: str) -> bool:
        """Check that *token* is the current valid token for *agent_id*.

        Uses constant-time comparison to prevent timing side-channels.
        """
        expected = self._agent_tokens.get(agent_id)
        if expected is None:
            return False
        return hmac.compare_digest(expected, token)

    def get_agent_id_for_token(self, token: str) -> str | None:
        """Reverse-lookup: return the agent_id that owns *token*, or None."""
        return self._token_to_agent.get(token)

    # ----- Session-scoped tokens -----

    @staticmethod
    def _canonical_role(role: str) -> str:
        """Normalize role strings to 'initiator' or 'responder'."""
        r = role.lower()
        if r in ("initiator", "seller", "proposer"):
            return "initiator"
        if r in ("responder", "buyer", "receiver"):
            return "responder"
        return r  # let validation catch invalid roles

    def register_session_tokens(
        self, session_id: str, initiator_id: str, responder_id: str,
    ) -> tuple[str, str]:
        """Issue tokens for both roles in a session.

        Returns ``(initiator_token, responder_token)``.
        """
        init_token = generate_token()
        resp_token = generate_token()
        expiry = time.time() + self._ttl_seconds
        self._session_tokens[(session_id, "initiator")] = init_token
        self._session_tokens[(session_id, "responder")] = resp_token
        self._session_expiry[(session_id, "initiator")] = expiry
        self._session_expiry[(session_id, "responder")] = expiry
        self._persist_session_tokens()
        return init_token, resp_token

    def _is_expired(self, key: tuple[str, str]) -> bool:
        exp = self._session_expiry.get(key)
        if exp is None:
            return False  # legacy/unexpiring
        return time.time() >= exp

    def _drop_expired(self, key: tuple[str, str]) -> None:
        self._session_tokens.pop(key, None)
        self._session_expiry.pop(key, None)

    def validate_session_token(
        self, session_id: str, role: str, token: str,
    ) -> bool:
        """Check that *token* matches the session+role pair.

        Uses constant-time comparison.
        """
        canonical = self._canonical_role(role)
        key = (session_id, canonical)
        expected = self._session_tokens.get(key)
        if expected is None:
            return False
        if self._is_expired(key):
            self._drop_expired(key)
            self._persist_session_tokens()
            return False
        return hmac.compare_digest(expected, token)

    def get_any_session_role(self, session_id: str, token: str) -> str | None:
        """Return the canonical role for *token* in *session_id*, or None."""
        for role_name in ("initiator", "responder"):
            key = (session_id, role_name)
            expected = self._session_tokens.get(key)
            if expected is None:
                continue
            if self._is_expired(key):
                self._drop_expired(key)
                continue
            if hmac.compare_digest(expected, token):
                return role_name
        return None

    # ----- Disk persistence (session tokens only) -----

    def _persist_session_tokens(self) -> None:
        """Atomically write session tokens to disk.

        Agent tokens are NOT persisted — they are reissued on each agent
        registration. Only per-session tokens (which responder clients may
        need across server restarts) are written.
        """
        try:
            self._persist_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            return

        payload: dict[str, Any] = {
            "version": "1",
            "ttl_seconds": self._ttl_seconds,
            "sessions": [
                {
                    "session_id": sid,
                    "role": role,
                    "token": token,
                    "expires_at": self._session_expiry.get((sid, role), 0.0),
                }
                for (sid, role), token in self._session_tokens.items()
            ],
        }

        try:
            fd, tmp_path = tempfile.mkstemp(
                prefix=".sessions-",
                suffix=".json.tmp",
                dir=str(self._persist_path.parent),
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(payload, f)
                os.replace(tmp_path, self._persist_path)
                try:
                    os.chmod(self._persist_path, 0o600)
                except OSError:
                    pass
            finally:
                # If mkstemp file still exists (e.g. replace failed), clean up.
                if os.path.exists(tmp_path):
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
        except OSError:
            return

    def _load_session_tokens(self) -> None:
        """Load persisted session tokens from disk, expiring stale ones."""
        if not self._persist_path.exists():
            return
        try:
            with open(self._persist_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except (OSError, json.JSONDecodeError):
            return

        now = time.time()
        changed = False
        for entry in payload.get("sessions", []):
            sid = entry.get("session_id")
            role = entry.get("role")
            token = entry.get("token")
            expires_at = float(entry.get("expires_at", 0.0))
            if not (sid and role and token):
                continue
            if expires_at and expires_at <= now:
                changed = True
                continue
            self._session_tokens[(sid, role)] = token
            self._session_expiry[(sid, role)] = expires_at or (
                now + self._ttl_seconds
            )

        if changed:
            # Rewrite without expired entries.
            self._persist_session_tokens()
