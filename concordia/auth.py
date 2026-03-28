"""Caller authentication for Concordia MCP tools.

Implements bearer-token authentication as specified in REMEDIATION_PLAN CP-05.
Tokens are 256-bit random hex strings issued at two scopes:

1. **Agent-scoped** — issued by ``concordia_register_agent``, required for
   registry, relay, want/have, and attestation operations referencing that agent.
2. **Session-scoped** — issued by ``concordia_open_session``, one per role,
   required for all negotiation tool calls within that session.

This is transport-level authentication, not cryptographic identity verification.
It prevents trivial impersonation from a second MCP client but does not prove
the caller possesses a specific Ed25519 private key.
"""

from __future__ import annotations

import hmac
import secrets


def generate_token() -> str:
    """Generate a 256-bit cryptographically random hex token."""
    return secrets.token_hex(32)


class AuthTokenStore:
    """Manages bearer tokens for agent and session scopes.

    Thread-safety: this class is designed for single-threaded use within
    the MCP server event loop — no locking is provided.
    """

    def __init__(self) -> None:
        # agent_id -> token
        self._agent_tokens: dict[str, str] = {}
        # (session_id, role_canonical) -> token
        self._session_tokens: dict[tuple[str, str], str] = {}
        # token -> agent_id  (reverse lookup for agent tokens)
        self._token_to_agent: dict[str, str] = {}

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
        self._session_tokens[(session_id, "initiator")] = init_token
        self._session_tokens[(session_id, "responder")] = resp_token
        return init_token, resp_token

    def validate_session_token(
        self, session_id: str, role: str, token: str,
    ) -> bool:
        """Check that *token* matches the session+role pair.

        Uses constant-time comparison.
        """
        canonical = self._canonical_role(role)
        expected = self._session_tokens.get((session_id, canonical))
        if expected is None:
            return False
        return hmac.compare_digest(expected, token)

    def get_any_session_role(self, session_id: str, token: str) -> str | None:
        """Return the canonical role for *token* in *session_id*, or None."""
        for role_name in ("initiator", "responder"):
            expected = self._session_tokens.get((session_id, role_name))
            if expected is not None and hmac.compare_digest(expected, token):
                return role_name
        return None
