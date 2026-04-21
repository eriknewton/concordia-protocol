"""Verascore reputation reporting — push negotiation receipts to Verascore.

Posts behavioral metadata from concluded Concordia sessions to the Verascore
transaction ingestion API. Only behavioral signals are sent (rounds, duration,
outcome, concession count) — never raw deal terms, prices, or counterparty
names. This is a hard constraint from §9.6 and CLAUDE.md rule #8.

Requires VERASCORE_ENABLED=true environment variable to activate, ensuring
no external data is transmitted without explicit user intent (CLAUDE.md rule #1).
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable

from .signing import KeyPair, canonical_json

if TYPE_CHECKING:
    from .session import Session

_logger = logging.getLogger("concordia.verascore")

VERASCORE_ENABLED_ENV = "VERASCORE_ENABLED"
VERASCORE_ENDPOINT_ENV = "VERASCORE_ENDPOINT"
DEFAULT_VERASCORE_ENDPOINT = "https://verascore.ai"


def compute_negotiation_competence(
    outcome: str,
    fulfillment_status: str,
    rounds: int,
    concessions_made: int,
) -> int:
    """Compute a negotiation competence score (0-100).

    Scoring:
        base = 50
        +15 if outcome is "agreed"
        +10 if fulfillment_status is "fulfilled"
        +5 per round (max +15) — deeper negotiations show more skill
        +10 if concessions_made > 0 (willingness to negotiate)
        -20 if outcome is "expired" or "withdrawn" (penalize abandonment)
    """
    score = 50

    if outcome == "agreed":
        score += 15
    elif outcome in ("expired", "withdrawn"):
        score -= 20

    if fulfillment_status == "fulfilled":
        score += 10

    score += min(rounds * 5, 15)

    if concessions_made > 0:
        score += 10

    return max(0, min(100, score))


class VerascoreClient:
    """HTTP client for the Verascore transaction ingestion API.

    Uses stdlib urllib.request — no external HTTP dependencies.
    """

    def __init__(self, base_url: str = "https://verascore.ai") -> None:
        self.base_url = base_url.rstrip("/")

    def report_concordia_receipt(
        self,
        session_data: dict[str, Any],
        key_pair: KeyPair,
        agent_did: str,
    ) -> dict[str, Any]:
        """Sign and POST a Concordia receipt to Verascore.

        Args:
            session_data: Behavioral metadata extracted from the session.
                Must contain: session_id, counterparty_did, outcome, rounds,
                duration_seconds, terms_count, concessions_made,
                fulfillment_status, negotiation_competence.
            key_pair: The agent's Ed25519 key pair for signing.
            agent_did: The agent's DID (e.g. "did:key:z6Mk...").

        Returns:
            The parsed JSON response from Verascore, or an error dict.

        Raises:
            ValueError: If signing fails.
        """
        payload = {
            "session_id": session_data["session_id"],
            "counterparty_did": session_data["counterparty_did"],
            "outcome": session_data["outcome"],
            "rounds": session_data["rounds"],
            "duration_seconds": session_data["duration_seconds"],
            "terms_count": session_data["terms_count"],
            "concessions_made": session_data["concessions_made"],
            "fulfillment_status": session_data["fulfillment_status"],
            "negotiation_competence": session_data["negotiation_competence"],
        }

        # Sign the canonical JSON of the payload
        payload_bytes = canonical_json(payload)
        raw_sig = key_pair.private_key.sign(payload_bytes)
        signature_hex = raw_sig.hex()

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        body = {
            "type": "concordia-receipt",
            "did": agent_did,
            "timestamp": timestamp,
            "signature": signature_hex,
            "payload": payload,
        }

        body_bytes = json.dumps(body).encode("utf-8")
        url = f"{self.base_url}/api/publish"

        req = urllib.request.Request(
            url,
            data=body_bytes,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                resp_body = resp.read().decode("utf-8")
                try:
                    return json.loads(resp_body)
                except json.JSONDecodeError:
                    return {"status": "ok", "raw_response": resp_body}
        except urllib.error.HTTPError as e:
            error_body = ""
            try:
                error_body = e.read().decode("utf-8")
            except Exception:
                pass
            return {
                "error": f"Verascore API returned HTTP {e.code}",
                "status_code": e.code,
                "detail": error_body,
            }
        except urllib.error.URLError as e:
            return {
                "error": f"Failed to connect to Verascore: {e.reason}",
            }


# ---------------------------------------------------------------------------
# WP5 v0.4.0 — Post-transition auto-hook
# ---------------------------------------------------------------------------

def _extract_session_data(session: "Session", agent_id: str) -> dict[str, Any]:
    """Build the behavioral-signal payload for a concluded session.

    Idempotency key for Verascore-side upsert is ``session_id``
    (see Verascore ``prisma.concordiaReceipt.upsert({where: {sessionId}})``).
    Behavioral fields only; no terms or prices, per CLAUDE.md rule #8.
    """
    from .types import OutcomeStatus, SessionState  # avoid circular import

    behavior = session.get_behavior(agent_id)
    counterparty_id = next(
        (aid for aid in session.parties if aid != agent_id), ""
    )
    outcome_map = {
        SessionState.AGREED: OutcomeStatus.AGREED.value,
        SessionState.REJECTED: OutcomeStatus.REJECTED.value,
        SessionState.EXPIRED: OutcomeStatus.EXPIRED.value,
    }
    outcome = outcome_map.get(session.state, "unknown")
    terms_count = len(session.terms) if session.terms else 0
    rounds = session.round_count
    fulfillment_status = "pending"
    competence = compute_negotiation_competence(
        outcome=outcome,
        fulfillment_status=fulfillment_status,
        rounds=rounds,
        concessions_made=behavior.concessions,
    )
    return {
        "session_id": session.session_id,
        "counterparty_did": counterparty_id,
        "outcome": outcome,
        "rounds": rounds,
        "duration_seconds": session.duration_seconds(),
        "terms_count": terms_count,
        "concessions_made": behavior.concessions,
        "fulfillment_status": fulfillment_status,
        "negotiation_competence": competence,
    }


def make_verascore_auto_hook(
    key_pair: KeyPair,
    agent_did: str,
    *,
    report_on: tuple[str, ...] = ("agreed",),
    endpoint: str | None = None,
    client: VerascoreClient | None = None,
) -> Callable[["Session"], None]:
    """Return a terminal-state callback that auto-reports to Verascore.

    Designed to be attached to ``Session.on_terminal``. Idempotent on the
    Verascore side — keyed on ``session_id`` — so duplicate fires (e.g.
    if both the auto-hook and an explicit call run) update rather than
    double-count.

    The callback is a no-op unless the ``VERASCORE_ENABLED`` env var is
    exactly ``"true"`` at call time. Endpoint precedence: explicit
    ``endpoint`` arg > ``VERASCORE_ENDPOINT`` env var > default
    ``https://verascore.ai``.

    Args:
        key_pair: The reporting agent's Ed25519 key pair, used to sign
            the outbound payload.
        agent_did: The reporting agent's DID.
        report_on: Terminal outcomes to report on. Defaults to
            ``("agreed",)`` — only AGREED sessions generate a report.
            Can be widened to include ``"rejected"`` / ``"expired"``
            if the caller wants full lifecycle visibility.
        endpoint: Optional base URL override. If provided, takes
            precedence over the ``VERASCORE_ENDPOINT`` env var.
        client: Optional injected ``VerascoreClient`` (for testing).

    Returns:
        A ``Callable[[Session], None]`` suitable for ``Session.on_terminal``.
    """
    def _hook(session: "Session") -> None:
        if os.environ.get(VERASCORE_ENABLED_ENV) != "true":
            return
        from .types import SessionState

        terminal_str_map = {
            SessionState.AGREED: "agreed",
            SessionState.REJECTED: "rejected",
            SessionState.EXPIRED: "expired",
        }
        outcome_str = terminal_str_map.get(session.state)
        if outcome_str is None or outcome_str not in report_on:
            return
        base = (
            endpoint
            or os.environ.get(VERASCORE_ENDPOINT_ENV)
            or DEFAULT_VERASCORE_ENDPOINT
        )
        http_client = client or VerascoreClient(base_url=base)
        session_data = _extract_session_data(session, agent_did)
        try:
            result = http_client.report_concordia_receipt(
                session_data=session_data,
                key_pair=key_pair,
                agent_did=agent_did,
            )
        except Exception as exc:
            _logger.warning(
                "Verascore auto-report raised %s for session %s",
                type(exc).__name__,
                session.session_id,
            )
            return
        if isinstance(result, dict) and "error" in result:
            _logger.warning(
                "Verascore auto-report failed for session %s: %s",
                session.session_id,
                result.get("error"),
            )
        else:
            _logger.info(
                "Verascore auto-report ok for session %s",
                session.session_id,
            )

    return _hook
