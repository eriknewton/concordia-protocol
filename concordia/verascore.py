"""Verascore reputation reporting — push negotiation receipts to Verascore.

Posts behavioral metadata from concluded Concordia sessions to the Verascore
transaction ingestion API. Only behavioral signals are sent (rounds, duration,
outcome, concession count) — never raw deal terms, prices, or counterparty
names. This is a hard constraint from §9.6 and CLAUDE.md rule #8.

Requires VERASCORE_ENABLED=true environment variable to activate, ensuring
no external data is transmitted without explicit user intent (CLAUDE.md rule #1).
"""

from __future__ import annotations

import base64
import json
import logging
import os
import urllib.request
import urllib.error
from typing import TYPE_CHECKING, Any, Callable, cast

from .cosign import CounterpartySigner, build_cosigned_receipt, did_key_for
from .signing import KeyPair, canonical_json

if TYPE_CHECKING:
    from .session import Session

_logger = logging.getLogger("concordia.verascore")

VERASCORE_ENABLED_ENV = "VERASCORE_ENABLED"
VERASCORE_ENDPOINT_ENV = "VERASCORE_ENDPOINT"
DEFAULT_VERASCORE_ENDPOINT = "https://verascore.ai"


def _b64url(raw: bytes) -> str:
    """Unpadded base64url, matching Verascore's bufferToBase64url / the decode
    in base64urlToBuffer (src/lib/crypto.ts), which re-adds padding on verify."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


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


def build_publish_body(
    session_data: dict[str, Any],
    key_pair: KeyPair,
    agent_did: str,
    *,
    counterparty_signer: CounterpartySigner | None = None,
) -> dict[str, Any]:
    """Build the complete signed ``/api/publish`` envelope (pure, no I/O).

    This is the single source of truth for the Concordia→Verascore transport
    envelope shape. ``VerascoreClient.report_concordia_receipt`` POSTs exactly
    this object; the cross-repo fixture generator emits exactly this object so
    Verascore's test suite can verify it with the real route-layer functions.

    Raises:
        ValueError: If the envelope cannot be built completely — e.g.
            ``agent_did`` does not match the signing key's ``did:key``, or
            the receipt is not canonicalizable. A partial or unverifiable
            envelope is never produced (CLAUDE.md rule #5, fail closed).
    """
    # ── Publisher identity must equal the signing key's did:key ──────────
    # Verascore's /api/publish IGNORES any caller-supplied agentId and
    # derives the publisher identity from the verified Ed25519 publicKey
    # (deriveAgentId -> did:key:z<base64url(0xed01||pubkey)>, see
    # src/lib/crypto.ts). The receipt's publisher party, the envelope's
    # publicKey, and data.did must all resolve to that same identity or the
    # publish is unverifiable. Fail closed if the caller passed a DID that
    # is not this key's did:key.
    expected_did = did_key_for(key_pair)
    if agent_did != expected_did:
        raise ValueError(
            "agent_did does not match the signing key's did:key; Verascore "
            "derives the publisher identity from the publicKey, so they must "
            f"be identical (expected {expected_did!r}, got {agent_did!r})"
        )

    # Bilateral receipt (parties[] with the counterparty co-signature when
    # available). This is the H1/H2 producer half: Verascore counts a
    # receipt toward a trust-bearing score only if the named counterparty
    # cryptographically co-signed it. Fail-closed to single-signed.
    receipt = build_cosigned_receipt(
        session_data,
        agent_did,
        counterparty_signer=counterparty_signer,
    )

    # ── Build the signed `data` object Verascore consumes ───────────────
    # The route extracts the receipt from data.receipt (extractConcordia-
    # ReceiptPayload) and canonicalizes THAT object for the co-signature
    # check, so the receipt must be nested untouched (no sibling keys mixed
    # in). data.did lets the route bind the publish to this publicKey and
    # reject DID squatting.
    data = {
        "did": agent_did,
        "receipt": receipt,
    }

    # The route verifies the publisher-envelope signature over
    # JSON.stringify(data) (route.ts: `Buffer.from(JSON.stringify(data))`).
    # canonical_json is byte-identical to ECMAScript JSON.stringify with
    # sorted keys; because the route re-stringifies the object it parsed
    # (preserving wire key order) and we send `data` with those same sorted
    # keys, the server reproduces these exact bytes. Signature is base64url
    # raw Ed25519 (NOT hex) and publicKey is base64url raw 32-byte key, both
    # matching the route's base64urlToBuffer decode.
    data_bytes = canonical_json(data)
    raw_sig = key_pair.private_key.sign(data_bytes)
    signature_b64url = _b64url(raw_sig)
    public_key_b64url = _b64url(key_pair.public_key_bytes())

    return {
        "type": "concordia-receipt",
        "publicKey": public_key_b64url,
        "signature": signature_b64url,
        "data": data,
    }


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
        *,
        counterparty_signer: CounterpartySigner | None = None,
    ) -> dict[str, Any]:
        """Sign and POST a Concordia receipt to Verascore.

        Args:
            session_data: Behavioral metadata extracted from the session.
                Must contain: session_id, counterparty_did, outcome, rounds,
                duration_seconds, terms_count, concessions_made,
                fulfillment_status, negotiation_competence.
            key_pair: The agent's Ed25519 key pair for signing.
            agent_did: The agent's DID (e.g. "did:key:z6Mk...").
            counterparty_signer: Optional collector for the counterparty's
                Ed25519 co-signature (see ``concordia.cosign``). When supplied
                and the counterparty signs, the emitted ``receipt`` carries the
                counterparty signature on its ``parties[]`` entry, so Verascore
                can verify it as bilateral (cryptographic-tier) evidence.
                FAIL CLOSED: if omitted, or the counterparty is unavailable, the
                receipt is emitted clearly single-signed — never with an empty or
                fabricated co-signature (CLAUDE.md rule #5).

        Returns:
            The parsed JSON response from Verascore, or an error dict.

        Raises:
            ValueError: If the envelope cannot be built completely — e.g.
                ``agent_did`` does not match the signing key's ``did:key``, or
                the receipt is not canonicalizable. A partial or unverifiable
                envelope is never transmitted (CLAUDE.md rule #5, fail closed).
        """
        # Envelope construction (identity check, co-signed receipt, signed
        # data object) lives in build_publish_body — the single source of
        # truth shared with the cross-repo fixture generator.
        body = build_publish_body(
            session_data,
            key_pair,
            agent_did,
            counterparty_signer=counterparty_signer,
        )

        # Serialize with the same canonical serializer so the on-wire `data`
        # sub-object is byte-identical to the signed `data_bytes` (sorted keys
        # at every level). Never emit a partial envelope.
        body_bytes = canonical_json(body)
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
                    return cast(dict[str, Any], json.loads(resp_body))
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
    counterparty_signer: CounterpartySigner | None = None,
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
        counterparty_signer: Optional collector for the counterparty's
            Ed25519 co-signature (see ``concordia.cosign``). When supplied,
            the auto-reported receipt is bilateral (counterparty-co-signed) and
            can earn Verascore's cryptographic trust tier. Fail-closed to a
            single-signed receipt when absent or the counterparty is unavailable.

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
                counterparty_signer=counterparty_signer,
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
