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
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any

from .signing import KeyPair, canonical_json


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
