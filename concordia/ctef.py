"""CTEF mappings for Concordia artifacts."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .predicate import Predicate


def predicate_to_ctef_claim(
    predicate: Predicate | dict[str, Any],
    *,
    verified_at: str | None = None,
) -> dict[str, Any]:
    """Map an authority-class predicate to a CTEF claim."""
    pred = predicate if isinstance(predicate, Predicate) else Predicate.from_dict(predicate)
    condition = pred.condition if isinstance(pred.condition, dict) else {}
    return {
        "claim_type": "authority",
        "claim_subtype": "predicate_evaluation",
        "artifact_ref": pred.predicate_id,
        "issuer": pred.issuer,
        "subject": pred.subject,
        "authority": pred.authority,
        "verified_at": verified_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "result": condition.get("result"),
    }


__all__ = ["predicate_to_ctef_claim"]
