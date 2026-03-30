"""Portable Receipt Bundles — self-contained, verifiable negotiation history.

An agent carries a ReceiptBundle as proof of its negotiation track record.
Any counterparty can verify it offline — no network calls to reputation
services needed.

Implements Viral Strategy item #18: session receipts as portable proof.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .signing import KeyPair, canonical_json, sign_message, verify_signature


# ---------------------------------------------------------------------------
# Bundle summary — precomputed aggregate stats
# ---------------------------------------------------------------------------

@dataclass
class BundleSummary:
    """Precomputed aggregate stats that a verifier cares about.

    Every field is deterministically recomputable from the attestations,
    so no trust in the summary is required — verifiers recompute and compare.
    """
    total_negotiations: int = 0
    agreements: int = 0
    agreement_rate: float = 0.0
    avg_concession_magnitude: float = 0.0
    fulfillment_rate: float = 0.0
    unique_counterparties: int = 0
    categories: list[str] = field(default_factory=list)
    earliest: str = ""
    latest: str = ""
    reasoning_rate: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_negotiations": self.total_negotiations,
            "agreements": self.agreements,
            "agreement_rate": self.agreement_rate,
            "avg_concession_magnitude": self.avg_concession_magnitude,
            "fulfillment_rate": self.fulfillment_rate,
            "unique_counterparties": self.unique_counterparties,
            "categories": self.categories,
            "earliest": self.earliest,
            "latest": self.latest,
            "reasoning_rate": self.reasoning_rate,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BundleSummary:
        return cls(
            total_negotiations=data.get("total_negotiations", 0),
            agreements=data.get("agreements", 0),
            agreement_rate=data.get("agreement_rate", 0.0),
            avg_concession_magnitude=data.get("avg_concession_magnitude", 0.0),
            fulfillment_rate=data.get("fulfillment_rate", 0.0),
            unique_counterparties=data.get("unique_counterparties", 0),
            categories=data.get("categories", []),
            earliest=data.get("earliest", ""),
            latest=data.get("latest", ""),
            reasoning_rate=data.get("reasoning_rate", 0.0),
        )


def _compute_summary(agent_id: str, attestations: list[dict[str, Any]]) -> BundleSummary:
    """Deterministically compute a BundleSummary from a list of attestations."""
    if not attestations:
        return BundleSummary()

    total = len(attestations)
    agreements = 0
    concession_magnitudes: list[float] = []
    fulfillment_count = 0
    fulfillment_total = 0
    reasoning_count = 0
    counterparties: set[str] = set()
    categories: set[str] = set()
    timestamps: list[str] = []

    for att in attestations:
        outcome = att.get("outcome", {})
        if outcome.get("status") == "agreed":
            agreements += 1

        parties = att.get("parties", [])
        for party in parties:
            pid = party.get("agent_id", "")
            if pid != agent_id:
                counterparties.add(pid)
            if pid == agent_id:
                behavior = party.get("behavior", {})
                cm = behavior.get("concession_magnitude")
                if cm is not None and isinstance(cm, (int, float)):
                    concession_magnitudes.append(float(cm))
                if behavior.get("reasoning_provided", False):
                    reasoning_count += 1

        # Fulfillment
        fulfillment = att.get("fulfillment")
        if fulfillment is not None:
            fulfillment_total += 1
            status = fulfillment.get("status", "")
            if status in ("fulfilled", "complete"):
                fulfillment_count += 1

        # Category
        meta = att.get("meta", {})
        cat = meta.get("category")
        if cat:
            categories.add(cat)

        # Timestamp
        ts = att.get("timestamp", "")
        if ts:
            timestamps.append(ts)

    timestamps.sort()

    avg_concession = 0.0
    if concession_magnitudes:
        avg_concession = sum(concession_magnitudes) / len(concession_magnitudes)

    fulfillment_rate = 0.0
    if fulfillment_total > 0:
        fulfillment_rate = fulfillment_count / fulfillment_total

    agreement_rate = agreements / total if total > 0 else 0.0
    reasoning_rate = reasoning_count / total if total > 0 else 0.0

    return BundleSummary(
        total_negotiations=total,
        agreements=agreements,
        agreement_rate=round(agreement_rate, 4),
        avg_concession_magnitude=round(avg_concession, 4),
        fulfillment_rate=round(fulfillment_rate, 4),
        unique_counterparties=len(counterparties),
        categories=sorted(categories),
        earliest=timestamps[0] if timestamps else "",
        latest=timestamps[-1] if timestamps else "",
        reasoning_rate=round(reasoning_rate, 4),
    )


# ---------------------------------------------------------------------------
# Receipt Bundle
# ---------------------------------------------------------------------------

@dataclass
class ReceiptBundle:
    """A portable, self-contained collection of session receipts.

    An agent carries this as proof of negotiation history.
    Any counterparty can verify it without contacting a reputation service.
    """
    bundle_id: str
    agent_id: str
    created_at: str
    attestations: list[dict[str, Any]]
    summary: BundleSummary
    agent_signature: str

    @classmethod
    def create(
        cls,
        agent_id: str,
        attestations: list[dict[str, Any]],
        key_pair: KeyPair,
    ) -> ReceiptBundle:
        """Build a bundle, compute summary, and sign it.

        Args:
            agent_id: The agent creating the bundle.
            attestations: List of attestation dicts to include.
            key_pair: The agent's Ed25519 key pair for signing.

        Returns:
            A signed ReceiptBundle.

        Raises:
            ValueError: If the agent_id is not a party in every attestation.
        """
        # Validate that agent appears in every attestation
        for i, att in enumerate(attestations):
            parties = att.get("parties", [])
            party_ids = [p.get("agent_id", "") for p in parties]
            if agent_id not in party_ids:
                raise ValueError(
                    f"Agent '{agent_id}' is not a party in attestation {i} "
                    f"(session: {att.get('session_id', 'unknown')})"
                )

        bundle_id = f"bundle_{uuid.uuid4().hex[:12]}"
        created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        summary = _compute_summary(agent_id, attestations)

        # Build the signable content
        signable = {
            "bundle_id": bundle_id,
            "agent_id": agent_id,
            "created_at": created_at,
            "attestations": attestations,
            "summary": summary.to_dict(),
        }

        signature = sign_message(signable, key_pair)

        return cls(
            bundle_id=bundle_id,
            agent_id=agent_id,
            created_at=created_at,
            attestations=attestations,
            summary=summary,
            agent_signature=signature,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the bundle to a dict."""
        return {
            "concordia_receipt_bundle": "0.1.0",
            "bundle_id": self.bundle_id,
            "agent_id": self.agent_id,
            "created_at": self.created_at,
            "attestations": self.attestations,
            "summary": self.summary.to_dict(),
            "agent_signature": self.agent_signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReceiptBundle:
        """Deserialize a bundle from a dict."""
        return cls(
            bundle_id=data["bundle_id"],
            agent_id=data["agent_id"],
            created_at=data["created_at"],
            attestations=data["attestations"],
            summary=BundleSummary.from_dict(data["summary"]),
            agent_signature=data["agent_signature"],
        )

    def to_json(self) -> str:
        """Canonical JSON for portability."""
        return canonical_json(self.to_dict()).decode("utf-8")


# ---------------------------------------------------------------------------
# Bundle verification
# ---------------------------------------------------------------------------

@dataclass
class BundleVerificationResult:
    """Result of verifying a receipt bundle."""
    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    summary_accurate: bool = True
    sybil_flags: dict[str, Any] = field(default_factory=dict)


def verify_bundle(
    bundle_dict: dict[str, Any],
    resolve_key: Callable[[str], Ed25519PublicKey | None],
) -> BundleVerificationResult:
    """Verify a received receipt bundle.

    Checks:
      (a) Bundle signature matches the agent's public key
      (b) Each attestation's party signatures are valid
      (c) The agent_id appears as a party in every attestation
      (d) Summary statistics match the attestations (no inflated claims)
      (e) Attestations are not duplicated

    Args:
        bundle_dict: The bundle as a dict (from ReceiptBundle.to_dict()).
        resolve_key: Callback that maps agent_id to Ed25519PublicKey, or None.

    Returns:
        BundleVerificationResult with errors/warnings.
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Required fields
    for f in ("bundle_id", "agent_id", "created_at", "attestations", "summary", "agent_signature"):
        if f not in bundle_dict:
            errors.append(f"Missing required field: '{f}'")
    if errors:
        return BundleVerificationResult(valid=False, errors=errors)

    agent_id = bundle_dict["agent_id"]
    attestations = bundle_dict["attestations"]
    signature = bundle_dict["agent_signature"]

    # (a) Verify bundle signature
    agent_key = resolve_key(agent_id)
    if agent_key is None:
        errors.append(f"Cannot resolve public key for bundle agent '{agent_id}'")
    else:
        signable = {
            k: v for k, v in bundle_dict.items()
            if k not in ("agent_signature", "concordia_receipt_bundle")
        }
        if not verify_signature(signable, signature, agent_key):
            errors.append("Bundle signature verification failed")

    # (c) Agent appears in every attestation
    for i, att in enumerate(attestations):
        parties = att.get("parties", [])
        party_ids = [p.get("agent_id", "") for p in parties]
        if agent_id not in party_ids:
            errors.append(
                f"Agent '{agent_id}' not a party in attestation {i}"
            )

    # (b) Verify each attestation's party signatures
    for i, att in enumerate(attestations):
        parties = att.get("parties", [])
        for j, party in enumerate(parties):
            pid = party.get("agent_id", "")
            sig = party.get("signature", "")
            if not sig:
                errors.append(f"Attestation {i}, party {j} ('{pid}'): empty signature")
                continue
            party_key = resolve_key(pid)
            if party_key is None:
                warnings.append(
                    f"Attestation {i}, party {j} ('{pid}'): cannot resolve key, signature not verified"
                )
                continue
            signable_party = {k: v for k, v in party.items() if k != "signature"}
            if not verify_signature(signable_party, sig, party_key):
                errors.append(
                    f"Attestation {i}, party {j} ('{pid}'): invalid signature"
                )

    # (e) Check for duplicated attestations
    att_ids = [a.get("attestation_id", "") for a in attestations]
    session_ids = [a.get("session_id", "") for a in attestations]
    if len(set(att_ids)) != len(att_ids):
        errors.append("Duplicate attestation_ids in bundle")
    if len(set(session_ids)) != len(session_ids):
        errors.append("Duplicate session_ids in bundle")

    # (d) Verify summary accuracy
    summary_accurate = True
    if attestations:
        recomputed = _compute_summary(agent_id, attestations)
        claimed = BundleSummary.from_dict(bundle_dict["summary"])

        mismatches: list[str] = []
        if claimed.total_negotiations != recomputed.total_negotiations:
            mismatches.append(f"total_negotiations: claimed {claimed.total_negotiations}, actual {recomputed.total_negotiations}")
        if claimed.agreements != recomputed.agreements:
            mismatches.append(f"agreements: claimed {claimed.agreements}, actual {recomputed.agreements}")
        if abs(claimed.agreement_rate - recomputed.agreement_rate) > 0.001:
            mismatches.append(f"agreement_rate: claimed {claimed.agreement_rate}, actual {recomputed.agreement_rate}")
        if abs(claimed.avg_concession_magnitude - recomputed.avg_concession_magnitude) > 0.001:
            mismatches.append(f"avg_concession_magnitude: claimed {claimed.avg_concession_magnitude}, actual {recomputed.avg_concession_magnitude}")
        if claimed.unique_counterparties != recomputed.unique_counterparties:
            mismatches.append(f"unique_counterparties: claimed {claimed.unique_counterparties}, actual {recomputed.unique_counterparties}")
        if sorted(claimed.categories) != sorted(recomputed.categories):
            mismatches.append(f"categories mismatch")
        if abs(claimed.reasoning_rate - recomputed.reasoning_rate) > 0.001:
            mismatches.append(f"reasoning_rate: claimed {claimed.reasoning_rate}, actual {recomputed.reasoning_rate}")

        if mismatches:
            summary_accurate = False
            for m in mismatches:
                errors.append(f"Summary mismatch: {m}")

    # Sybil screening
    sybil_flags = screen_bundle(bundle_dict)

    if sybil_flags.get("flagged", False):
        for flag, flagged in sybil_flags.items():
            if flag != "flagged" and flagged:
                warnings.append(f"Sybil signal: {flag}")

    return BundleVerificationResult(
        valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
        summary_accurate=summary_accurate,
        sybil_flags=sybil_flags,
    )


# ---------------------------------------------------------------------------
# Sybil screening for bundles
# ---------------------------------------------------------------------------

def screen_bundle(bundle_dict: dict[str, Any]) -> dict[str, Any]:
    """Screen a bundle for Sybil patterns.

    Flags:
      - low_counterparty_diversity: fewer unique counterparties than expected
      - timing_anomaly: multiple sessions with suspiciously fast durations (<5s)
      - symmetric_concessions: identical concession patterns across sessions
      - self_dealing: agent appears on both sides of any attestation

    Returns a dict of signal names to booleans, plus a 'flagged' key.
    """
    agent_id = bundle_dict.get("agent_id", "")
    attestations = bundle_dict.get("attestations", [])

    low_diversity = False
    timing_anomaly = False
    symmetric_concessions_flag = False
    self_dealing = False

    if not attestations:
        return {
            "low_counterparty_diversity": False,
            "timing_anomaly": False,
            "symmetric_concessions": False,
            "self_dealing": False,
            "flagged": False,
        }

    # Self-dealing
    for att in attestations:
        parties = att.get("parties", [])
        ids = [p.get("agent_id", "") for p in parties]
        if len(ids) >= 2 and ids[0] == ids[1]:
            self_dealing = True
            break

    # Low counterparty diversity
    counterparties: set[str] = set()
    for att in attestations:
        for party in att.get("parties", []):
            pid = party.get("agent_id", "")
            if pid != agent_id:
                counterparties.add(pid)
    # Flag if >3 attestations but only 1 counterparty
    if len(attestations) > 3 and len(counterparties) <= 1:
        low_diversity = True

    # Timing anomaly: >50% of sessions are suspiciously fast
    fast_count = 0
    for att in attestations:
        duration = att.get("outcome", {}).get("duration_seconds", 999)
        if duration < 5:
            fast_count += 1
    if len(attestations) > 1 and fast_count > len(attestations) / 2:
        timing_anomaly = True

    # Symmetric concessions
    symmetric_count = 0
    for att in attestations:
        parties = att.get("parties", [])
        if len(parties) >= 2:
            behaviors = [p.get("behavior", {}) for p in parties]
            cm0 = behaviors[0].get("concession_magnitude", -1)
            cm1 = behaviors[1].get("concession_magnitude", -2)
            if cm0 == cm1 and cm0 > 0:
                symmetric_count += 1
    if len(attestations) > 1 and symmetric_count > len(attestations) / 2:
        symmetric_concessions_flag = True

    flagged = any([low_diversity, timing_anomaly, symmetric_concessions_flag, self_dealing])

    return {
        "low_counterparty_diversity": low_diversity,
        "timing_anomaly": timing_anomaly,
        "symmetric_concessions": symmetric_concessions_flag,
        "self_dealing": self_dealing,
        "flagged": flagged,
    }


# ---------------------------------------------------------------------------
# Bundle freshness check
# ---------------------------------------------------------------------------

DEFAULT_FRESHNESS_HOURS = 720  # 30 days


def check_freshness(
    bundle_dict: dict[str, Any],
    max_age_hours: float = DEFAULT_FRESHNESS_HOURS,
) -> tuple[bool, str]:
    """Check if a bundle is within the freshness threshold.

    Returns (is_fresh, message).
    """
    created_at = bundle_dict.get("created_at", "")
    if not created_at:
        return False, "Bundle has no created_at timestamp"

    try:
        created = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return False, f"Invalid created_at format: {created_at}"

    now = datetime.now(timezone.utc)
    age_hours = (now - created).total_seconds() / 3600

    if age_hours > max_age_hours:
        return False, f"Bundle is {age_hours:.1f} hours old (threshold: {max_age_hours}h)"

    return True, f"Bundle is {age_hours:.1f} hours old (within {max_age_hours}h threshold)"


# ---------------------------------------------------------------------------
# In-memory bundle store (session-scoped)
# ---------------------------------------------------------------------------

class BundleStore:
    """In-memory store for receipt bundles created in the current session."""

    MAX_BUNDLES = 1000

    def __init__(self) -> None:
        self._bundles: dict[str, dict[str, Any]] = {}
        self._by_agent: dict[str, list[str]] = {}

    def store(self, bundle: ReceiptBundle) -> None:
        """Store a bundle."""
        if len(self._bundles) >= self.MAX_BUNDLES:
            raise ValueError("Bundle store capacity reached")
        bundle_dict = bundle.to_dict()
        self._bundles[bundle.bundle_id] = bundle_dict
        if bundle.agent_id not in self._by_agent:
            self._by_agent[bundle.agent_id] = []
        self._by_agent[bundle.agent_id].append(bundle.bundle_id)

    def get(self, bundle_id: str) -> dict[str, Any] | None:
        return self._bundles.get(bundle_id)

    def list_by_agent(self, agent_id: str) -> list[dict[str, Any]]:
        bundle_ids = self._by_agent.get(agent_id, [])
        return [self._bundles[bid] for bid in bundle_ids if bid in self._bundles]

    def count(self) -> int:
        return len(self._bundles)
