"""Reputation Scorer — computes reputation scores from aggregated attestations.

The scoring engine consumes attestations from the store and produces
composite reputation scores with confidence intervals. Scoring models
are pluggable — the reference implementation provides a general-purpose
model with weighted behavioral signals.

Scoring dimensions (from §9.6 behavioral fields):
    - Agreement rate: fraction of negotiations that reached AGREED
    - Concession willingness: normalized concession magnitude across sessions
    - Fulfillment rate: fraction of agreed deals that were fulfilled
    - Reasoning rate: fraction of sessions where agent used reasoning field
    - Consistency: low variance in behavioral signals across sessions
    - Responsiveness: average concession count (shows engagement)

The overall score is a weighted combination of these dimensions, with
a confidence value that increases with attestation count and counterparty
diversity.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from .store import AttestationStore, StoredAttestation


# ---------------------------------------------------------------------------
# Score components
# ---------------------------------------------------------------------------

@dataclass
class ScoreComponents:
    """Individual scoring dimensions."""
    agreement_rate: float = 0.0
    concession_willingness: float = 0.0
    fulfillment_rate: float = 0.0
    reasoning_rate: float = 0.0
    consistency: float = 0.0
    responsiveness: float = 0.0

    def to_dict(self) -> dict[str, float]:
        return {
            "agreement_rate": round(self.agreement_rate, 4),
            "concession_willingness": round(self.concession_willingness, 4),
            "fulfillment_rate": round(self.fulfillment_rate, 4),
            "reasoning_rate": round(self.reasoning_rate, 4),
            "consistency": round(self.consistency, 4),
            "responsiveness": round(self.responsiveness, 4),
        }


@dataclass
class ReputationScore:
    """A computed reputation score with metadata."""
    agent_id: str
    overall_score: float
    confidence: float
    components: ScoreComponents
    total_negotiations: int
    total_agreements: int
    agreement_rate: float
    fulfillment_rate: float
    avg_concession_willingness: float
    reasoning_rate: float
    median_rounds_to_agreement: int
    categories_active: list[str]
    counterparty_count: int
    sybil_flagged_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_score": round(self.overall_score, 4),
            "confidence": round(self.confidence, 4),
            "components": self.components.to_dict(),
            "total_negotiations": self.total_negotiations,
            "total_agreements": self.total_agreements,
            "agreement_rate": round(self.agreement_rate, 4),
            "fulfillment_rate": round(self.fulfillment_rate, 4),
            "avg_concession_willingness": round(self.avg_concession_willingness, 4),
            "reasoning_rate": round(self.reasoning_rate, 4),
            "median_rounds_to_agreement": self.median_rounds_to_agreement,
            "categories_active": self.categories_active,
            "counterparty_count": self.counterparty_count,
            "sybil_flagged_count": self.sybil_flagged_count,
        }


# ---------------------------------------------------------------------------
# Scoring weights
# ---------------------------------------------------------------------------

# Default weights for the general-purpose scoring model.
# These can be overridden for domain-specific models.
DEFAULT_WEIGHTS = {
    "agreement_rate": 0.25,
    "concession_willingness": 0.15,
    "fulfillment_rate": 0.25,
    "reasoning_rate": 0.10,
    "consistency": 0.10,
    "responsiveness": 0.15,
}


# ---------------------------------------------------------------------------
# Reputation Scorer
# ---------------------------------------------------------------------------

class ReputationScorer:
    """Computes reputation scores from attestation data.

    The scorer reads attestations from the store, extracts behavioral
    signals for a given agent, and combines them into a weighted score.
    """

    def __init__(
        self,
        store: AttestationStore,
        weights: dict[str, float] | None = None,
    ):
        self.store = store
        self.weights = weights or DEFAULT_WEIGHTS

    def score(
        self,
        agent_id: str,
        category: str | None = None,
        value_range: str | None = None,
        role: str | None = None,
    ) -> ReputationScore | None:
        """Compute a reputation score for an agent.

        Args:
            agent_id: The agent to score.
            category: Optional — filter attestations to this category.
            value_range: Optional — filter to this value range.
            role: Optional — filter to attestations where agent had this role.

        Returns:
            A ReputationScore, or None if the agent has no attestations.
        """
        attestations = self.store.get_by_agent(agent_id)
        if not attestations:
            return None

        # Apply filters
        filtered = self._filter(attestations, agent_id, category, value_range, role)
        if not filtered:
            return None

        # Extract behavioral signals
        signals = self._extract_signals(filtered, agent_id)

        # Compute score components
        components = self._compute_components(signals)

        # Weighted overall score
        overall = sum(
            self.weights.get(dim, 0.0) * getattr(components, dim, 0.0)
            for dim in self.weights
        )
        overall = max(0.0, min(1.0, overall))

        # Confidence: increases with count and counterparty diversity
        confidence = self._compute_confidence(signals)

        # Sybil-flagged attestations reduce the score
        sybil_count = signals["sybil_flagged_count"]
        if sybil_count > 0 and signals["total"] > 0:
            sybil_ratio = sybil_count / signals["total"]
            overall *= (1.0 - sybil_ratio * 0.5)  # up to 50% penalty
            confidence *= (1.0 - sybil_ratio * 0.3)

        return ReputationScore(
            agent_id=agent_id,
            overall_score=overall,
            confidence=confidence,
            components=components,
            total_negotiations=signals["total"],
            total_agreements=signals["agreements"],
            agreement_rate=components.agreement_rate,
            fulfillment_rate=components.fulfillment_rate,
            avg_concession_willingness=components.concession_willingness,
            reasoning_rate=components.reasoning_rate,
            median_rounds_to_agreement=signals["median_rounds"],
            categories_active=signals["categories"],
            counterparty_count=signals["counterparty_count"],
            sybil_flagged_count=sybil_count,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _filter(
        self,
        attestations: list[StoredAttestation],
        agent_id: str,
        category: str | None,
        value_range: str | None,
        role: str | None,
    ) -> list[StoredAttestation]:
        """Filter attestations by optional criteria."""
        result = attestations

        if category:
            result = [
                a for a in result
                if a.attestation.get("meta", {}).get("category", "")
                .startswith(category)
            ]

        if value_range:
            result = [
                a for a in result
                if a.attestation.get("meta", {}).get("value_range", "")
                == value_range
            ]

        if role:
            result = [
                a for a in result
                if any(
                    p.get("agent_id") == agent_id and p.get("role") == role
                    for p in a.attestation.get("parties", [])
                )
            ]

        return result

    def _extract_signals(
        self,
        attestations: list[StoredAttestation],
        agent_id: str,
    ) -> dict[str, Any]:
        """Extract raw behavioral signals from filtered attestations."""
        total = len(attestations)
        agreements = 0
        fulfilled = 0
        fulfilled_applicable = 0
        reasoning_count = 0
        concession_magnitudes: list[float] = []
        offer_counts: list[int] = []
        rounds_to_agreement: list[int] = []
        categories: set[str] = set()
        counterparties: set[str] = set()
        sybil_flagged = 0

        for record in attestations:
            att = record.attestation
            outcome = att.get("outcome", {})
            status = outcome.get("status", "")

            if status == "agreed":
                agreements += 1
                rounds_to_agreement.append(outcome.get("rounds", 0))

            # Fulfillment tracking
            fulfillment = att.get("fulfillment")
            if fulfillment and status == "agreed":
                fulfilled_applicable += 1
                if fulfillment.get("status") == "fulfilled":
                    fulfilled += 1

            # Category tracking
            cat = att.get("meta", {}).get("category", "")
            if cat:
                categories.add(cat)

            # Sybil flags
            if record.sybil_signals.flagged:
                sybil_flagged += 1

            # Per-agent behavioral signals
            for party in att.get("parties", []):
                if party.get("agent_id") == agent_id:
                    behavior = party.get("behavior", {})
                    cm = behavior.get("concession_magnitude", 0.0)
                    concession_magnitudes.append(cm)
                    offer_counts.append(behavior.get("offers_made", 0))
                    if behavior.get("reasoning_provided", False):
                        reasoning_count += 1
                else:
                    counterparties.add(party.get("agent_id", ""))

        # Median rounds to agreement
        median_rounds = 0
        if rounds_to_agreement:
            sorted_rounds = sorted(rounds_to_agreement)
            mid = len(sorted_rounds) // 2
            median_rounds = sorted_rounds[mid]

        return {
            "total": total,
            "agreements": agreements,
            "fulfilled": fulfilled,
            "fulfilled_applicable": fulfilled_applicable,
            "reasoning_count": reasoning_count,
            "concession_magnitudes": concession_magnitudes,
            "offer_counts": offer_counts,
            "median_rounds": median_rounds,
            "categories": sorted(categories),
            "counterparty_count": len(counterparties),
            "sybil_flagged_count": sybil_flagged,
        }

    def _compute_components(self, signals: dict[str, Any]) -> ScoreComponents:
        """Compute individual scoring dimensions from raw signals."""
        total = signals["total"]
        if total == 0:
            return ScoreComponents()

        # Agreement rate
        agreement_rate = signals["agreements"] / total

        # Concession willingness: average concession magnitude, capped at 1.0
        magnitudes = signals["concession_magnitudes"]
        avg_concession = (
            sum(magnitudes) / len(magnitudes) if magnitudes else 0.0
        )
        # Normalize: moderate concessions (0.1–0.3) are ideal
        # Too high suggests capitulation, too low suggests rigidity
        if avg_concession <= 0.3:
            concession_score = avg_concession / 0.3  # linear up to 0.3
        else:
            # Diminishing returns above 0.3
            concession_score = 1.0 - (avg_concession - 0.3) * 0.5
        concession_score = max(0.0, min(1.0, concession_score))

        # Fulfillment rate
        if signals["fulfilled_applicable"] > 0:
            fulfillment_rate = signals["fulfilled"] / signals["fulfilled_applicable"]
        else:
            fulfillment_rate = 1.0  # benefit of the doubt when no data

        # Reasoning rate
        reasoning_rate = signals["reasoning_count"] / total

        # Consistency: low variance in offer counts suggests predictable behavior
        offer_counts = signals["offer_counts"]
        if len(offer_counts) >= 2:
            mean_offers = sum(offer_counts) / len(offer_counts)
            variance = sum((x - mean_offers) ** 2 for x in offer_counts) / len(offer_counts)
            # Normalize: lower variance = higher consistency
            consistency = 1.0 / (1.0 + math.sqrt(variance))
        else:
            consistency = 0.5  # neutral with insufficient data

        # Responsiveness: average offers per session, normalized
        avg_offers = (
            sum(offer_counts) / len(offer_counts) if offer_counts else 0.0
        )
        # 1-5 offers is ideal engagement range
        if avg_offers <= 5:
            responsiveness = min(1.0, avg_offers / 3.0)
        else:
            responsiveness = max(0.5, 1.0 - (avg_offers - 5) * 0.1)

        return ScoreComponents(
            agreement_rate=agreement_rate,
            concession_willingness=concession_score,
            fulfillment_rate=fulfillment_rate,
            reasoning_rate=reasoning_rate,
            consistency=consistency,
            responsiveness=responsiveness,
        )

    def _compute_confidence(self, signals: dict[str, Any]) -> float:
        """Compute confidence level based on data quantity and diversity.

        Confidence increases with:
        - More attestations (diminishing returns after ~50)
        - More diverse counterparties
        - Lower sybil flag ratio
        """
        total = signals["total"]
        counterparties = signals["counterparty_count"]

        # Volume component: logarithmic growth, saturates around 50
        volume_conf = min(1.0, math.log(1 + total) / math.log(51))

        # Diversity component: more counterparties = higher confidence
        diversity_conf = min(1.0, math.log(1 + counterparties) / math.log(21))

        # Combined: weighted average
        confidence = 0.6 * volume_conf + 0.4 * diversity_conf

        return max(0.0, min(1.0, confidence))
