"""Discovery layer — Want and Have registries (§7).

Agents publish Wants (demand) and Haves (supply). A matching service
finds overlapping deal spaces and notifies both parties.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


@dataclass
class Want:
    """A structured expression of demand — what an agent is looking for (§7.1)."""

    agent_id: str
    category: str
    terms: dict[str, dict[str, Any]]
    location: dict[str, Any] | None = None
    ttl: int = 604800  # 7 days
    notify: bool = True
    id: str = field(default_factory=lambda: _new_id("want"))

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": "concordia.want",
            "id": self.id,
            "agent_id": self.agent_id,
            "category": self.category,
            "terms": self.terms,
            "ttl": self.ttl,
            "notify": self.notify,
        }
        if self.location:
            d["location"] = self.location
        return d


@dataclass
class Have:
    """A structured expression of supply — what an agent has to offer (§7.2)."""

    agent_id: str
    category: str
    terms: dict[str, dict[str, Any]]
    location: dict[str, Any] | None = None
    ttl: int = 2592000  # 30 days
    id: str = field(default_factory=lambda: _new_id("have"))

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": "concordia.have",
            "id": self.id,
            "agent_id": self.agent_id,
            "category": self.category,
            "terms": self.terms,
            "ttl": self.ttl,
        }
        if self.location:
            d["location"] = self.location
        return d


@dataclass
class Match:
    """A match notification when a Want and Have overlap (§7.4)."""

    want_id: str
    have_id: str
    overlap: dict[str, Any]
    score: float
    match_id: str = field(default_factory=lambda: _new_id("match"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "concordia.match",
            "match_id": self.match_id,
            "want_id": self.want_id,
            "have_id": self.have_id,
            "overlap": self.overlap,
            "score": self.score,
            "suggestion": "negotiate.open",
        }


def find_matches(wants: list[Want], haves: list[Have]) -> list[Match]:
    """Simple matching: find Want/Have pairs with compatible categories and terms.

    This is a reference implementation of the matching algorithm (§7.3).
    Production systems would use more sophisticated matching.
    """
    matches: list[Match] = []
    for want in wants:
        for have in haves:
            if want.agent_id == have.agent_id:
                continue
            if not _categories_compatible(want.category, have.category):
                continue
            overlap, score = _compute_overlap(want.terms, have.terms)
            if score > 0:
                matches.append(Match(
                    want_id=want.id,
                    have_id=have.id,
                    overlap=overlap,
                    score=score,
                ))
    return matches


def _categories_compatible(want_cat: str, have_cat: str) -> bool:
    """Check if categories are compatible (prefix match)."""
    return have_cat.startswith(want_cat) or want_cat.startswith(have_cat)


def _compute_overlap(
    want_terms: dict[str, dict[str, Any]],
    have_terms: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], float]:
    """Compute the overlap between want and have terms.

    Returns (overlap_dict, score) where score is 0-1.
    """
    overlap: dict[str, Any] = {}
    matched = 0
    total = len(want_terms)

    for term_id, want_spec in want_terms.items():
        if term_id not in have_terms:
            continue
        have_spec = have_terms[term_id]

        # Numeric range overlap
        want_max = want_spec.get("max")
        have_min = have_spec.get("min")
        if want_max is not None and have_min is not None:
            if want_max >= have_min:
                currency = want_spec.get("currency", have_spec.get("currency"))
                overlap[term_id] = {
                    "range": [have_min, want_max],
                }
                if currency:
                    overlap[term_id]["currency"] = currency
                matched += 1
            continue

        # Categorical / exact match
        want_val = want_spec.get("value")
        have_val = have_spec.get("value")
        if want_val and have_val:
            overlap[term_id] = {"value": have_val}
            matched += 1

    score = matched / total if total > 0 else 0.0
    return overlap, round(score, 2)
