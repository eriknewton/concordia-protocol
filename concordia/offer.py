"""Offer construction and validation (§6).

Supports the four offer types defined by the Concordia Protocol:
basic, partial, conditional, and bundle offers.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Union


def _offer_id() -> str:
    return f"off_{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# §6.1  Basic Offer — assigns values to all terms
# ---------------------------------------------------------------------------

@dataclass
class BasicOffer:
    """A complete offer assigning values to all terms."""

    terms: dict[str, dict[str, Any]]
    valid_until: str | None = None
    offer_id: str = field(default_factory=_offer_id)

    def to_body(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "offer_id": self.offer_id,
            "terms": self.terms,
            "complete": True,
        }
        if self.valid_until:
            body["valid_until"] = self.valid_until
        return body


# ---------------------------------------------------------------------------
# §6.2  Partial Offer — some terms left open
# ---------------------------------------------------------------------------

@dataclass
class PartialOffer:
    """A partial offer that leaves some terms unspecified."""

    terms: dict[str, dict[str, Any]]
    open_terms: list[str]
    valid_until: str | None = None
    offer_id: str = field(default_factory=_offer_id)

    def to_body(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "offer_id": self.offer_id,
            "terms": self.terms,
            "open_terms": self.open_terms,
            "complete": False,
        }
        if self.valid_until:
            body["valid_until"] = self.valid_until
        return body


# ---------------------------------------------------------------------------
# §6.3  Conditional Offer — if/then relationships
# ---------------------------------------------------------------------------

@dataclass
class Condition:
    """A single if/then clause within a conditional offer."""
    if_clause: dict[str, Any]
    then_clause: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"if": self.if_clause, "then": self.then_clause}


@dataclass
class ConditionalOffer:
    """An offer with if/then relationships between terms."""

    conditions: list[Condition]
    complete: bool = True
    valid_until: str | None = None
    offer_id: str = field(default_factory=_offer_id)

    def to_body(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "offer_id": self.offer_id,
            "conditions": [c.to_dict() for c in self.conditions],
            "complete": self.complete,
        }
        if self.valid_until:
            body["valid_until"] = self.valid_until
        return body


# ---------------------------------------------------------------------------
# §6.4  Bundle Offer — multiple grouped options
# ---------------------------------------------------------------------------

@dataclass
class Bundle:
    """A single bundle within a bundle offer."""
    bundle_id: str
    label: str
    terms: dict[str, dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "label": self.label,
            "terms": self.terms,
        }


@dataclass
class BundleOffer:
    """An offer presenting multiple bundles to choose from."""

    bundles: list[Bundle]
    select: str = "one_of"
    valid_until: str | None = None
    offer_id: str = field(default_factory=_offer_id)

    def to_body(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "offer_id": self.offer_id,
            "bundles": [b.to_dict() for b in self.bundles],
            "select": self.select,
        }
        if self.valid_until:
            body["valid_until"] = self.valid_until
        return body


# ---------------------------------------------------------------------------
# Convenience: unified Offer type
# ---------------------------------------------------------------------------

Offer = Union[BasicOffer, PartialOffer, ConditionalOffer, BundleOffer]


def offer_to_body(offer: Offer) -> dict[str, Any]:
    """Convert any offer type to its body dict."""
    return offer.to_body()
