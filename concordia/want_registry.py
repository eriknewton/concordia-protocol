"""Want Registry & Matching Engine — demand-side discovery (§7).

Agents publish structured **Wants** (demand) and **Haves** (supply). The
matching engine finds overlapping deal space and produces Match notifications,
each with an overlap description and a quality score.

Schemas follow §7.1 (Want), §7.2 (Have), §7.4 (Match notification).

The matching algorithm (§7.3):
    1. Category compatibility (hierarchical prefix match)
    2. Constraint compatibility (buyer max ≥ seller min, enum overlap)
    3. Location compatibility (Haversine distance ≤ radius)
    4. Match quality score (term alignment)
    5. Notify both parties

This module is pure data + logic — no I/O, no networking.  MCP tools in
``mcp_server.py`` wrap it for external access.
"""

from __future__ import annotations

import math
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EARTH_RADIUS_KM = 6_371.0


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Want:
    """A structured expression of demand (§7.1)."""

    id: str
    agent_id: str
    category: str
    terms: dict[str, Any]
    location: dict[str, Any] | None = None
    ttl: int = 604_800  # 7 days default
    notify: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: float = 0.0

    def __post_init__(self) -> None:
        if self.expires_at == 0.0:
            self.expires_at = time.time() + self.ttl

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": "concordia.want",
            "id": self.id,
            "agent_id": self.agent_id,
            "category": self.category,
            "terms": self.terms,
            "ttl": self.ttl,
            "notify": self.notify,
            "created_at": self.created_at,
        }
        if self.location:
            d["location"] = self.location
        if self.metadata:
            d["metadata"] = self.metadata
        return d


@dataclass
class Have:
    """A structured expression of supply (§7.2)."""

    id: str
    agent_id: str
    category: str
    terms: dict[str, Any]
    location: dict[str, Any] | None = None
    ttl: int = 2_592_000  # 30 days default
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: float = 0.0

    def __post_init__(self) -> None:
        if self.expires_at == 0.0:
            self.expires_at = time.time() + self.ttl

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": "concordia.have",
            "id": self.id,
            "agent_id": self.agent_id,
            "category": self.category,
            "terms": self.terms,
            "ttl": self.ttl,
            "created_at": self.created_at,
        }
        if self.location:
            d["location"] = self.location
        if self.metadata:
            d["metadata"] = self.metadata
        return d


@dataclass
class Match:
    """A match notification between a Want and a Have (§7.4)."""

    match_id: str
    want_id: str
    have_id: str
    want_agent_id: str
    have_agent_id: str
    overlap: dict[str, Any]
    score: float
    suggestion: str = "negotiate.open"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "concordia.match",
            "match_id": self.match_id,
            "want_id": self.want_id,
            "have_id": self.have_id,
            "want_agent_id": self.want_agent_id,
            "have_agent_id": self.have_agent_id,
            "overlap": self.overlap,
            "score": round(self.score, 4),
            "suggestion": self.suggestion,
            "created_at": self.created_at,
        }


# ---------------------------------------------------------------------------
# Geometry helpers
# ---------------------------------------------------------------------------

def _haversine_km(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    """Great-circle distance between two points in kilometres."""
    lat1, lng1, lat2, lng2 = (math.radians(v) for v in (lat1, lng1, lat2, lng2))
    dlat = lat2 - lat1
    dlng = lng2 - lng1
    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlng / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(a))


# ---------------------------------------------------------------------------
# Matching logic
# ---------------------------------------------------------------------------

def categories_compatible(want_cat: str, have_cat: str) -> bool:
    """Check hierarchical category compatibility (prefix match per §7.3).

    ``electronics.cameras`` matches ``electronics.cameras.mirrorless`` and
    vice-versa (a more-specific Have can satisfy a broader Want, and a
    more-specific Want can be satisfied by a broader Have).
    """
    if want_cat == have_cat:
        return True
    return want_cat.startswith(have_cat + ".") or have_cat.startswith(want_cat + ".")


def _extract_coords(loc: dict[str, Any]) -> tuple[float, float] | None:
    """Pull (lat, lng) out of either want-style or have-style location."""
    if "coordinates" in loc:
        c = loc["coordinates"]
        return (c.get("lat"), c.get("lng"))
    if "of" in loc:
        c = loc["of"]
        return (c.get("lat"), c.get("lng"))
    if "lat" in loc and "lng" in loc:
        return (loc["lat"], loc["lng"])
    return None


def locations_compatible(
    want_loc: dict[str, Any] | None,
    have_loc: dict[str, Any] | None,
) -> tuple[bool, float | None]:
    """Check location constraints.  Returns (compatible, distance_km | None)."""
    if want_loc is None or have_loc is None:
        return True, None  # no constraint → compatible

    want_coords = _extract_coords(want_loc)
    have_coords = _extract_coords(have_loc)
    if want_coords is None or have_coords is None:
        return True, None

    dist = _haversine_km(want_coords[0], want_coords[1], have_coords[0], have_coords[1])
    radius = want_loc.get("within_km")
    if radius is not None:
        return dist <= radius, dist
    return True, dist


def _condition_rank(condition: str) -> int:
    """Ordinal rank for standard condition values (higher = better)."""
    ranks = {"poor": 0, "fair": 1, "good": 2, "like_new": 3, "new": 4}
    return ranks.get(condition.lower(), -1)


def compute_term_overlap(
    want_terms: dict[str, Any],
    have_terms: dict[str, Any],
) -> tuple[dict[str, Any], float]:
    """Compute the overlap between Want terms and Have terms.

    Returns (overlap_dict, score_0_to_1).

    For each term present in both:
      - **price**: overlap if buyer_max >= seller_min.
      - **condition (enum)**: overlap if Have meets minimum.
      - **item (fuzzy)**: always overlaps (fuzzy match is a service concern).
      - **other numeric**: overlap if ranges intersect.
      - **other string**: overlap if values match.

    Score is the average of per-term scores.
    """
    overlap: dict[str, Any] = {}
    scores: list[float] = []

    all_keys = set(want_terms.keys()) | set(have_terms.keys())
    shared_keys = set(want_terms.keys()) & set(have_terms.keys())

    for key in shared_keys:
        wt = want_terms[key]
        ht = have_terms[key]

        # --- price / numeric range terms ---
        if isinstance(wt, dict) and isinstance(ht, dict):
            w_max = wt.get("max")
            h_min = ht.get("min")
            w_min = wt.get("min")
            h_max = ht.get("max")

            # Standard price: want.max vs have.min
            if w_max is not None and h_min is not None:
                if w_max >= h_min:
                    lo = h_min
                    hi = w_max
                    midpoint = (lo + hi) / 2
                    spread = hi - lo
                    overlap[key] = {
                        "range": [lo, hi],
                    }
                    currency = wt.get("currency") or ht.get("currency")
                    if currency:
                        overlap[key]["currency"] = currency
                    # Score: tighter overlap → higher score (1.0 if exact match)
                    max_span = max(hi, 1)
                    scores.append(1.0 - min(spread / max_span, 1.0) * 0.5)
                else:
                    # No overlap on price
                    return {}, 0.0

            # Condition / enum terms
            elif "min" in wt and ("value" in ht or "enum" in wt):
                want_min_rank = _condition_rank(wt["min"])
                have_rank = _condition_rank(ht.get("value", ""))
                if want_min_rank >= 0 and have_rank >= 0:
                    if have_rank >= want_min_rank:
                        overlap[key] = {
                            "value": ht["value"],
                            "meets_minimum": True,
                        }
                        scores.append(min(1.0, have_rank / max(want_min_rank, 1)))
                    else:
                        return {}, 0.0
                else:
                    # Unknown enum values — be lenient
                    overlap[key] = {"value": ht.get("value"), "meets_minimum": None}
                    scores.append(0.5)

            # Fuzzy item match
            elif wt.get("match") == "fuzzy" or ht.get("match") == "fuzzy":
                overlap[key] = {
                    "want_value": wt.get("value", ""),
                    "have_value": ht.get("value", ""),
                    "match_type": "fuzzy",
                }
                scores.append(0.7)  # fuzzy always passes, moderate score

            # Exact value match
            elif "value" in wt and "value" in ht:
                if wt["value"] == ht["value"]:
                    overlap[key] = {"value": wt["value"]}
                    scores.append(1.0)
                else:
                    overlap[key] = {
                        "want_value": wt["value"],
                        "have_value": ht["value"],
                        "exact_match": False,
                    }
                    scores.append(0.3)

            else:
                # Unrecognised term structure — include but score neutral
                overlap[key] = {"want": wt, "have": ht}
                scores.append(0.5)

    # Bonus/penalty for unmatched terms
    unmatched = all_keys - shared_keys
    for key in unmatched:
        scores.append(0.4)  # mild penalty for missing info

    final_score = sum(scores) / max(len(scores), 1)
    return overlap, final_score


def compute_match(want: Want, have: Have) -> Match | None:
    """Attempt to match a Want against a Have.

    Returns a Match if the deal space overlaps, otherwise None.
    """
    # Step 1: Category compatibility
    if not categories_compatible(want.category, have.category):
        return None

    # Step 2: Skip if same agent (can't negotiate with yourself)
    if want.agent_id == have.agent_id:
        return None

    # Step 3: Skip expired entries
    if want.is_expired or have.is_expired:
        return None

    # Step 4: Term overlap
    overlap, score = compute_term_overlap(want.terms, have.terms)
    if score == 0.0:
        return None

    # Step 5: Location compatibility
    loc_ok, distance_km = locations_compatible(want.location, have.location)
    if not loc_ok:
        return None

    # Adjust score based on location proximity
    if distance_km is not None:
        radius = (want.location or {}).get("within_km")
        if radius and radius > 0:
            proximity = 1.0 - (distance_km / radius)
            score = score * 0.8 + proximity * 0.2
        if distance_km is not None:
            overlap["_location"] = {"distance_km": round(distance_km, 2)}

    match_id = f"match_{uuid.uuid4().hex[:12]}"
    return Match(
        match_id=match_id,
        want_id=want.id,
        have_id=have.id,
        want_agent_id=want.agent_id,
        have_agent_id=have.agent_id,
        overlap=overlap,
        score=score,
    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class WantRegistry:
    """In-memory Want/Have registry with matching engine.

    Stores Wants and Haves, lazily expires them, and computes matches.
    """

    # Resource limits
    MAX_WANTS = 50_000
    MAX_HAVES = 50_000
    MAX_MATCHES = 100_000

    def __init__(self) -> None:
        self._wants: dict[str, Want] = {}
        self._haves: dict[str, Have] = {}
        self._matches: dict[str, Match] = {}
        # Index: agent_id → set of want/have ids
        self._agent_wants: dict[str, set[str]] = {}
        self._agent_haves: dict[str, set[str]] = {}

    # -- Wants ---------------------------------------------------------------

    def post_want(
        self,
        agent_id: str,
        category: str,
        terms: dict[str, Any],
        location: dict[str, Any] | None = None,
        ttl: int = 604_800,
        notify: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[Want, list[Match]]:
        """Post a Want and immediately match against existing Haves.

        Returns (want, list_of_matches).
        """
        # Check want registry limit
        if len(self._wants) >= self.MAX_WANTS:
            raise ValueError("Want registry limit reached")

        want_id = f"want_{uuid.uuid4().hex[:12]}"
        want = Want(
            id=want_id,
            agent_id=agent_id,
            category=category,
            terms=terms,
            location=location,
            ttl=ttl,
            notify=notify,
            metadata=metadata or {},
        )
        self._wants[want_id] = want
        self._agent_wants.setdefault(agent_id, set()).add(want_id)

        # Match against all active Haves
        matches = self._match_want(want)
        return want, matches

    def get_want(self, want_id: str) -> Want | None:
        want = self._wants.get(want_id)
        if want and want.is_expired:
            self._remove_want(want_id)
            return None
        return want

    def withdraw_want(self, want_id: str) -> bool:
        if want_id in self._wants:
            self._remove_want(want_id)
            return True
        return False

    def list_wants(self, agent_id: str | None = None) -> list[Want]:
        self._expire_wants()
        if agent_id:
            ids = self._agent_wants.get(agent_id, set())
            return [self._wants[wid] for wid in ids if wid in self._wants]
        return list(self._wants.values())

    def _remove_want(self, want_id: str) -> None:
        want = self._wants.pop(want_id, None)
        if want:
            agent_set = self._agent_wants.get(want.agent_id)
            if agent_set:
                agent_set.discard(want_id)

    def _expire_wants(self) -> None:
        expired = [wid for wid, w in self._wants.items() if w.is_expired]
        for wid in expired:
            self._remove_want(wid)

    # -- Haves ---------------------------------------------------------------

    def post_have(
        self,
        agent_id: str,
        category: str,
        terms: dict[str, Any],
        location: dict[str, Any] | None = None,
        ttl: int = 2_592_000,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[Have, list[Match]]:
        """Post a Have and immediately match against existing Wants.

        Returns (have, list_of_matches).
        """
        # Check have registry limit
        if len(self._haves) >= self.MAX_HAVES:
            raise ValueError("Have registry limit reached")

        have_id = f"have_{uuid.uuid4().hex[:12]}"
        have = Have(
            id=have_id,
            agent_id=agent_id,
            category=category,
            terms=terms,
            location=location,
            ttl=ttl,
            metadata=metadata or {},
        )
        self._haves[have_id] = have
        self._agent_haves.setdefault(agent_id, set()).add(have_id)

        # Match against all active Wants
        matches = self._match_have(have)
        return have, matches

    def get_have(self, have_id: str) -> Have | None:
        have = self._haves.get(have_id)
        if have and have.is_expired:
            self._remove_have(have_id)
            return None
        return have

    def withdraw_have(self, have_id: str) -> bool:
        if have_id in self._haves:
            self._remove_have(have_id)
            return True
        return False

    def list_haves(self, agent_id: str | None = None) -> list[Have]:
        self._expire_haves()
        if agent_id:
            ids = self._agent_haves.get(agent_id, set())
            return [self._haves[hid] for hid in ids if hid in self._haves]
        return list(self._haves.values())

    def _remove_have(self, have_id: str) -> None:
        have = self._haves.pop(have_id, None)
        if have:
            agent_set = self._agent_haves.get(have.agent_id)
            if agent_set:
                agent_set.discard(have_id)

    def _expire_haves(self) -> None:
        expired = [hid for hid, h in self._haves.items() if h.is_expired]
        for hid in expired:
            self._remove_have(hid)

    # -- Matching ------------------------------------------------------------

    def _match_want(self, want: Want) -> list[Match]:
        """Match a new Want against all existing Haves."""
        matches: list[Match] = []
        for have in list(self._haves.values()):
            if have.is_expired:
                continue
            m = compute_match(want, have)
            if m is not None:
                # Cap stored matches at MAX_MATCHES
                if len(self._matches) < self.MAX_MATCHES:
                    self._matches[m.match_id] = m
                matches.append(m)
        # Sort by score descending
        matches.sort(key=lambda m: m.score, reverse=True)
        return matches

    def _match_have(self, have: Have) -> list[Match]:
        """Match a new Have against all existing Wants."""
        matches: list[Match] = []
        for want in list(self._wants.values()):
            if want.is_expired:
                continue
            m = compute_match(want, have)
            if m is not None:
                # Cap stored matches at MAX_MATCHES
                if len(self._matches) < self.MAX_MATCHES:
                    self._matches[m.match_id] = m
                matches.append(m)
        matches.sort(key=lambda m: m.score, reverse=True)
        return matches

    def find_matches(
        self,
        want_id: str | None = None,
        have_id: str | None = None,
        agent_id: str | None = None,
        limit: int = 20,
    ) -> list[Match]:
        """Query stored matches by want_id, have_id, or agent_id."""
        results: list[Match] = []
        for m in self._matches.values():
            if want_id and m.want_id != want_id:
                continue
            if have_id and m.have_id != have_id:
                continue
            if agent_id and m.want_agent_id != agent_id and m.have_agent_id != agent_id:
                continue
            results.append(m)
        results.sort(key=lambda m: m.score, reverse=True)
        return results[:limit]

    def get_match(self, match_id: str) -> Match | None:
        return self._matches.get(match_id)

    # -- Search (category browsing) ------------------------------------------

    def search_wants(
        self,
        category: str | None = None,
        limit: int = 20,
    ) -> list[Want]:
        """Browse active Wants, optionally filtered by category."""
        self._expire_wants()
        results: list[Want] = []
        for want in self._wants.values():
            if category and not categories_compatible(category, want.category):
                continue
            results.append(want)
        results.sort(key=lambda w: w.created_at, reverse=True)
        return results[:limit]

    def search_haves(
        self,
        category: str | None = None,
        limit: int = 20,
    ) -> list[Have]:
        """Browse active Haves, optionally filtered by category."""
        self._expire_haves()
        results: list[Have] = []
        for have in self._haves.values():
            if category and not categories_compatible(category, have.category):
                continue
            results.append(have)
        results.sort(key=lambda h: h.created_at, reverse=True)
        return results[:limit]

    # -- Stats ---------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        """Summary statistics for the registry."""
        self._expire_wants()
        self._expire_haves()
        return {
            "active_wants": len(self._wants),
            "active_haves": len(self._haves),
            "total_matches": len(self._matches),
            "unique_agents": len(
                set(self._agent_wants.keys()) | set(self._agent_haves.keys())
            ),
        }
