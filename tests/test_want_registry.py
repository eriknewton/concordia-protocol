"""Tests for the Want Registry & Matching Engine (§7).

Covers:
    - Want/Have data models: creation, expiration, serialisation
    - Category compatibility: exact, prefix, hierarchical
    - Location compatibility: Haversine distance, radius constraints
    - Term overlap: price ranges, condition enums, fuzzy items, exact values
    - Match scoring and ranking
    - WantRegistry: post, withdraw, search, find_matches, stats
    - MCP tool integration: all 10 Want Registry tools via handle_tool_call
    - Full marketplace lifecycle: post Want → post Have → match → negotiate
"""

from __future__ import annotations

import json
import time
from typing import Any

import pytest

from concordia.want_registry import (
    Want,
    Have,
    Match,
    WantRegistry,
    categories_compatible,
    locations_compatible,
    compute_term_overlap,
    compute_match,
    _haversine_km,
    _condition_rank,
)


# ===================================================================
# Category compatibility
# ===================================================================

class TestCategoryCompatibility:

    def test_exact_match(self):
        assert categories_compatible("electronics", "electronics") is True

    def test_want_broader_than_have(self):
        assert categories_compatible("electronics", "electronics.cameras") is True

    def test_have_broader_than_want(self):
        assert categories_compatible("electronics.cameras.mirrorless", "electronics.cameras") is True

    def test_unrelated(self):
        assert categories_compatible("electronics", "furniture") is False

    def test_partial_overlap_not_hierarchical(self):
        assert categories_compatible("electronics.cameras", "electronics.audio") is False

    def test_deep_hierarchy(self):
        assert categories_compatible(
            "electronics.cameras",
            "electronics.cameras.mirrorless.fullframe",
        ) is True


# ===================================================================
# Location compatibility
# ===================================================================

class TestLocationCompatibility:

    def test_no_constraints(self):
        ok, dist = locations_compatible(None, None)
        assert ok is True
        assert dist is None

    def test_want_only(self):
        ok, _ = locations_compatible(
            {"within_km": 50, "of": {"lat": 37.77, "lng": -122.42}},
            None,
        )
        assert ok is True

    def test_close_enough(self):
        want_loc = {"within_km": 50, "of": {"lat": 37.7749, "lng": -122.4194}}
        have_loc = {"coordinates": {"lat": 37.7849, "lng": -122.4094}}
        ok, dist = locations_compatible(want_loc, have_loc)
        assert ok is True
        assert dist is not None
        assert dist < 50

    def test_too_far(self):
        want_loc = {"within_km": 1, "of": {"lat": 37.77, "lng": -122.42}}
        have_loc = {"coordinates": {"lat": 38.77, "lng": -122.42}}
        ok, dist = locations_compatible(want_loc, have_loc)
        assert ok is False
        assert dist > 1

    def test_haversine_known_distance(self):
        # SF to LA ≈ 559 km
        dist = _haversine_km(37.7749, -122.4194, 34.0522, -118.2437)
        assert 550 < dist < 570


# ===================================================================
# Condition ranking
# ===================================================================

class TestConditionRank:

    def test_ordering(self):
        assert _condition_rank("poor") < _condition_rank("fair")
        assert _condition_rank("fair") < _condition_rank("good")
        assert _condition_rank("good") < _condition_rank("like_new")
        assert _condition_rank("like_new") < _condition_rank("new")

    def test_unknown(self):
        assert _condition_rank("unknown_value") == -1


# ===================================================================
# Term overlap
# ===================================================================

class TestTermOverlap:

    def test_price_overlap(self):
        want = {"price": {"max": 2500, "currency": "USD"}}
        have = {"price": {"min": 1800, "currency": "USD"}}
        overlap, score = compute_term_overlap(want, have)
        assert "price" in overlap
        assert overlap["price"]["range"] == [1800, 2500]
        assert score > 0

    def test_price_no_overlap(self):
        want = {"price": {"max": 1000, "currency": "USD"}}
        have = {"price": {"min": 1500, "currency": "USD"}}
        overlap, score = compute_term_overlap(want, have)
        assert score == 0.0

    def test_condition_meets_minimum(self):
        want = {"condition": {"min": "good", "enum": ["new", "like_new", "good", "fair", "poor"]}}
        have = {"condition": {"value": "like_new"}}
        overlap, score = compute_term_overlap(want, have)
        assert "condition" in overlap
        assert overlap["condition"]["meets_minimum"] is True
        assert score > 0

    def test_condition_below_minimum(self):
        want = {"condition": {"min": "like_new"}}
        have = {"condition": {"value": "fair"}}
        overlap, score = compute_term_overlap(want, have)
        assert score == 0.0

    def test_fuzzy_item(self):
        want = {"item": {"match": "fuzzy", "value": "Canon EOS R5"}}
        have = {"item": {"value": "Canon EOS R5"}}
        overlap, score = compute_term_overlap(want, have)
        assert "item" in overlap
        assert overlap["item"]["match_type"] == "fuzzy"
        assert score > 0

    def test_exact_value_match(self):
        want = {"color": {"value": "red"}}
        have = {"color": {"value": "red"}}
        overlap, score = compute_term_overlap(want, have)
        assert score > 0

    def test_exact_value_mismatch(self):
        want = {"color": {"value": "red"}}
        have = {"color": {"value": "blue"}}
        overlap, score = compute_term_overlap(want, have)
        assert score > 0  # doesn't fail, just lower score
        assert overlap["color"]["exact_match"] is False

    def test_multi_term_spec_example(self):
        """The exact terms from the §7.1/§7.2 spec examples."""
        want_terms = {
            "item": {"match": "fuzzy", "value": "Canon EOS R5 or equivalent"},
            "price": {"max": 2500.00, "currency": "USD"},
            "condition": {"min": "good", "enum": ["new", "like_new", "good", "fair", "poor"]},
        }
        have_terms = {
            "item": {"value": "Canon EOS R5", "description": "15K shutter count"},
            "price": {"min": 1800.00, "currency": "USD"},
            "condition": {"value": "like_new"},
        }
        overlap, score = compute_term_overlap(want_terms, have_terms)
        assert "item" in overlap
        assert "price" in overlap
        assert "condition" in overlap
        assert score > 0.5

    def test_unmatched_terms_reduce_score(self):
        want = {"price": {"max": 2000}, "warranty": {"value": "12_months"}}
        have = {"price": {"min": 1500}}
        _, score_partial = compute_term_overlap(want, have)

        want2 = {"price": {"max": 2000}}
        have2 = {"price": {"min": 1500}}
        _, score_full = compute_term_overlap(want2, have2)

        assert score_full > score_partial


# ===================================================================
# compute_match
# ===================================================================

class TestComputeMatch:

    def _want(self, **kw) -> Want:
        defaults = dict(
            id="w1", agent_id="buyer",
            category="electronics.cameras",
            terms={"price": {"max": 2500, "currency": "USD"}},
        )
        defaults.update(kw)
        return Want(**defaults)

    def _have(self, **kw) -> Have:
        defaults = dict(
            id="h1", agent_id="seller",
            category="electronics.cameras",
            terms={"price": {"min": 1800, "currency": "USD"}},
        )
        defaults.update(kw)
        return Have(**defaults)

    def test_basic_match(self):
        m = compute_match(self._want(), self._have())
        assert m is not None
        assert m.want_id == "w1"
        assert m.have_id == "h1"
        assert m.score > 0

    def test_no_match_category(self):
        m = compute_match(
            self._want(category="electronics"),
            self._have(category="furniture"),
        )
        assert m is None

    def test_no_match_same_agent(self):
        m = compute_match(
            self._want(agent_id="same"),
            self._have(agent_id="same"),
        )
        assert m is None

    def test_no_match_price(self):
        m = compute_match(
            self._want(terms={"price": {"max": 1000}}),
            self._have(terms={"price": {"min": 1500}}),
        )
        assert m is None

    def test_location_reduces_scope(self):
        w = self._want(location={"within_km": 10, "of": {"lat": 37.77, "lng": -122.42}})
        h_near = self._have(location={"coordinates": {"lat": 37.78, "lng": -122.41}})
        h_far = self._have(id="h2", location={"coordinates": {"lat": 40.71, "lng": -74.01}})

        assert compute_match(w, h_near) is not None
        assert compute_match(w, h_far) is None


# ===================================================================
# Want/Have data model
# ===================================================================

class TestWantModel:

    def test_to_dict(self):
        w = Want(
            id="w1", agent_id="buyer", category="electronics",
            terms={"price": {"max": 100}},
        )
        d = w.to_dict()
        assert d["type"] == "concordia.want"
        assert d["id"] == "w1"
        assert d["category"] == "electronics"

    def test_expiration(self):
        w = Want(
            id="w1", agent_id="buyer", category="electronics",
            terms={}, ttl=0,
            expires_at=time.time() - 1,
        )
        assert w.is_expired is True


class TestHaveModel:

    def test_to_dict(self):
        h = Have(
            id="h1", agent_id="seller", category="electronics",
            terms={"price": {"min": 100}},
        )
        d = h.to_dict()
        assert d["type"] == "concordia.have"
        assert d["id"] == "h1"

    def test_expiration(self):
        h = Have(
            id="h1", agent_id="seller", category="electronics",
            terms={}, ttl=0,
            expires_at=time.time() - 1,
        )
        assert h.is_expired is True


class TestMatchModel:

    def test_to_dict(self):
        m = Match(
            match_id="m1",
            want_id="w1", have_id="h1",
            want_agent_id="buyer", have_agent_id="seller",
            overlap={"price": {"range": [100, 200]}},
            score=0.85,
        )
        d = m.to_dict()
        assert d["type"] == "concordia.match"
        assert d["score"] == 0.85
        assert d["suggestion"] == "negotiate.open"


# ===================================================================
# WantRegistry
# ===================================================================

class TestWantRegistry:

    def test_post_want_no_matches(self):
        reg = WantRegistry()
        want, matches = reg.post_want(
            agent_id="buyer", category="electronics",
            terms={"price": {"max": 100}},
        )
        assert want.id.startswith("want_")
        assert matches == []
        assert reg.stats()["active_wants"] == 1

    def test_post_have_no_matches(self):
        reg = WantRegistry()
        have, matches = reg.post_have(
            agent_id="seller", category="electronics",
            terms={"price": {"min": 50}},
        )
        assert have.id.startswith("have_")
        assert matches == []
        assert reg.stats()["active_haves"] == 1

    def test_post_want_then_have_matches(self):
        reg = WantRegistry()
        reg.post_want(
            agent_id="buyer", category="electronics.cameras",
            terms={"price": {"max": 2500, "currency": "USD"}},
        )
        have, matches = reg.post_have(
            agent_id="seller", category="electronics.cameras",
            terms={"price": {"min": 1800, "currency": "USD"}},
        )
        assert len(matches) == 1
        assert matches[0].want_agent_id == "buyer"
        assert matches[0].have_agent_id == "seller"

    def test_post_have_then_want_matches(self):
        reg = WantRegistry()
        reg.post_have(
            agent_id="seller", category="electronics.cameras",
            terms={"price": {"min": 1800}},
        )
        want, matches = reg.post_want(
            agent_id="buyer", category="electronics.cameras",
            terms={"price": {"max": 2500}},
        )
        assert len(matches) == 1

    def test_multiple_matches_sorted(self):
        reg = WantRegistry()
        reg.post_want(
            agent_id="buyer", category="electronics",
            terms={"price": {"max": 2000}},
        )
        # Tighter overlap → higher score
        reg.post_have(
            agent_id="seller_close", category="electronics",
            terms={"price": {"min": 1900}},
        )
        reg.post_have(
            agent_id="seller_wide", category="electronics",
            terms={"price": {"min": 500}},
        )
        # Post another want to trigger matching
        _, matches = reg.post_want(
            agent_id="buyer2", category="electronics",
            terms={"price": {"max": 2000}},
        )
        assert len(matches) == 2

    def test_no_self_match(self):
        reg = WantRegistry()
        reg.post_want(
            agent_id="same_agent", category="electronics",
            terms={"price": {"max": 2000}},
        )
        _, matches = reg.post_have(
            agent_id="same_agent", category="electronics",
            terms={"price": {"min": 1000}},
        )
        assert len(matches) == 0

    def test_withdraw_want(self):
        reg = WantRegistry()
        want, _ = reg.post_want(
            agent_id="buyer", category="electronics", terms={},
        )
        assert reg.withdraw_want(want.id) is True
        assert reg.get_want(want.id) is None
        assert reg.stats()["active_wants"] == 0

    def test_withdraw_have(self):
        reg = WantRegistry()
        have, _ = reg.post_have(
            agent_id="seller", category="electronics", terms={},
        )
        assert reg.withdraw_have(have.id) is True
        assert reg.get_have(have.id) is None
        assert reg.stats()["active_haves"] == 0

    def test_withdraw_nonexistent(self):
        reg = WantRegistry()
        assert reg.withdraw_want("fake") is False
        assert reg.withdraw_have("fake") is False

    def test_get_want(self):
        reg = WantRegistry()
        want, _ = reg.post_want(
            agent_id="buyer", category="electronics", terms={},
        )
        retrieved = reg.get_want(want.id)
        assert retrieved is not None
        assert retrieved.agent_id == "buyer"

    def test_get_have(self):
        reg = WantRegistry()
        have, _ = reg.post_have(
            agent_id="seller", category="electronics", terms={},
        )
        retrieved = reg.get_have(have.id)
        assert retrieved is not None
        assert retrieved.agent_id == "seller"

    def test_list_wants(self):
        reg = WantRegistry()
        reg.post_want(agent_id="a1", category="electronics", terms={})
        reg.post_want(agent_id="a2", category="furniture", terms={})
        assert len(reg.list_wants()) == 2
        assert len(reg.list_wants(agent_id="a1")) == 1

    def test_list_haves(self):
        reg = WantRegistry()
        reg.post_have(agent_id="s1", category="electronics", terms={})
        reg.post_have(agent_id="s2", category="furniture", terms={})
        assert len(reg.list_haves()) == 2
        assert len(reg.list_haves(agent_id="s1")) == 1

    def test_search_wants_by_category(self):
        reg = WantRegistry()
        reg.post_want(agent_id="a1", category="electronics.cameras", terms={})
        reg.post_want(agent_id="a2", category="furniture", terms={})
        results = reg.search_wants(category="electronics")
        assert len(results) == 1
        assert results[0].category == "electronics.cameras"

    def test_search_haves_by_category(self):
        reg = WantRegistry()
        reg.post_have(agent_id="s1", category="electronics.cameras", terms={})
        reg.post_have(agent_id="s2", category="furniture", terms={})
        results = reg.search_haves(category="electronics")
        assert len(results) == 1

    def test_find_matches_by_agent(self):
        reg = WantRegistry()
        reg.post_want(agent_id="buyer", category="electronics", terms={"price": {"max": 2000}})
        reg.post_have(agent_id="seller", category="electronics", terms={"price": {"min": 1000}})
        matches = reg.find_matches(agent_id="buyer")
        assert len(matches) == 1
        assert matches[0].want_agent_id == "buyer"

    def test_stats(self):
        reg = WantRegistry()
        reg.post_want(agent_id="a1", category="electronics", terms={"price": {"max": 2000}})
        reg.post_have(agent_id="s1", category="electronics", terms={"price": {"min": 1000}})
        stats = reg.stats()
        assert stats["active_wants"] == 1
        assert stats["active_haves"] == 1
        assert stats["total_matches"] == 1
        assert stats["unique_agents"] == 2


# ===================================================================
# MCP Tool integration tests
# ===================================================================

class TestWantRegistryMcpTools:

    @pytest.fixture(autouse=True)
    def reset_registry(self):
        from concordia.mcp_server import _want_registry
        _want_registry._wants.clear()
        _want_registry._haves.clear()
        _want_registry._matches.clear()
        _want_registry._agent_wants.clear()
        _want_registry._agent_haves.clear()
        yield

    def _parse(self, result_str: str) -> dict:
        return json.loads(result_str)

    def test_post_want(self):
        from concordia.mcp_server import tool_post_want
        result = self._parse(tool_post_want(
            agent_id="buyer_01",
            category="electronics.cameras",
            terms={"price": {"max": 2500, "currency": "USD"}},
        ))
        assert result["want"]["type"] == "concordia.want"
        assert result["want"]["agent_id"] == "buyer_01"
        assert result["match_count"] == 0

    def test_post_have(self):
        from concordia.mcp_server import tool_post_have
        result = self._parse(tool_post_have(
            agent_id="seller_01",
            category="electronics.cameras",
            terms={"price": {"min": 1800, "currency": "USD"}},
        ))
        assert result["have"]["type"] == "concordia.have"
        assert result["match_count"] == 0

    def test_post_want_then_have_matches(self):
        from concordia.mcp_server import tool_post_want, tool_post_have
        tool_post_want(
            agent_id="buyer_01",
            category="electronics.cameras",
            terms={"price": {"max": 2500, "currency": "USD"}},
        )
        result = self._parse(tool_post_have(
            agent_id="seller_01",
            category="electronics.cameras",
            terms={"price": {"min": 1800, "currency": "USD"}},
        ))
        assert result["match_count"] == 1
        match = result["immediate_matches"][0]
        assert match["type"] == "concordia.match"
        assert match["score"] > 0

    def test_get_want(self):
        from concordia.mcp_server import tool_post_want, tool_get_want
        posted = self._parse(tool_post_want(
            agent_id="buyer", category="electronics", terms={},
        ))
        want_id = posted["want"]["id"]
        result = self._parse(tool_get_want(want_id=want_id))
        assert result["found"] is True
        assert result["want"]["agent_id"] == "buyer"

    def test_get_want_not_found(self):
        from concordia.mcp_server import tool_get_want
        result = self._parse(tool_get_want(want_id="fake"))
        assert result["found"] is False

    def test_get_have(self):
        from concordia.mcp_server import tool_post_have, tool_get_have
        posted = self._parse(tool_post_have(
            agent_id="seller", category="electronics", terms={},
        ))
        have_id = posted["have"]["id"]
        result = self._parse(tool_get_have(have_id=have_id))
        assert result["found"] is True

    def test_withdraw_want(self):
        from concordia.mcp_server import tool_post_want, tool_withdraw_want
        posted = self._parse(tool_post_want(
            agent_id="buyer", category="electronics", terms={},
        ))
        result = self._parse(tool_withdraw_want(want_id=posted["want"]["id"]))
        assert result["withdrawn"] is True

    def test_withdraw_have(self):
        from concordia.mcp_server import tool_post_have, tool_withdraw_have
        posted = self._parse(tool_post_have(
            agent_id="seller", category="electronics", terms={},
        ))
        result = self._parse(tool_withdraw_have(have_id=posted["have"]["id"]))
        assert result["withdrawn"] is True

    def test_find_matches(self):
        from concordia.mcp_server import tool_post_want, tool_post_have, tool_find_matches
        tool_post_want(agent_id="buyer", category="electronics", terms={"price": {"max": 2000}})
        tool_post_have(agent_id="seller", category="electronics", terms={"price": {"min": 1000}})
        result = self._parse(tool_find_matches(agent_id="buyer"))
        assert result["count"] == 1

    def test_search_wants(self):
        from concordia.mcp_server import tool_post_want, tool_search_wants
        tool_post_want(agent_id="b1", category="electronics.cameras", terms={})
        tool_post_want(agent_id="b2", category="furniture", terms={})
        result = self._parse(tool_search_wants(category="electronics"))
        assert result["count"] == 1

    def test_search_haves(self):
        from concordia.mcp_server import tool_post_have, tool_search_haves
        tool_post_have(agent_id="s1", category="electronics.cameras", terms={})
        tool_post_have(agent_id="s2", category="furniture", terms={})
        result = self._parse(tool_search_haves(category="electronics"))
        assert result["count"] == 1

    def test_registry_stats(self):
        from concordia.mcp_server import tool_post_want, tool_post_have, tool_want_registry_stats
        tool_post_want(agent_id="buyer", category="electronics", terms={"price": {"max": 2000}})
        tool_post_have(agent_id="seller", category="electronics", terms={"price": {"min": 1000}})
        result = self._parse(tool_want_registry_stats())
        assert result["active_wants"] == 1
        assert result["active_haves"] == 1
        assert result["total_matches"] == 1

    # -- Full marketplace lifecycle via handle_tool_call --

    def test_full_marketplace_lifecycle(self):
        """End-to-end: post Want → post Have → match → open negotiation."""
        from concordia.mcp_server import handle_tool_call

        # Buyer posts a Want
        want_result = handle_tool_call("concordia_post_want", {
            "agent_id": "buyer_agent",
            "category": "electronics.cameras.mirrorless",
            "terms": {
                "item": {"match": "fuzzy", "value": "Canon EOS R5 or equivalent"},
                "price": {"max": 2500.00, "currency": "USD"},
                "condition": {"min": "good", "enum": ["new", "like_new", "good", "fair", "poor"]},
            },
            "location": {"within_km": 50, "of": {"lat": 37.7749, "lng": -122.4194}},
        })
        assert want_result["match_count"] == 0
        want_id = want_result["want"]["id"]

        # Seller posts a Have — should immediately match
        have_result = handle_tool_call("concordia_post_have", {
            "agent_id": "seller_agent",
            "category": "electronics.cameras.mirrorless",
            "terms": {
                "item": {"value": "Canon EOS R5", "description": "15K shutter count"},
                "price": {"min": 1800.00, "currency": "USD"},
                "condition": {"value": "like_new"},
            },
            "location": {"coordinates": {"lat": 37.7849, "lng": -122.4094}},
        })
        assert have_result["match_count"] == 1
        match = have_result["immediate_matches"][0]
        assert match["score"] > 0.5
        assert match["want_agent_id"] == "buyer_agent"
        assert match["have_agent_id"] == "seller_agent"

        # Query matches
        matches = handle_tool_call("concordia_find_matches", {
            "agent_id": "buyer_agent",
        })
        assert matches["count"] == 1

        # Open negotiation based on the match
        session = handle_tool_call("concordia_open_session", {
            "initiator_id": "seller_agent",
            "responder_id": "buyer_agent",
            "terms": {
                "price": {"type": "numeric", "label": "Price", "unit": "USD"},
                "condition": {"type": "categorical", "label": "Condition"},
            },
        })
        assert "session_id" in session

        # Make offer and accept
        handle_tool_call("concordia_propose", {
            "session_id": session["session_id"],
            "role": "initiator",
            "terms": {"price": {"value": 2000}, "condition": {"value": "like_new"}},
        })
        result = handle_tool_call("concordia_accept", {
            "session_id": session["session_id"],
            "role": "responder",
        })
        assert result["state"] == "agreed"

        # Verify stats
        stats = handle_tool_call("concordia_want_registry_stats", {})
        assert stats["active_wants"] == 1
        assert stats["active_haves"] == 1
        assert stats["total_matches"] == 1

        # Withdraw the Want (deal done)
        withdrawn = handle_tool_call("concordia_withdraw_want", {
            "want_id": want_id,
        })
        assert withdrawn["withdrawn"] is True
