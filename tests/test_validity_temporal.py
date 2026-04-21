"""Tests for three-mode validity_temporal on attestations (WP3, v0.4.0).

Modes:
- absolute: {mode, from, until}
- relative: {mode, from, duration_seconds}
- window: {mode, start, end, duration_seconds}
"""

from datetime import datetime, timedelta, timezone

import pytest

from concordia import (
    Agent,
    BasicOffer,
    SessionState,
    generate_attestation,
    is_valid_now,
    is_valid_attestation,
)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def session_pair():
    seller = Agent("seller_vt")
    buyer = Agent("buyer_vt")
    terms = {"price": {"value": 10.0, "currency": "USD"}}
    session = seller.open_session(counterparty=buyer.identity, terms=terms)
    buyer.join_session(session)
    buyer.accept_session()
    seller.send_offer(BasicOffer(terms={"price": {"value": 10.0, "currency": "USD"}}))
    buyer.accept_offer()
    assert session.state == SessionState.AGREED
    return session, {
        seller.identity.agent_id: seller.key_pair,
        buyer.identity.agent_id: buyer.key_pair,
    }


class TestValidityTemporalAbsolute:
    def test_in_window(self, session_pair):
        session, kps = session_pair
        now = datetime.now(timezone.utc)
        vt = {"mode": "absolute",
              "from": _iso(now - timedelta(hours=1)),
              "until": _iso(now + timedelta(hours=1))}
        att = generate_attestation(session, kps, validity_temporal=vt)
        assert att["validity_temporal"]["mode"] == "absolute"
        assert is_valid_now(att)

    def test_pre_window(self, session_pair):
        session, kps = session_pair
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        vt = {"mode": "absolute",
              "from": _iso(future),
              "until": _iso(future + timedelta(hours=1))}
        att = generate_attestation(session, kps, validity_temporal=vt)
        assert not is_valid_now(att)

    def test_post_window(self, session_pair):
        session, kps = session_pair
        past = datetime.now(timezone.utc) - timedelta(hours=2)
        vt = {"mode": "absolute",
              "from": _iso(past),
              "until": _iso(past + timedelta(hours=1))}
        att = generate_attestation(session, kps, validity_temporal=vt)
        assert not is_valid_now(att)

    def test_until_before_from_rejected(self, session_pair):
        session, kps = session_pair
        now = datetime.now(timezone.utc)
        vt = {"mode": "absolute",
              "from": _iso(now + timedelta(hours=1)),
              "until": _iso(now)}
        with pytest.raises(ValueError, match="until must be after"):
            generate_attestation(session, kps, validity_temporal=vt)

    def test_missing_field_rejected(self, session_pair):
        session, kps = session_pair
        with pytest.raises(ValueError, match="missing"):
            generate_attestation(
                session, kps,
                validity_temporal={"mode": "absolute",
                                   "from": _iso(datetime.now(timezone.utc))},
            )


class TestValidityTemporalRelative:
    def test_in_window(self, session_pair):
        session, kps = session_pair
        anchor = datetime.now(timezone.utc) - timedelta(minutes=30)
        vt = {"mode": "relative", "from": _iso(anchor),
              "duration_seconds": 3600}
        att = generate_attestation(session, kps, validity_temporal=vt)
        assert is_valid_now(att)

    def test_past_window(self, session_pair):
        session, kps = session_pair
        anchor = datetime.now(timezone.utc) - timedelta(hours=2)
        vt = {"mode": "relative", "from": _iso(anchor),
              "duration_seconds": 3600}
        att = generate_attestation(session, kps, validity_temporal=vt)
        assert not is_valid_now(att)

    def test_duration_zero_rejected(self, session_pair):
        session, kps = session_pair
        vt = {"mode": "relative",
              "from": _iso(datetime.now(timezone.utc)),
              "duration_seconds": 0}
        with pytest.raises(ValueError, match="positive int"):
            generate_attestation(session, kps, validity_temporal=vt)


class TestValidityTemporalWindow:
    def test_valid_when_anchored_window_fits(self, session_pair):
        session, kps = session_pair
        now = datetime.now(timezone.utc)
        vt = {"mode": "window",
              "start": _iso(now - timedelta(hours=1)),
              "end": _iso(now + timedelta(hours=3)),
              "duration_seconds": 3600}
        att = generate_attestation(session, kps, validity_temporal=vt)
        assert is_valid_now(att)

    def test_invalid_when_insufficient_tail_remains(self, session_pair):
        session, kps = session_pair
        now = datetime.now(timezone.utc)
        vt = {"mode": "window",
              "start": _iso(now - timedelta(hours=4)),
              "end": _iso(now + timedelta(minutes=5)),
              "duration_seconds": 3600}
        att = generate_attestation(session, kps, validity_temporal=vt)
        assert not is_valid_now(att)

    def test_invalid_before_start(self, session_pair):
        session, kps = session_pair
        future = datetime.now(timezone.utc) + timedelta(hours=2)
        vt = {"mode": "window",
              "start": _iso(future),
              "end": _iso(future + timedelta(hours=3)),
              "duration_seconds": 3600}
        att = generate_attestation(session, kps, validity_temporal=vt)
        assert not is_valid_now(att)

    def test_duration_exceeds_span_rejected(self, session_pair):
        session, kps = session_pair
        now = datetime.now(timezone.utc)
        vt = {"mode": "window",
              "start": _iso(now),
              "end": _iso(now + timedelta(hours=1)),
              "duration_seconds": 7200}
        with pytest.raises(ValueError, match="exceeds the window span"):
            generate_attestation(session, kps, validity_temporal=vt)

    def test_end_before_start_rejected(self, session_pair):
        session, kps = session_pair
        now = datetime.now(timezone.utc)
        vt = {"mode": "window",
              "start": _iso(now + timedelta(hours=1)),
              "end": _iso(now),
              "duration_seconds": 10}
        with pytest.raises(ValueError, match="end must be after"):
            generate_attestation(session, kps, validity_temporal=vt)


class TestValidityTemporalAbsent:
    def test_default_has_no_field(self, session_pair):
        session, kps = session_pair
        att = generate_attestation(session, kps)
        assert "validity_temporal" not in att
        assert is_valid_now(att)


class TestValidityTemporalInvalidMode:
    def test_unknown_mode_rejected(self, session_pair):
        session, kps = session_pair
        with pytest.raises(ValueError, match="mode"):
            generate_attestation(
                session, kps,
                validity_temporal={"mode": "eternal"},
            )


class TestValidityTemporalSchema:
    def test_schema_accepts_each_mode(self, session_pair):
        session, kps = session_pair
        now = datetime.now(timezone.utc)
        cases = [
            {"mode": "absolute",
             "from": _iso(now - timedelta(hours=1)),
             "until": _iso(now + timedelta(hours=1))},
            {"mode": "relative", "from": _iso(now), "duration_seconds": 3600},
            {"mode": "window",
             "start": _iso(now - timedelta(hours=1)),
             "end": _iso(now + timedelta(hours=3)),
             "duration_seconds": 3600},
        ]
        for vt in cases:
            att = generate_attestation(session, kps, validity_temporal=vt)
            assert is_valid_attestation(att), f"Schema rejected mode={vt['mode']}"
