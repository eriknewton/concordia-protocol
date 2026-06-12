"""Tests for the L3 attestation-context hardening (security audit 2026-06-09).

Attestations record behavioral signals, never raw deal terms (SPEC
section 9.6.6). Before this hardening, caller-supplied ``value_range``,
``category``, and ``references`` free text was persisted and exported
verbatim, letting a party stuff its own actual deal terms into a signed
attestation. These tests pin the fail-closed validation:

- ``value_range`` is an enumerated logarithmic bucket vocabulary plus a
  shape-validated 3-letter currency code; anything else raises.
- ``category`` is a dotted lowercase taxonomy path with a length cap.
- ``references`` entries are count-capped, string-length-capped, and the
  ``extensions`` escape hatch is size-capped in canonical-JSON bytes.
- Invalid input is rejected, never coerced, and never echoed back in the
  error text (content-injection lens).
- Previously issued attestations are unaffected: validation runs at
  issuance only; party-signature verification never re-validates meta.
"""

import pytest

from concordia import (
    Agent,
    BasicOffer,
    SessionState,
    generate_attestation,
    verify_signature,
)
from concordia.attestation import (
    MAX_CATEGORY_LENGTH,
    MAX_REFERENCE_EXTENSIONS_BYTES,
    MAX_REFERENCE_ID_LENGTH,
    MAX_REFERENCE_OPTIONAL_STRING_LENGTH,
    MAX_REFERENCE_RELATIONSHIP_LENGTH,
    MAX_REFERENCE_TYPE_LENGTH,
    MAX_REFERENCES,
    VALUE_RANGE_BUCKETS,
)


@pytest.fixture
def agreed_session():
    seller = Agent("seller_l3")
    buyer = Agent("buyer_l3")
    terms = {
        "price": {"value": 4350.0, "currency": "USD"},
        "qty": {"value": 1},
    }
    session = seller.open_session(counterparty=buyer.identity, terms=terms)
    buyer.join_session(session)
    buyer.accept_session()
    seller.send_offer(BasicOffer(terms={
        "price": {"value": 4350.0, "currency": "USD"},
        "qty": {"value": 1},
    }), reasoning="firm price")
    buyer.accept_offer()
    assert session.state == SessionState.AGREED
    return session, seller, buyer


def _key_pairs(seller, buyer):
    return {seller.identity.agent_id: seller.key_pair,
            buyer.identity.agent_id: buyer.key_pair}


class TestValueRangeBucketVocabulary:
    @pytest.mark.parametrize("bucket", VALUE_RANGE_BUCKETS)
    def test_every_bucket_accepted(self, agreed_session, bucket):
        session, seller, buyer = agreed_session
        att = generate_attestation(
            session, _key_pairs(seller, buyer),
            value_range=f"{bucket}_USD",
        )
        assert att["meta"]["value_range"] == f"{bucket}_USD"

    @pytest.mark.parametrize("currency", ["EUR", "JPY", "GBP", "CHF"])
    def test_currency_codes_shape_validated_not_enumerated(
        self, agreed_session, currency
    ):
        session, seller, buyer = agreed_session
        att = generate_attestation(
            session, _key_pairs(seller, buyer),
            value_range=f"1000-5000_{currency}",
        )
        assert att["meta"]["value_range"] == f"1000-5000_{currency}"

    @pytest.mark.parametrize("bad", [
        # Free-text deal terms: the L3 exploit itself.
        "I will pay $4,350 for the camera",
        "price=4350 USD, qty=1, ship to 90210",
        # Exact-price encoding through a range-shaped string.
        "4350-4351_USD",
        "4350-4350_USD",
        # Non-vocabulary band (previously accepted).
        "500-1500_USD",
        # Currency shape violations.
        "1000-5000_usd",
        "1000-5000_USDT",
        "1000-5000_US",
        "1000-5000",
        "1000-5000 USD",
        # Structure violations.
        "_USD",
        "1000-5000_",
        "1000-5000_USD ",
        " 1000-5000_USD",
        "1000-5000_USD\n",
    ])
    def test_free_text_and_near_misses_rejected(self, agreed_session, bad):
        session, seller, buyer = agreed_session
        with pytest.raises(ValueError, match="value_range"):
            generate_attestation(
                session, _key_pairs(seller, buyer), value_range=bad
            )

    def test_rejected_not_coerced(self, agreed_session):
        """Fail-closed: no attestation object is produced on bad input."""
        session, seller, buyer = agreed_session
        with pytest.raises(ValueError):
            generate_attestation(
                session, _key_pairs(seller, buyer),
                value_range="totally free text",
            )

    def test_error_does_not_echo_input(self, agreed_session):
        """Content-injection lens: invalid input never rides in the error."""
        session, seller, buyer = agreed_session
        injected = "EVIL_INJECTED_MARKER_${jndi}"
        with pytest.raises(ValueError) as excinfo:
            generate_attestation(
                session, _key_pairs(seller, buyer), value_range=injected
            )
        assert injected not in str(excinfo.value)
        assert "EVIL_INJECTED_MARKER" not in str(excinfo.value)

    def test_omitted_value_range_still_fine(self, agreed_session):
        session, seller, buyer = agreed_session
        att = generate_attestation(session, _key_pairs(seller, buyer))
        assert "value_range" not in att["meta"]


class TestCategoryTaxonomy:
    @pytest.mark.parametrize("ok", [
        "electronics",
        "electronics.cameras",
        "electronics.cameras.mirrorless",
        "compute.gpu",
        "zero-score-only",
        "a_b.c-d.e2",
    ])
    def test_taxonomy_paths_accepted(self, agreed_session, ok):
        session, seller, buyer = agreed_session
        att = generate_attestation(
            session, _key_pairs(seller, buyer), category=ok
        )
        assert att["meta"]["category"] == ok

    @pytest.mark.parametrize("bad", [
        "Selling 4 units at $1200 each",
        "electronics cameras",
        "Electronics",
        "electronics..cameras",
        ".electronics",
        "electronics.",
        "x" * (MAX_CATEGORY_LENGTH + 1),
        "electronics.cameras!",
    ])
    def test_prose_and_malformed_rejected(self, agreed_session, bad):
        session, seller, buyer = agreed_session
        with pytest.raises(ValueError, match="category"):
            generate_attestation(
                session, _key_pairs(seller, buyer), category=bad
            )

    def test_max_length_boundary_accepted(self, agreed_session):
        session, seller, buyer = agreed_session
        boundary = "x" * MAX_CATEGORY_LENGTH
        att = generate_attestation(
            session, _key_pairs(seller, buyer), category=boundary
        )
        assert att["meta"]["category"] == boundary

    def test_error_does_not_echo_input(self, agreed_session):
        session, seller, buyer = agreed_session
        injected = "EVIL CATEGORY $4,350 deal terms"
        with pytest.raises(ValueError) as excinfo:
            generate_attestation(
                session, _key_pairs(seller, buyer), category=injected
            )
        assert "EVIL" not in str(excinfo.value)
        assert "4,350" not in str(excinfo.value)


def _ref(i=0):
    return {"type": "receipt", "id": f"att_{i:08x}", "relationship": "references"}


class TestReferencesCaps:
    def test_count_at_cap_accepted(self, agreed_session):
        session, seller, buyer = agreed_session
        refs = [_ref(i) for i in range(MAX_REFERENCES)]
        att = generate_attestation(
            session, _key_pairs(seller, buyer), references=refs
        )
        assert len(att["references"]) == MAX_REFERENCES

    def test_count_over_cap_rejected(self, agreed_session):
        session, seller, buyer = agreed_session
        refs = [_ref(i) for i in range(MAX_REFERENCES + 1)]
        with pytest.raises(ValueError, match="references"):
            generate_attestation(
                session, _key_pairs(seller, buyer), references=refs
            )

    @pytest.mark.parametrize("field,cap", [
        ("type", MAX_REFERENCE_TYPE_LENGTH),
        ("id", MAX_REFERENCE_ID_LENGTH),
        ("relationship", MAX_REFERENCE_RELATIONSHIP_LENGTH),
    ])
    def test_required_string_caps(self, agreed_session, field, cap):
        session, seller, buyer = agreed_session
        ok_ref = _ref()
        ok_ref[field] = "x" * cap
        att = generate_attestation(
            session, _key_pairs(seller, buyer), references=[ok_ref]
        )
        assert att["references"][0][field] == "x" * cap

        bad_ref = _ref()
        bad_ref[field] = "x" * (cap + 1)
        with pytest.raises(ValueError, match=field):
            generate_attestation(
                session, _key_pairs(seller, buyer), references=[bad_ref]
            )

    @pytest.mark.parametrize("field", ["version", "signed_at", "signer_did"])
    def test_optional_string_caps(self, agreed_session, field):
        session, seller, buyer = agreed_session
        ok_ref = _ref()
        ok_ref[field] = "x" * MAX_REFERENCE_OPTIONAL_STRING_LENGTH
        att = generate_attestation(
            session, _key_pairs(seller, buyer), references=[ok_ref]
        )
        assert att["references"][0][field]

        bad_ref = _ref()
        bad_ref[field] = "x" * (MAX_REFERENCE_OPTIONAL_STRING_LENGTH + 1)
        with pytest.raises(ValueError, match=field):
            generate_attestation(
                session, _key_pairs(seller, buyer), references=[bad_ref]
            )

    @pytest.mark.parametrize("field", ["version", "signed_at", "signer_did"])
    def test_optional_non_string_rejected(self, agreed_session, field):
        session, seller, buyer = agreed_session
        bad_ref = _ref()
        bad_ref[field] = {"sneaky": "object"}
        with pytest.raises(ValueError, match=field):
            generate_attestation(
                session, _key_pairs(seller, buyer), references=[bad_ref]
            )

    def test_extensions_small_dict_roundtrips(self, agreed_session):
        session, seller, buyer = agreed_session
        ref = _ref()
        ref["extensions"] = {"chain_depth": 2}
        att = generate_attestation(
            session, _key_pairs(seller, buyer), references=[ref]
        )
        assert att["references"][0]["extensions"] == {"chain_depth": 2}

    def test_extensions_non_dict_rejected(self, agreed_session):
        session, seller, buyer = agreed_session
        ref = _ref()
        ref["extensions"] = "free text deal terms: $4,350"
        with pytest.raises(ValueError, match="extensions"):
            generate_attestation(
                session, _key_pairs(seller, buyer), references=[ref]
            )

    def test_extensions_oversize_rejected(self, agreed_session):
        session, seller, buyer = agreed_session
        ref = _ref()
        ref["extensions"] = {"blob": "x" * (MAX_REFERENCE_EXTENSIONS_BYTES + 1)}
        with pytest.raises(ValueError, match="extensions"):
            generate_attestation(
                session, _key_pairs(seller, buyer), references=[ref]
            )

    def test_extensions_unserializable_rejected(self, agreed_session):
        session, seller, buyer = agreed_session
        ref = _ref()
        ref["extensions"] = {"bad": float("nan")}
        with pytest.raises(ValueError, match="extensions"):
            generate_attestation(
                session, _key_pairs(seller, buyer), references=[ref]
            )


class TestSignatureRoundTripUnaffected:
    def test_full_attestation_with_validated_context_verifies(
        self, agreed_session
    ):
        session, seller, buyer = agreed_session
        key_pairs = _key_pairs(seller, buyer)
        att = generate_attestation(
            session, key_pairs,
            category="electronics.cameras",
            value_range="1000-5000_USD",
            references=[_ref()],
        )
        for party in att["parties"]:
            kp = key_pairs[party["agent_id"]]
            assert verify_signature(party, party["signature"], kp.public_key)

    def test_previously_issued_legacy_meta_still_verifies(
        self, agreed_session
    ):
        """Backward compat: validation is issuance-side only.

        Attestations issued before this hardening may carry non-vocabulary
        meta values. Party signatures cover each party's own behavior
        record, not meta, so verification of old attestations is
        unchanged. Simulate one by mutating meta after generation.
        """
        session, seller, buyer = agreed_session
        key_pairs = _key_pairs(seller, buyer)
        att = generate_attestation(session, key_pairs)
        att["meta"]["value_range"] = "500-1500_USD"
        att["meta"]["category"] = "Legacy Free Text Category"
        for party in att["parties"]:
            kp = key_pairs[party["agent_id"]]
            assert verify_signature(party, party["signature"], kp.public_key)
