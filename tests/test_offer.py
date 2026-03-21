"""Tests for offer construction and validation (§6)."""

from concordia import (
    BasicOffer,
    Bundle,
    BundleOffer,
    Condition,
    ConditionalOffer,
    PartialOffer,
)


class TestBasicOffer:
    def test_complete_flag(self):
        offer = BasicOffer(terms={"price": {"value": 150.00, "currency": "USD"}})
        body = offer.to_body()
        assert body["complete"] is True
        assert body["terms"]["price"]["value"] == 150.00
        assert "offer_id" in body

    def test_valid_until(self):
        offer = BasicOffer(
            terms={"price": {"value": 100.00}},
            valid_until="2026-04-01T00:00:00Z",
        )
        body = offer.to_body()
        assert body["valid_until"] == "2026-04-01T00:00:00Z"

    def test_multi_term(self):
        offer = BasicOffer(terms={
            "price": {"value": 150.00, "currency": "USD"},
            "condition": {"value": "good", "enum": ["new", "like_new", "good", "fair"]},
            "delivery_method": {"value": "shipping"},
            "delivery_date": {"value": "2026-04-01", "type": "date"},
        })
        body = offer.to_body()
        assert len(body["terms"]) == 4
        assert body["complete"] is True


class TestPartialOffer:
    def test_incomplete_flag(self):
        offer = PartialOffer(
            terms={"price": {"value": 140.00, "currency": "USD"}},
            open_terms=["delivery_method", "delivery_date"],
        )
        body = offer.to_body()
        assert body["complete"] is False
        assert body["open_terms"] == ["delivery_method", "delivery_date"]
        assert len(body["terms"]) == 1


class TestConditionalOffer:
    def test_conditions_structure(self):
        offer = ConditionalOffer(conditions=[
            Condition(
                if_clause={"delivery_method": "local_pickup"},
                then_clause={"price": {"value": 130.00, "currency": "USD"}},
            ),
            Condition(
                if_clause={"delivery_method": "shipping"},
                then_clause={"price": {"value": 145.00, "currency": "USD"}},
            ),
        ])
        body = offer.to_body()
        assert len(body["conditions"]) == 2
        assert body["conditions"][0]["if"]["delivery_method"] == "local_pickup"
        assert body["conditions"][0]["then"]["price"]["value"] == 130.00
        assert body["complete"] is True


class TestBundleOffer:
    def test_bundles_structure(self):
        offer = BundleOffer(bundles=[
            Bundle(
                bundle_id="bundle_1",
                label="Just the camera",
                terms={"item": {"value": "Canon EOS R5"}, "price": {"value": 2200.00}},
            ),
            Bundle(
                bundle_id="bundle_2",
                label="Camera + lens kit",
                terms={
                    "items": {"value": ["Canon EOS R5", "RF 24-105mm f/4L"]},
                    "price": {"value": 2800.00},
                },
            ),
        ])
        body = offer.to_body()
        assert len(body["bundles"]) == 2
        assert body["select"] == "one_of"
        assert body["bundles"][0]["label"] == "Just the camera"
        assert body["bundles"][1]["terms"]["price"]["value"] == 2800.00

    def test_custom_offer_id(self):
        offer = BasicOffer(
            terms={"price": {"value": 100.00}},
            offer_id="my_custom_id",
        )
        assert offer.to_body()["offer_id"] == "my_custom_id"
