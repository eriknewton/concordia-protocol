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
- Previously issued attestations: party-signature verification and the
  reputation read/ingest path (AttestationStore.ingest) never re-validate
  meta, so both are unchanged. Schema validation (validate_attestation /
  is_valid_attestation) DOES now reject legacy free-form meta values;
  that is part of the BREAKING change and is pinned below.

Review fixes (codex security review, 2026-06-11) extend the coverage:

- Reference string fields ban whitespace at issuance and in the schemas
  (finding 1).
- The embedded $defs.reference in both attestation schema files stays in
  lockstep with reference.schema.json (finding 3).
- extensions objects are structurally pre-checked (depth/node bounds)
  before canonicalization (finding 4).
- Schema validation errors never echo the rejected instance value
  (finding 5).
- The legacy read-side behavior is pinned explicitly (finding 6).
"""

import copy
import json
from pathlib import Path

import pytest

from concordia import (
    Agent,
    BasicOffer,
    SessionState,
    generate_attestation,
    validate_attestation,
    validate_message,
    verify_signature,
)
from concordia.attestation import (
    MAX_CATEGORY_LENGTH,
    MAX_REFERENCE_EXTENSIONS_BYTES,
    MAX_REFERENCE_EXTENSIONS_DEPTH,
    MAX_REFERENCE_EXTENSIONS_NODES,
    MAX_REFERENCE_ID_LENGTH,
    MAX_REFERENCE_OPTIONAL_STRING_LENGTH,
    MAX_REFERENCE_RELATIONSHIP_LENGTH,
    MAX_REFERENCE_TYPE_LENGTH,
    MAX_REFERENCES,
    VALUE_RANGE_BUCKETS,
)
from concordia.reputation import AttestationStore
from concordia.signing import KeyPair, sign_message


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


# ---------------------------------------------------------------------------
# Review fixes (codex security review, 2026-06-11)
# ---------------------------------------------------------------------------


class TestReferenceWhitespaceBan:
    """Finding 1: identifier-shaped reference fields reject any whitespace.

    Length caps alone still let a reference carry prose deal terms
    ("price=4350 USD qty=1"). Legitimate identifiers (UUIDs, DIDs, URNs,
    ISO timestamps, semver) never contain whitespace, so any \\s is
    rejected fail-closed at issuance and by the schema pattern.
    """

    ALL_FIELDS = ("type", "id", "relationship", "version", "signed_at",
                  "signer_did")

    @pytest.mark.parametrize("field", ALL_FIELDS)
    @pytest.mark.parametrize("bad", [
        "price=4350 USD qty=1",
        "a b",
        "a\tb",
        "a\nb",
        "a\rb",
        "trailing ",
        " leading",
        "x\n",
    ])
    def test_whitespace_rejected_at_issuance(self, agreed_session, field, bad):
        session, seller, buyer = agreed_session
        ref = _ref()
        ref[field] = bad
        with pytest.raises(ValueError, match="whitespace-free"):
            generate_attestation(
                session, _key_pairs(seller, buyer), references=[ref]
            )

    @pytest.mark.parametrize("field,ok", [
        ("id", "urn:concordia:attestation:att_0f9b2c1a"),
        ("type", "receipt"),
        ("relationship", "references"),
        ("version", "1.2.3-rc.1+build.5"),
        ("signed_at", "2026-05-07T18:30:00Z"),
        ("signer_did", "did:web:log.example.dev:agent-7"),
    ])
    def test_legitimate_identifiers_accepted(self, agreed_session, field, ok):
        session, seller, buyer = agreed_session
        ref = _ref()
        ref[field] = ok
        att = generate_attestation(
            session, _key_pairs(seller, buyer), references=[ref]
        )
        assert att["references"][0][field] == ok

    @pytest.mark.parametrize("field", ["version", "signed_at", "signer_did"])
    def test_empty_optional_string_rejected(self, agreed_session, field):
        """Mirrors the schema pattern ^\\S+$, which requires 1+ chars."""
        session, seller, buyer = agreed_session
        ref = _ref()
        ref[field] = ""
        with pytest.raises(ValueError, match=field):
            generate_attestation(
                session, _key_pairs(seller, buyer), references=[ref]
            )

    def test_error_does_not_echo_input(self, agreed_session):
        session, seller, buyer = agreed_session
        ref = _ref()
        ref["id"] = "EVIL_MARKER price=4350 USD qty=1"
        with pytest.raises(ValueError) as excinfo:
            generate_attestation(
                session, _key_pairs(seller, buyer), references=[ref]
            )
        assert "EVIL_MARKER" not in str(excinfo.value)
        assert "4350" not in str(excinfo.value)


class TestExtensionsStructuralPrecheck:
    """Finding 4: structure is bounded BEFORE canonical serialization.

    The 2048-canonical-byte cap is enforced after full canonicalization,
    so without a pre-check a pathological extensions object would be
    fully walked just to be rejected. Depth and node-count bounds bail
    early instead. Depth counts every level including scalar leaves; the
    extensions object itself is depth 1.
    """

    @staticmethod
    def _chain(n_dicts):
        """Build n_dicts nested dicts; the innermost holds a scalar."""
        value = 0
        for _ in range(n_dicts):
            value = {"a": value}
        return value

    def test_depth_at_bound_accepted(self, agreed_session):
        session, seller, buyer = agreed_session
        ref = _ref()
        # Dicts at depths 1..7, scalar leaf at depth 8: within the bound.
        ref["extensions"] = self._chain(MAX_REFERENCE_EXTENSIONS_DEPTH - 1)
        att = generate_attestation(
            session, _key_pairs(seller, buyer), references=[ref]
        )
        assert att["references"][0]["extensions"] == ref["extensions"]

    def test_depth_over_bound_rejected(self, agreed_session):
        session, seller, buyer = agreed_session
        ref = _ref()
        # Dicts at depths 1..8, scalar leaf at depth 9: over the bound.
        ref["extensions"] = self._chain(MAX_REFERENCE_EXTENSIONS_DEPTH)
        with pytest.raises(ValueError, match="nesting depth"):
            generate_attestation(
                session, _key_pairs(seller, buyer), references=[ref]
            )

    def test_deeply_nested_list_rejected(self, agreed_session):
        session, seller, buyer = agreed_session
        value = [0]
        for _ in range(MAX_REFERENCE_EXTENSIONS_DEPTH):
            value = [value]
        ref = _ref()
        ref["extensions"] = {"a": value}
        with pytest.raises(ValueError, match="nesting depth"):
            generate_attestation(
                session, _key_pairs(seller, buyer), references=[ref]
            )

    def test_node_count_at_bound_accepted(self, agreed_session):
        session, seller, buyer = agreed_session
        ref = _ref()
        # Nodes: extensions dict (1) + list (1) + 254 scalars = 256.
        ref["extensions"] = {"a": [0] * (MAX_REFERENCE_EXTENSIONS_NODES - 2)}
        att = generate_attestation(
            session, _key_pairs(seller, buyer), references=[ref]
        )
        assert att["references"][0]["extensions"] == ref["extensions"]

    def test_node_count_over_bound_rejected(self, agreed_session):
        session, seller, buyer = agreed_session
        ref = _ref()
        # Nodes: extensions dict (1) + list (1) + 255 scalars = 257.
        ref["extensions"] = {"a": [0] * (MAX_REFERENCE_EXTENSIONS_NODES - 1)}
        with pytest.raises(ValueError, match="nodes"):
            generate_attestation(
                session, _key_pairs(seller, buyer), references=[ref]
            )

    def test_wide_object_rejected_by_node_bound_not_byte_cap(
        self, agreed_session
    ):
        """A huge flat object trips the cheap node bound, not the byte cap."""
        session, seller, buyer = agreed_session
        ref = _ref()
        ref["extensions"] = {f"k{i}": 0 for i in range(10_000)}
        with pytest.raises(ValueError, match="nodes"):
            generate_attestation(
                session, _key_pairs(seller, buyer), references=[ref]
            )


def _schema_path(*parts):
    return Path(__file__).resolve().parent.parent.joinpath(*parts)


class TestSchemaLockstep:
    """Finding 3: the embedded $defs.reference in BOTH attestation schema
    files carries the same caps and whitespace pattern as
    reference.schema.json, and references[] is count-capped.
    """

    REFERENCE_FIELDS = ("id", "type", "relationship", "version",
                        "signed_at", "signer_did")

    @staticmethod
    def _load(path):
        with open(path) as f:
            return json.load(f)

    def test_three_schema_files_in_lockstep(self):
        canonical = self._load(
            _schema_path("schemas", "reference.schema.json")
        )["properties"]
        for schema_file in (
            _schema_path("schemas", "attestation.schema.json"),
            _schema_path("attestation.schema.json"),
        ):
            embedded = self._load(schema_file)["$defs"]["reference"][
                "properties"
            ]
            for field in self.REFERENCE_FIELDS:
                for key in ("maxLength", "pattern", "minLength"):
                    assert embedded[field].get(key) == canonical[field].get(
                        key
                    ), f"{schema_file.name}: {field}.{key} out of lockstep"

    def test_attestation_schemas_cap_references_count(self):
        for schema_file in (
            _schema_path("schemas", "attestation.schema.json"),
            _schema_path("attestation.schema.json"),
        ):
            schema = self._load(schema_file)
            assert (
                schema["properties"]["references"]["maxItems"]
                == MAX_REFERENCES
            ), f"{schema_file.name}: references maxItems out of lockstep"

    def test_embedded_reference_caps_enforced_by_validator(self):
        att = _legacy_style_attestation()
        att["meta"] = {"category": "electronics.cameras"}
        att["references"] = [{
            "id": "x" * (MAX_REFERENCE_ID_LENGTH + 1),
            "type": "y" * (MAX_REFERENCE_TYPE_LENGTH + 1),
            "relationship": "z" * (MAX_REFERENCE_RELATIONSHIP_LENGTH + 1),
        }]
        errors = validate_attestation(att)
        assert (
            "$.references[0].id: violates 'maxLength' constraint: "
            f"{MAX_REFERENCE_ID_LENGTH}"
        ) in errors
        assert (
            "$.references[0].type: violates 'maxLength' constraint: "
            f"{MAX_REFERENCE_TYPE_LENGTH}"
        ) in errors
        assert (
            "$.references[0].relationship: violates 'maxLength' constraint: "
            f"{MAX_REFERENCE_RELATIONSHIP_LENGTH}"
        ) in errors

    def test_embedded_reference_whitespace_pattern_enforced_by_validator(
        self,
    ):
        att = _legacy_style_attestation()
        att["meta"] = {"category": "electronics.cameras"}
        att["references"] = [{
            "id": "price=4350 USD qty=1",
            "type": "receipt",
            "relationship": "references",
        }]
        errors = validate_attestation(att)
        assert any(
            error.startswith("$.references[0].id:")
            and "violates 'pattern'" in error
            for error in errors
        )
        assert not any("4350" in error for error in errors)

    def test_references_over_count_cap_rejected_by_validator(self):
        att = _legacy_style_attestation()
        att["meta"] = {"category": "electronics.cameras"}
        att["references"] = [
            {
                "id": f"urn:concordia:attestation:att_{i:08x}",
                "type": "receipt",
                "relationship": "references",
            }
            for i in range(MAX_REFERENCES + 1)
        ]
        errors = validate_attestation(att)
        assert (
            f"$.references: violates 'maxItems' constraint: {MAX_REFERENCES}"
            in errors
        )


class TestNoEchoSchemaValidationErrors:
    """Finding 5: schema validation errors report the JSON path and the
    violated constraint, never the rejected instance value (parse-boundary
    posture: never echo attacker-controlled input).
    """

    def test_attestation_pattern_failure_does_not_echo(self):
        att = _legacy_style_attestation()
        att["meta"] = {
            "value_range": "SECRET_MARKER price 4350 USD qty 1",
            "category": "ANOTHER_MARKER Cameras & Photo",
        }
        errors = validate_attestation(att)
        assert errors
        assert any(e.startswith("$.meta.value_range:") for e in errors)
        assert any(e.startswith("$.meta.category:") for e in errors)
        joined = "\n".join(errors)
        assert "SECRET_MARKER" not in joined
        assert "ANOTHER_MARKER" not in joined
        assert "4350" not in joined

    def test_attestation_maxlength_failure_does_not_echo(self):
        att = _legacy_style_attestation()
        att["summary"] = "INSTANCE_MARKER " + "x" * 1100
        errors = validate_attestation(att)
        assert "$.summary: violates 'maxLength' constraint: 1024" in errors
        assert not any("INSTANCE_MARKER" in e for e in errors)

    def test_message_enum_failure_does_not_echo(self):
        msg = {
            "concordia": "0.1.0",
            "type": "negotiate.EVIL_TYPE_MARKER price=4350",
            "id": "msg_1",
            "session_id": "ses_1",
            "timestamp": "2026-03-21T00:00:00Z",
            "from": {"agent_id": "a"},
            "body": {},
            "signature": "sig",
        }
        errors = validate_message(msg)
        assert any(
            e.startswith("$.type:") and "violates 'enum'" in e
            for e in errors
        )
        assert not any("EVIL_TYPE_MARKER" in e for e in errors)
        assert not any("4350" in e for e in errors)

    def test_message_type_failure_does_not_echo(self):
        msg = {
            "concordia": "0.1.0",
            "type": "negotiate.open",
            "id": "msg_1",
            "session_id": "ses_1",
            "timestamp": "2026-03-21T00:00:00Z",
            "from": {"agent_id": "a"},
            "body": "TYPE_MARKER not an object",
            "signature": "sig",
        }
        errors = validate_message(msg)
        assert any(
            e.startswith("$.body:") and "violates 'type'" in e
            for e in errors
        )
        assert not any("TYPE_MARKER" in e for e in errors)

    def test_required_failures_still_name_missing_property(self):
        """'required' keeps the upstream message: it names only
        schema-side property names, never instance content."""
        errors = validate_attestation({"concordia_attestation": "0.1.0"})
        assert any("'meta' is a required property" in e for e in errors)


def _legacy_style_attestation():
    """A fully schema-valid attestation EXCEPT for whatever the caller
    mutates afterwards. Used by the read-side and no-echo pins."""
    behavior = {
        "offers_made": 1,
        "concessions": 0,
        "concession_magnitude": 0,
        "signals_shared": 0,
        "constraints_declared": 0,
        "constraints_violated": 0,
        "reasoning_provided": True,
        "withdrawal": False,
    }
    return {
        "concordia_attestation": "0.1.0",
        "attestation_id": "att_legacy_pin",
        "session_id": "ses_legacy_pin",
        "timestamp": "2026-05-10T14:22:08Z",
        "outcome": {
            "status": "agreed",
            "rounds": 2,
            "duration_seconds": 60,
            "terms_count": 3,
            "resolution_mechanism": "direct",
        },
        "parties": [
            {
                "agent_id": "agent_legacy_a",
                "role": "initiator",
                "behavior": copy.deepcopy(behavior),
                "signature": "sig_a",
            },
            {
                "agent_id": "agent_legacy_b",
                "role": "responder",
                "behavior": copy.deepcopy(behavior),
                "signature": "sig_b",
            },
        ],
        "meta": {
            "category": "electronics.cameras",
            "value_range": "1000-5000_USD",
            "extensions_used": [],
            "mediator_invoked": False,
        },
        "transcript_hash": "sha256:" + "a" * 64,
        "fulfillment": None,
    }


class TestLegacyReadPathPinned:
    """Finding 6: pin the actual read-side behavior for a legacy
    attestation with free-form meta values.

    The reputation ingest path (AttestationStore.ingest) verifies
    signatures and structure but does NOT schema-validate meta, so stored
    legacy attestations continue to ingest and score: unchanged, pinned
    here. Schema validation (validate_attestation) DOES now reject legacy
    free-form meta values: that is part of the BREAKING change, also
    pinned here.
    """

    @staticmethod
    def _signed_legacy_attestation():
        keys = {
            "agent_legacy_a": KeyPair.generate(),
            "agent_legacy_b": KeyPair.generate(),
        }
        att = _legacy_style_attestation()
        # Legacy free-form meta values, as issued before the hardening.
        att["meta"] = {
            "category": "Cameras & Photo > Digital Cameras",
            "value_range": "500-1500_USD",
        }
        for party in att["parties"]:
            del party["signature"]
            party["signature"] = sign_message(
                party, keys[party["agent_id"]]
            )
        return att, keys

    def test_reputation_ingest_accepts_legacy_free_form_meta(self):
        att, keys = self._signed_legacy_attestation()
        store = AttestationStore()
        accepted, result = store.ingest(
            att, lambda agent_id: (
                keys[agent_id].public_key if agent_id in keys else None
            ),
        )
        assert accepted, result.errors
        assert result.valid
        stored = store.get("att_legacy_pin")
        assert stored is not None
        # The legacy meta values are stored verbatim; ingest never
        # schema-validates or rewrites meta.
        assert stored.attestation["meta"]["category"] == (
            "Cameras & Photo > Digital Cameras"
        )
        assert stored.attestation["meta"]["value_range"] == "500-1500_USD"

    def test_schema_validation_rejects_legacy_free_form_meta(self):
        att, _keys = self._signed_legacy_attestation()
        errors = validate_attestation(att)
        assert any(e.startswith("$.meta.category:") for e in errors)
        assert any(e.startswith("$.meta.value_range:") for e in errors)
        # And the rejected legacy values are never echoed back.
        joined = "\n".join(errors)
        assert "Cameras & Photo" not in joined
        assert "500-1500" not in joined
