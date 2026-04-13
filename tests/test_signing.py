"""Tests for message signing and verification (§9.2)."""

from concordia import KeyPair, ES256KeyPair, sign_message, verify_signature


class TestKeyPair:
    def test_generate(self):
        kp = KeyPair.generate()
        assert kp.private_key is not None
        assert kp.public_key is not None

    def test_public_key_bytes_length(self):
        kp = KeyPair.generate()
        assert len(kp.public_key_bytes()) == 32

    def test_public_key_b64(self):
        kp = KeyPair.generate()
        b64 = kp.public_key_b64()
        assert isinstance(b64, str)
        assert len(b64) > 0

    def test_different_keys(self):
        kp1 = KeyPair.generate()
        kp2 = KeyPair.generate()
        assert kp1.public_key_bytes() != kp2.public_key_bytes()


class TestSignAndVerify:
    def test_sign_and_verify(self):
        kp = KeyPair.generate()
        data = {"concordia": "0.1.0", "type": "negotiate.open", "body": {"terms": {}}}
        sig = sign_message(data, kp)
        assert verify_signature(data, sig, kp.public_key)

    def test_tampered_data_fails(self):
        kp = KeyPair.generate()
        data = {"concordia": "0.1.0", "type": "negotiate.open", "body": {"terms": {}}}
        sig = sign_message(data, kp)
        data["type"] = "negotiate.accept"  # tamper
        assert not verify_signature(data, sig, kp.public_key)

    def test_wrong_key_fails(self):
        kp1 = KeyPair.generate()
        kp2 = KeyPair.generate()
        data = {"concordia": "0.1.0", "type": "negotiate.offer", "body": {}}
        sig = sign_message(data, kp1)
        assert not verify_signature(data, sig, kp2.public_key)

    def test_signature_excludes_signature_field(self):
        kp = KeyPair.generate()
        data = {
            "concordia": "0.1.0",
            "type": "negotiate.open",
            "body": {},
            "signature": "old_signature_should_be_ignored",
        }
        sig = sign_message(data, kp)
        # Verify with the signature field present — it should be excluded
        data["signature"] = sig
        assert verify_signature(data, sig, kp.public_key)

    def test_canonical_json_deterministic(self):
        from concordia.signing import canonical_json

        d1 = {"b": 2, "a": 1}
        d2 = {"a": 1, "b": 2}
        assert canonical_json(d1) == canonical_json(d2)


class TestCrossLanguageCanonicalJSON:
    """Cross-language canonical JSON vectors (SEC-003).

    These vectors MUST produce byte-identical output in both Python
    (canonical_json / _stable_stringify) and TypeScript (stableStringify).
    The expected values here are the shared contract between both repos.
    """

    def test_sorts_keys_alphabetically(self):
        from concordia.signing import canonical_json
        assert canonical_json({"z": 1, "a": 2, "m": 3}) == b'{"a":2,"m":3,"z":1}'

    def test_sorts_nested_keys_recursively(self):
        from concordia.signing import canonical_json
        assert canonical_json({"b": {"d": 1, "c": 2}, "a": 3}) == b'{"a":3,"b":{"c":2,"d":1}}'

    def test_compact_separators(self):
        from concordia.signing import canonical_json
        assert canonical_json({"a": [1, 2, 3]}) == b'{"a":[1,2,3]}'

    def test_integer_numbers_no_decimal(self):
        from concordia.signing import canonical_json
        assert canonical_json({"v": 1}) == b'{"v":1}'
        assert canonical_json({"v": 42}) == b'{"v":42}'
        assert canonical_json({"v": 0}) == b'{"v":0}'
        assert canonical_json({"v": -7}) == b'{"v":-7}'

    def test_integer_valued_floats_no_decimal(self):
        """Python 1.0 must serialize as '1' to match V8's JSON.stringify."""
        from concordia.signing import _stable_stringify
        assert _stable_stringify({"v": 1.0}) == '{"v":1}'
        assert _stable_stringify({"v": 42.0}) == '{"v":42}'
        assert _stable_stringify({"v": -7.0}) == '{"v":-7}'

    def test_boolean_and_null(self):
        from concordia.signing import canonical_json
        assert canonical_json({"a": True, "b": False, "c": None}) == b'{"a":true,"b":false,"c":null}'

    def test_empty_structures(self):
        from concordia.signing import canonical_json
        assert canonical_json({}) == b'{}'
        assert canonical_json({"a": []}) == b'{"a":[]}'
        assert canonical_json({"a": {}}) == b'{"a":{}}'

    def test_string_escaping_control_chars(self):
        from concordia.signing import canonical_json
        assert canonical_json({"a": "line1\nline2"}) == b'{"a":"line1\\nline2"}'
        assert canonical_json({"a": 'quote"here'}) == b'{"a":"quote\\"here"}'
        assert canonical_json({"a": "back\\slash"}) == b'{"a":"back\\\\slash"}'

    def test_preserves_non_ascii_unicode(self):
        """Non-ASCII must NOT be escaped — raw UTF-8 to match V8."""
        from concordia.signing import canonical_json
        assert canonical_json({"a": "café"}) == '{"a":"café"}'.encode("utf-8")
        assert canonical_json({"a": "你好"}) == '{"a":"你好"}'.encode("utf-8")
        assert canonical_json({"emoji": "☺"}) == '{"emoji":"☺"}'.encode("utf-8")

    def test_deeply_nested(self):
        from concordia.signing import canonical_json
        assert canonical_json({"a": {"b": {"c": {"d": 1}}}}) == b'{"a":{"b":{"c":{"d":1}}}}'

    def test_arrays_mixed_types(self):
        from concordia.signing import canonical_json
        assert canonical_json({"a": [1, "two", True, None, {"k": "v"}]}) == \
            b'{"a":[1,"two",true,null,{"k":"v"}]}'

    def test_rejects_negative_zero(self):
        import pytest
        from concordia.signing import canonical_json
        with pytest.raises(ValueError, match="negative zero"):
            canonical_json({"v": -0.0})

    def test_rejects_nan(self):
        import math
        import pytest
        from concordia.signing import canonical_json
        with pytest.raises(ValueError, match="special float"):
            canonical_json({"v": float("nan")})

    def test_rejects_infinity(self):
        import pytest
        from concordia.signing import canonical_json
        with pytest.raises(ValueError, match="special float"):
            canonical_json({"v": float("inf")})
        with pytest.raises(ValueError, match="special float"):
            canonical_json({"v": float("-inf")})

    def test_shared_cross_language_vectors(self):
        """Exact byte-level vectors matching TypeScript test suite."""
        from concordia.signing import canonical_json

        vectors = [
            ({"a": 1}, b'{"a":1}'),
            ({"b": "hello", "a": "world"}, b'{"a":"world","b":"hello"}'),
            ({"x": [1, 2, 3]}, b'{"x":[1,2,3]}'),
            ({"n": None}, b'{"n":null}'),
            ({"t": True, "f": False}, b'{"f":false,"t":true}'),
            ({"nested": {"z": 1, "a": 2}}, b'{"nested":{"a":2,"z":1}}'),
            ({"s": "café"}, '{"s":"café"}'.encode("utf-8")),
            ({"s": "你好世界"}, '{"s":"你好世界"}'.encode("utf-8")),
            ({"s": "line\nnew"}, b'{"s":"line\\nnew"}'),
            ({"empty": {}}, b'{"empty":{}}'),
            ({"arr": []}, b'{"arr":[]}'),
            ({"v": -42}, b'{"v":-42}'),
            ({"v": 0}, b'{"v":0}'),
            ({"mix": [None, True, "a", 1, {"k": "v"}]}, b'{"mix":[null,true,"a",1,{"k":"v"}]}'),
        ]
        for data, expected in vectors:
            assert canonical_json(data) == expected, f"Failed for input: {data}"

    def test_ecmascript_number_formatting(self):
        """Verify number formatting matches V8's JSON.stringify output."""
        from concordia.signing import _format_number_ecmascript

        # Integer-valued floats → no decimal point
        assert _format_number_ecmascript(1.0) == "1"
        assert _format_number_ecmascript(42.0) == "42"
        assert _format_number_ecmascript(0.0) == "0"
        assert _format_number_ecmascript(-7.0) == "-7"

        # Regular integers
        assert _format_number_ecmascript(1) == "1"
        assert _format_number_ecmascript(42) == "42"
        assert _format_number_ecmascript(-100) == "-100"

        # Non-integer floats
        assert _format_number_ecmascript(1.5) == "1.5"
        assert _format_number_ecmascript(0.1) == "0.1"
        assert _format_number_ecmascript(-0.5) == "-0.5"

        # Small decimals — V8 uses decimal notation down to 5e-7
        assert _format_number_ecmascript(0.000005) == "0.000005"


class TestHashChain:
    """Test transcript hash chain integrity (§9.3)."""

    def test_valid_chain(self):
        from concordia import validate_chain, GENESIS_HASH, compute_hash

        msg1 = {"concordia": "0.1.0", "id": "1", "prev_hash": GENESIS_HASH, "body": {}}
        msg2 = {"concordia": "0.1.0", "id": "2", "prev_hash": compute_hash(msg1), "body": {}}
        msg3 = {"concordia": "0.1.0", "id": "3", "prev_hash": compute_hash(msg2), "body": {}}
        assert validate_chain([msg1, msg2, msg3])

    def test_broken_chain(self):
        from concordia import validate_chain, GENESIS_HASH

        msg1 = {"concordia": "0.1.0", "id": "1", "prev_hash": GENESIS_HASH, "body": {}}
        msg2 = {"concordia": "0.1.0", "id": "2", "prev_hash": "sha256:wrong", "body": {}}
        assert not validate_chain([msg1, msg2])

    def test_empty_chain(self):
        from concordia import validate_chain
        assert validate_chain([])

    def test_session_transcript_chain(self):
        """End-to-end: a real session's transcript must form a valid chain."""
        from concordia import Agent, BasicOffer, validate_chain

        seller = Agent("s")
        buyer = Agent("b")
        session = seller.open_session(counterparty=buyer.identity, terms={"p": {"value": 100}})
        buyer.join_session(session)
        buyer.accept_session()
        offer = BasicOffer(terms={"p": {"value": 90}})
        buyer.send_offer(offer)
        seller.accept_offer()
        assert validate_chain(session.transcript)


class TestES256KeyPair:
    def test_generate(self):
        kp = ES256KeyPair.generate()
        assert kp.private_key is not None
        assert kp.public_key is not None

    def test_public_key_bytes(self):
        kp = ES256KeyPair.generate()
        pub = kp.public_key_bytes()
        # Uncompressed P-256 point: 1 byte prefix + 32 bytes x + 32 bytes y = 65
        assert len(pub) == 65
        assert pub[0] == 0x04  # uncompressed point prefix

    def test_public_key_b64(self):
        kp = ES256KeyPair.generate()
        b64 = kp.public_key_b64()
        assert isinstance(b64, str)
        assert len(b64) > 0

    def test_different_keys(self):
        kp1 = ES256KeyPair.generate()
        kp2 = ES256KeyPair.generate()
        assert kp1.public_key_bytes() != kp2.public_key_bytes()


class TestES256SignAndVerify:
    def test_sign_and_verify(self):
        kp = ES256KeyPair.generate()
        data = {"concordia": "0.1.0", "type": "negotiate.open", "body": {"terms": {}}}
        sig = sign_message(data, kp, alg="ES256")
        assert verify_signature(data, sig, kp.public_key, alg="ES256")

    def test_tampered_data_fails(self):
        kp = ES256KeyPair.generate()
        data = {"concordia": "0.1.0", "type": "negotiate.open", "body": {"terms": {}}}
        sig = sign_message(data, kp, alg="ES256")
        data["type"] = "negotiate.accept"  # tamper
        assert not verify_signature(data, sig, kp.public_key, alg="ES256")

    def test_wrong_key_fails(self):
        kp1 = ES256KeyPair.generate()
        kp2 = ES256KeyPair.generate()
        data = {"concordia": "0.1.0", "type": "negotiate.offer", "body": {}}
        sig = sign_message(data, kp1, alg="ES256")
        assert not verify_signature(data, sig, kp2.public_key, alg="ES256")

    def test_signature_excludes_signature_field(self):
        kp = ES256KeyPair.generate()
        data = {
            "concordia": "0.1.0",
            "type": "negotiate.open",
            "body": {},
            "signature": "old_signature_should_be_ignored",
        }
        sig = sign_message(data, kp, alg="ES256")
        data["signature"] = sig
        assert verify_signature(data, sig, kp.public_key, alg="ES256")


class TestCrossAlgorithmRejection:
    """ES256 signatures must not verify as EdDSA and vice versa."""

    def test_es256_sig_fails_eddsa_verify(self):
        es_kp = ES256KeyPair.generate()
        ed_kp = KeyPair.generate()
        data = {"msg": "test cross-alg"}
        sig = sign_message(data, es_kp, alg="ES256")
        # Try verifying ES256 sig with EdDSA key — must fail
        assert not verify_signature(data, sig, ed_kp.public_key, alg="EdDSA")

    def test_eddsa_sig_fails_es256_verify(self):
        ed_kp = KeyPair.generate()
        es_kp = ES256KeyPair.generate()
        data = {"msg": "test cross-alg"}
        sig = sign_message(data, ed_kp, alg="EdDSA")
        # Try verifying EdDSA sig with ES256 key — must fail
        assert not verify_signature(data, sig, es_kp.public_key, alg="ES256")

    def test_wrong_key_type_for_sign_raises(self):
        import pytest
        ed_kp = KeyPair.generate()
        es_kp = ES256KeyPair.generate()
        data = {"msg": "test"}
        with pytest.raises(TypeError):
            sign_message(data, ed_kp, alg="ES256")
        with pytest.raises(TypeError):
            sign_message(data, es_kp, alg="EdDSA")
