"""Tests for Ed25519 message signing and verification (§9.2)."""

from concordia import KeyPair, sign_message, verify_signature


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
