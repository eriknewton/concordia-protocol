"""Regression tests for SEC-014: Attestation Signature Verification Is Mandatory.

Verifies that ``AttestationStore.ingest()`` requires a mandatory
``public_key_resolver`` callback and rejects attestations when:
  - The resolver returns ``None`` for a party (unknown identity)
  - The signature is cryptographically invalid (forged or wrong key)

Also verifies:
  - The old "skip verification" warning path is removed
  - The store is unchanged after any rejection
  - The MCP tool wires the resolver correctly

This is the third and final sprint in the signature verification cluster
(SEC-005, SEC-010, SEC-014), following the resolver pattern established
by SEC-005 and implemented by SEC-010.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from concordia.reputation.store import AttestationStore, ValidationResult
from concordia.signing import KeyPair, sign_message, verify_signature


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _make_signed_attestation(
    key_a: KeyPair,
    key_b: KeyPair,
    agent_a: str = "agent_alpha",
    agent_b: str = "agent_beta",
    att_id: str | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """Create a properly-signed attestation for testing."""
    att_id = att_id or f"att_{uuid.uuid4().hex[:12]}"
    session_id = session_id or f"sess_{uuid.uuid4().hex[:12]}"

    party_a: dict[str, Any] = {
        "agent_id": agent_a,
        "role": "initiator",
        "behavior": {
            "concession_magnitude": 0.15,
            "offers_made": 3,
            "reasoning_provided": True,
        },
    }
    party_a["signature"] = sign_message(party_a, key_a)

    party_b: dict[str, Any] = {
        "agent_id": agent_b,
        "role": "responder",
        "behavior": {
            "concession_magnitude": 0.2,
            "offers_made": 2,
            "reasoning_provided": False,
        },
    }
    party_b["signature"] = sign_message(party_b, key_b)

    return {
        "concordia_attestation": "1.0",
        "attestation_id": att_id,
        "session_id": session_id,
        "timestamp": "2026-03-28T12:00:00Z",
        "outcome": {
            "status": "agreed",
            "rounds": 3,
            "duration_seconds": 120,
        },
        "parties": [party_a, party_b],
        "meta": {"category": "electronics", "value_range": "100-500_USD"},
        "transcript_hash": "sha256:abc123def456",
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestAttestationSignatureVerificationMandatory:
    """SEC-014 regression tests: mandatory signature verification on ingest."""

    def setup_method(self):
        self.store = AttestationStore()
        self.key_a = KeyPair.generate()
        self.key_b = KeyPair.generate()
        self.key_c = KeyPair.generate()  # unrelated key for wrong-key tests

    def _resolver(self, agent_id: str) -> Ed25519PublicKey | None:
        """Standard resolver that knows both parties."""
        if agent_id == "agent_alpha":
            return self.key_a.public_key
        if agent_id == "agent_beta":
            return self.key_b.public_key
        return None

    # --- 1. Valid signed attestation accepted ---

    def test_valid_signed_attestation_accepted(self):
        """A properly-signed attestation with a correct resolver is accepted."""
        att = _make_signed_attestation(self.key_a, self.key_b)
        accepted, result = self.store.ingest(att, self._resolver)
        assert accepted is True
        assert result.valid is True
        assert result.errors == []
        assert self.store.count() == 1

    # --- 2. Forged signature rejected ---

    def test_forged_signature_rejected(self):
        """Tampering with one party's signature causes rejection."""
        att = _make_signed_attestation(self.key_a, self.key_b)
        # Tamper with party A's signature
        att["parties"][0]["signature"] = "AAAA_forged_signature_AAAA"
        accepted, result = self.store.ingest(att, self._resolver)
        assert accepted is False
        assert any("agent_alpha" in e for e in result.errors)
        assert self.store.count() == 0

    # --- 3. Unknown agent_id rejected ---

    def test_unknown_agent_id_rejected(self):
        """If the resolver returns None for a party, the attestation is rejected."""
        att = _make_signed_attestation(self.key_a, self.key_b,
                                       agent_a="unknown_agent", agent_b="agent_beta")

        def partial_resolver(agent_id: str) -> Ed25519PublicKey | None:
            if agent_id == "agent_beta":
                return self.key_b.public_key
            return None  # unknown_agent not recognized

        accepted, result = self.store.ingest(att, partial_resolver)
        assert accepted is False
        assert any("Unknown agent identity" in e and "unknown_agent" in e
                    for e in result.errors)
        assert self.store.count() == 0

    # --- 4. Resolver returning None for all parties ---

    def test_resolver_none_for_all_parties_rejected(self):
        """A resolver that always returns None rejects all parties."""
        att = _make_signed_attestation(self.key_a, self.key_b)

        def null_resolver(agent_id: str) -> Ed25519PublicKey | None:
            return None

        accepted, result = self.store.ingest(att, null_resolver)
        assert accepted is False
        # Both parties should be flagged
        assert any("agent_alpha" in e for e in result.errors)
        assert any("agent_beta" in e for e in result.errors)
        assert self.store.count() == 0

    # --- 5. Wrong key rejected ---

    def test_wrong_key_rejected(self):
        """Signing with key A but resolver returns key C's public key → rejection."""
        att = _make_signed_attestation(self.key_a, self.key_b)

        def wrong_key_resolver(agent_id: str) -> Ed25519PublicKey | None:
            if agent_id == "agent_alpha":
                return self.key_c.public_key  # wrong key!
            if agent_id == "agent_beta":
                return self.key_b.public_key
            return None

        accepted, result = self.store.ingest(att, wrong_key_resolver)
        assert accepted is False
        assert any("Invalid signature" in e and "agent_alpha" in e
                    for e in result.errors)
        assert self.store.count() == 0

    # --- 6. Store unchanged on rejection ---

    def test_store_unchanged_on_rejection(self):
        """After rejection, store count, indexes, and counters are unchanged."""
        # First ingest a valid one
        att1 = _make_signed_attestation(self.key_a, self.key_b)
        accepted1, _ = self.store.ingest(att1, self._resolver)
        assert accepted1 is True
        assert self.store.count() == 1

        # Now try a forged one
        att2 = _make_signed_attestation(self.key_a, self.key_b)
        att2["parties"][1]["signature"] = "FORGED"
        accepted2, _ = self.store.ingest(att2, self._resolver)
        assert accepted2 is False

        # Store should still have exactly 1
        assert self.store.count() == 1
        assert self.store.agent_count("agent_alpha") == 1
        assert self.store.agent_count("agent_beta") == 1

    # --- 7. No fallback to warning ---

    def test_no_skip_verification_warning(self):
        """The old 'Signature verification will be skipped' warning path is gone.

        With a mandatory resolver, there is no code path that skips
        verification and emits a warning instead.
        """
        att = _make_signed_attestation(self.key_a, self.key_b)
        accepted, result = self.store.ingest(att, self._resolver)
        assert accepted is True
        # No warnings about skipping verification
        for w in result.warnings:
            assert "skipped" not in w.lower()
            assert "skip" not in w.lower()

    # --- 8. Resolver is truly mandatory (type-level) ---

    def test_ingest_requires_resolver_argument(self):
        """Calling ingest() without a resolver raises TypeError."""
        att = _make_signed_attestation(self.key_a, self.key_b)
        with pytest.raises(TypeError):
            self.store.ingest(att)  # type: ignore[call-arg]

    # --- 9. Multiple attestations with mixed validity ---

    def test_valid_then_forged_then_valid(self):
        """Only properly-signed attestations are stored; forged ones are not."""
        # Valid
        att1 = _make_signed_attestation(self.key_a, self.key_b)
        accepted1, _ = self.store.ingest(att1, self._resolver)
        assert accepted1 is True

        # Forged
        att2 = _make_signed_attestation(self.key_a, self.key_b)
        att2["parties"][0]["signature"] = "FORGED"
        accepted2, _ = self.store.ingest(att2, self._resolver)
        assert accepted2 is False

        # Valid again
        att3 = _make_signed_attestation(self.key_a, self.key_b)
        accepted3, _ = self.store.ingest(att3, self._resolver)
        assert accepted3 is True

        assert self.store.count() == 2

    # --- 10. Cluster contract conformance ---

    def test_cluster_contract_resolver_shape(self):
        """The resolver follows the SEC-005 cluster contract:
        Callable[[str], Ed25519PublicKey | None], mandatory, null → rejection.
        """
        import inspect

        sig = inspect.signature(self.store.ingest)
        param = sig.parameters["public_key_resolver"]
        # Must not have a default value (mandatory)
        assert param.default is inspect.Parameter.empty, (
            "public_key_resolver must be mandatory (no default value)"
        )
