"""v0.7 alpha gate: pyproject.toml + concordia.__version__ at 0.7.0a0.

The package's __version__ stays in lockstep so envelope.py
(which embeds ``concordia.__version__`` into envelope payloads via
``session_protocol_version``) emits v0.7.0a0 on the wire.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import concordia


_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _read_pyproject_version() -> str:
    """Read ``version = "x.y.z"`` from pyproject.toml without depending on tomllib."""
    text = _PYPROJECT.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, flags=re.MULTILINE)
    assert match is not None, "pyproject.toml must declare a project version"
    return match.group(1)


class TestPyprojectVersion:
    def test_pyproject_at_0_7_0a0(self):
        assert _read_pyproject_version() == "0.7.0a0"

    def test_module_version_at_0_7_0a0(self):
        assert concordia.__version__ == "0.7.0a0"

    def test_module_and_pyproject_in_lockstep(self):
        assert concordia.__version__ == _read_pyproject_version()

    def test_envelope_session_protocol_version_at_0_7_0a0(self):
        """Envelope payload embeds concordia.__version__; verify on the wire."""
        from concordia import (
            Agent,
            BasicOffer,
            SessionState,
            generate_attestation,
        )
        from concordia.envelope import build_trust_evidence_envelope
        from concordia.signing import KeyPair

        seller = Agent("seller_v06_pv")
        buyer = Agent("buyer_v06_pv")
        terms = {"price": {"value": 10.0, "currency": "USD"},
                 "qty": {"value": 1}}
        session = seller.open_session(counterparty=buyer.identity, terms=terms)
        buyer.join_session(session)
        buyer.accept_session()
        seller.send_offer(BasicOffer(terms={
            "price": {"value": 10.0, "currency": "USD"},
            "qty": {"value": 1},
        }))
        buyer.accept_offer()
        assert session.state == SessionState.AGREED

        att = generate_attestation(session, {
            seller.identity.agent_id: seller.key_pair,
            buyer.identity.agent_id: buyer.key_pair,
        })
        envelope = build_trust_evidence_envelope(
            att,
            KeyPair.generate(),
            provider_did="did:web:example.org:provider",
            provider_kid="key-1",
            subject_did="did:web:example.org:subject",
        )
        assert envelope["payload"]["session_protocol_version"] == "0.7.0a0"
