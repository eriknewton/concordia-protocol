#!/usr/bin/env python3
"""Concordia "Hello World" — the simplest possible negotiation."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from concordia import Agent, BasicOffer, generate_attestation

# Create two agents (Ed25519 keys are generated automatically)
seller = Agent("seller")
buyer = Agent("buyer")

# Seller opens a negotiation with one term: price
session = seller.open_session(
    counterparty=buyer.identity,
    terms={"price": {"value": 100.00, "currency": "USD"}},
)
buyer.join_session(session)
buyer.accept_session()

# Buyer counters at $80
buyer.send_counter(BasicOffer(terms={"price": {"value": 80.00, "currency": "USD"}}))

# Seller accepts
seller.accept_offer()

# Done — print the result
print(f"State: {session.state.value}")
print(f"Agreed price: $80.00")
print(f"Messages exchanged: {len(session.transcript)}")

# Generate attestation
att = generate_attestation(session, {"seller": seller.key_pair, "buyer": buyer.key_pair})
print(f"Attestation outcome: {att['outcome']['status']}")
print(f"Transcript hash: {att['transcript_hash'][:40]}...")
