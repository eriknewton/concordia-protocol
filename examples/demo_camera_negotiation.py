#!/usr/bin/env python3
"""Concordia Protocol Demo — Used Camera Negotiation

Two agents negotiate the sale of a used Canon EOS R5 camera.
Demonstrates the full negotiation lifecycle with real Ed25519 signing,
hash-chain transcript integrity, schema validation, and attestation
generation.

Run:
    python examples/demo_camera_negotiation.py
"""

import json
import sys
from pathlib import Path

# Ensure the package is importable when run from the repo root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from concordia import (
    Agent,
    BasicOffer,
    Flexibility,
    PreferenceSignal,
    ResolutionMechanism,
    SessionState,
    TimingConfig,
    generate_attestation,
    is_valid_attestation,
    is_valid_message,
    validate_chain,
    verify_signature,
)

# ── Styling helpers ──────────────────────────────────────────────────

BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def header(text: str) -> None:
    print(f"\n{BOLD}{'═' * 60}{RESET}")
    print(f"{BOLD}  {text}{RESET}")
    print(f"{BOLD}{'═' * 60}{RESET}\n")


def step(agent_name: str, action: str, detail: str = "") -> None:
    color = BLUE if "Seller" in agent_name else GREEN
    print(f"  {color}{BOLD}{agent_name}{RESET} → {action}")
    if detail:
        print(f"    {DIM}{detail}{RESET}")


def status(label: str, value: str, ok: bool = True) -> None:
    mark = f"{GREEN}✓{RESET}" if ok else f"{RED}✗{RESET}"
    print(f"  {mark} {label}: {value}")


# ── Demo ─────────────────────────────────────────────────────────────

def main() -> None:
    header("CONCORDIA PROTOCOL DEMO — Used Camera Negotiation")

    # ── 1. Create agents ─────────────────────────────────────────────
    print(f"{BOLD}1. Creating agents with Ed25519 key pairs{RESET}\n")

    seller = Agent("agent_seller_sf_01", principal_id="seller_principal")
    buyer = Agent("agent_buyer_oak_42", principal_id="buyer_principal")

    print(f"  Seller: {seller.agent_id}")
    print(f"    Public key: {seller.key_pair.public_key_b64()[:32]}...")
    print(f"  Buyer:  {buyer.agent_id}")
    print(f"    Public key: {buyer.key_pair.public_key_b64()[:32]}...")

    # ── 2. Define the term space and open session ────────────────────
    header("2. Seller opens negotiation session")

    terms = {
        "item": {
            "value": "Canon EOS R5",
            "description": "Used Canon EOS R5, ~15K shutter count, excellent condition",
        },
        "price": {
            "value": 2400.00,
            "currency": "USD",
        },
        "condition": {
            "value": "like_new",
            "enum": ["new", "like_new", "good", "fair", "poor"],
        },
        "delivery_method": {
            "value": "shipping",
            "enum": ["shipping", "local_pickup"],
        },
        "delivery_date": {
            "value": "2026-04-01",
            "type": "date",
        },
        "warranty": {
            "value": False,
            "type": "boolean",
        },
    }

    timing = TimingConfig(session_ttl=3600, offer_ttl=300, max_rounds=10)

    session = seller.open_session(
        counterparty=buyer.identity,
        terms=terms,
        timing=timing,
        reasoning=(
            "I'm selling my Canon EOS R5. It's in excellent condition with only "
            "15K shutter actuations. I'm asking $2,400 which I believe is fair "
            "for the condition. Open to negotiation on delivery details."
        ),
    )

    step("Seller", "negotiate.open", f"Session: {session.session_id}")
    step("Seller", f"State: {session.state.value}", "6 terms defined")
    print(f"    Terms: item, price, condition, delivery_method, delivery_date, warranty")

    # ── 3. Buyer accepts the session ─────────────────────────────────
    header("3. Buyer accepts the session")

    buyer.join_session(session)
    buyer.accept_session(
        reasoning="Interested in the Canon R5. Let's discuss terms."
    )

    step("Buyer", "negotiate.accept_session")
    status("State", session.state.value)

    # ── 4. Buyer shares preference signals ───────────────────────────
    header("4. Buyer shares preference signals")

    buyer.signal(
        PreferenceSignal(
            priority_ranking=["price", "condition", "delivery_date"],
            flexibility={
                "delivery_method": Flexibility.VERY_FLEXIBLE,
                "warranty": Flexibility.SOMEWHAT_FLEXIBLE,
                "delivery_date": Flexibility.SOMEWHAT_FLEXIBLE,
            },
        ),
        reasoning=(
            "Price is my top priority, but I also care about condition. "
            "I'm flexible on delivery logistics."
        ),
    )

    step("Buyer", "negotiate.signal", "Priority: price > condition > delivery_date")

    # ── 5. Buyer makes a counter-offer ───────────────────────────────
    header("5. Buyer counters with $2,000")

    counter1 = BasicOffer(terms={
        "item": {"value": "Canon EOS R5"},
        "price": {"value": 2000.00, "currency": "USD"},
        "condition": {"value": "like_new"},
        "delivery_method": {"value": "local_pickup"},
        "delivery_date": {"value": "2026-03-28", "type": "date"},
        "warranty": {"value": False},
    })
    buyer.send_counter(
        counter1,
        reasoning=(
            "I'd like to offer $2,000. I can do local pickup which saves you "
            "shipping hassle and costs, and I can come get it this Saturday. "
            "That said, $2,400 is above market for a used R5 with 15K actuations."
        ),
    )

    step("Buyer", "negotiate.counter", "$2,400 → $2,000 (local pickup)")

    # ── 6. Seller counters at $2,250 ─────────────────────────────────
    header("6. Seller counters at $2,250")

    counter2 = BasicOffer(terms={
        "item": {"value": "Canon EOS R5"},
        "price": {"value": 2250.00, "currency": "USD"},
        "condition": {"value": "like_new"},
        "delivery_method": {"value": "local_pickup"},
        "delivery_date": {"value": "2026-03-29", "type": "date"},
        "warranty": {"value": False},
    })
    seller.send_counter(
        counter2,
        reasoning=(
            "I appreciate the quick pickup offer. I can come down to $2,250 — "
            "that's a $150 concession. This camera has very low shutter count and "
            "includes the original box and all accessories. How about Sunday for "
            "the handoff? That gives me time to do a final sensor clean."
        ),
    )

    step("Seller", "negotiate.counter", "$2,400 → $2,250 (concession: $150)")

    # ── 7. Buyer accepts the offer ───────────────────────────────────
    header("7. Buyer accepts the final offer")

    buyer.accept_offer(
        offer_id=counter2.offer_id,
        reasoning=(
            "Deal. $2,250 for a like-new R5 with local pickup on Sunday works "
            "for me. Looking forward to it."
        ),
    )

    step("Buyer", "negotiate.accept", f"Offer {counter2.offer_id}")
    status("State", session.state.value, session.state == SessionState.AGREED)

    # ── 8. Verify transcript integrity ───────────────────────────────
    header("8. Verifying transcript integrity")

    # Hash chain validation
    chain_valid = validate_chain(session.transcript)
    status("Hash chain", "intact" if chain_valid else "BROKEN", chain_valid)

    # Signature verification on every message
    key_map = {
        seller.agent_id: seller.key_pair.public_key,
        buyer.agent_id: buyer.key_pair.public_key,
    }
    all_sigs_valid = True
    for i, msg in enumerate(session.transcript):
        sender_id = msg["from"]["agent_id"]
        pub = key_map[sender_id]
        sig = msg["signature"]
        valid = verify_signature(msg, sig, pub)
        if not valid:
            all_sigs_valid = False
        status(
            f"Message {i+1} ({msg['type']})",
            f"sig {'valid' if valid else 'INVALID'}",
            valid,
        )

    # Schema validation on every message
    all_schema_valid = True
    for i, msg in enumerate(session.transcript):
        valid = is_valid_message(msg)
        if not valid:
            all_schema_valid = False
    status("All messages schema-valid", str(all_schema_valid), all_schema_valid)

    print(f"\n  Transcript: {len(session.transcript)} messages, "
          f"{session.round_count} offer/counter rounds")

    # ── 9. Generate attestation ──────────────────────────────────────
    header("9. Generating reputation attestation")

    key_pairs = {
        seller.agent_id: seller.key_pair,
        buyer.agent_id: buyer.key_pair,
    }

    attestation = generate_attestation(
        session,
        key_pairs,
        category="electronics.cameras.mirrorless",
        value_range="1000-5000_USD",
        resolution_mechanism=ResolutionMechanism.DIRECT,
    )

    # Validate against schema
    att_valid = is_valid_attestation(attestation)
    status("Attestation schema-valid", str(att_valid), att_valid)

    # Display attestation summary
    print(f"\n  {BOLD}Attestation Summary:{RESET}")
    print(f"    ID:         {attestation['attestation_id']}")
    print(f"    Session:    {attestation['session_id']}")
    print(f"    Outcome:    {attestation['outcome']['status']}")
    print(f"    Rounds:     {attestation['outcome']['rounds']}")
    print(f"    Duration:   {attestation['outcome']['duration_seconds']}s")
    print(f"    Resolution: {attestation['outcome']['resolution_mechanism']}")
    print(f"    Category:   {attestation['meta']['category']}")
    print(f"    Value:      {attestation['meta']['value_range']}")

    print(f"\n  {BOLD}Party Behavior:{RESET}")
    for party in attestation["parties"]:
        b = party["behavior"]
        print(f"    {party['agent_id']} ({party['role']}):")
        print(f"      Offers made:     {b['offers_made']}")
        print(f"      Concessions:     {b['concessions']}")
        print(f"      Magnitude:       {b['concession_magnitude']:.2%}")
        print(f"      Reasoning:       {b['reasoning_provided']}")
        print(f"      Signals shared:  {b['signals_shared']}")

    print(f"\n  Transcript hash: {attestation['transcript_hash'][:40]}...")

    # ── 10. Print the full agreement ─────────────────────────────────
    header("10. Final Agreement")

    print(f"  {BOLD}Agreed Terms:{RESET}")
    agreed_terms = counter2.terms
    for term_id, term_val in agreed_terms.items():
        val = term_val.get("value", term_val)
        unit = term_val.get("currency", "")
        print(f"    {term_id}: {val} {unit}".rstrip())

    print(f"\n  Signed by:")
    for party in attestation["parties"]:
        sig_preview = party["signature"][:32] + "..."
        print(f"    {party['agent_id']}: {sig_preview}")

    # ── Summary ──────────────────────────────────────────────────────
    header("Negotiation Complete")

    all_ok = chain_valid and all_sigs_valid and all_schema_valid and att_valid
    if all_ok:
        print(f"  {GREEN}{BOLD}All verifications passed.{RESET}")
        print(f"  The agreement is cryptographically signed, the transcript is")
        print(f"  hash-chain verified, and the attestation is schema-valid.")
    else:
        print(f"  {RED}{BOLD}Some verifications failed.{RESET}")
        sys.exit(1)

    print()


if __name__ == "__main__":
    main()
