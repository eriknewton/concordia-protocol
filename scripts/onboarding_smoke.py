#!/usr/bin/env python3
"""Installed-package onboarding smoke for the public Concordia surface.

Documented adopter path:
    pip install '.[server]'
    python scripts/onboarding_smoke.py

Run after a non-editable install. Do not use the dev extra for this smoke.
"""

from __future__ import annotations

import contextlib
import copy
import importlib
import io
import sys
from collections.abc import Callable
from typing import Any, cast


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _check_signature_round_trip() -> None:
    from concordia import KeyPair, sign_message, verify_signature

    key_pair = KeyPair.generate()
    message: dict[str, Any] = {
        "kind": "onboarding-smoke",
        "counter": 1,
        "nested": {"ok": True},
    }

    signature = sign_message(message, key_pair)

    _assert(
        verify_signature(message, signature, key_pair.public_key) is True,
        "fresh Ed25519 signature did not verify",
    )


def _check_tamper_rejected() -> None:
    from concordia import KeyPair, sign_message, verify_signature

    key_pair = KeyPair.generate()
    message = {"kind": "onboarding-smoke", "counter": 1}
    signature = sign_message(message, key_pair)
    tampered = dict(message)
    tampered["counter"] = 2

    _assert(
        verify_signature(tampered, signature, key_pair.public_key) is False,
        "tampered message verified successfully",
    )


def _check_verification_material_round_trip() -> None:
    from concordia import KeyPair, public_key_from_b64url, sign_message, verify_signature

    key_pair = KeyPair.generate()
    message = {"kind": "third-party-verify", "counter": 3}
    signature = sign_message(message, key_pair)
    material = key_pair.verification_material()
    padded = material["public_key_b64url"]
    unpadded = padded.rstrip("=")

    reconstructed_padded = public_key_from_b64url(padded)
    reconstructed_unpadded = public_key_from_b64url(unpadded)

    _assert(
        verify_signature(message, signature, reconstructed_padded) is True,
        "padded verification material did not reconstruct a verifying key",
    )
    _assert(
        verify_signature(message, signature, reconstructed_unpadded) is True,
        "unpadded verification material did not reconstruct a verifying key",
    )


def _check_attestation_round_trip() -> None:
    from concordia import Agent, BasicOffer, generate_attestation, verify_attestation

    seller = Agent("onboarding_seller")
    buyer = Agent("onboarding_buyer")
    session = seller.open_session(
        counterparty=buyer.identity,
        terms={"price": {"type": "numeric", "label": "Price", "unit": "USD"}},
    )
    buyer.join_session(session)
    buyer.accept_session()
    seller.send_offer(
        BasicOffer(terms={"price": {"value": 100}}),
        reasoning="Opening public API smoke.",
    )
    buyer.accept_offer(reasoning="Accepted public API smoke.")

    key_pairs = {
        seller.agent_id: seller.key_pair,
        buyer.agent_id: buyer.key_pair,
    }
    public_keys = {
        agent_id: key_pair.public_key for agent_id, key_pair in key_pairs.items()
    }
    attestation = generate_attestation(
        session,
        key_pairs,
        category="onboarding.smoke",
        value_range="100-500_USD",
    )

    result = verify_attestation(attestation, public_keys)
    _assert(result.valid is True, f"attestation did not verify: {result.errors}")

    tampered = copy.deepcopy(attestation)
    tampered["parties"][0]["behavior"]["offers_made"] += 1
    tamper_result = verify_attestation(tampered, public_keys)
    _assert(
        tamper_result.valid is False,
        "party behavior tamper verified successfully",
    )


def _check_mcp_tools_registered() -> None:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        mcp_server = importlib.import_module("concordia.mcp_server")

    tool_manager = getattr(mcp_server.mcp, "_tool_manager", None)
    _assert(tool_manager is not None, "FastMCP tool manager is missing")
    list_tools = getattr(tool_manager, "list_tools", None)
    _assert(callable(list_tools), "FastMCP tool manager cannot list tools")

    list_tools_func = cast(Callable[[], list[Any]], list_tools)
    tools = list_tools_func()
    by_name: dict[str, Any] = {}
    for tool in tools:
        name = getattr(tool, "name", None)
        if isinstance(name, str):
            by_name[name] = tool

    _assert(len(by_name) > 0, "no MCP tools are registered")

    provider_tools = {
        "concordia_session_receipt_envelope",
        "concordia_reputation_report",
    }
    for tool_name in provider_tools:
        _assert(tool_name in by_name, f"{tool_name} is not registered")
        description = getattr(by_name[tool_name], "description", "")
        _assert(isinstance(description, str), f"{tool_name} has no description")
        folded = description.lower()
        for fragment in ("explicit", "provider", "no default", "provider-neutral"):
            _assert(
                fragment in folded,
                f"{tool_name} description does not mention {fragment!r}",
            )


def _check_top_level_canonicalize_import() -> None:
    from concordia import canonicalize_jcs

    canonical = canonicalize_jcs({"b": 2, "a": 1})
    _assert(canonical == b'{"a":1,"b":2}', "canonicalize_jcs did not sort keys")


CHECKS: tuple[tuple[str, Callable[[], None]], ...] = (
    ("signature round trip", _check_signature_round_trip),
    ("tamper rejected", _check_tamper_rejected),
    ("verification material round trip", _check_verification_material_round_trip),
    ("attestation round trip", _check_attestation_round_trip),
    ("MCP tools registered", _check_mcp_tools_registered),
    ("top-level canonicalize_jcs import", _check_top_level_canonicalize_import),
)


def main() -> int:
    for name, check in CHECKS:
        try:
            check()
        except Exception as exc:
            print(
                f"CHECK {name}: FAIL ({type(exc).__name__}: {exc})",
                file=sys.stderr,
            )
            return 1
        print(f"CHECK {name}: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
