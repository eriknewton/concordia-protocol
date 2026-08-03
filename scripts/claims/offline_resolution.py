#!/usr/bin/env python3
"""Prove predicate resolution succeeds from a local mirror with network blocked."""

from __future__ import annotations

import sys
import urllib.request
from collections.abc import Callable
from typing import Any

from concordia.predicate import sign_predicate, verify_predicate
from concordia.predicate_resolver import BasicHttpsResolver
from concordia.signing import KeyPair

PREDICATE_ID = "urn:concordia:predicate:offline_resolution_claim"


def signed_predicate() -> Any:
    return sign_predicate(
        {
            "predicate_id": PREDICATE_ID,
            "type": "urn:concordia:predicate-type:authority_gate:v1",
            "authority": "urn:concordia:authority:policy",
            "issuer": "did:web:issuer.example#key-1",
            "subject": "did:web:subject.example#agent",
            "condition": {"result": "satisfied"},
            "issued_at": "2026-05-14T00:00:00Z",
            "expires_at": "2027-06-14T00:00:00Z",
            "references": [],
            "algorithm": "EdDSA",
            "status": "active",
            "signature": "",
        },
        KeyPair.generate(),
    )


def main() -> int:
    original_urlopen: Callable[..., Any] = urllib.request.urlopen

    def blocked_urlopen(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("network access attempted during offline predicate resolution")

    urllib.request.urlopen = blocked_urlopen
    poison_installed = urllib.request.urlopen is blocked_urlopen
    if not poison_installed:
        print("[FAIL] urllib.request.urlopen poison was not installed", file=sys.stderr)
        return 1

    try:
        predicate = signed_predicate()
        resolver = BasicHttpsResolver(
            base_url="https://issuer.example/predicates",
            mirror={predicate.predicate_id: predicate},
        )
        result = verify_predicate(predicate.predicate_id, resolver=resolver)
        if not result.valid:
            print(
                "[FAIL] offline mirror predicate verification failed: "
                f"{result.failure_reason}",
                file=sys.stderr,
            )
            return 1
        if predicate.predicate_id not in resolver.cache:
            print("[FAIL] offline mirror resolution did not populate resolver cache", file=sys.stderr)
            return 1
    except Exception as exc:
        print(f"[FAIL] offline mirror resolution failed: {exc}", file=sys.stderr)
        return 1
    finally:
        urllib.request.urlopen = original_urlopen

    print(
        "[OK] predicate resolved and verified from local mirror with "
        "urllib.request.urlopen blocked"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
