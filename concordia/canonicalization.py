"""RFC 8785 JSON Canonicalization Scheme (JCS): named surface.

This module is the public, spec-named entry point for canonical JSON
serialization at the mandate layer (and any caller that wants the same
guarantees). The load-bearing implementation lives in
``concordia.signing.canonical_json`` and was originally introduced for
cross-repo signature parity with Sanctuary's TypeScript
``stableStringify`` (SEC-003). That implementation matches V8's
``JSON.stringify`` with sorted keys, which is the same guarantee
RFC 8785 specifies (number formatting per ECMA-262 §6.1.6.1.20, sorted
keys, no whitespace, raw UTF-8 outside the seven JSON escapes).

References:
  - RFC 8785: https://www.rfc-editor.org/rfc/rfc8785
  - ECMA-262 Number.prototype.toString:
    https://tc39.es/ecma262/#sec-numeric-types-number-tostring

The semantics this module guarantees:

1. Object keys sorted lexicographically by UTF-16 code units.
2. No whitespace between JSON tokens.
3. Strings serialized with the seven RFC 8259 mandatory escapes plus
   ``\\u00XX`` for control characters U+0000-U+001F; all other
   characters (including non-ASCII) emitted as raw UTF-8.
4. Numbers formatted per ECMA-262 ``Number::toString`` (RFC 8785 §3.2.2.3
   defers to ECMA-262), with special-float rejection (NaN, Infinity,
   ``-0.0``) raising ``ValueError``.
5. ``null`` for Python ``None``; booleans serialize as ``true`` / ``false``.

Convenience helpers in this module:

  - ``canonicalize_jcs(data)``: explicit JCS-name alias for the
    canonical serializer.
  - ``canonicalize_mandate(mandate)``: strips the ``signature`` field
    before serializing (the signing-input shape for both the existing
    issuer-signature check and the WP4 resolver-based verifier).
"""

from __future__ import annotations

from typing import Any

from .signing import canonical_json
from .models.mandate import Mandate


# JCS specification identifier: surfaces in audit trails / debug output
# so downstream consumers can confirm the canonicalization regime by
# string match rather than by guessing.
JCS_SPEC_ID = "RFC8785-JCS"


def canonicalize_jcs(data: Any) -> bytes:
    """Serialize ``data`` per RFC 8785 JSON Canonicalization Scheme.

    Returns UTF-8 encoded bytes suitable for digest / signature input.
    Rejects non-finite floats (NaN, Infinity, ``-0.0``) with
    ``ValueError`` because JCS cannot represent them deterministically.

    Delegates to ``concordia.signing.canonical_json``; this is the
    spec-named alias so callers that want JCS guarantees do not have
    to know the signing-module implementation detail.
    """
    # canonical_json accepts dicts but the underlying _stable_stringify
    # handles every JCS-supported type. Allow the same generality here
    # by feeding any value to the stable serializer via a dict wrapper
    # only when needed.
    if isinstance(data, dict):
        return canonical_json(data)
    # For non-dict roots, defer to the same underlying serializer by
    # importing the private helper. JCS roots may be any JSON value.
    from .signing import _stable_stringify, _check_no_special_floats

    _check_no_special_floats(data)
    return _stable_stringify(data).encode("utf-8")


def canonicalize_predicate(predicate: Any) -> bytes:
    """Return JCS canonical predicate signing bytes.

    Predicate signatures cover the full predicate object except the
    ``signature`` member. This helper accepts either a predicate-like object
    exposing ``to_dict()`` or a JSON-compatible mapping.
    """
    if hasattr(predicate, "to_dict"):
        predicate_dict = predicate.to_dict()
    else:
        predicate_dict = dict(predicate)
    predicate_dict.pop("signature", None)
    return canonicalize_jcs(predicate_dict)


def canonicalize_mandate(mandate: Mandate | dict[str, Any]) -> bytes:
    """Return the canonical bytes used for mandate signing / verification.

    Strips the ``signature`` field before serialization. The
    signature covers everything except itself, so the canonical bytes
    must omit it for both signing and verifying paths.

    Accepts either a ``Mandate`` instance or its dict serialization
    (the form ``Mandate.to_dict()`` produces). Output is byte-stable
    across the two input forms (``to_dict()`` is the round-trip
    canonical form).
    """
    if isinstance(mandate, Mandate):
        mandate_dict = mandate.to_dict()
    else:
        mandate_dict = dict(mandate)
    mandate_dict.pop("signature", None)
    return canonicalize_jcs(mandate_dict)
