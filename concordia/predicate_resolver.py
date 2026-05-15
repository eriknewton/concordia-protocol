"""Basic-tier predicate resolver for Concordia v0.6."""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from .predicate import Predicate, verify_predicate
from .canonicalization import canonicalize_predicate


class ResolverProtocolError(Exception):
    """Raised when predicate resolution fails due to transport or parse errors."""


@dataclass
class PredicateCacheEntry:
    predicate: Predicate
    etag: str | None = None
    canonical_sha256: str | None = None


@dataclass
class BasicHttpsResolver:
    """Resolve predicates from HTTPS URLs or configured local mirror objects."""

    base_url: str | None = None
    mirror: dict[str, dict[str, Any] | Predicate] | None = None
    timeout: float = 5.0
    check_signature: bool = True
    cache: dict[str, PredicateCacheEntry] = field(default_factory=dict)

    def __call__(self, predicate_id: str) -> Predicate | None:
        if predicate_id in self.cache:
            return self.cache[predicate_id].predicate
        if self.mirror is not None and predicate_id in self.mirror:
            return self._from_payload(predicate_id, self.mirror[predicate_id])
        if self.base_url is None:
            return None
        if not self.base_url.startswith("https://"):
            raise ResolverProtocolError("BasicHttpsResolver requires HTTPS base_url")
        url = self.base_url.rstrip("/") + "/" + urllib.parse.quote(predicate_id, safe="")
        request = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
                etag = response.headers.get("ETag")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise ResolverProtocolError(f"predicate fetch failed: {exc}") from exc
        except Exception as exc:
            raise ResolverProtocolError(f"predicate fetch failed: {exc}") from exc
        return self._from_payload(predicate_id, payload, etag=etag)

    def _from_payload(
        self,
        requested_id: str,
        payload: dict[str, Any] | Predicate,
        *,
        etag: str | None = None,
    ) -> Predicate:
        try:
            predicate = payload if isinstance(payload, Predicate) else Predicate.from_dict(payload)
            canonical_sha256 = hashlib.sha256(canonicalize_predicate(predicate)).hexdigest()
        except Exception as exc:
            raise ResolverProtocolError(f"predicate parse failed: {exc}") from exc
        if self.check_signature:
            result = verify_predicate(predicate)
            if not result.valid:
                raise ResolverProtocolError(
                    f"resolved predicate is invalid: {result.failure_reason}"
                )
        self.cache[requested_id] = PredicateCacheEntry(
            predicate=predicate,
            etag=etag,
            canonical_sha256=canonical_sha256,
        )
        return predicate


__all__ = ["BasicHttpsResolver", "PredicateCacheEntry", "ResolverProtocolError"]
