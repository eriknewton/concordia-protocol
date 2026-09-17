"""Set-binding verification over a reconstructed transcript chain (SPEC §9.6.5b).

A receipt's ``chain_head`` and ``message_count`` describe a transcript. This
module covers the two conditions under which a verifier may credit that
description: a transcript has to be supplied at all, and the supplied messages
have to rebuild into exactly one chain from their ``prev_hash`` links, whatever
order the presenter chose for them.
"""

from __future__ import annotations

import copy
import hashlib
import json
import time
from pathlib import Path
from typing import Any

import pytest

from concordia import Agent, BasicOffer, generate_attestation, verify_attestation
from concordia.attestation import (
    MAX_SET_BINDING_TRANSCRIPT_MESSAGES,
    evaluate_receipt_set_binding,
)
from concordia.message import GENESIS_HASH, compute_hash
from concordia.signing import canonical_json


@pytest.fixture
def agreed_receipt() -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    """An agreed session's attestation, its transcript, and its public keys."""
    seller = Agent("seller_setbinding")
    buyer = Agent("buyer_setbinding")
    terms = {"price": {"value": 150.00, "currency": "USD"}}
    session = seller.open_session(counterparty=buyer.identity, terms=terms)
    buyer.join_session(session)
    buyer.accept_session()
    seller.send_offer(
        BasicOffer(terms={"price": {"value": 135.00, "currency": "USD"}}),
        reasoning="Fair price for the condition",
    )
    buyer.accept_offer(reasoning="Looks good")

    key_pairs = {
        seller.identity.agent_id: seller.key_pair,
        buyer.identity.agent_id: buyer.key_pair,
    }
    attestation = generate_attestation(session, key_pairs)
    public_keys = {
        agent_id: key_pair.public_key for agent_id, key_pair in key_pairs.items()
    }
    return attestation, list(session.transcript), public_keys


class TestTranscriptIsRequired:
    def test_no_transcript_is_unestablished_not_bound(self, agreed_receipt):
        attestation, _transcript, _keys = agreed_receipt

        state, errors = evaluate_receipt_set_binding(attestation)

        assert state == "fields_present_unverified"
        assert errors == []

    def test_no_transcript_still_verifies_and_warns(self, agreed_receipt):
        attestation, _transcript, public_keys = agreed_receipt

        result = verify_attestation(attestation, public_keys)

        assert result.valid is True
        assert result.set_binding_state == "fields_present_unverified"
        assert any("set binding is unestablished" in w for w in result.warnings)

    def test_malformed_fields_without_a_transcript_still_error(self, agreed_receipt):
        attestation, _transcript, _keys = agreed_receipt
        attestation = copy.deepcopy(attestation)
        attestation["chain_head"] = "sha256:NOTLOWERHEX"

        state, errors = evaluate_receipt_set_binding(attestation)

        assert state == "error"
        assert any("requires chain_head" in error for error in errors)

    def test_supplied_transcript_binds(self, agreed_receipt):
        attestation, transcript, _keys = agreed_receipt

        state, errors = evaluate_receipt_set_binding(attestation, transcript)

        assert state == "bound"
        assert errors == []


class TestChainReconstruction:
    def test_presented_order_does_not_decide_the_chain(self, agreed_receipt):
        attestation, transcript, _keys = agreed_receipt
        shuffled = [transcript[-1], *transcript[:-1]]

        state, errors = evaluate_receipt_set_binding(attestation, shuffled)

        assert state == "bound", errors

    def test_fork_is_rejected(self, agreed_receipt):
        attestation, transcript, _keys = agreed_receipt
        attestation = copy.deepcopy(attestation)
        sibling = copy.deepcopy(transcript[1])
        sibling["id"] = f"{sibling['id']}_fork"
        sibling["prev_hash"] = compute_hash(transcript[0])
        presented = [*transcript, sibling]
        attestation["message_count"] = len(presented)

        state, errors = evaluate_receipt_set_binding(attestation, presented)

        assert state == "error"
        assert any("forks" in error for error in errors)

    def test_orphan_is_rejected(self, agreed_receipt):
        attestation, transcript, _keys = agreed_receipt
        attestation = copy.deepcopy(attestation)
        orphan = copy.deepcopy(transcript[1])
        orphan["id"] = f"{orphan['id']}_orphan"
        orphan["prev_hash"] = "sha256:" + ("ab" * 32)
        presented = [transcript[0], orphan, *transcript[1:]]
        attestation["message_count"] = len(presented)

        state, errors = evaluate_receipt_set_binding(attestation, presented)

        assert state == "error"
        assert any("orphan" in error for error in errors)

    def test_two_messages_without_prev_hash_are_rejected(self, agreed_receipt):
        attestation, transcript, _keys = agreed_receipt
        attestation = copy.deepcopy(attestation)
        second_root = copy.deepcopy(transcript[0])
        second_root["id"] = f"{second_root['id']}_root"
        second_root["prev_hash"] = GENESIS_HASH
        presented = [transcript[0], second_root, *transcript[1:]]
        attestation["message_count"] = len(presented)

        state, errors = evaluate_receipt_set_binding(attestation, presented)

        assert state == "error"
        assert any("root messages" in error for error in errors)

    def test_no_root_is_rejected_as_the_orphan_it_actually_is(self, agreed_receipt):
        """Dropping the root does not exercise the bare "no root message"
        fallback: the message that pointed at the dropped root becomes an
        ORPHAN (its prev_hash now matches no presented message), and that
        orphan error is recorded before the rootless check ever runs. Cycle
        detection now runs only when it can change the diagnosis (2026-09-16
        delta-11 gate, Codex P1): with the orphan error already present,
        _find_cycle is skipped and the generic "no root message" text is
        never appended alongside it, so the orphan is the ONLY, and the
        more specific, reported reason. (Fail-before against 5176dfc: the
        old code ran _find_cycle and appended "no root message" as a second,
        redundant error unconditionally; this test used to assert on that
        redundant text instead of the primary orphan diagnosis.)
        """
        attestation, transcript, _keys = agreed_receipt

        state, errors = evaluate_receipt_set_binding(attestation, transcript[1:])

        assert state == "error"
        assert errors == [
            "transcript message 0 is an orphan: its prev_hash matches no presented message"
        ]

    def test_explicit_null_prev_hash_is_not_a_root(self, agreed_receipt):
        attestation, transcript, _keys = agreed_receipt
        presented = copy.deepcopy(transcript)
        presented[0]["prev_hash"] = None

        state, errors = evaluate_receipt_set_binding(attestation, presented)

        assert state == "error"
        assert any("explicit null prev_hash" in error for error in errors)

    def test_shuffled_valid_chain_still_binds(self, agreed_receipt):
        """A valid chain presented out of order reconstructs and binds.

        Reconstruction reads prev_hash links, never the array position, so
        this must pass under any permutation of a genuinely valid chain, not
        only the single rotation covered by
        test_presented_order_does_not_decide_the_chain.
        """
        attestation, transcript, _keys = agreed_receipt
        assert len(transcript) >= 3
        permutation = [len(transcript) - 2, *range(len(transcript) - 2), len(transcript) - 1]
        shuffled = [transcript[index] for index in permutation]

        state, errors = evaluate_receipt_set_binding(attestation, shuffled)

        assert state == "bound", errors

    def test_equal_size_substitution_is_rejected(self, agreed_receipt):
        attestation, transcript, _keys = agreed_receipt
        substitute = copy.deepcopy(transcript[1])
        substitute["id"] = f"{substitute['id']}_substitute"
        presented = [transcript[0], substitute, *transcript[2:]]

        assert len(presented) == attestation["message_count"]
        assert compute_hash(presented[-1]) == attestation["chain_head"]
        state, errors = evaluate_receipt_set_binding(attestation, presented)

        assert state == "error"
        assert errors

    def test_duplicate_message_is_rejected(self, agreed_receipt):
        attestation, transcript, _keys = agreed_receipt
        attestation = copy.deepcopy(attestation)
        presented = [transcript[0], copy.deepcopy(transcript[0]), *transcript[1:]]
        attestation["message_count"] = len(presented)

        state, errors = evaluate_receipt_set_binding(attestation, presented)

        assert state == "error"
        assert any("more than once" in error for error in errors)

    def test_links_under_the_signature_stripped_convention_are_rejected(
        self, agreed_receipt
    ):
        attestation, transcript, _keys = agreed_receipt
        attestation = copy.deepcopy(attestation)
        relinked = [copy.deepcopy(transcript[0])]
        for message in transcript[1:]:
            variant = copy.deepcopy(message)
            stripped = {
                key: value
                for key, value in relinked[-1].items()
                if key != "signature"
            }
            digest = hashlib.sha256(canonical_json(stripped)).hexdigest()
            variant["prev_hash"] = f"sha256:{digest}"
            relinked.append(variant)
        attestation["chain_head"] = compute_hash(relinked[-1])

        assert len(relinked) == attestation["message_count"]
        state, errors = evaluate_receipt_set_binding(attestation, relinked)

        assert state == "error"
        assert any("orphan" in error for error in errors)

    def test_message_that_is_not_an_object_fails_closed(self, agreed_receipt):
        attestation, transcript, _keys = agreed_receipt

        state, errors = evaluate_receipt_set_binding(
            attestation, [*transcript[:-1], "not-a-message"]
        )

        assert state == "error"
        assert any("not a JSON object" in error for error in errors)


class TestCycleDetectionAndTheClosingInvariant:
    """A cycle among prev_hash links is named 'cycle', not 'no root message'.

    A genuinely mutual prev_hash cycle cannot be constructed with the real
    compute_hash: closing the loop needs message A's digest to equal what
    message B points at AND message B's digest to equal what A points at
    simultaneously, and compute_hash covers the WHOLE message including its
    own prev_hash field -- solving that pair of equations is exactly as hard
    as inverting SHA-256 (a hash preimage search), for any cycle length.
    These tests patch concordia.attestation.compute_hash with a fixed
    id-to-digest lookup so the GRAPH topology (which is what the fix under
    test reasons about) can be constructed directly, without needing a real
    hash preimage. The patched function is exercised through the public
    evaluate_receipt_set_binding entry point, not through a private helper,
    so this still proves the SDK-level behavior a caller observes.
    """

    DIGESTS = {
        "chain_1": "a" * 64,
        "chain_2": "b" * 64,
        "chain_3": "c" * 64,
        "chain_4": "d" * 64,
        "chain_5": "e" * 64,
        "cycle_a": "f" * 64,
        "cycle_b": "0" * 63 + "1",
    }

    @classmethod
    def _fake_hash(cls, message: dict[str, Any]) -> str:
        return f"sha256:{cls.DIGESTS[message['id']]}"

    @classmethod
    def _linked_chain(cls, length: int) -> list[dict[str, Any]]:
        chain: list[dict[str, Any]] = [{"id": "chain_1", "from": {"agent_id": "alice"}}]
        for position in range(2, length + 1):
            predecessor_id = f"chain_{position - 1}"
            chain.append(
                {
                    "id": f"chain_{position}",
                    "from": {"agent_id": "alice"},
                    "prev_hash": f"sha256:{cls.DIGESTS[predecessor_id]}",
                }
            )
        return chain

    def test_pure_two_cycle_is_rejected_and_named(self, monkeypatch):
        monkeypatch.setattr("concordia.attestation.compute_hash", self._fake_hash)
        cycle_a = {
            "id": "cycle_a",
            "from": {"agent_id": "alice"},
            "prev_hash": f"sha256:{self.DIGESTS['cycle_b']}",
        }
        cycle_b = {
            "id": "cycle_b",
            "from": {"agent_id": "alice"},
            "prev_hash": f"sha256:{self.DIGESTS['cycle_a']}",
        }
        receipt = {
            "concordia_attestation": "0.5.0",
            "chain_head": GENESIS_HASH,
            "message_count": 2,
        }

        state, errors = evaluate_receipt_set_binding(receipt, [cycle_a, cycle_b])

        assert state == "error"
        # Exact string, not just "contains 'cycle'" (Codex P2, 2026-09-16
        # delta-11 gate): cycle_a is transcript index 0, cycle_b is index 1;
        # cycle_a's prev_hash points at cycle_b and cycle_b's prev_hash
        # points back at cycle_a, so _find_cycle's walk from index 0 visits
        # [0, 1] and closes back on 0 -- named "0, 1, 0" in walk order.
        assert errors == [
            "transcript contains a prev_hash cycle through messages 0, 1, 0: "
            "prev_hash links point to each other with no root; a chain has "
            "exactly one message without prev_hash"
        ]
        # Not the generic wording: the whole point of naming the cycle is
        # that a reader (or a caller matching on substring) can tell this
        # apart from an ordinary rootless malformed transcript.
        assert not any(error == "transcript has no root message" for error in errors)

    def test_cycle_beside_a_real_chain_is_rejected_and_named(self, monkeypatch):
        """The walk-length closing invariant's own regression test (item 6).

        A genuinely valid five-message chain, plus two extra messages that
        link only to each other: the walk from the root reconstructs the
        five-message chain and never reaches the two extras, so the
        ``len(chain) != len(transcript)`` closing invariant is the ONLY
        thing that refuses crediting the five-message chain as the receipt's
        (larger, `message_count`-mismatched) claimed set. Verified by hand
        for this round: commenting out that check (and its
        ``return [], errors``) makes THIS test fail -- the function then
        returns the five-message ``chain`` as a successful reconstruction,
        and this test's own `state == "error"` / `"cycle" in errors`
        assertions fail because the surrounding
        ``evaluate_receipt_set_binding`` instead reports a plain
        `message_count`/`chain_head` mismatch against the 7-message receipt,
        never reaching this function's cycle-naming at all. That confirms
        the check is load-bearing, not merely present.
        """
        monkeypatch.setattr("concordia.attestation.compute_hash", self._fake_hash)
        cycle_a = {
            "id": "cycle_a",
            "from": {"agent_id": "alice"},
            "prev_hash": f"sha256:{self.DIGESTS['cycle_b']}",
        }
        cycle_b = {
            "id": "cycle_b",
            "from": {"agent_id": "alice"},
            "prev_hash": f"sha256:{self.DIGESTS['cycle_a']}",
        }
        transcript = [*self._linked_chain(5), cycle_a, cycle_b]
        receipt = {
            "concordia_attestation": "0.5.0",
            "chain_head": GENESIS_HASH,
            "message_count": len(transcript),
        }

        state, errors = evaluate_receipt_set_binding(receipt, transcript)

        assert state == "error"
        # Exact string (Codex P2, 2026-09-16 delta-11 gate): the walk from
        # the root (chain_1..chain_5) visits indices 0-4 and stops, leaving
        # cycle_a (index 5) and cycle_b (index 6) as the leftover; the
        # leftover walk starts at 5, visits [5, 6], and closes back on 5.
        assert errors == [
            "transcript contains a prev_hash cycle through messages 5, 6, 5 "
            "beside the reconstructed chain: the walk from the root visits "
            "5 of 7 presented messages"
        ]


class TestCycleDetectionIsLinearNotQuadratic:
    """AGENTS.md rule 8 (adversarial-complexity): a rootless, reverse-ordered
    chain ending in ONE orphan drives ``_reconstruct_single_chain`` into the
    ``not roots`` branch without any real hash cycle, and it is exactly this
    shape -- not a cycle -- that the OLD ``_find_cycle`` (``node in path`` /
    ``path.index(node)``, each an O(len(path)) scan) walked in O(n^2) before
    finally hitting the ``node not in predecessor_of`` break (Codex P1,
    2026-09-16 delta-11 gate). Measured against HEAD 5176dfc with real
    ``compute_hash`` (no mocking): 8k/16k/32k messages took 0.16s/0.54s/
    1.95s -- consistent with quadratic growth (~4x per doubling), not
    linear. Post-fix (position-map ``_find_cycle`` PLUS the gate that skips
    calling it at all once the orphan error already explains the
    rejection): 0.06s/0.12s/0.24s -- consistent with linear growth (~2x per
    doubling).
    """

    @staticmethod
    def _build_rootless_reverse_chain(n: int) -> list[dict[str, Any]]:
        """Build ``n`` real, hash-linked messages M_0..M_{n-1} where M_0's
        prev_hash is garbage (an orphan: matches no presented digest) and
        M_i (i>=1) legitimately links to M_{i-1} via the REAL compute_hash --
        no monkeypatched digest lookup, so this exercises the exact
        production hashing path, not a topology stand-in. The returned
        transcript presents them in REVERSE (M_{n-1} first, M_0 last): this
        is what makes predecessor_of's insertion order put the ENTIRE
        (n-1)-length chain behind the very first outer-loop `start`, so one
        walk pays for the whole thing instead of the cost being spread
        (and mostly skipped by the `state`-resolved short-circuit) across
        many short walks.
        """
        messages: list[dict[str, Any]] = [
            {"id": "m0", "from": {"agent_id": "adversary"}, "prev_hash": f"sha256:{'f' * 64}"}
        ]
        for i in range(1, n):
            prev_digest = compute_hash(messages[i - 1])
            messages.append(
                {"id": f"m{i}", "from": {"agent_id": "adversary"}, "prev_hash": prev_digest}
            )
        return list(reversed(messages))

    def test_32k_rootless_reverse_orphan_chain_verifies_linearly(self) -> None:
        n = 32_000
        transcript = self._build_rootless_reverse_chain(n)
        receipt = {
            "concordia_attestation": "0.5.0",
            "chain_head": GENESIS_HASH,
            "message_count": n,
        }

        start = time.perf_counter()
        state, errors = evaluate_receipt_set_binding(receipt, transcript)
        elapsed = time.perf_counter() - start

        assert state == "error"
        # The gate (this round's second half of item 2) means the orphan
        # alone explains the rejection; _find_cycle never runs for this
        # shape, so this is the SAME diagnosis a caller got before the fix,
        # just without the wasted O(n^2) (now-moot, since skipped) walk.
        assert errors == [
            f"transcript message {n - 1} is an orphan: its prev_hash matches no presented message"
        ]
        # Ceiling = 1.0s: comfortably above the measured post-fix linear
        # runtime (~0.24s at n=32000, itself already >4x headroom over a
        # slower CI box) while well below the measured pre-fix quadratic
        # runtime (~1.95s at n=32000, this class's own docstring) -- a
        # regression back to O(n^2) trips this, ordinary CI variance does
        # not.
        assert elapsed < 1.0, f"expected linear-time verification, took {elapsed:.3f}s"


class TestTranscriptSizeCap:
    """MAX_SET_BINDING_TRANSCRIPT_MESSAGES (2026-09-16 delta-11 gate, Codex
    P1's second half): a transcript longer than any transcript a Concordia
    relay session could ever legitimately produce is rejected by name
    before any per-message hashing or chain-walking work runs.
    """

    def test_transcript_over_the_cap_is_rejected_by_name_before_any_walk(self) -> None:
        # Each element only needs to be a dict for the length check to fire
        # before reconstruction ever inspects one -- no real prev_hash
        # chain, and no compute_hash call, is needed to prove the cap runs
        # first.
        n = MAX_SET_BINDING_TRANSCRIPT_MESSAGES + 1
        transcript = [{"id": f"m{i}"} for i in range(n)]
        receipt = {"concordia_attestation": "0.5.0", "chain_head": GENESIS_HASH, "message_count": n}

        state, errors = evaluate_receipt_set_binding(receipt, transcript)

        assert state == "error"
        assert errors == [
            f"transcript has {n} messages, exceeding the maximum of "
            f"{MAX_SET_BINDING_TRANSCRIPT_MESSAGES}"
        ]

    def test_transcript_at_the_cap_is_not_rejected_for_size(self, agreed_receipt) -> None:
        # At exactly the cap, the size check must not fire; whatever this
        # transcript is rejected for (it is far too short to be a real
        # message_count-matching chain) has to be a DIFFERENT reason.
        _attestation, transcript, _keys = agreed_receipt
        padded = transcript + [{"id": f"pad{i}"} for i in range(MAX_SET_BINDING_TRANSCRIPT_MESSAGES - len(transcript))]
        receipt = {
            "concordia_attestation": "0.5.0",
            "chain_head": GENESIS_HASH,
            "message_count": len(padded),
        }

        state, errors = evaluate_receipt_set_binding(receipt, padded)

        assert state == "error"
        assert not any("exceeding the maximum" in error for error in errors)


class TestSharedConformanceVectors:
    """The Python verifier's verdict on the vectors the JS SDK also executes.

    The same file is read by js-sdk/tests/attestation-set-binding-reconstruction
    .test.ts, so a divergence between the two SDKs shows up as one of these
    assertions failing on one side only.
    """

    VECTORS = Path(__file__).resolve().parent.parent / "conformance" / "vectors"
    REJECT_IDS = tuple(
        f"mut-synthetic-receipt-set-reconstruction-000{index}" for index in range(1, 9)
    )

    def _pair(
        self, section: str, vector_id: str
    ) -> tuple[dict[str, Any], list[dict[str, Any]] | None]:
        path = self.VECTORS / section / f"{vector_id}.json"
        vector = json.loads(path.read_text(encoding="utf-8"))
        return vector["input"]["receipt"], vector["input"].get("messages")

    def test_positive_vector_binds(self):
        receipt, messages = self._pair(
            "positive", "pos-synthetic-receipt-set-binding-reconstruction"
        )

        assert evaluate_receipt_set_binding(receipt, messages) == ("bound", [])

    @pytest.mark.parametrize("vector_id", REJECT_IDS)
    def test_reject_vector_is_not_bound(self, vector_id):
        receipt, messages = self._pair("mutation", vector_id)

        state, _errors = evaluate_receipt_set_binding(receipt, messages)

        assert state != "bound"
        if messages is None:
            assert state == "fields_present_unverified"
        else:
            assert state == "error"

    @pytest.mark.parametrize("vector_id", REJECT_IDS)
    def test_reject_vector_defeats_a_digest_and_count_comparison(self, vector_id):
        """Each reject vector must be one a weak verifier would have accepted.

        A vector a digest-and-count comparison already refuses proves nothing
        about reconstruction, so the guard would be untested by it.
        """
        receipt, messages = self._pair("mutation", vector_id)
        if messages is None:
            return

        assert receipt["message_count"] == len(messages)
        assert receipt["chain_head"] == compute_hash(messages[-1])
