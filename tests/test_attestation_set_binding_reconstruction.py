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
    """AGENTS.md rule 8 (adversarial-complexity), asserted as an OPERATION
    COUNT, never as wall-clock time in any form: a millisecond ceiling
    encodes one machine's speed (the JS sibling's round-12 ceiling failed on
    the CI runners with no regression anywhere), and a wall-clock n-versus-2n
    ratio of two separately scheduled minima is still a flaky oracle (JIT
    warm-up, contention, throttling and GC can push a linear ratio past 3 or
    hide a quadratic term; Codex P2, 2026-09-17 delta-13 gate). A count of
    visits is the same integer on every machine, so the assertions here are
    exact bounds, read through the test-only observer hook
    ``concordia.attestation._operation_observer``.

    Two shapes, because they reach different code (Codex P2, 2026-09-16
    delta-12 gate: the round-12 test built only the orphan shape, whose
    rejection is explained before ``_find_cycle`` runs, so the finder itself
    was never exercised at scale):
      - a genuine n-message prev_hash CYCLE, built with a monkeypatched
        ``compute_hash`` (the technique of TestCycleDetectionAndTheClosing
        Invariant, since a real cycle is a SHA-256 preimage search): no root,
        no orphan, no fork, so ``_reconstruct_single_chain`` reaches
        ``_find_cycle`` with every message in ``predecessor_of`` and the
        finder walks the whole cycle;
      - the rootless reverse-ordered chain ending in ONE orphan, with real
        hashing: the exact input that drove the old O(n^2) finder (Codex P1,
        delta-11 gate), now rejected on the orphan alone before the finder,
        whose cost is one digest per presented message.
    Mirrors the describe block of the same name in
    js-sdk/tests/attestation-set-binding-reconstruction.test.ts.
    """

    # Upper bound on finder visits per presented message, from the finder's
    # own structure: every node is appended to exactly one walk's ``path``
    # (a later walk stops at a node an earlier walk resolved), which is n
    # visits, and every walk ends in exactly one terminating visit (a resolved
    # node, a root, or the revisit that closes a cycle); a walk appends at
    # least its own start node, so there are at most n walks, hence at most
    # n more terminating visits: 2n in all.
    VISITS_PER_MESSAGE = 2
    # The count for 2n against the count for n: exactly 2 for a linear
    # finder, about 4 for the old quadratic one. 2.5 leaves room for the
    # constant terminating visit(s) without admitting a quadratic term.
    DOUBLING_BOUND = 2.5

    @staticmethod
    def _cycle_digest(index: int) -> str:
        # index + 1, so index 0's digest is not the all-zero GENESIS_HASH
        # (which would make its successor a root). Must match cycleDigest in
        # the JS sibling.
        return f"sha256:{index + 1:064x}"

    @classmethod
    def _cycle_fake_hash(cls, message: dict[str, Any]) -> str:
        return cls._cycle_digest(int(str(message["id"])[1:]))

    @classmethod
    def _build_genuine_cycle(cls, n: int) -> list[dict[str, Any]]:
        """c_i links to c_{i-1} and c_0 links to c_{n-1}: one n-cycle, no root."""
        return [{"id": f"c{i}", "prev_hash": cls._cycle_digest((i - 1) % n)} for i in range(n)]

    @staticmethod
    def _expected_cycle_diagnosis(n: int) -> str:
        # _find_cycle iterates predecessor_of in insertion (transcript index)
        # order, so the walk starts at index 0 and follows prev_hash:
        # 0, n-1, n-2, ..., 1, then closes on 0. Must match
        # expectedCycleDiagnosis in the JS sibling.
        walk = [0, *range(n - 1, 0, -1), 0]
        return (
            "transcript contains a prev_hash cycle through messages "
            f"{', '.join(str(index) for index in walk)}: prev_hash links point to "
            "each other with no root; a chain has exactly one message without "
            "prev_hash"
        )

    @staticmethod
    def _build_rootless_reverse_chain(n: int) -> list[dict[str, Any]]:
        """Build ``n`` real, hash-linked messages M_0..M_{n-1} where M_0's
        prev_hash is garbage (an orphan: matches no presented digest) and
        M_i (i>=1) legitimately links to M_{i-1} via the REAL compute_hash --
        no monkeypatched digest lookup, so this exercises the exact
        production hashing path, not a topology stand-in. The returned
        transcript presents them in REVERSE (M_{n-1} first, M_0 last): this
        is what made the old finder's insertion order put the ENTIRE
        (n-1)-length chain behind the very first outer-loop ``start``.
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

    @staticmethod
    def _count_verify(
        monkeypatch: pytest.MonkeyPatch, transcript: list[dict[str, Any]]
    ) -> tuple[int, int, list[str]]:
        """Verify once and return ``(finder_visits, digests, errors)``: finder
        visits through the observer hook, digests by wrapping whatever
        ``compute_hash`` the module currently holds (the real one, or the
        cycle fake a test installed first); both wrappers delegate, so the
        verdict is unchanged."""
        import concordia.attestation as attestation_module

        finder_visits = 0
        digests = 0

        def observe(operation: str) -> None:
            nonlocal finder_visits
            if operation == "cycle_finder_visit":
                finder_visits += 1

        inner_hash = attestation_module.compute_hash

        def counting_hash(message: dict[str, Any]) -> str:
            nonlocal digests
            digests += 1
            return inner_hash(message)

        monkeypatch.setattr("concordia.attestation._operation_observer", observe)
        monkeypatch.setattr("concordia.attestation.compute_hash", counting_hash)
        receipt = {
            "concordia_attestation": "0.5.0",
            "chain_head": GENESIS_HASH,
            "message_count": len(transcript),
        }
        _state, errors = evaluate_receipt_set_binding(receipt, transcript)
        return finder_visits, digests, errors

    def test_genuine_cycle_reaches_find_cycle_and_walks_it_in_linear_visits(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("concordia.attestation.compute_hash", self._cycle_fake_hash)
        n = 32_000

        small_visits, small_digests, small_errors = self._count_verify(
            monkeypatch, self._build_genuine_cycle(n)
        )
        large_visits, large_digests, large_errors = self._count_verify(
            monkeypatch, self._build_genuine_cycle(2 * n)
        )

        # The finder walked the whole cycle: only _find_cycle produces this
        # diagnosis, and it names every index.
        assert small_errors == [self._expected_cycle_diagnosis(n)]
        assert large_errors == [self._expected_cycle_diagnosis(2 * n)]
        # One digest per presented message on the way in.
        assert (small_digests, large_digests) == (n, 2 * n)
        # The finder's cost, as visits: linear in n by the bound derived
        # above, and doubling with n, never quadrupling.
        assert 0 < small_visits <= self.VISITS_PER_MESSAGE * n, small_visits
        assert 0 < large_visits <= self.VISITS_PER_MESSAGE * 2 * n, large_visits
        assert large_visits <= self.DOUBLING_BOUND * small_visits, (small_visits, large_visits)

    def test_orphan_chain_never_reaches_find_cycle_and_costs_one_digest_per_message(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        n = 16_000

        small_visits, small_digests, small_errors = self._count_verify(
            monkeypatch, self._build_rootless_reverse_chain(n)
        )
        large_visits, large_digests, large_errors = self._count_verify(
            monkeypatch, self._build_rootless_reverse_chain(2 * n)
        )

        # The orphan alone explains the rejection; the gate keeps the finder
        # out of it entirely, so its visit count is zero at both sizes.
        assert (small_visits, large_visits) == (0, 0)
        assert small_errors == [
            f"transcript message {n - 1} is an orphan: its prev_hash matches no presented message"
        ]
        assert large_errors == [
            f"transcript message {2 * n - 1} is an orphan: its prev_hash matches no "
            f"presented message"
        ]
        # The whole cost of this shape is one digest per presented message.
        assert (small_digests, large_digests) == (n, 2 * n)


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

    # Cap BEFORE any element is read (Codex P1, 2026-09-16 delta-12 gate; the
    # JS sibling pins the same order against its boundary snapshot). An
    # element canonical_json cannot serialize, planted at index 0, is the
    # observable: over the cap it must never be reached; at the cap it must
    # be, proving the cap is the only thing that stood before it.
    @staticmethod
    def _transcript_with_poison_at_zero(n: int) -> list[dict[str, Any]]:
        transcript: list[dict[str, Any]] = [{"id": f"m{i}"} for i in range(n)]
        transcript[0] = {"id": object()}
        return transcript

    def test_cap_is_decided_before_any_element_is_read(self) -> None:
        n = MAX_SET_BINDING_TRANSCRIPT_MESSAGES + 1
        receipt = {"concordia_attestation": "0.5.0", "chain_head": GENESIS_HASH, "message_count": n}

        state, errors = evaluate_receipt_set_binding(
            receipt, self._transcript_with_poison_at_zero(n)
        )

        assert state == "error"
        assert errors == [
            f"transcript has {n} messages, exceeding the maximum of "
            f"{MAX_SET_BINDING_TRANSCRIPT_MESSAGES}"
        ]

    def test_at_the_cap_the_elements_are_read(self) -> None:
        n = MAX_SET_BINDING_TRANSCRIPT_MESSAGES
        receipt = {"concordia_attestation": "0.5.0", "chain_head": GENESIS_HASH, "message_count": n}

        with pytest.raises(TypeError):
            evaluate_receipt_set_binding(receipt, self._transcript_with_poison_at_zero(n))


    # Exactly ONE ``__len__`` read of the caller's list (Codex P1, 2026-09-17
    # delta-13 gate: ``not transcript`` was a first ``__len__`` call and the
    # cap's ``len(transcript)`` a second, so a list subclass could answer
    # the two differently). The JS sibling pins the same single read with a
    # Proxy counting ``length`` gets.
    class _LenCountingList(list):  # type: ignore[type-arg]
        def __init__(self, items: list[dict[str, Any]]) -> None:
            # list.__init__ extends from the plain list's items without
            # calling THIS class's __len__; the counter starts after it.
            super().__init__(items)
            self.len_calls = 0

        def __len__(self) -> int:
            self.len_calls += 1
            return super().__len__()

    def test_over_cap_path_reads_the_length_exactly_once(self) -> None:
        n = MAX_SET_BINDING_TRANSCRIPT_MESSAGES + 1
        transcript = self._LenCountingList([{"id": f"m{i}"} for i in range(n)])
        receipt = {"concordia_attestation": "0.5.0", "chain_head": GENESIS_HASH, "message_count": n}

        state, errors = evaluate_receipt_set_binding(receipt, transcript)

        assert state == "error"
        assert errors == [
            f"transcript has {n} messages, exceeding the maximum of "
            f"{MAX_SET_BINDING_TRANSCRIPT_MESSAGES}"
        ]
        assert transcript.len_calls == 1

    def test_accept_path_reads_the_length_exactly_once(
        self, agreed_receipt: tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]
    ) -> None:
        attestation, transcript, _public_keys = agreed_receipt
        counting = self._LenCountingList(transcript)

        state, errors = evaluate_receipt_set_binding(attestation, counting)

        assert (state, errors) == ("bound", [])
        assert counting.len_calls == 1


class TestTranscriptCapIsCrossPinned:
    """Four independent literals carry the cap (the two SDKs and the two
    conformance reference runners, which import no SDK). This test and its
    JS sibling each read all four plus the shared fixture
    tests/fixtures/set_binding_limits.json, so a one-sided edit fails CI in
    both languages (Codex P2, 2026-09-16 delta-12 gate)."""

    REPO = Path(__file__).resolve().parent.parent

    @classmethod
    def _literal_in(cls, rel_path: str, pattern: str) -> int:
        import re

        source = (cls.REPO / rel_path).read_text(encoding="utf-8")
        match = re.search(pattern, source, re.MULTILINE)
        assert match is not None, f"{rel_path}: MAX_SET_BINDING_TRANSCRIPT_MESSAGES not found"
        return int(match.group(1).replace("_", ""))

    def test_cap_equals_the_fixture_the_js_sdk_and_both_runners(self) -> None:
        fixture = json.loads(
            (self.REPO / "tests" / "fixtures" / "set_binding_limits.json").read_text(encoding="utf-8")
        )
        assert MAX_SET_BINDING_TRANSCRIPT_MESSAGES == fixture["max_set_binding_transcript_messages"]
        assert MAX_SET_BINDING_TRANSCRIPT_MESSAGES == self._literal_in(
            "js-sdk/src/attestation/attestation.ts",
            r"^export const MAX_SET_BINDING_TRANSCRIPT_MESSAGES = ([\d_]+);$",
        )
        assert MAX_SET_BINDING_TRANSCRIPT_MESSAGES == self._literal_in(
            "conformance/reference-runner-js/runner.mjs",
            r"^const MAX_SET_BINDING_TRANSCRIPT_MESSAGES = ([\d_]+);$",
        )
        assert MAX_SET_BINDING_TRANSCRIPT_MESSAGES == self._literal_in(
            "conformance/reference-runner/runner.py",
            r"^MAX_SET_BINDING_TRANSCRIPT_MESSAGES = ([\d_]+)$",
        )


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
