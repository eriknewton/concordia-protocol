# Retained third-party artifacts

Artifacts authored elsewhere, retained byte-verbatim so a cross-check has a
fixed thing to check against. Nothing here is a Concordia fixture, and nothing
here is rewritten, reformatted, or normalized on the way in.

This directory is deliberately outside `docs/interop/`. The interop gate
(`scripts/claims/clean_room_verify.py docs/interop/`) requires every published
`sha256:` field to be re-derivable from bytes in the same directory, which is
the right rule for artifacts this repository authors and the wrong rule for
artifacts it merely retains: a third-party artifact can legitimately name a
digest whose preimage the author never published.

| Directory | Author | What it is |
|-----------|--------|------------|
| [`giskard09-decision-binding-context-digest-v1/`](giskard09-decision-binding-context-digest-v1/) | giskard09 | The `decision_binding_ref` `context_digest` conformance vectors from `argentum-core`, announced in [A2A Discussion #1734](https://github.com/a2aproject/A2A/discussions/1734#discussioncomment-17896767). Cross-checked against Concordia's RFC 8785 canonicalizer by `tests/test_a2a_1734_context_digest_interop.py`. |
| [`chopmob-cloud-jcs-edge-v1/`](chopmob-cloud-jcs-edge-v1/) | chopmob-cloud (AlgoVoi) | The `jcs_edge_v1` RFC 8785 canonicalization edge-case vectors from `algovoi-jcs-conformance-vectors`, announced in [A2A Issue #1140](https://github.com/a2aproject/A2A/issues/1140). Retained with the upstream Apache-2.0 `LICENSE` and `NOTICE`. Cross-checked against Concordia's RFC 8785 canonicalizer by `tests/test_a2a_1140_jcs_edge_interop.py`, converting the one-time 2026-07-19 10/10 reproduction into a standing check. |

Each directory carries a `PROVENANCE.json` recording the source repository,
path, commit, retrieval date, and a SHA-256 over the retained bytes. The digest
is asserted in CI.

**Why the digest pin matters.** Failure mode it guards against: a silently
re-fetched or hand-edited copy still cross-checks cleanly against itself, so
the comparison reports agreement while proving nothing. The pin is what makes
"we recomputed their published values" a statement about their bytes rather
than about ours.

Authorship and copyright of the retained files remain with their authors. This
repository claims neither, and a passing cross-check is never third-party
verification of Concordia: it is agreement between two independently authored
artifacts.
