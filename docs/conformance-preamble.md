<!-- not-a-claim -->

## What this document covers

This page lists the conformance claims Concordia makes about itself and the check that enforces
each one. It is generated from `docs/claims.yaml`. A claim reaches this page only after something
exists that fails when the claim stops matching the repository. The suite behind it is specified
in `conformance/RUNNER_CONTRACT.md`, with more than a thousand vectors executed by two reference
runners in independent languages, and `README.md` carries a copy-paste verification block.

Three things sit outside it.

**Scoring.** Concordia defines how a negotiation record is formed, signed, and verified. How any
service turns those records into a reputation score, including which signals it weights, how it
decays them, and what it forgives, is outside this specification. This page makes no statement
about any scoring model, including Verascore's, a service written by the author of this
specification (see Disclosure below).

**Enforcement.** Concordia describes artifacts and how to verify them. Whether an agent runtime
confines what an agent can reach at execution time is a separate concern, handled by separate
software. Nothing in the specification requires any particular runtime.

**Stewardship.** As of 2026-08-01, Concordia has one editor, Erik Newton. This page describes the
specification's checkable properties and takes no position on how the specification should be
governed in future.

## Disclosure

The author of this specification also authors Verascore, a reputation service that consumes
Concordia records, and Sanctuary, an agent runtime. The reference Python SDK ships an optional,
off-by-default adapter for Verascore (`concordia.verascore`), disclosed in `SPEC.md` §9.6.7. No
conformance runner imports or invokes it, and the clean-room CI jobs assert the Concordia SDK
itself is absent from the runner's import path. Agent-profile vectors do carry legacy field names
beginning `verascore_`, with `reputation.example` as their sample provider: the SDK retains those
fields for signature compatibility with records issued before its provider-neutral reputation
fields landed, and the specification defines none of them.

None of this asks to be taken on trust. CI executes every check on this page from a fresh checkout
on every push, page generation fails if a referenced CI job disappears, and the adapter and field
statements above can be checked by grepping a clone.

## Where independence stands, as of 2026-08-01

Both shipped implementations, the Python SDK and the TypeScript SDK, are written by the author of
this specification. One separate implementation has byte-reproduced one published vector, and that
reproduction is recorded in `docs/interop/`. A full independent implementation of the
specification does not exist today. Closing that gap is deliberately cheap: the smallest profile
in `conformance/IMPLEMENTATIONS.md` is roughly 20 lines in most languages, and a reported
conformance run gets a registry row.

This section carries a date because it describes a state that is expected to change.

<!-- /not-a-claim -->
