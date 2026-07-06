# Concordia RFCs

Substantive changes to the Concordia Protocol (new message types, offer
shapes, state-machine transitions, attestation semantics, bridge contracts, or
any change to the wire format) go through a lightweight RFC (Request For
Comments) process so the design and its tradeoffs are recorded before code
lands.

Small bug fixes, documentation edits, and internal refactors do **not** need an
RFC. Open a normal pull request for those. When in doubt, open an issue first
and a maintainer will tell you whether an RFC is warranted.

## How to file an RFC

1. Copy the template below into a new file in this directory named
   `NNNN-short-title.md`, where `NNNN` is the next unused four-digit number
   (zero-padded, e.g. `0001-conditional-offer-revocation.md`).
2. Fill in every section. Keep it concise; link to the SPEC sections you are
   changing.
3. Open a pull request that adds the RFC file. The pull request thread is where
   discussion happens.

## Lifecycle

An RFC moves through these states. Record the current state in the `Status`
field of the RFC's front matter.

- **Draft**: authored and opened as a pull request; under active revision.
- **Discussion**: open for maintainer and community review on the pull
  request thread. The author iterates in response to feedback.
- **Accepted**: a maintainer has approved the design. The RFC is merged and may
  now be implemented. Implementation lands in follow-up pull requests that
  reference the RFC number.
- **Rejected**: the design will not be adopted. The RFC is merged (or closed)
  with a short rationale so the decision is discoverable and not re-litigated.

Superseded RFCs stay in this directory for the historical record; mark them
`Superseded by NNNN` in the `Status` field.

## Template

```markdown
# RFC NNNN: <short title>

- **Status:** Draft
- **Author(s):** <name or handle>
- **Created:** YYYY-MM-DD
- **SPEC sections touched:** <e.g. SPEC 4.2, 9.6>

## Summary

One paragraph: what does this change, in plain terms?

## Motivation

What problem does this solve? Who hits it, and how often? What does the
protocol get wrong or fail to express today? Why is the status quo not good
enough?

## Design

The proposed change in detail. Cover the wire format, message/offer/state
semantics, validation rules, and any backward-compatibility or migration
concerns. Include concrete examples. Note the security and privacy
implications: Concordia attestations must never carry raw deal terms, and any
new signed surface must specify its canonical-serialization and verification
rules.

## Alternatives

Other approaches considered and why they were not chosen. "Do nothing" is a
valid alternative to weigh.

## Open Questions

Anything unresolved that reviewers should weigh in on.
```
