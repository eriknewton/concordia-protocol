# Concordia A2A Negotiation Extension - Working Draft

**Status:** Draft only. Not filed, sponsored, submitted, endorsed, or registered
with the A2A project. This document does not announce an external submission.

**Sequencing:** The IETF agreement-evidence work remains ahead of any external
A2A filing or public extension wording. Any external filing, message, or claim
about A2A adoption requires Erik's approval.

**Owner:** Erik Newton

## 1. Purpose and scope

This document is a bounded proposal for carrying Concordia negotiation messages
over A2A. It uses A2A's existing extension declaration and activation surfaces;
it does not propose a change to A2A core types, task states, authentication,
authorization, or transport bindings.

Concordia remains the authority for the negotiation envelope, lifecycle, offer
semantics, signatures, and transcript rules in `SPEC.md`. A2A remains the
communication and task-coordination layer. This draft defines only the seam
between them.

This is an integration draft, not an IETF submission and not a claim that an
official A2A extension exists.

## 2. Extension identity

The working extension URI is:

```text
https://concordiaprotocol.dev/a2a-ext/negotiation/v1
```

The URI is under Concordia's domain because no Concordia extension has been
filed with or sponsored into `a2aproject`. The URI is not under an official A2A
namespace and must not be described as registered or approved.

The URI versions independently of the Concordia wire identifier and the edition
of `SPEC.md`. A breaking change to the declaration or activation contract would
require a new URI version.

## 3. Agent Card declaration

A supporting agent declares the extension in the A2A `AgentCard`'s
`capabilities.extensions` array. `capabilities` is an `AgentCapabilities`
object, not an array of Concordia capability records:

```json
{
  "capabilities": {
    "extensions": [
      {
        "uri": "https://concordiaprotocol.dev/a2a-ext/negotiation/v1",
        "description": "Structured multi-attribute negotiation to agreement",
        "required": false,
        "params": {
          "roles": ["buyer", "seller"],
          "categories": ["electronics"],
          "resolution_mechanisms": ["split", "foa", "tradeoff"]
        }
      }
    ]
  }
}
```

`params` is an extension-specific advertisement of matching facets. It does
not change the Concordia offer schema and does not constitute a guarantee that
the agent will accept a particular negotiation.

`required` is `false` in this profile. A2A's flag means that a client must
understand and comply with an extension marked `true`; a request that does not
activate a required extension must be rejected. Concordia negotiation is
optional, so ordinary A2A requests remain possible for clients that do not
support this draft.

The current Concordia SDK emits this Agent Card fragment through
`RegisteredAgent.to_agent_card()`. It does not, by that fact alone, implement
an A2A server, request-header activation, or an interoperable carrier adapter.

## 4. Activation

Extensions are inactive by default. A client requests activation for an
individual request by listing the URI in the `A2A-Extensions` header:

```http
A2A-Extensions: https://concordiaprotocol.dev/a2a-ext/negotiation/v1
```

The agent activates the requested extension when supported and SHOULD echo the
activated URI in the response header. An absent echo means that this extension
was not activated; an implementation MUST NOT assume activation and proceed
with Concordia semantics.

The extension does not bypass the agent's existing authentication or
authorization checks. Any new data or behavior is untrusted input and remains
subject to those checks.

## 5. Proposed carrier semantics

The bounded working proposal is:

1. Carry one Concordia envelope as an A2A `Part` whose one content member is
   structured `data`. Earlier A2A SDKs called this shape `DataPart`; the current
   A2A protocol uses one `Part` type with a `data` member.
2. Keep the Concordia envelope's signature and canonicalization rules exactly
   as specified by `SPEC.md` §§4.1 and 9.2.
3. Correlate negotiation messages using Concordia's session identifier inside
   the signed envelope. Do not use an A2A task or context identifier as the
   negotiation identifier.
4. Keep carrier metadata outside the signed Concordia bytes. A failed,
   cancelled, or completed A2A task does not by itself retract, accept, or
   conclude a Concordia offer or session.

This preserves the distinction between A2A task lifecycle and Concordia
negotiation lifecycle. Multiple A2A tasks may carry messages for one Concordia
session, subject to the parties' authorization and implementation policy.

The private v1 prototype freezes this candidate wire shape for testing only:

```json
{
  "data": {
    "type": "https://concordiaprotocol.dev/a2a-ext/negotiation/v1#envelope",
    "version": "1",
    "envelope": { "concordia": "0.1.0", "type": "negotiate.offer" }
  },
  "metadata": {
    "https://concordiaprotocol.dev/a2a-ext/negotiation/v1": {
      "schema": "https://concordiaprotocol.dev/a2a-ext/negotiation/v1/schema/data-part.json"
    }
  },
  "mediaType": "application/vnd.concordia.negotiation+json"
}
```

The abbreviated `envelope` above is illustrative; a real carrier contains one
complete schema-valid signed Concordia envelope. `data` has exactly the three
members shown. `text`, `raw`, or `url` content members on the same Part are a
hard refusal. Other extension metadata may coexist outside the namespaced
Concordia metadata entry.

The carrier is interpreted only when the extension is active for the request.
Carrier-shaped bytes do not activate themselves. The signed envelope's
`session_id` is authoritative; A2A `taskId`, `contextId`, Message metadata, and
Artifact metadata remain outside the envelope and MUST NOT be copied into it.

The shared carrier-shape fixture is
`tests/fixtures/a2a-negotiation-carrier-v1/part.json`; the candidate schema is
`schemas/a2a_negotiation_part.schema.json`. Python and TypeScript reference
helpers build and parse the same JSON value without requiring either A2A SDK. The
parser validates the Concordia envelope's schema shape but does not substitute
for Concordia signature, transcript, lifecycle, or authorization verification.

This remains a private prototype, not a published wire commitment. External
review can still replace the candidate shape before any filing; after a public
v1 is published, a breaking carrier change requires a new extension URI.

## 6. Non-goals and claims boundary

This draft does not define or claim:

- an A2A registry entry, official extension status, or A2A project endorsement;
- payment, settlement, fulfillment, identity verification, or reputation
  scoring;
- end-to-end encryption of A2A or Concordia traffic;
- a change to A2A task state or task completion semantics; or
- an implementation of A2A transport support in the Concordia SDK.

The Concordia privacy, signing, and trust limits remain those stated in
`SPEC.md`. In particular, signed Concordia messages are not thereby encrypted,
and an A2A intermediary may read carrier content unless a separately specified
confidentiality mechanism is used.

## 7. Open decisions before external review

The following are deliberately unresolved:

1. Whether the candidate carrier shape and schema location become the public
   v1 contract after external review.
2. The final external conformance fixture bundle beyond the private positive
   fixture and fail-closed SDK regressions.
3. Whether the profile should carry all Concordia envelopes or only a bounded
   receipt/artifact subset in its first public revision.
4. The review and co-ownership path for any A2A-facing submission after the
   IETF lane is settled.

Until these decisions are resolved and Erik approves the wording, this file is
only a working draft. It must not be sent to an A2A issue, mailing list, or
external collaborator as a filed or endorsed proposal.
