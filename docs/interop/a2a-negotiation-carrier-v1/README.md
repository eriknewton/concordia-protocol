# A2A negotiation carrier v1 fixture

`part.json` pins the candidate A2A carrier structure shared by the Python and
TypeScript prototypes. Both SDKs must parse it and must build an equal JSON
value from its embedded Concordia envelope.

This is a **carrier-shape fixture**, not a cryptographic conformance vector.
The `signature` value is an explicit placeholder. Carrier parsing performs
Concordia message-schema validation only; an application must still run the
normal Concordia signature, transcript, lifecycle, freshness, and
authorization verification before acting on the envelope.

The fixture and schema remain private prototype inputs. They are not evidence
that the extension has been filed, registered, or accepted by the A2A project.
