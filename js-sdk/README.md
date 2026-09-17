# @concordia-protocol/sdk

TypeScript reference implementation of the Concordia Protocol: signed agreement
primitives for autonomous agents. Agents propose, counter, accept, and commit,
and every step carries an Ed25519 signature over canonical JSON, so an outcome
can be verified by anyone without trusting the agent that produced it.

This package is byte-for-byte compatible with the Python reference
implementation (`concordia-protocol` on PyPI): the same input produces the same
canonical bytes, the same signature, and the same validation result in both
languages.

Status: alpha. Apache-2.0. Spec and Python SDK at
<https://github.com/eriknewton/concordia-protocol>.

## Install

```sh
npm install @concordia-protocol/sdk
```

Requires Node.js 20 or newer. The package ships ESM and CommonJS builds plus
TypeScript types, so both `import` and `require` work.

## Quickstart

Generate a key pair, sign an authority predicate, and verify it. The built-in
`urn:concordia:predicate-type:authority_gate:v1` profile is registered when the
module loads, so no profile registration call is needed.

```ts
import { generateKeyPair, signPredicate, verifyPredicate, verify } from '@concordia-protocol/sdk';

const keyPair = generateKeyPair();

const signed = signPredicate(
  {
    predicate_id: 'urn:concordia:predicate:quickstart_authority',
    type: 'urn:concordia:predicate-type:authority_gate:v1',
    authority: 'urn:concordia:authority:procurement',
    issuer: 'did:web:issuer.example#key-1',
    subject: 'did:web:buyer.example#agent',
    condition: { result: 'satisfied' },
    issued_at: '2026-05-14T00:00:00Z',
    expires_at: '2126-06-14T00:00:00Z',
    references: [],
    algorithm: 'EdDSA',
    status: 'active',
    signature: '',
  },
  keyPair,
);

const semanticResult = verifyPredicate(signed);
console.log(semanticResult.valid); // true

const publicKey = keyPair.publicKeyBytes();
const signatureOnly = verify(signed.toDict(), signed.signature, publicKey);
console.log(signatureOnly); // true
```

`verifyPredicate` checks the predicate schema, built-in type profile, signature,
lifecycle, subject binding, and references. The low-level `verify()` call checks
only the Ed25519 signature over canonical JSON using the public key. It is the
portable path for a third party that has an artifact, its signature, and the
issuer public key; it needs no process-local predicate profile registration.

Predicate ids must start with `urn:concordia:predicate:`. Built-in predicate
types use full URNs such as `urn:concordia:predicate-type:authority_gate:v1`;
bare shorthand such as `authority_gate` is not accepted.

## Low-Level Object Signing

You can also sign and verify any Concordia object directly. The signature is
taken over the canonical JSON of the object, so any tampering is detected.

```ts
import { generateKeyPair, sign, verify } from '@concordia-protocol/sdk';

const keyPair = generateKeyPair();

const offer = {
  type: 'offer',
  terms: { price: 1200, currency: 'USD', quantity: 10 },
  from: 'agent-a',
};

const signature = sign(offer, keyPair); // URL-safe base64 Ed25519 signature
console.log(verify(offer, signature, keyPair)); // true

// Any change to the signed object fails verification.
const tampered = { ...offer, terms: { price: 1 } };
console.log(verify(tampered, signature, keyPair)); // false
```

`sign` excludes a top-level `signature` field before signing, so you can attach
the signature to the same object and re-verify it later. `verify` never throws
on a bad signature or key; it returns `false`, matching the Python verifier.

## Canonical JSON

Signatures are deterministic because they sign canonical bytes (RFC 8785 JCS),
not whatever key order your object literal happened to use.

```ts
import { canonicalizeJcs } from '@concordia-protocol/sdk';

// Same content, different key order, identical canonical bytes.
const a = canonicalizeJcs({ b: 2, a: 1 });
const b = canonicalizeJcs({ a: 1, b: 2 });
console.log(a.equals(b)); // true
```

**Accepted input.** `canonicalizeJcs` accepts a value iff, recursively at
every nesting level, one of the following holds:

- a **primitive**, by JSON type: `null`; a boolean; a string with no
  unpaired UTF-16 surrogate; or a finite number that is not `-0` and, when
  it is integer-valued and `String(value)` prints it in plain decimal, lies
  within `Number.MAX_SAFE_INTEGER` (an integer-valued number at or beyond
  1e21 prints in exponential form and is accepted as a float, which is why
  `parseJsonStrict` / `fromJsonText` refuse the plain-decimal literal in the
  source text before it is parsed). `undefined`, a function, a symbol and a
  bigint are refused;
- an **Array** (`Array.isArray`) whose own prototype is exactly this realm's
  `Array.prototype`, AND whose own property descriptors, observed once
  through `Object.getOwnPropertyDescriptors`, hold an enumerable data
  descriptor at every index below `length`: an accessor element throws, and
  a sparse hole throws;
- an **object** (checked only when `Array.isArray` is false, never as a
  fallback pair) whose own prototype is exactly `null` or exactly this
  realm's `Object.prototype`, AND whose own string-keyed properties,
  observed the same way, are enumerable data descriptors only: an accessor
  property throws; a non-enumerable property and a symbol-keyed property
  are omitted, never read.

The prototype test alone is not the predicate: a same-realm plain object
with an enumerable accessor, or a sparse array, satisfies the prototype test
and still throws. Nothing else is inspected: not a hop count, not
`Object.prototype.toString`, not the value's construction history. An
accepted value is snapshotted once, keeping only its own enumerable,
non-accessor, string-keyed data.

Because the check is a prototype-identity test and nothing more, it is
satisfied by values `JSON.parse` cannot itself produce. **Proxies are not
detected:** a Proxy whose `getPrototypeOf` and `getOwnPropertyDescriptors`
traps present a same-realm plain object or Array is snapshotted as the
plain data those traps returned, once; the SDK does not attempt to detect
Proxies. A builtin or class instance (`Date`, `Map`, `new Foo()`) is
refused as constructed, but is accepted once its own prototype has been
retargeted to `null` or this realm's `Object.prototype`, and is then
snapshotted as whatever own enumerable data it carries -- the check cannot
see, and does not claim to see, what the value used to be. Values from
another realm (an iframe, a `node:vm` context) fail the same identity test
-- a cross-realm `Object.prototype` is a distinct object -- and must be
re-parsed here (`fromJsonText(text)` is provided) rather than retargeted by
hand. The library does not defend against replacement of this realm's
builtins; a hostile same-realm environment is outside every JavaScript
library's contract.

```ts
import { fromJsonText, canonicalizeJcs } from '@concordia-protocol/sdk';

// A value from another realm must be re-parsed here before canonicalizing.
const foreignJsonText = JSON.stringify(valueFromAnotherRealm);
canonicalizeJcs(fromJsonText(foreignJsonText));
```

## What this SDK provides

The public API surface (see `src/index.ts`) covers:

- **Canonical JSON:** `canonicalizeJcs` and `canonicalizePredicate` plus the
  strict parser `parseJsonStrict`, the cross-realm re-parse helper
  `fromJsonText`, and the `checkNoSpecialFloats` guard.
- **Ed25519 signing:** `generateKeyPair` / `KeyPair`, `sign` / `verify` over an
  object, `signJson` / `verifyJson` over a JSON string, and the
  `toBase64Url` / `fromBase64Url` helpers.
- **Core types:** the `SessionState`, `MessageType`, `TermType`,
  `OutcomeStatus`, and related enumerations, plus `Term`, `AgentIdentity`,
  `BehaviorRecord`, and their serialization helpers.
- **Negotiation session:** the `Session` state machine
  (PROPOSED -> ACTIVE -> AGREED / REJECTED / EXPIRED -> DORMANT) with a strict
  transition table, signature-verified message application, hash-chain transcript
  helpers (`computeHash`, `validateChain`, `GENESIS_HASH`), and
  `computeConcession`.
- **Signed predicates:** `signPredicate` / `verifyPredicate`,
  `validatePredicateForWrite`, the type-profile registry, and `validateReference`
  with its size bounds.
- **Mandate credentials:** the `Mandate` and `DelegationLink` models, `signMandate`
  / `signDelegation`, constraint and temporal validation, delegation-scope
  composition, and the full `verifyMandate` over all five checks.
- **Reputation attestation:** `generateAttestation` (behavioral signals only,
  never the raw deal terms), `generateReceiptSummary`, `computeTranscriptHash`,
  and the temporal-validity checks.
- **Schema validation:** `validateMessage`, `validateApprovalReceipt`, and
  `validateFulfillmentAttestation` (each returning a CPython-`jsonschema`-identical
  ordered error list), plus the full `verifyApprovalReceipt` human-in-the-loop
  receipt verifier.

The mandate revocation-endpoint network fetch is deferred (an injectable hook
covers the no-revocation outcome). The attestation schema validator
(`validateAttestation`) is available now, with error output matching the
Python reference.

## Parity with the Python SDK

Every primitive in this package is validated against fixtures generated by the
Python reference implementation, so a message signed in Python verifies in
TypeScript and vice versa. If you find a case where the two disagree on canonical
bytes, a signature, or a validation result, that is a bug; please report it (see
[SECURITY.md](https://github.com/eriknewton/concordia-protocol/blob/main/SECURITY.md)
for cryptographic-correctness issues).

## License

Apache-2.0. Copyright 2026 Erik Newton.
