/**
 * Set-binding verification over a reconstructed transcript chain (SPEC 9.6.5b).
 *
 * A receipt's `chain_head` and `message_count` describe a transcript. This file
 * covers the two conditions under which a verifier may credit that description:
 * a transcript has to be supplied at all, and the supplied messages have to
 * rebuild into exactly one chain from their `prev_hash` links, whatever order
 * the presenter chose for them. The shared conformance vectors are executed
 * here too, so the TypeScript verifier and the Python verifier are held to the
 * same verdict on the same bytes.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

import * as sessionModule from '../src/session/index.js';
import { GENESIS_HASH, computeHash } from '../src/session/index.js';
import {
  verifyReceiptSetBinding,
  MAX_SET_BINDING_TRANSCRIPT_MESSAGES,
} from '../src/attestation/index.js';
import { setOperationObserverForTests } from '../src/attestation/attestation.js';
import { canonicalizeJcs } from '../src/canonical/canonicalize.js';
import { CanonicalizationError } from '../src/canonical/checks.js';

// The cycle-detection describe block below installs a `vi.spyOn` on
// `sessionModule.hashCanonicalBytes` inside individual `it`s, with no
// restore of its own -- so, with no file-level cleanup, that mock leaked
// into every test that ran AFTER it in file order, including the real
// (non-mocked) `computeHash` calls this file's adversarial-complexity
// block makes. Restoring after every test is what makes test order not
// matter; add coverage below the cycle-detection block, not above it,
// without this and it fails for a reason that has nothing to do with the
// new coverage.
afterEach(() => {
  vi.restoreAllMocks();
  setOperationObserverForTests(undefined);
});

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS = join(__dirname, '..', '..', 'conformance', 'vectors');

type Msg = Record<string, unknown>;

function loadVector(section: string, id: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(VECTORS, section, `${id}.json`), 'utf8')) as Record<
    string,
    unknown
  >;
}

function vectorPair(vector: Record<string, unknown>): {
  receipt: Record<string, unknown>;
  messages: Msg[] | null;
} {
  const input = vector.input as Record<string, unknown>;
  const messages = input.messages as Msg[] | undefined;
  return {
    receipt: input.receipt as Record<string, unknown>,
    messages: messages ?? null,
  };
}

const RECONSTRUCTION_REJECT_IDS = [
  'mut-synthetic-receipt-set-reconstruction-0001',
  'mut-synthetic-receipt-set-reconstruction-0002',
  'mut-synthetic-receipt-set-reconstruction-0003',
  'mut-synthetic-receipt-set-reconstruction-0004',
  'mut-synthetic-receipt-set-reconstruction-0005',
  'mut-synthetic-receipt-set-reconstruction-0006',
  'mut-synthetic-receipt-set-reconstruction-0007',
  'mut-synthetic-receipt-set-reconstruction-0008',
];

describe('receipt set-binding over the shared conformance vectors', () => {
  it('binds the positive reconstruction vector', () => {
    const vector = loadVector('positive', 'pos-synthetic-receipt-set-binding-reconstruction');
    const { receipt, messages } = vectorPair(vector);

    expect(verifyReceiptSetBinding(receipt, messages)).toEqual({ state: 'bound', errors: [] });
  });

  for (const id of RECONSTRUCTION_REJECT_IDS) {
    it(`refuses to bind ${id}`, () => {
      const vector = loadVector('mutation', id);
      const { receipt, messages } = vectorPair(vector);
      const result = verifyReceiptSetBinding(receipt, messages);

      expect(result.state).not.toBe('bound');
      if (messages === null) {
        // The transcript-absent vector reports the unestablished state rather
        // than an error, because nothing about the receipt is malformed.
        expect(result.state).toBe('fields_present_unverified');
      } else {
        expect(result.state).toBe('error');
        expect(result.errors.length).toBeGreaterThan(0);
      }
    });
  }

  it('each reject vector is one a digest-and-count comparison would accept', () => {
    for (const id of RECONSTRUCTION_REJECT_IDS) {
      const { receipt, messages } = vectorPair(loadVector('mutation', id));
      if (messages === null) continue;
      expect(receipt.message_count).toBe(messages.length);
      expect(receipt.chain_head).toBe(computeHash(messages[messages.length - 1]!));
    }
  });
});

describe('a transcript is required before set binding is credited', () => {
  it('reports the unestablished state when no transcript is supplied', () => {
    const { receipt } = vectorPair(
      loadVector('positive', 'pos-synthetic-receipt-set-binding-reconstruction'),
    );

    expect(verifyReceiptSetBinding(receipt)).toEqual({
      state: 'fields_present_unverified',
      errors: [],
    });
  });

  it('still errors on malformed fields when no transcript is supplied', () => {
    const { receipt } = vectorPair(
      loadVector('positive', 'pos-synthetic-receipt-set-binding-reconstruction'),
    );
    const malformed = { ...receipt, chain_head: 'sha256:NOTLOWERHEX' };
    const result = verifyReceiptSetBinding(malformed);

    expect(result.state).toBe('error');
    expect(result.errors.some((e) => e.includes('requires chain_head'))).toBe(true);
  });
});

describe('chain reconstruction ignores the presented order', () => {
  const base = vectorPair(
    loadVector('positive', 'pos-synthetic-receipt-set-binding-reconstruction'),
  );

  it('binds a transcript handed over out of order', () => {
    const messages = base.messages!;
    const shuffled = [messages[messages.length - 1]!, ...messages.slice(0, -1)];

    expect(verifyReceiptSetBinding(base.receipt, shuffled)).toEqual({
      state: 'bound',
      errors: [],
    });
  });

  it('rejects a message inherited through the prototype chain outright (Grok finding 2, 2026-09-16 delta-7 gate)', () => {
    // 2026-09-16 delta-6 gate: canonicalizeJcs no longer checked prototype
    // identity at all (rejectForeignPrototype was itself a cross-realm
    // regression -- Codex P2 -- rejecting valid JSON parsed in a different
    // realm), so an object built via Object.create(proto) canonicalized
    // fine as plain data with the inherited-only prev_hash still
    // unreachable through snapshotPlainJson's own-property walk: `linked`
    // read as a second root rather than as a rejection, restoring the
    // reconstruction-witnessing shape from before the round-5
    // foreign-prototype check existed. The delta-7 fix (finding 2) adds a
    // realm-AGNOSTIC plain-data test -- prototype null within two hops --
    // that does not reopen the cross-realm case (a `JSON.parse` result from
    // any realm is still exactly two hops) but does refuse this shape: a
    // message whose OWN prototype is a custom object, not
    // `Object.prototype`, is three hops from null, one past the two-hop
    // budget, so the whole message is refused outright now instead of
    // merely having its inherited link ignored -- a strictly stronger
    // closure of the same channel (see the sibling non-enumerable-own-
    // property and toJSON tests below, which use a plain-prototype message
    // and so still reach the graceful "second root" outcome, unaffected by
    // this fix).
    const messages = base.messages!;
    const root = messages.find((message) => message.prev_hash === GENESIS_HASH);
    if (!root) throw new Error('fixture has no genesis-root message');
    const other = messages.find((message) => message !== root)!;
    const { prev_hash: _dropped, ...restFields } = other;
    // The link is offered SOLELY through the prototype: `linked` has no own
    // `prev_hash` at all, only an inherited one, and its own prototype is a
    // custom object rather than `Object.prototype`.
    const linked = Object.assign(
      Object.create({ prev_hash: computeHash(root) }) as Msg,
      restFields,
    );
    // Preconditions the construction depends on, not assertions about the
    // code under test.
    expect(Object.prototype.hasOwnProperty.call(linked, 'prev_hash')).toBe(false);
    expect(linked.prev_hash).toBeDefined();
    expect(Object.getPrototypeOf(Object.getPrototypeOf(linked))).not.toBeNull();

    const receipt = { ...base.receipt, message_count: 2, chain_head: GENESIS_HASH };

    expect(() => verifyReceiptSetBinding(receipt, [root, linked])).toThrow(CanonicalizationError);
  });

  it('does not consume a prev_hash defined as a non-enumerable own property', () => {
    const messages = base.messages!;
    // Same genesis-seeded construction as the prototype-chain case above, but
    // the link this time is an OWN property: `hasOwnProperty` is true for it,
    // it is merely non-enumerable, which is exactly the gap `Object.keys`
    // (and so `computeHash`'s `stableStringify`) leaves open. A prior fix
    // that swapped `in` for `hasOwnProperty` already rejects the inherited
    // case above, but still accepted this one and returned `bound` (P1,
    // 2026-09-16 Codex delta gate,
    // Review/Concordia/PR243_Gate_2026-09-16/OUT_delta2_codex.txt).
    const root = messages.find((message) => message.prev_hash === GENESIS_HASH);
    if (!root) throw new Error('fixture has no genesis-root message');
    const rest = messages.filter((message) => message !== root);
    const phantom: Msg[] = [{ ...root }];
    for (const original of rest) {
      const { prev_hash: _dropped, ...restFields } = original;
      const linked: Msg = { ...restFields };
      Object.defineProperty(linked, 'prev_hash', {
        value: computeHash(phantom[phantom.length - 1]!),
        enumerable: false,
        configurable: true,
      });
      phantom.push(linked);
    }
    // Every non-root phantom message truly has an OWN, non-enumerable
    // prev_hash: this is the precondition the whole construction depends on,
    // not an assertion about the code under test.
    for (const message of phantom.slice(1)) {
      expect(Object.prototype.hasOwnProperty.call(message, 'prev_hash')).toBe(true);
      expect(Object.prototype.propertyIsEnumerable.call(message, 'prev_hash')).toBe(false);
    }
    const receipt = {
      ...base.receipt,
      message_count: phantom.length,
      chain_head: computeHash(phantom[phantom.length - 1]!),
    };

    // A `hasOwnProperty`-only check (no enumerability, no projection) reads
    // this link, walks a chain that genuinely reconstructs, and returns
    // "bound" -- the projection fix must treat every non-root phantom
    // message as a second root instead, exactly as it does for the
    // inherited case above.
    const result = verifyReceiptSetBinding(receipt, phantom);
    expect(result.state).not.toBe('bound');
    expect(result.state).toBe('error');
    expect(result.errors.some((e) => e.includes('root messages'))).toBe(true);
  });

  it('does not consume a prev_hash injected by an own non-enumerable toJSON', () => {
    // Same genesis-seeded construction as the two phantom-chain cases above,
    // but the link is opened through a THIRD channel neither prior fix
    // closed: a `toJSON` method. `JSON.stringify` invokes `toJSON`, own or
    // inherited, before it ever reaches `Object.keys`; `computeHash`'s
    // `stableStringify` never calls `toJSON` at all (it walks `Object.keys`
    // directly). A projection built with `JSON.parse(JSON.stringify(...))`
    // therefore reads a link the digest never covers, which is exactly what
    // the digest-and-view-from-one-canonical-bytes fix closes (delta-3,
    // 2026-09-16 Codex gate,
    // Review/Concordia/PR243_Gate_2026-09-16/OUT_delta3_codex.txt).
    const messages = base.messages!;
    const root = messages.find((message) => message.prev_hash === GENESIS_HASH);
    if (!root) throw new Error('fixture has no genesis-root message');
    const rest = messages.filter((message) => message !== root);
    const phantom: Msg[] = [{ ...root }];
    for (const original of rest) {
      const { prev_hash: _dropped, ...restFields } = original;
      const predecessorDigest = computeHash(phantom[phantom.length - 1]!);
      const linked: Msg = { ...restFields };
      Object.defineProperty(linked, 'toJSON', {
        value: () => ({ ...linked, prev_hash: predecessorDigest }),
        enumerable: false,
        configurable: true,
      });
      phantom.push(linked);
    }
    // Every non-root phantom message has no own ENUMERABLE prev_hash (a
    // `JSON.stringify`-based projection is the only thing that ever sees
    // one), and `JSON.stringify` genuinely surfaces the injected link -- both
    // are the preconditions this construction depends on, not assertions
    // about the code under test.
    for (const message of phantom.slice(1)) {
      expect(Object.prototype.hasOwnProperty.call(message, 'prev_hash')).toBe(false);
      const stringified = JSON.parse(JSON.stringify(message)) as Msg;
      expect(typeof stringified.prev_hash).toBe('string');
    }
    const receipt = {
      ...base.receipt,
      message_count: phantom.length,
      chain_head: computeHash(phantom[phantom.length - 1]!),
    };

    // A JSON.stringify-round-trip projection reads this link, walks a chain
    // that genuinely reconstructs, and returns "bound" -- the
    // canonical-bytes fix must treat every non-root phantom message as a
    // second root instead, exactly as it does for the two channels above.
    const result = verifyReceiptSetBinding(receipt, phantom);
    expect(result.state).not.toBe('bound');
    expect(result.state).toBe('error');
    expect(result.errors.some((e) => e.includes('root messages'))).toBe(true);
  });

  it('rejects a message with a toJSON inherited through the prototype chain outright (Grok finding 2, 2026-09-16 delta-7 gate)', () => {
    // Combines the prototype-chain channel with the toJSON channel: the
    // fabricated link is reachable only by looking up `toJSON` through the
    // prototype AND calling it, which `JSON.stringify` does and
    // `snapshotPlainJson`'s own-descriptor walk never does either way, so
    // the toJSON channel was always closed on its own separate merits. The
    // delta-7 fix (finding 2) closes the CARRYING shape as well: `linked`'s
    // own prototype (the object literal holding `toJSON`) is not
    // `Object.prototype`, so it is three hops from null, one past the
    // two-hop plain-object budget, and the whole message is now refused
    // outright rather than merely having its toJSON channel ignored (see
    // the sibling prototype-chain test above for the non-toJSON case of the
    // same shape).
    const messages = base.messages!;
    const root = messages.find((message) => message.prev_hash === GENESIS_HASH);
    if (!root) throw new Error('fixture has no genesis-root message');
    const other = messages.find((message) => message !== root)!;
    const { prev_hash: _dropped, ...restFields } = other;
    const predecessorDigest = computeHash(root);
    const proto = {
      toJSON(this: Msg) {
        return { ...this, prev_hash: predecessorDigest };
      },
    };
    const linked = Object.assign(Object.create(proto) as Msg, restFields);
    // Preconditions the construction depends on, not assertions about the
    // code under test.
    expect(Object.prototype.hasOwnProperty.call(linked, 'prev_hash')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(linked, 'toJSON')).toBe(false);
    const stringified = JSON.parse(JSON.stringify(linked)) as Msg;
    expect(typeof stringified.prev_hash).toBe('string');
    expect(Object.getPrototypeOf(Object.getPrototypeOf(linked))).not.toBeNull();

    const receipt = { ...base.receipt, message_count: 2, chain_head: GENESIS_HASH };

    expect(() => verifyReceiptSetBinding(receipt, [root, linked])).toThrow(CanonicalizationError);
  });

  it('rejects a set with no root message as the orphan it actually is', () => {
    // The fixture is presented shuffled (not chain order), so the root is
    // wherever prev_hash === GENESIS_HASH lands, never necessarily index 0.
    // Dropping the root does not exercise the bare "no root message"
    // fallback: the message that pointed at the dropped root becomes an
    // ORPHAN (its prev_hash now matches no presented message), and that
    // orphan error is recorded before the rootless check ever runs. Cycle
    // detection now runs only when it can change the diagnosis (2026-09-16
    // delta-11 gate, Codex P1): with the orphan error already present,
    // findCycle is skipped and the generic "no root message" text is
    // never appended alongside it, so the orphan is the ONLY, and the more
    // specific, reported reason. (Fail-before against 5176dfc: the old
    // code ran findCycle and appended "no root message" as a second,
    // redundant error unconditionally; this test used to assert on that
    // redundant text instead of the primary orphan diagnosis.) Must match
    // test_no_root_is_rejected_as_the_orphan_it_actually_is in
    // tests/test_attestation_set_binding_reconstruction.py.
    const messages = base.messages!;
    const withoutRoot = messages.filter((message) => message.prev_hash !== GENESIS_HASH);
    expect(withoutRoot.length).toBe(messages.length - 1);
    const result = verifyReceiptSetBinding(base.receipt, withoutRoot);

    expect(result.state).toBe('error');
    expect(result.errors).toEqual([
      'transcript message 2 is an orphan: its prev_hash matches no presented message',
    ]);
  });

  it('rejects an explicit null prev_hash as a root', () => {
    const messages = base.messages!;
    const nullRoot = { ...messages[0]!, prev_hash: null };
    const presented = [nullRoot, ...messages.slice(1)];
    const result = verifyReceiptSetBinding(base.receipt, presented);

    expect(result.state).toBe('error');
    expect(result.errors.some((e) => e.includes('explicit null prev_hash'))).toBe(true);
  });

  it('binds a shuffled chain under a permutation distinct from the fixture order', () => {
    const messages = base.messages!;
    expect(messages.length).toBeGreaterThanOrEqual(3);
    // Rotate by two rather than one, so this exercises a different
    // permutation than the single-rotation case above.
    const shuffled = [...messages.slice(2), ...messages.slice(0, 2)];

    expect(verifyReceiptSetBinding(base.receipt, shuffled)).toEqual({
      state: 'bound',
      errors: [],
    });
  });

  it('rejects a second root message', () => {
    const messages = base.messages!;
    const secondRoot = { ...messages[0]!, id: 'second_root', prev_hash: GENESIS_HASH };
    const receipt = { ...base.receipt, message_count: messages.length + 1 };
    const result = verifyReceiptSetBinding(receipt, [...messages, secondRoot]);

    expect(result.state).toBe('error');
    expect(result.errors.some((e) => e.includes('root messages'))).toBe(true);
  });

  it('rejects a duplicated message', () => {
    const messages = base.messages!;
    const receipt = { ...base.receipt, message_count: messages.length + 1 };
    const result = verifyReceiptSetBinding(receipt, [...messages, { ...messages[0]! }]);

    expect(result.state).toBe('error');
    expect(result.errors.some((e) => e.includes('more than once'))).toBe(true);
  });

  it('rejects links computed over the signature-stripped form', () => {
    const messages = base.messages!;
    const relinked: Msg[] = [{ ...messages[0]! }];
    for (const message of messages.slice(1)) {
      const previous = relinked[relinked.length - 1]!;
      const stripped = Object.fromEntries(
        Object.entries(previous).filter(([key]) => key !== 'signature'),
      );
      const digest = createHash('sha256').update(canonicalizeJcs(stripped)).digest('hex');
      relinked.push({ ...message, prev_hash: `sha256:${digest}` });
    }
    const receipt = { ...base.receipt, chain_head: computeHash(relinked[relinked.length - 1]!) };
    const result = verifyReceiptSetBinding(receipt, relinked);

    expect(result.state).toBe('error');
    expect(result.errors.some((e) => e.includes('orphan'))).toBe(true);
  });
});

describe('a value is read once, on the read that serializes it (Codex delta-5 gate, 2026-09-16)', () => {
  // These three regression tests each proved a genuine fail-open against
  // 6b63c34 before this round's fix (verified by stashing the fix, running
  // this exact construction, and observing the vulnerable result quoted in
  // each test's comment; unstashing then reproduced the CanonicalizationError
  // asserted below). The mechanism in all three: a getter can answer one read
  // of a caller-controlled object differently than a later read of the SAME
  // object, so code that reads a value more than once for two different
  // purposes can be shown one value for the first purpose and a different one
  // for the second. The fix removes the second read (attestation.ts,
  // runner.mjs) and refuses any accessor property outright, on its
  // descriptor, before its value is ever read at all (canonicalize.ts).

  it('rejects a transcript whose terminal prev_hash getter answers reconstruction and the chain_head rehash differently', () => {
    // Codex P1: an enumerable `prev_hash` getter returned the true
    // predecessor digest while `reconstructSingleChain` built canonicalBytes
    // for both messages (2 reads: the pre-fix checkNoSpecialFloats pre-pass,
    // then stableStringify, within that ONE canonicalizeJcs(child) call), so
    // the chain reconstructed correctly. It then returned GENESIS_HASH on
    // every later read, so the pre-fix code's SEPARATE
    // `computeHash(chain[chain.length - 1])` rehash (2 more reads) hashed a
    // message whose prev_hash reads as GENESIS_HASH -- bytes the attacker
    // can precompute and set as the receipt's `chain_head` -- while
    // reconstruction had validated the link using the FIRST read's bytes,
    // never these. Reproduced against 6b63c34: `verifyReceiptSetBinding`
    // returned `{ state: 'bound', errors: [] }`, a genuine fail-open.
    const root: Msg = {
      from: { agent_id: 'alice' },
      content: 'root',
      prev_hash: GENESIS_HASH,
      signature: 'deadbeef',
    };
    const childFields: Msg = {
      from: { agent_id: 'bob' },
      content: 'child',
      signature: 'cafebabe',
    };
    const trueLink = computeHash(root);
    let reads = 0;
    const child: Msg = { ...childFields };
    Object.defineProperty(child, 'prev_hash', {
      // The pre-fix canonicalizeJcs(child) call inside reconstructSingleChain
      // consumes reads 1 and 2 (checkNoSpecialFloats's own traversal, then
      // stableStringify's); both must still answer trueLink so the FIRST
      // canonicalization -- the one link validation actually runs against --
      // is self-consistent. Only reads 3 onward (the separate, later
      // computeHash(chain[chain.length - 1]) rehash) see the flip.
      get() {
        reads += 1;
        return reads <= 2 ? trueLink : GENESIS_HASH;
      },
      enumerable: true,
      configurable: true,
    });
    // The chain_head an attacker controlling `child` can precompute: the hash
    // of the same fields with a plain prev_hash of GENESIS_HASH, i.e. exactly
    // what the pre-fix code's later, separate rehash would produce.
    const attackerChainHead = computeHash({ ...childFields, prev_hash: GENESIS_HASH });
    const receipt = {
      concordia_attestation: '0.5.0',
      message_count: 2,
      chain_head: attackerChainHead,
    };

    expect(() => verifyReceiptSetBinding(receipt, [root, child])).toThrow(CanonicalizationError);
  });

  it('rejects a message with a numeric accessor that answers a special-float guard 1 and then serializes NaN', () => {
    // Codex P2: an enumerable numeric getter returned 1 (a safe integer) on
    // its first read and NaN afterward. Pre-fix, checkNoSpecialFloats's
    // pre-pass consumed the first read (1 passes every special-float check)
    // and stableStringify's own read consumed the second (NaN, serialized by
    // JSON.stringify as the literal `null`). Reproduced against 6b63c34:
    // canonicalizeJcs returned the bytes `{"amount":null}` instead of
    // throwing.
    let reads = 0;
    const message: Msg = { from: { agent_id: 'alice' }, prev_hash: GENESIS_HASH };
    Object.defineProperty(message, 'amount', {
      get() {
        reads += 1;
        return reads <= 1 ? 1 : NaN;
      },
      enumerable: true,
      configurable: true,
    });
    const receipt = { concordia_attestation: '0.5.0', message_count: 1, chain_head: GENESIS_HASH };

    expect(() => verifyReceiptSetBinding(receipt, [message])).toThrow(CanonicalizationError);
  });

  it('rejects a message with a numeric accessor that answers a special-float guard 1 and then serializes -0', () => {
    // Same shape as the NaN case, flipping to -0 instead. Reproduced against
    // 6b63c34: canonicalizeJcs returned the bytes `{"amount":0}` instead of
    // throwing -- JSON.stringify(-0) renders "0", silently dropping the sign
    // checkNoSpecialFloats exists to reject.
    let reads = 0;
    const message: Msg = { from: { agent_id: 'alice' }, prev_hash: GENESIS_HASH };
    Object.defineProperty(message, 'amount', {
      get() {
        reads += 1;
        return reads <= 1 ? 1 : -0;
      },
      enumerable: true,
      configurable: true,
    });
    const receipt = { concordia_attestation: '0.5.0', message_count: 1, chain_head: GENESIS_HASH };

    expect(() => verifyReceiptSetBinding(receipt, [message])).toThrow(CanonicalizationError);
  });

  it('still binds plain data carrying the same values as the three rejected constructions (no regression)', () => {
    // Same message shapes as the three cases above, but every field is a
    // plain data property, not an accessor: proves the fix rejects
    // ACCESSORS specifically, never a field name, a value, or a chain this
    // shape otherwise reconstructs correctly.
    const root: Msg = {
      from: { agent_id: 'alice' },
      content: 'root',
      prev_hash: GENESIS_HASH,
      signature: 'deadbeef',
    };
    const child: Msg = {
      from: { agent_id: 'bob' },
      content: 'child',
      signature: 'cafebabe',
      prev_hash: computeHash(root),
    };
    const plainChainReceipt = {
      concordia_attestation: '0.5.0',
      message_count: 2,
      chain_head: computeHash(child),
    };
    expect(verifyReceiptSetBinding(plainChainReceipt, [root, child])).toEqual({
      state: 'bound',
      errors: [],
    });

    const numericMessage: Msg = { from: { agent_id: 'alice' }, prev_hash: GENESIS_HASH, amount: 1 };
    const numericReceipt = {
      concordia_attestation: '0.5.0',
      message_count: 1,
      chain_head: computeHash(numericMessage),
    };
    expect(verifyReceiptSetBinding(numericReceipt, [numericMessage])).toEqual({
      state: 'bound',
      errors: [],
    });
  });
});

describe('the caller-supplied transcript is snapshotted once, at the boundary (Codex/Grok delta-6 gate, 2026-09-16)', () => {
  const base = vectorPair(
    loadVector('positive', 'pos-synthetic-receipt-set-binding-reconstruction'),
  );

  it('a Proxy transcript array cannot answer one length to an early read and a shorter one to a later read', () => {
    // Codex P1 reproduction, proved fail-before against 37bfca7 (stashed
    // this test's fix, ran this exact construction, observed { state:
    // 'bound', errors: [] } for a receipt naming only ONE message while the
    // backing array genuinely holds two; unstashed and reproduced the
    // rejection below). Pre-fix, `reconstructSingleChain` read
    // `transcript.length` on every loop-condition check across FOUR
    // separate passes (the validation loop, `.map()`, the link-reading
    // loop, and the closing invariant): a Proxy answering 2 for the first
    // few reads (enough for validation and `.map()` to see both messages)
    // and 1 from then on made the link-reading loop skip message 1's link
    // entirely and made the closing invariant compare against the SAME
    // shrunken length the walk had already used, so nothing ever caught the
    // mismatch. Post-fix, `verifyReceiptSetBinding` reads `.length` exactly
    // once, inside `snapshotPlainJson`, before ANY check runs -- there is
    // no earlier or later read left for this Proxy to answer differently.
    const messages = base.messages!;
    const validRoot = messages.find((message) => message.prev_hash === GENESIS_HASH);
    if (!validRoot) throw new Error('fixture has no genesis-root message');
    const secondReal = messages.find((message) => message !== validRoot)!;
    // A genuine second link: if the snapshot sees both elements (as it must,
    // reading `.length` only once), this closes into a real two-message
    // chain, not an orphan or a fork.
    const secondRoot = { ...secondReal, prev_hash: computeHash(validRoot) };
    const backing = [validRoot, secondRoot];
    let reads = 0;
    const proxied = new Proxy(backing, {
      get(target, prop, receiver) {
        if (prop === 'length') {
          reads += 1;
          // Generous enough to cover the pre-fix validation loop's three
          // boundary checks (index 0, 1, 2) plus `.map()`'s single internal
          // read, all still answering the true length; every read after
          // that lies.
          return reads <= 4 ? 2 : 1;
        }
        return Reflect.get(target, prop, receiver);
      },
    });
    // Names only the first message: the receipt a set-substitution attack
    // would need the verifier to credit.
    const receipt = {
      ...base.receipt,
      message_count: 1,
      chain_head: computeHash(validRoot),
    };

    const result = verifyReceiptSetBinding(receipt, proxied as unknown as Msg[]);
    // Never bound for the one-message receipt: the snapshot reads the
    // array's actual length exactly once, so it sees the true two elements
    // and the reconstructed two-message set mismatches this receipt's
    // one-message claim on BOTH fields the receipt asserts -- never the
    // silently-truncated one-message view that returned `bound` pre-fix
    // (Grok finding 3, 2026-09-16 delta-7 gate: the prior assertion checked
    // only `not.toBe('bound')`, which `legacy_set_unbound` or
    // `fields_present_unverified` would also have satisfied without
    // proving the snapshot actually saw both elements).
    expect(result).toEqual({
      state: 'error',
      errors: [
        'message_count mismatch: attestation has 1, transcript has 2',
        'chain_head mismatch: attestation does not match transcript final message hash',
      ],
    });
  });

  it('a descriptor value getter answering ++n on each call is read exactly once (Grok finding 1a, 2026-09-16 delta-7 gate)', () => {
    // Grok reproduction, proved fail-before against e1239db: the object
    // branch of snapshotPlainJson read each member through Object.keys (one
    // [[GetOwnProperty]] to test enumerability, which ALSO reads the
    // descriptor's `value` getter, because the trap result is converted via
    // ToPropertyDescriptor regardless of which fields the caller asked
    // about) and then a SEPARATE Object.getOwnPropertyDescriptor call (a
    // second [[GetOwnProperty]], reading the getter again): the snapshot
    // kept the SECOND answer, canonicalizing `amount` as 2 instead of 1.
    // Post-fix, snapshotPlainJson calls Object.getOwnPropertyDescriptors
    // exactly once per object, which performs exactly one
    // [[GetOwnProperty]] per key, so the getter fires once and the snapshot
    // keeps the ONLY answer there is: `n` below stays 1.
    let n = 0;
    const root: Msg = { from: { agent_id: 'alice' }, prev_hash: GENESIS_HASH };
    const message = new Proxy(root, {
      ownKeys(target) {
        return [...Reflect.ownKeys(target), 'amount'];
      },
      getOwnPropertyDescriptor(target, prop) {
        if (prop === 'amount') {
          return {
            enumerable: true,
            configurable: true,
            writable: true,
            get value() {
              n += 1;
              return n;
            },
          };
        }
        return Reflect.getOwnPropertyDescriptor(target, prop);
      },
    });
    // The chain_head a caller presenting the FIRST (and, post-fix, only)
    // answer can compute; a caller relying on the pre-fix second-read
    // behavior would need `amount: 2` here instead.
    const receipt = {
      ...base.receipt,
      message_count: 1,
      chain_head: computeHash({ ...root, amount: 1 }),
    };

    const result = verifyReceiptSetBinding(receipt, [message as unknown as Msg]);
    expect(result).toEqual({ state: 'bound', errors: [] });
    expect(n).toBe(1);
  });

  it('a getOwnPropertyDescriptor trap that lies starting on its second call for a key never reaches that second call (Grok finding 1b, 2026-09-16 delta-7 gate)', () => {
    // Grok reproduction, proved fail-before against e1239db: same
    // double-observation shape as above, this time with the TRAP itself
    // changing its answer rather than a getter on the descriptor object.
    // Pre-fix, Object.keys's enumerability check was call 1 for `amount`
    // (honest) and the loop's own Object.getOwnPropertyDescriptor was call
    // 2 (the lie), so the snapshot kept the lie, canonicalizing `amount` as
    // "lie" instead of "honest". Post-fix, the sole
    // Object.getOwnPropertyDescriptors call is call 1 for every key: the
    // trap never gets a second call to lie on.
    const perKeyCalls: Record<string, number> = {};
    const root: Msg = { from: { agent_id: 'alice' }, prev_hash: GENESIS_HASH, amount: 'honest' };
    const message = new Proxy(root, {
      getOwnPropertyDescriptor(target, prop) {
        if (typeof prop === 'string') {
          perKeyCalls[prop] = (perKeyCalls[prop] ?? 0) + 1;
        }
        if (prop === 'amount' && (perKeyCalls['amount'] ?? 0) > 1) {
          return { value: 'lie', enumerable: true, configurable: true, writable: true };
        }
        return Reflect.getOwnPropertyDescriptor(target, prop);
      },
    });
    const receipt = {
      ...base.receipt,
      message_count: 1,
      chain_head: computeHash(root),
    };

    const result = verifyReceiptSetBinding(receipt, [message as unknown as Msg]);
    expect(result).toEqual({ state: 'bound', errors: [] });
    expect(perKeyCalls['amount']).toBe(1);
  });

  it('canonicalizeJcs on a plain (non-Proxy) transcript still binds two real messages (no regression)', () => {
    const messages = base.messages!;
    const validRoot = messages.find((message) => message.prev_hash === GENESIS_HASH)!;
    const secondReal = messages.find((message) => message !== validRoot)!;
    const secondRoot = { ...secondReal, prev_hash: computeHash(validRoot) };
    const receipt = {
      ...base.receipt,
      message_count: 2,
      chain_head: computeHash(secondRoot),
    };

    expect(verifyReceiptSetBinding(receipt, [validRoot, secondRoot])).toEqual({
      state: 'bound',
      errors: [],
    });
  });
});

describe('"__proto__" survives the double snapshot (boundary snapshot, then canonicalizeJcs\'s own snapshot inside reconstructSingleChain) (Grok/Codex verbatim, 2026-09-16 delta-7 gate, fix round 8)', () => {
  it('binds a transcript whose message carries a JSON "__proto__" key exactly as the same transcript without it', () => {
    // JSON.parse creates "__proto__" as an ordinary own enumerable data
    // property, exactly as any caller handing this SDK a parsed request
    // body would produce it. `verifyReceiptSetBinding` snapshots
    // `callerTranscript` once at its own boundary; `reconstructSingleChain`
    // then calls `canonicalizeJcs` on each element of THAT snapshot, which
    // snapshots it a second time -- this is the "second snapshot inside
    // set-binding" the fix must also cover, not just a single top-level
    // canonicalizeJcs call. Fail-before against 23439e2: the first
    // snapshot's `out[key] = ...` already dropped/retargeted on
    // "__proto__", so this path never reached a second snapshot carrying
    // the key at all.
    const withProto = JSON.parse(
      `{"from":{"agent_id":"alice"},"prev_hash":${JSON.stringify(GENESIS_HASH)},"__proto__":{"x":1}}`,
    ) as Msg;
    const withoutProto: Msg = { from: { agent_id: 'alice' }, prev_hash: GENESIS_HASH };

    const receiptWithProto = {
      concordia_attestation: '0.5.0',
      message_count: 1,
      chain_head: computeHash(withProto),
    };
    const receiptWithoutProto = {
      concordia_attestation: '0.5.0',
      message_count: 1,
      chain_head: computeHash(withoutProto),
    };

    expect(verifyReceiptSetBinding(receiptWithProto, [withProto])).toEqual({
      state: 'bound',
      errors: [],
    });
    expect(verifyReceiptSetBinding(receiptWithoutProto, [withoutProto])).toEqual({
      state: 'bound',
      errors: [],
    });
    // The two messages canonicalize to different bytes ("__proto__" is real
    // JSON content, not a discarded artifact), so their digests must
    // differ -- proving the key was actually stored and hashed, not merely
    // "did not throw."
    expect(computeHash(withProto)).not.toBe(computeHash(withoutProto));
  });
});

describe('a cycle among prev_hash links is named "cycle", not "no root message" (2026-09-16 fix round 11)', () => {
  // A genuinely mutual prev_hash cycle cannot be built with the real
  // hashCanonicalBytes: closing the loop needs message A's digest to equal
  // what message B points at AND message B's digest to equal what A
  // points at simultaneously, and the digest covers the WHOLE message
  // including its own prev_hash field -- solving that pair of equations is
  // exactly as hard as inverting SHA-256 (a hash preimage search), for any
  // cycle length. These tests replace hashCanonicalBytes (imported from
  // ../src/session/index.js, a SEPARATE module from attestation.ts, so a
  // namespace-import spy intercepts the live binding attestation.ts calls
  // through) with a fixed id-to-digest lookup so the GRAPH topology (what
  // the fix under test reasons about) can be constructed directly, without
  // needing a real hash preimage. The patched function is exercised through
  // the public verifyReceiptSetBinding entry point, not a private helper,
  // so this still proves the SDK-level behavior a caller observes. Mirrors
  // TestCycleDetectionAndTheClosingInvariant in
  // tests/test_attestation_set_binding_reconstruction.py; must match its
  // verdicts.

  const DIGESTS: Record<string, string> = {
    chain_1: 'a'.repeat(64),
    chain_2: 'b'.repeat(64),
    chain_3: 'c'.repeat(64),
    chain_4: 'd'.repeat(64),
    chain_5: 'e'.repeat(64),
    cycle_a: 'f'.repeat(64),
    cycle_b: '0'.repeat(63) + '1',
  };

  function installFakeHash(): void {
    vi.spyOn(sessionModule, 'hashCanonicalBytes').mockImplementation((bytes: Buffer) => {
      const text = bytes.toString('utf8');
      for (const [id, digest] of Object.entries(DIGESTS)) {
        if (text.includes(`"id":${JSON.stringify(id)}`)) return `sha256:${digest}`;
      }
      throw new Error(`installFakeHash: no fixture digest for canonical bytes ${text}`);
    });
  }

  function linkedChain(length: number): Msg[] {
    const chain: Msg[] = [{ id: 'chain_1', from: { agent_id: 'alice' } }];
    for (let position = 2; position <= length; position += 1) {
      const predecessorId = `chain_${position - 1}`;
      chain.push({
        id: `chain_${position}`,
        from: { agent_id: 'alice' },
        prev_hash: `sha256:${DIGESTS[predecessorId]}`,
      });
    }
    return chain;
  }

  function cyclePair(): [Msg, Msg] {
    return [
      { id: 'cycle_a', from: { agent_id: 'alice' }, prev_hash: `sha256:${DIGESTS.cycle_b}` },
      { id: 'cycle_b', from: { agent_id: 'alice' }, prev_hash: `sha256:${DIGESTS.cycle_a}` },
    ];
  }

  it('rejects a pure two-cycle (no root) and names it "cycle", not "no root message"', () => {
    installFakeHash();
    const [cycleA, cycleB] = cyclePair();
    const receipt = { concordia_attestation: '0.5.0', chain_head: GENESIS_HASH, message_count: 2 };

    const result = verifyReceiptSetBinding(receipt, [cycleA, cycleB]);

    expect(result.state).toBe('error');
    // Exact string, not just "contains 'cycle'" (Codex P2, 2026-09-16
    // delta-11 gate): cycleA is transcript index 0, cycleB is index 1;
    // cycleA's prev_hash points at cycleB and cycleB's prev_hash points
    // back at cycleA, so findCycle's walk from index 0 visits [0, 1] and
    // closes back on 0 -- named "0, 1, 0" in walk order. Must match
    // test_pure_two_cycle_is_rejected_and_named in
    // tests/test_attestation_set_binding_reconstruction.py.
    expect(result.errors).toEqual([
      'transcript contains a prev_hash cycle through messages 0, 1, 0: prev_hash links point ' +
        'to each other with no root; a chain has exactly one message without prev_hash',
    ]);
    expect(result.errors).not.toContain(
      'transcript has no root message: a chain has exactly one message without prev_hash',
    );
  });

  it('rejects a cycle beside a real chain and names it "cycle" -- the walk-length closing invariant\'s own regression test (item 6)', () => {
    // A genuinely valid five-message chain, plus two extra messages that
    // link only to each other: the walk from the root reconstructs the
    // five-message chain and never reaches the two extras, so the
    // `chain.length !== transcript.length` closing invariant is the ONLY
    // thing that refuses crediting the five-message chain as the receipt's
    // (larger, message_count-mismatched) claimed set. Verified by hand for
    // this round: commenting out that check (and its early return) makes
    // this exact assertion fail, because reconstructSingleChain then
    // returns the five-message chain as a successful reconstruction, and
    // verifyReceiptSetBinding instead reports a plain message_count /
    // chain_head mismatch against the 7-message receipt, never reaching
    // the cycle-naming branch at all -- proving the check is load-bearing,
    // not merely present.
    installFakeHash();
    const [cycleA, cycleB] = cyclePair();
    const transcript = [...linkedChain(5), cycleA, cycleB];
    const receipt = {
      concordia_attestation: '0.5.0',
      chain_head: GENESIS_HASH,
      message_count: transcript.length,
    };

    const result = verifyReceiptSetBinding(receipt, transcript);

    expect(result.state).toBe('error');
    // Exact string (Codex P2, 2026-09-16 delta-11 gate): the walk from the
    // root (chain_1..chain_5) visits indices 0-4 and stops, leaving cycleA
    // (index 5) and cycleB (index 6) as the leftover; the leftover walk
    // starts at 5, visits [5, 6], and closes back on 5. Must match
    // test_cycle_beside_a_real_chain_is_rejected_and_named in
    // tests/test_attestation_set_binding_reconstruction.py.
    expect(result.errors).toEqual([
      'transcript contains a prev_hash cycle through messages 5, 6, 5 beside the ' +
        'reconstructed chain: the walk from the root visits 5 of 7 presented messages',
    ]);
  });
});

describe('cycle detection is linear, not quadratic (AGENTS.md rule 8, 2026-09-16 delta-11 and delta-12 gates)', () => {
  // Cost is asserted as an OPERATION COUNT, never as wall-clock time in any
  // form: a millisecond ceiling encodes one machine's speed (round 12's
  // 1000 ms ceiling held at 540 ms on the MacBook and failed at 1858 and
  // 2224 ms on the CI runners with no regression anywhere), and a wall-clock
  // n-versus-2n ratio of two separately scheduled minima is still a flaky
  // oracle (JIT warm-up, contention, throttling and GC can push a linear
  // ratio past 3 or hide a quadratic term; Codex P2, 2026-09-17 delta-13
  // gate). A count of visits is the same integer on every machine, so the
  // assertions here are exact bounds, read through the test-only observer
  // hook setOperationObserverForTests and a call-counting spy on the digest.
  //
  // Two shapes, because they reach different code (Codex P2, delta-12 gate:
  // the round-12 test built only the orphan shape, whose rejection is
  // explained before findCycle runs, so the finder itself was never
  // exercised at scale):
  //   - a genuine n-message prev_hash CYCLE, built with mocked digests (the
  //     technique of the cycle-naming tests above, since a real cycle is a
  //     SHA-256 preimage search): no root, no orphan, no fork, so
  //     reconstructSingleChain reaches findCycle with every message in
  //     predecessorOf and the finder walks the whole cycle. The diagnosis
  //     names every index in walk order, which is the proof it ran.
  //   - the rootless reverse-ordered chain ending in ONE orphan, with real
  //     hashing: the exact input that drove the old O(n^2) finder (Codex P1,
  //     delta-11 gate), now rejected on the orphan alone before findCycle,
  //     whose cost is one digest per presented message.
  // Sizes: the cycle shape runs to 2n = 128_000, the range the cap's
  // derivation cites (MAX_SET_BINDING_TRANSCRIPT_MESSAGES in attestation.ts).
  // Mirrors TestCycleDetectionIsLinearNotQuadratic in
  // tests/test_attestation_set_binding_reconstruction.py.

  // Upper bound on finder visits per presented message, from the finder's
  // own structure: every node is appended to exactly one walk's `path` (a
  // later walk stops at a node an earlier walk resolved), which is n visits,
  // and every walk ends in exactly one terminating visit (a resolved node, a
  // root, or the revisit that closes a cycle); a walk appends at least its
  // own start node, so there are at most n walks, hence at most n more
  // terminating visits: 2n in all.
  const VISITS_PER_MESSAGE = 2;
  // The count for 2n against the count for n: exactly 2 for a linear finder,
  // about 4 for the old quadratic one. 2.5 leaves room for the constant
  // terminating visit(s) without admitting a quadratic term.
  const DOUBLING_BOUND = 2.5;
  const LONG_TEST_TIMEOUT_MS = 180_000;

  // Digest of message `c<i>`: i + 1 in 64 hex digits (offset by one so that
  // index 0's digest is not the all-zero GENESIS_HASH, which would make its
  // successor a root), read off the canonical bytes (which carry the id) by
  // the hashCanonicalBytes mock, so a cycle of any length is a lookup, not a
  // preimage search.
  function cycleDigest(i: number): string {
    return `sha256:${(i + 1).toString(16).padStart(64, '0')}`;
  }

  function installCycleFakeHash(): ReturnType<typeof vi.spyOn> {
    return vi.spyOn(sessionModule, 'hashCanonicalBytes').mockImplementation((bytes: Buffer) => {
      const match = /"id":"c(\d+)"/.exec(bytes.toString('utf8'));
      if (match === null) throw new Error('installCycleFakeHash: no c<i> id in canonical bytes');
      return cycleDigest(Number(match[1]));
    });
  }

  // c_i links to c_{i-1} and c_0 links to c_{n-1}: one n-cycle, no root.
  function buildGenuineCycle(n: number): Array<Record<string, unknown>> {
    return Array.from({ length: n }, (_, i) => ({
      id: `c${i}`,
      prev_hash: cycleDigest((i + n - 1) % n),
    }));
  }

  // findCycle iterates predecessorOf in insertion (transcript index) order,
  // so the walk starts at index 0 and follows prev_hash: 0, n-1, n-2, ...,
  // 1, then closes on 0. Must match _find_cycle's walk in
  // concordia/attestation.py (same expected text in its sibling test).
  function expectedCycleDiagnosis(n: number): string {
    const walk = [0];
    for (let i = n - 1; i >= 1; i -= 1) walk.push(i);
    walk.push(0);
    return (
      `transcript contains a prev_hash cycle through messages ${walk.join(', ')}: ` +
      `prev_hash links point to each other with no root; a chain has exactly one ` +
      `message without prev_hash`
    );
  }

  // Verify once and return the finder's visit count (through the observer
  // hook), the digest count (calls on `hashSpy` during this verification
  // only), and the errors. Both counters are exact integers, not timings.
  function countVerify(
    transcript: Array<Record<string, unknown>>,
    hashSpy: { mock: { calls: unknown[] }; mockClear: () => void },
  ): { finderVisits: number; digests: number; errors: string[] } {
    const receipt = {
      concordia_attestation: '0.5.0',
      chain_head: GENESIS_HASH,
      message_count: transcript.length,
    };
    let finderVisits = 0;
    setOperationObserverForTests((operation) => {
      if (operation === 'cycle_finder_visit') finderVisits += 1;
    });
    hashSpy.mockClear();
    const errors = verifyReceiptSetBinding(receipt, transcript).errors;
    setOperationObserverForTests(undefined);
    return { finderVisits, digests: hashSpy.mock.calls.length, errors };
  }

  it(
    'walks a genuine 128k-message prev_hash cycle through findCycle in visits linear in n (at most 2n, and 2n costs at most 2.5x n)',
    { timeout: LONG_TEST_TIMEOUT_MS },
    () => {
      const hashSpy = installCycleFakeHash();
      const n = 64_000;
      const small = countVerify(buildGenuineCycle(n), hashSpy);
      const large = countVerify(buildGenuineCycle(2 * n), hashSpy);

      // The finder ran, over the WHOLE cycle, in both sizes: only findCycle
      // produces this diagnosis, and it names every index.
      expect(small.errors).toEqual([expectedCycleDiagnosis(n)]);
      expect(large.errors).toEqual([expectedCycleDiagnosis(2 * n)]);
      // One digest per presented message on the way in.
      expect([small.digests, large.digests]).toEqual([n, 2 * n]);
      // The finder's cost, as visits: linear in n by the bound derived
      // above, and doubling with n, never quadrupling.
      expect(small.finderVisits).toBeGreaterThan(0);
      expect(small.finderVisits).toBeLessThanOrEqual(VISITS_PER_MESSAGE * n);
      expect(large.finderVisits).toBeLessThanOrEqual(VISITS_PER_MESSAGE * 2 * n);
      expect(large.finderVisits).toBeLessThanOrEqual(DOUBLING_BOUND * small.finderVisits);
    },
  );

  function buildRootlessReverseChain(n: number): Array<Record<string, unknown>> {
    const messages: Array<Record<string, unknown>> = [
      { id: 'm0', from: { agent_id: 'adversary' }, prev_hash: `sha256:${'f'.repeat(64)}` },
    ];
    for (let i = 1; i < n; i += 1) {
      const prevDigest = computeHash(messages[i - 1]!);
      messages.push({ id: `m${i}`, from: { agent_id: 'adversary' }, prev_hash: prevDigest });
    }
    return [...messages].reverse();
  }

  it(
    'rejects a rootless reverse-ordered orphan chain on the orphan alone, at one digest per message and zero finder visits',
    { timeout: LONG_TEST_TIMEOUT_MS },
    () => {
      const n = 32_000;
      // Built BEFORE the spy is installed, so construction's own computeHash
      // calls are not counted; the spy passes every call through to the real
      // digest.
      const smallChain = buildRootlessReverseChain(n);
      const largeChain = buildRootlessReverseChain(2 * n);
      const hashSpy = vi.spyOn(sessionModule, 'hashCanonicalBytes');
      const small = countVerify(smallChain, hashSpy);
      const large = countVerify(largeChain, hashSpy);

      // The orphan alone explains the rejection; findCycle never runs for
      // this shape, so the diagnosis is the plain orphan error at both sizes
      // and the finder's visit count is zero.
      expect(small.errors).toEqual([
        `transcript message ${n - 1} is an orphan: its prev_hash matches no presented message`,
      ]);
      expect(large.errors).toEqual([
        `transcript message ${2 * n - 1} is an orphan: its prev_hash matches no presented message`,
      ]);
      expect([small.finderVisits, large.finderVisits]).toEqual([0, 0]);
      // The whole cost of this shape is one digest per presented message.
      expect([small.digests, large.digests]).toEqual([n, 2 * n]);
    },
  );
});

describe('MAX_SET_BINDING_TRANSCRIPT_MESSAGES (2026-09-16 delta-11 gate, Codex P1 second half)', () => {
  // A transcript longer than any transcript a Concordia relay session could
  // ever legitimately produce is rejected by name before any per-message
  // hashing or chain-walking work runs.

  it('rejects a transcript over the cap by name before any walk', () => {
    // Each element only needs to be an object for the length check to fire
    // before reconstruction ever inspects one -- no real prev_hash chain,
    // and no computeHash call, is needed to prove the cap runs first.
    const n = MAX_SET_BINDING_TRANSCRIPT_MESSAGES + 1;
    const transcript = Array.from({ length: n }, (_, i) => ({ id: `m${i}` }));
    const receipt = { concordia_attestation: '0.5.0', chain_head: GENESIS_HASH, message_count: n };

    const result = verifyReceiptSetBinding(receipt, transcript);

    expect(result.state).toBe('error');
    expect(result.errors).toEqual([
      `transcript has ${n} messages, exceeding the maximum of ` +
        `${MAX_SET_BINDING_TRANSCRIPT_MESSAGES}`,
    ]);
  });

  it('does not reject a transcript at the cap for size', () => {
    // At exactly the cap, the size check must not fire; whatever this
    // transcript is rejected for (every element is rootless padding, so
    // multiple roots is the actual reason) has to be a DIFFERENT reason.
    const n = MAX_SET_BINDING_TRANSCRIPT_MESSAGES;
    const transcript = Array.from({ length: n }, (_, i) => ({ id: `m${i}` }));
    const receipt = { concordia_attestation: '0.5.0', chain_head: GENESIS_HASH, message_count: n };

    const result = verifyReceiptSetBinding(receipt, transcript);

    expect(result.state).toBe('error');
    expect(result.errors.some((e) => e.includes('exceeding the maximum'))).toBe(false);
  });

  // Cap BEFORE the snapshot (Codex P1, 2026-09-16 delta-12 gate): the
  // boundary snapshot is an O(n) traversal that throws on the first
  // accessor, so the order is observable from outside through an accessor
  // planted at element 0. Over the cap it must never be reached; at the cap
  // it must be (proving the cap is the only thing that stood before it).
  function transcriptWithAccessorAtZero(n: number): {
    transcript: Array<Record<string, unknown>>;
    getterReads: () => number;
  } {
    const transcript = Array.from({ length: n }, (_, i) => ({ id: `m${i}` }));
    let reads = 0;
    Object.defineProperty(transcript[0]!, 'id', {
      get() {
        reads += 1;
        return 'm0';
      },
      enumerable: true,
      configurable: true,
    });
    return { transcript, getterReads: () => reads };
  }

  it('checks the cap on the caller array BEFORE the snapshot: an over-cap transcript with an accessor at element 0 gets the named cap error, not a CanonicalizationError', () => {
    const n = MAX_SET_BINDING_TRANSCRIPT_MESSAGES + 1;
    const { transcript, getterReads } = transcriptWithAccessorAtZero(n);
    const receipt = { concordia_attestation: '0.5.0', chain_head: GENESIS_HASH, message_count: n };

    const result = verifyReceiptSetBinding(receipt, transcript);

    expect(result.state).toBe('error');
    expect(result.errors).toEqual([
      `transcript has ${n} messages, exceeding the maximum of ` +
        `${MAX_SET_BINDING_TRANSCRIPT_MESSAGES}`,
    ]);
    expect(getterReads()).toBe(0);
  });

  it('at exactly the cap the snapshot runs, so the same accessor at element 0 is refused by the snapshot', () => {
    const n = MAX_SET_BINDING_TRANSCRIPT_MESSAGES;
    const { transcript } = transcriptWithAccessorAtZero(n);
    const receipt = { concordia_attestation: '0.5.0', chain_head: GENESIS_HASH, message_count: n };

    expect(() => verifyReceiptSetBinding(receipt, transcript)).toThrow(CanonicalizationError);
  });

  it('reads the caller array length exactly once for the cap and never snapshots an over-cap array', () => {
    const target = Array.from({ length: MAX_SET_BINDING_TRANSCRIPT_MESSAGES + 1 }, (_, i) => ({
      id: `m${i}`,
    }));
    let lengthReads = 0;
    let ownKeysReads = 0;
    const proxied = new Proxy(target, {
      get(t, property, receiver) {
        if (property === 'length') lengthReads += 1;
        return Reflect.get(t, property, receiver);
      },
      ownKeys(t) {
        // The snapshot's single Object.getOwnPropertyDescriptors call is the
        // only thing that would invoke this trap.
        ownKeysReads += 1;
        return Reflect.ownKeys(t);
      },
    });
    const receipt = {
      concordia_attestation: '0.5.0',
      chain_head: GENESIS_HASH,
      message_count: target.length,
    };

    const result = verifyReceiptSetBinding(receipt, proxied);

    expect(result.errors).toEqual([
      `transcript has ${target.length} messages, exceeding the maximum of ` +
        `${MAX_SET_BINDING_TRANSCRIPT_MESSAGES}`,
    ]);
    expect(lengthReads).toBe(1);
    expect(ownKeysReads).toBe(0);
  });

  it('reads the caller array length exactly once on the accept path too (the snapshot observes the descriptor map, never `length` again)', () => {
    // Codex P1, 2026-09-17 delta-13 gate: the Python SDK read the length
    // twice (a truthiness test, then the cap); its fix and this test pin ONE
    // read in both languages, on the path that goes on to bind.
    const vector = loadVector('positive', 'pos-synthetic-receipt-set-binding-reconstruction');
    const { receipt, messages } = vectorPair(vector);
    let lengthReads = 0;
    let ownKeysReads = 0;
    const proxied = new Proxy(messages!, {
      get(t, property, receiver) {
        if (property === 'length') lengthReads += 1;
        return Reflect.get(t, property, receiver);
      },
      ownKeys(t) {
        ownKeysReads += 1;
        return Reflect.ownKeys(t);
      },
    });

    const result = verifyReceiptSetBinding(receipt, proxied);

    expect(result).toEqual({ state: 'bound', errors: [] });
    expect(lengthReads).toBe(1);
    // Exactly one descriptor-map observation: the boundary snapshot.
    expect(ownKeysReads).toBe(1);
  });
});

describe('MAX_SET_BINDING_TRANSCRIPT_MESSAGES is cross-pinned to every other literal (2026-09-16 delta-12 gate, Codex P2)', () => {
  // Four independent literals carry the cap (the two SDKs and the two
  // conformance reference runners, which import no SDK). This test and its
  // Python sibling (TestTranscriptCapIsCrossPinned in
  // tests/test_attestation_set_binding_reconstruction.py) each read all four
  // plus the shared fixture, so a one-sided edit fails CI in both languages.
  const REPO = join(__dirname, '..', '..');

  function literalIn(relPath: string, pattern: RegExp): number {
    const source = readFileSync(join(REPO, relPath), 'utf8');
    const match = pattern.exec(source);
    if (match === null)
      throw new Error(`${relPath}: MAX_SET_BINDING_TRANSCRIPT_MESSAGES not found`);
    return Number(match[1]!.replace(/_/g, ''));
  }

  it('equals the shared fixture, the Python SDK, and both reference runners', () => {
    const fixture = JSON.parse(
      readFileSync(join(REPO, 'tests', 'fixtures', 'set_binding_limits.json'), 'utf8'),
    ) as { max_set_binding_transcript_messages: number };
    expect(MAX_SET_BINDING_TRANSCRIPT_MESSAGES).toBe(fixture.max_set_binding_transcript_messages);
    expect(
      literalIn('concordia/attestation.py', /^MAX_SET_BINDING_TRANSCRIPT_MESSAGES = ([\d_]+)$/m),
    ).toBe(MAX_SET_BINDING_TRANSCRIPT_MESSAGES);
    expect(
      literalIn(
        'conformance/reference-runner-js/runner.mjs',
        /^const MAX_SET_BINDING_TRANSCRIPT_MESSAGES = ([\d_]+);$/m,
      ),
    ).toBe(MAX_SET_BINDING_TRANSCRIPT_MESSAGES);
    expect(
      literalIn(
        'conformance/reference-runner/runner.py',
        /^MAX_SET_BINDING_TRANSCRIPT_MESSAGES = ([\d_]+)$/m,
      ),
    ).toBe(MAX_SET_BINDING_TRANSCRIPT_MESSAGES);
  });
});
