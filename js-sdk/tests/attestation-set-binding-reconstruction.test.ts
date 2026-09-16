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

import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

import { GENESIS_HASH, computeHash } from '../src/session/index.js';
import { verifyReceiptSetBinding } from '../src/attestation/index.js';
import { canonicalizeJcs } from '../src/canonical/canonicalize.js';
import { CanonicalizationError } from '../src/canonical/checks.js';

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

  it('rejects a set with no root message', () => {
    // The fixture is presented shuffled (not chain order), so the root is
    // wherever prev_hash === GENESIS_HASH lands, never necessarily index 0.
    const messages = base.messages!;
    const withoutRoot = messages.filter((message) => message.prev_hash !== GENESIS_HASH);
    expect(withoutRoot.length).toBe(messages.length - 1);
    const result = verifyReceiptSetBinding(base.receipt, withoutRoot);

    expect(result.state).toBe('error');
    expect(result.errors.some((e) => e.includes('no root message'))).toBe(true);
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
