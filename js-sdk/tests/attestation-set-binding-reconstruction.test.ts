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

  it('does not consume a prev_hash inherited through the prototype chain', () => {
    // 2026-09-16 delta-5 gate: canonicalizeJcs now refuses any object whose
    // prototype is not Object.prototype or null, before stableStringify ever
    // reaches Object.keys (see rejectForeignPrototype, canonicalize.ts). An
    // object built via Object.create(proto) -- the shape this test
    // constructs below -- can no longer be canonicalized AT ALL, so its
    // inherited prev_hash is categorically unreachable rather than merely
    // unconsulted. This supersedes the previous version of this test, which
    // built a self-consistent multi-message phantom chain by calling
    // computeHash on each PRIOR phantom message to link the next one; that
    // construction itself now throws (computeHash is canonicalizeJcs), so a
    // single non-root message making the same claim is enough to prove the
    // channel is closed, and closed earlier than the root/no-root
    // determination the previous version observed.
    const messages = base.messages!;
    const root = messages.find((message) => message.prev_hash === GENESIS_HASH);
    if (!root) throw new Error('fixture has no genesis-root message');
    const other = messages.find((message) => message !== root)!;
    const { prev_hash: _dropped, ...restFields } = other;
    // The link is offered SOLELY through the prototype: `linked` has no own
    // `prev_hash` at all, only an inherited one.
    const linked = Object.assign(
      Object.create({ prev_hash: computeHash(root) }) as Msg,
      restFields,
    );
    // Precondition the construction depends on, not an assertion about the
    // code under test.
    expect(Object.prototype.hasOwnProperty.call(linked, 'prev_hash')).toBe(false);
    expect(linked.prev_hash).toBeDefined();

    // The receipt's fields are never inspected: the rejection fires while
    // reconstructSingleChain canonicalizes each message, before
    // message_count or chain_head is compared against anything.
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

  it('does not consume a prev_hash injected by a toJSON inherited through the prototype chain', () => {
    // Combines the prototype-chain channel with the toJSON channel: the
    // fabricated link is reachable only by looking up `toJSON` through the
    // prototype AND calling it, which `JSON.stringify` does and
    // `stableStringify`'s `Object.keys` walk never does either way. 2026-09-16
    // delta-5 gate: canonicalizeJcs now refuses this object's foreign
    // prototype outright (see rejectForeignPrototype, canonicalize.ts),
    // before stableStringify would even get to not-calling toJSON -- a
    // strictly earlier rejection than the previous version of this test
    // observed. As in the sibling prototype-chain test above, a
    // self-consistent multi-message phantom chain can no longer be built
    // here (computeHash on a PRIOR phantom message now throws), so a single
    // non-root message is enough to prove the channel is closed.
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
