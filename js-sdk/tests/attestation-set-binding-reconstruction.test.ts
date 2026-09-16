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
    const messages = base.messages!;
    // Rebuild the chain from scratch rather than reusing the fixture's own
    // links: computeHash only ever sees OWN enumerable properties (see
    // `canonicalizeJcs` -> `stableStringify`, which walks `Object.keys`), so
    // dropping a message's own `prev_hash` while leaving its other fields
    // untouched changes that message's digest -- an `in`-based reconstruction
    // would then orphan on the very first hop, passing this test whether or
    // not the vulnerable check is fixed (this is why the original version of
    // this test could not distinguish the two implementations). To isolate
    // root detection as the only variable, each non-root message here is
    // reconstructed with no own `prev_hash` at all, and the link is offered
    // solely through the prototype, set to the CORRECTLY recomputed hash of
    // the preceding phantom message -- so the chain is internally
    // self-consistent and only the root/no-root determination differs.
    // Mirrors the reproduction probe from the 2026-09-16 Codex delta gate
    // (Review/Concordia/PR243_Gate_2026-09-16/OUT_delta_codex.txt).
    const phantom: Msg[] = [{ ...messages[0]! }];
    for (const original of messages.slice(1)) {
      const { prev_hash: _dropped, ...rest } = original;
      const linked = Object.assign(
        Object.create({ prev_hash: computeHash(phantom[phantom.length - 1]!) }) as Msg,
        rest,
      );
      phantom.push(linked);
    }
    // Every non-root phantom message truly has no own prev_hash: this is the
    // precondition the whole construction depends on, not an assertion about
    // the code under test.
    for (const message of phantom.slice(1)) {
      expect(Object.prototype.hasOwnProperty.call(message, 'prev_hash')).toBe(false);
      expect(message.prev_hash).toBeDefined();
    }
    const receipt = {
      ...base.receipt,
      message_count: phantom.length,
      chain_head: computeHash(phantom[phantom.length - 1]!),
    };

    // An `in`-based check reads the inherited link, walks a chain that
    // genuinely reconstructs (every digest matches), and returns "bound" --
    // a real fail-open, not a cosmetic one. The own-property check must
    // treat every non-root phantom message as a second root instead.
    const result = verifyReceiptSetBinding(receipt, phantom);
    expect(result.state).not.toBe('bound');
    expect(result.state).toBe('error');
    expect(result.errors.some((e) => e.includes('root messages'))).toBe(true);
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
