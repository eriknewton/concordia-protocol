import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import {
  A2A_CARRIER_MEDIA_TYPE,
  A2A_CARRIER_SCHEMA_URI,
  A2A_CARRIER_TYPE,
  A2A_CARRIER_VERSION,
  A2A_EXTENSION_URI,
  A2ACarrierError,
  buildA2ADataPart,
  parseA2ADataPart,
  type A2ADataPart,
} from '../src/a2a/carrier.js';

const fixturePath = fileURLToPath(
  new URL('../../docs/interop/a2a-negotiation-carrier-v1/part.json', import.meta.url),
);

function fixture(): A2ADataPart {
  return JSON.parse(readFileSync(fixturePath, 'utf8')) as A2ADataPart;
}

describe('A2A negotiation carrier v1', () => {
  it('consumes the shared fixture as the exact cross-language contract', () => {
    const part = fixture();
    const envelope = structuredClone(part.data.envelope);

    expect(buildA2ADataPart(envelope)).toEqual(part);
    expect(parseA2ADataPart(part, [A2A_EXTENSION_URI])).toEqual(envelope);
    expect(part.data.type).toBe(A2A_CARRIER_TYPE);
    expect(part.data.version).toBe(A2A_CARRIER_VERSION);
    expect(part.mediaType).toBe(A2A_CARRIER_MEDIA_TYPE);
    expect(part.metadata[A2A_EXTENSION_URI]).toEqual({ schema: A2A_CARRIER_SCHEMA_URI });
  });

  it('does not alias input or parsed objects', () => {
    const source = fixture();
    const envelope = structuredClone(source.data.envelope);
    const part = buildA2ADataPart(envelope);
    const body = envelope.body as { terms: { delivery_days: { value: number } } };
    body.terms.delivery_days.value = 99;
    expect(
      (part.data.envelope.body as { terms: { delivery_days: { value: number } } }).terms
        .delivery_days.value,
    ).toBe(7);

    const parsed = parseA2ADataPart(part, [A2A_EXTENSION_URI]);
    parsed.session_id = 'tampered';
    expect(part.data.envelope.session_id).toBe('ses_a2a_carrier_0001');
  });

  it('requires explicit activation', () => {
    for (const active of [[], ['https://example.test/other/v1']]) {
      expect(() => parseA2ADataPart(fixture(), active)).toThrow(/extension is not active/);
    }
  });

  it.each([
    [
      'conflicting content',
      (p: Record<string, unknown>) => (p.text = 'conflict'),
      /content member/,
    ],
    [
      'wrong media type',
      (p: Record<string, unknown>) => (p.mediaType = 'application/json'),
      /mediaType/,
    ],
    ['wrong type', (p: A2ADataPart) => (p.data.type = 'wrong'), /type/],
    ['wrong version', (p: A2ADataPart) => (p.data.version = '2'), /version/],
    ['extra data', (p: A2ADataPart) => Object.assign(p.data, { extra: true }), /data members/],
    ['missing metadata', (p: A2ADataPart) => delete p.metadata[A2A_EXTENSION_URI], /metadata/],
    [
      'wrong schema',
      (p: A2ADataPart) => (p.metadata[A2A_EXTENSION_URI] = { schema: 'wrong' }),
      /schema/,
    ],
    ['invalid envelope', (p: A2ADataPart) => delete p.data.envelope.signature, /invalid envelope/],
  ])('rejects %s', (_name, mutate, expected) => {
    const part = fixture();
    (mutate as (part: A2ADataPart & Record<string, unknown>) => void)(part);
    expect(() => parseA2ADataPart(part, [A2A_EXTENSION_URI])).toThrow(expected as RegExp);
  });

  it('never treats A2A task or context identifiers as the Concordia session id', () => {
    const part = fixture();
    part.metadata.a2a = { taskId: 'task-other', contextId: 'ctx-other' };
    const envelope = parseA2ADataPart(part, [A2A_EXTENSION_URI]);
    expect(envelope.session_id).toBe('ses_a2a_carrier_0001');
    expect(envelope).not.toHaveProperty('taskId');
    expect(envelope).not.toHaveProperty('contextId');
  });

  it.each(['taskId', 'contextId', 'task_id', 'context_id'])(
    'refuses carrier identifier %s inside the signed envelope',
    (a2aId) => {
      const part = fixture();
      part.data.envelope[a2aId] = 'carrier-owned';
      expect(() => parseA2ADataPart(part, [A2A_EXTENSION_URI])).toThrow(
        /A2A identifiers belong outside signed bytes/,
      );
    },
  );

  it('does not echo untrusted values in errors', () => {
    const sentinel = 'SECRET-SENTINEL-DO-NOT-ECHO';
    const part = fixture();
    part.data.envelope.type = sentinel;
    try {
      parseA2ADataPart(part, [A2A_EXTENSION_URI]);
      throw new Error('expected parse to fail');
    } catch (error) {
      expect(error).toBeInstanceOf(A2ACarrierError);
      expect(String(error)).not.toContain(sentinel);
    }
  });
});
