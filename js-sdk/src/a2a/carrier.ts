import { validateMessage } from '../validation/schema-validator.js';

export const A2A_EXTENSION_URI = 'https://concordiaprotocol.dev/a2a-ext/negotiation/v1';
export const A2A_CARRIER_TYPE = `${A2A_EXTENSION_URI}#envelope`;
export const A2A_CARRIER_VERSION = '1';
export const A2A_CARRIER_SCHEMA_URI = `${A2A_EXTENSION_URI}/schema/data-part.json`;
export const A2A_CARRIER_MEDIA_TYPE = 'application/vnd.concordia.negotiation+json';

const DATA_KEYS = new Set(['type', 'version', 'envelope']);
const A2A_CONTENT_KEYS = ['text', 'raw', 'url'];
const A2A_ID_KEYS = ['taskId', 'contextId', 'task_id', 'context_id'];

export type ConcordiaEnvelope = Record<string, unknown>;

export interface A2ADataPart {
  data: {
    type: string;
    version: string;
    envelope: ConcordiaEnvelope;
  };
  metadata: Record<string, { schema: string } | unknown>;
  mediaType: string;
  [key: string]: unknown;
}

export class A2ACarrierError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'A2ACarrierError';
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: ReadonlySet<string>): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.size && actual.every((key) => keys.has(key));
}

function validateEnvelope(envelope: unknown): ConcordiaEnvelope {
  if (!isRecord(envelope)) {
    throw new A2ACarrierError('invalid envelope: expected an object');
  }
  if (A2A_ID_KEYS.some((key) => Object.hasOwn(envelope, key))) {
    throw new A2ACarrierError('invalid envelope: A2A identifiers belong outside signed bytes');
  }
  if (validateMessage(envelope).length > 0) {
    throw new A2ACarrierError('invalid envelope: Concordia message validation failed');
  }
  return envelope;
}

export function buildA2ADataPart(envelope: ConcordiaEnvelope): A2ADataPart {
  const validated = validateEnvelope(envelope);
  return {
    data: {
      type: A2A_CARRIER_TYPE,
      version: A2A_CARRIER_VERSION,
      envelope: structuredClone(validated),
    },
    metadata: {
      [A2A_EXTENSION_URI]: {
        schema: A2A_CARRIER_SCHEMA_URI,
      },
    },
    mediaType: A2A_CARRIER_MEDIA_TYPE,
  };
}

export function parseA2ADataPart(
  part: unknown,
  activeExtensions: readonly string[],
): ConcordiaEnvelope {
  if (!activeExtensions.includes(A2A_EXTENSION_URI)) {
    throw new A2ACarrierError('Concordia A2A extension is not active');
  }
  if (!isRecord(part)) {
    throw new A2ACarrierError('invalid A2A part: expected an object');
  }
  if (A2A_CONTENT_KEYS.some((key) => Object.hasOwn(part, key))) {
    throw new A2ACarrierError('invalid A2A part: conflicting content member');
  }
  if (part.mediaType !== A2A_CARRIER_MEDIA_TYPE) {
    throw new A2ACarrierError('invalid A2A part mediaType');
  }

  const data = part.data;
  if (!isRecord(data)) {
    throw new A2ACarrierError('invalid A2A part data');
  }
  if (!hasExactKeys(data, DATA_KEYS)) {
    throw new A2ACarrierError('invalid A2A part data members');
  }
  if (data.type !== A2A_CARRIER_TYPE) {
    throw new A2ACarrierError('invalid A2A carrier type');
  }
  if (data.version !== A2A_CARRIER_VERSION) {
    throw new A2ACarrierError('invalid A2A carrier version');
  }

  const metadata = part.metadata;
  if (!isRecord(metadata)) {
    throw new A2ACarrierError('invalid A2A carrier metadata');
  }
  const extensionMetadata = metadata[A2A_EXTENSION_URI];
  if (!isRecord(extensionMetadata)) {
    throw new A2ACarrierError('invalid A2A carrier metadata');
  }
  if (!hasExactKeys(extensionMetadata, new Set(['schema']))) {
    throw new A2ACarrierError('invalid A2A carrier metadata members');
  }
  if (extensionMetadata.schema !== A2A_CARRIER_SCHEMA_URI) {
    throw new A2ACarrierError('invalid A2A carrier schema');
  }

  return structuredClone(validateEnvelope(data.envelope));
}
