import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { parseJsonStrict } from '../src/canonical/parse.js';
import { CanonicalizationError } from '../src/canonical/checks.js';
import {
  canonicalizeJcs,
  canonicalizePredicate,
} from '../src/canonical/canonicalize.js';
import {
  sign,
  verify,
  signJson,
  verifyJson,
  generateKeyPair,
  SigningError,
} from '../src/crypto/signing.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

describe('parseJsonStrict - rejects bare unsafe integer literals at ingest', () => {
  // The corner the canonicalizer guard cannot close: a bare integer >= ~1e21
  // written in PLAIN DECIMAL parses to a JS double that String()s as
  // EXPONENTIAL, slipping past the post-parse guard, while a Python peer holding
  // it as an int emits full decimal -> canonical-bytes divergence. The
  // parse-boundary scan reads the SOURCE literal, before the lossy double, and
  // rejects it.
  it('rejects a bare 21-digit integer as the whole document', () => {
    expect(() => parseJsonStrict('123456789012345678901')).toThrow(
      CanonicalizationError,
    );
  });

  it('rejects a bare 21-digit integer nested in an object', () => {
    expect(() =>
      parseJsonStrict('{"limit":123456789012345678901}'),
    ).toThrow(CanonicalizationError);
  });

  it('rejects a bare 21-digit integer nested in an array', () => {
    expect(() =>
      parseJsonStrict('{"xs":[1,123456789012345678901,2]}'),
    ).toThrow(CanonicalizationError);
  });

  it('rejects 9007199254740993 (2^53 + 1, the canonical 16-17 digit example)', () => {
    expect(() => parseJsonStrict('{"x":9007199254740993}')).toThrow(
      CanonicalizationError,
    );
  });

  it('rejects 9007199254740992 (2^53 itself, the first unsafe integer)', () => {
    expect(() => parseJsonStrict('{"x":9007199254740992}')).toThrow(
      CanonicalizationError,
    );
  });

  it('rejects a large negative unsafe integer', () => {
    expect(() => parseJsonStrict('{"x":-9007199254740993}')).toThrow(
      CanonicalizationError,
    );
  });

  it('rejects a 20-digit plain-decimal integer', () => {
    expect(() => parseJsonStrict('{"x":12345678901234567890}')).toThrow(
      CanonicalizationError,
    );
  });

  it('rejects an unsafe integer nested deep in the structure', () => {
    expect(() =>
      parseJsonStrict('{"a":{"b":[{"c":123456789012345678901}]}}'),
    ).toThrow(CanonicalizationError);
  });

  it('error names the offending literal and points to the string escape hatch', () => {
    try {
      parseJsonStrict('{"x":123456789012345678901}');
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(CanonicalizationError);
      const message = (err as Error).message;
      // The exact source literal is reported (not the lossy/exponential double).
      expect(message).toContain('123456789012345678901');
      expect(message).toContain('JSON strings');
    }
  });
});

describe('parseJsonStrict - accepts safe integers and all float forms', () => {
  it('accepts Number.MAX_SAFE_INTEGER (2^53 - 1) and preserves it', () => {
    const out = parseJsonStrict('{"x":9007199254740991}') as {
      x: number;
    };
    expect(out.x).toBe(9007199254740991);
  });

  it('accepts small safe integers (including negatives and zero)', () => {
    expect(parseJsonStrict('{"x":42,"y":-1,"z":0}')).toEqual({
      x: 42,
      y: -1,
      z: 0,
    });
  });

  it('accepts non-integer floats unchanged', () => {
    expect(parseJsonStrict('{"a":1.5,"b":-3.25}')).toEqual({
      a: 1.5,
      b: -3.25,
    });
  });

  it('accepts large exponential floats (the 1e+30 / 1e+21 parity band)', () => {
    expect(parseJsonStrict('{"x":1e+30}')).toEqual({ x: 1e30 });
    expect(parseJsonStrict('{"x":1e21}')).toEqual({ x: 1e21 });
  });

  it('accepts negative and fractional exponential floats', () => {
    expect(parseJsonStrict('{"a":-2.5e-9,"b":6.022E23}')).toEqual({
      a: -2.5e-9,
      b: 6.022e23,
    });
  });
});

describe('parseJsonStrict - the legitimate 1e30 float still round-trips', () => {
  // This is the case the parse boundary must NOT break: an exponential float is
  // parity-safe (Python parses it as a float and emits the byte-identical
  // exponential string), so it passes ingest and canonicalizes to 1e+30.
  it('parses then canonicalizes 1e30 to 1e+30', () => {
    const parsed = parseJsonStrict('{"x":1e30}');
    expect(canonicalizeJcs(parsed).toString('utf8')).toBe('{"x":1e+30}');
  });

  it('parses the already-exponential 1e+30 source identically', () => {
    const parsed = parseJsonStrict('{"limit":1e+30,"result":"satisfied"}');
    expect(canonicalizeJcs(parsed).toString('utf8')).toBe(
      '{"limit":1e+30,"result":"satisfied"}',
    );
  });

  it('round-trips predicate fixture vector_08 (real Python-sourced 1e+30) via parseJsonStrict', () => {
    // vector_08's condition.limit is 1e+30. Ingesting the fixture through the
    // hardened parse and canonicalizing must reproduce the byte-identical
    // fixture -- proving the parse boundary leaves the legitimate large float
    // untouched.
    const expectedPath = join(
      __dirname,
      'fixtures/predicate_canonical/vector_08/expected_canonical.txt',
    );
    const expectedRaw = readFileSync(expectedPath, 'utf8').replace(/\n$/, '');
    const predicate = parseJsonStrict(expectedRaw) as Record<string, unknown>;
    expect(canonicalizePredicate(predicate).toString('utf8')).toBe(expectedRaw);
  });
});

describe('parseJsonStrict + canonicalizeJcs - layered defense, no fail-open gap', () => {
  // 1e20 sits in the seam between the two layers: written exponentially in
  // source, so the parse scan treats it as float-form and lets it through;
  // but it String()s as plain decimal ("100000000000000000000"), so the
  // downstream canonicalizer guard rejects it. The point is that nothing in the
  // seam is silently ACCEPTED with divergent bytes -- a value the parse scan
  // does not reject is still caught at canonicalization. Both layers fail
  // closed; neither falls open.
  it('1e20 passes ingest but is still rejected at canonicalization', () => {
    const parsed = parseJsonStrict('{"x":1e20}'); // exponential source: allowed
    expect(() => canonicalizeJcs(parsed)).toThrow(CanonicalizationError);
  });

  it('a plain-decimal 1e20 (21 digits, no exponent) is rejected at ingest', () => {
    expect(() =>
      parseJsonStrict('{"x":100000000000000000000}'),
    ).toThrow(CanonicalizationError);
  });
});

describe('parseJsonStrict - big integers carried as strings (the escape hatch)', () => {
  it('accepts a 21-digit integer carried as a JSON string', () => {
    const out = parseJsonStrict('{"id":"123456789012345678901"}') as {
      id: string;
    };
    expect(out.id).toBe('123456789012345678901');
  });

  it('canonicalizes a string-carried big integer identically', () => {
    const parsed = parseJsonStrict('{"id":"9007199254740993"}');
    expect(canonicalizeJcs(parsed).toString('utf8')).toBe(
      '{"id":"9007199254740993"}',
    );
  });

  it('does not misread a big integer embedded in string text', () => {
    expect(() =>
      parseJsonStrict('{"note":"limit is 123456789012345678901 units"}'),
    ).not.toThrow();
  });

  it('does not misread a big integer after an escaped quote inside a string', () => {
    // Source: {"a":"\"123456789012345678901"} -- the digits live inside the
    // string, after an escaped quote, and must not be inspected as a number.
    expect(() =>
      parseJsonStrict('{"a":"\\"123456789012345678901"}'),
    ).not.toThrow();
  });

  it('does not misread a big-integer-looking object KEY (keys are strings)', () => {
    expect(() =>
      parseJsonStrict('{"123456789012345678901":1}'),
    ).not.toThrow();
  });
});

describe('parseJsonStrict - input validation', () => {
  it('propagates a native SyntaxError for malformed JSON (not a CanonicalizationError)', () => {
    expect(() => parseJsonStrict('{not valid json')).toThrow(SyntaxError);
    expect(() => parseJsonStrict('{not valid json')).not.toThrow(
      CanonicalizationError,
    );
  });

  it('throws CanonicalizationError for a non-string argument', () => {
    // @ts-expect-error -- exercising the runtime guard on a wrong-typed call.
    expect(() => parseJsonStrict(123)).toThrow(CanonicalizationError);
  });

  it('accepts bare safe-integer and string documents', () => {
    expect(parseJsonStrict('42')).toBe(42);
    expect(parseJsonStrict('"123456789012345678901"')).toBe(
      '123456789012345678901',
    );
  });
});

describe('signJson / verifyJson - hardened signing-ingest entry points', () => {
  it('signs JSON identically to signing the parsed object (no canonical drift)', () => {
    const kp = generateKeyPair();
    const obj = { message_type: 'OFFER', amount: 7, nested: { b: 2, a: 1 } };
    const json = JSON.stringify(obj);
    expect(signJson(json, kp)).toBe(sign(obj, kp));
  });

  it('round-trips: signJson then verifyJson over the same JSON text', () => {
    const kp = generateKeyPair();
    const json = '{"message_type":"ACCEPT","amount":3}';
    const sig = signJson(json, kp);
    expect(verifyJson(json, sig, kp.publicKey)).toBe(true);
  });

  it('interoperates across the object and JSON paths in both directions', () => {
    const kp = generateKeyPair();
    const obj = { message_type: 'OFFER', amount: 5 };
    const json = JSON.stringify(obj);
    // object-signed -> JSON-verified
    expect(verifyJson(json, sign(obj, kp), kp.publicKey)).toBe(true);
    // JSON-signed -> object-verified
    expect(verify(obj, signJson(json, kp), kp.publicKey)).toBe(true);
  });

  it('signJson rejects a bare unsafe integer literal (fail-closed at signing)', () => {
    const kp = generateKeyPair();
    expect(() =>
      signJson('{"amount":123456789012345678901}', kp),
    ).toThrow(CanonicalizationError);
  });

  it('signJson rejects a non-object top-level JSON value', () => {
    const kp = generateKeyPair();
    expect(() => signJson('42', kp)).toThrow(SigningError);
    expect(() => signJson('[1,2,3]', kp)).toThrow(SigningError);
  });

  it('verifyJson throws (fail-closed) on a bare unsafe integer literal', () => {
    const kp = generateKeyPair();
    const sig = sign({ amount: 1 }, kp);
    expect(() =>
      verifyJson('{"amount":123456789012345678901}', sig, kp.publicKey),
    ).toThrow(CanonicalizationError);
  });

  it('verifyJson returns false (does not throw) on a bad signature', () => {
    const kp = generateKeyPair();
    expect(
      verifyJson('{"message_type":"OFFER"}', 'not-a-signature', kp.publicKey),
    ).toBe(false);
  });

  it('verifyJson returns false for a tampered payload under a valid signature', () => {
    const kp = generateKeyPair();
    const sig = signJson('{"amount":3}', kp);
    expect(verifyJson('{"amount":4}', sig, kp.publicKey)).toBe(false);
  });

  it('verifyJson returns false for a non-object top-level JSON value', () => {
    const kp = generateKeyPair();
    const sig = sign({ a: 1 }, kp);
    expect(verifyJson('42', sig, kp.publicKey)).toBe(false);
  });
});
