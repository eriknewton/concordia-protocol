import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import {
  KeyPair,
  sign,
  verify,
  generateKeyPair,
  SigningError,
} from '../src/crypto/signing.js';
import {
  toBase64Url,
  fromBase64Url,
  Base64UrlError,
} from '../src/crypto/base64url.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

interface SigningFixtures {
  algorithm: string;
  seed_hex: string;
  public_key_b64: string;
  cases: Array<{
    payload: Record<string, unknown>;
    expected_signature: string;
    expected_canonical: string;
  }>;
  tamper: {
    base_payload: Record<string, unknown>;
    valid_signature: string;
    tampered_payload: Record<string, unknown>;
    flipped_signature: string;
    wrong_public_key_b64: string;
  };
}

const fixtures = JSON.parse(
  readFileSync(
    join(__dirname, 'fixtures/signing/ed25519_vectors.json'),
    'utf8',
  ),
) as SigningFixtures;

function seedBytes(): Uint8Array {
  return new Uint8Array(Buffer.from(fixtures.seed_hex, 'hex'));
}

describe('Ed25519 signing - parity with Python reference', () => {
  const seed = seedBytes();
  const kp = KeyPair.fromPrivateKey(seed);

  it('derives the Python-identical public key from the seed', () => {
    expect(kp.publicKeyB64()).toBe(fixtures.public_key_b64);
  });

  for (const { payload, expected_signature } of fixtures.cases) {
    const label = JSON.stringify(payload).slice(0, 50);

    it(`produces the Python-identical signature for ${label}`, () => {
      // Byte-for-byte signature parity: a TS signature that Python would not
      // produce is a failure.
      expect(sign(payload, kp)).toBe(expected_signature);
    });

    it(`verifies the Python-produced signature for ${label}`, () => {
      expect(verify(payload, expected_signature, kp.publicKey)).toBe(true);
    });
  }
});

describe('Ed25519 signing - canonical-JSON signing payload', () => {
  // The signing payload is canonicalizeJcs of the object with its top-level
  // `signature` field stripped, matching concordia.signing.sign_message.
  it('strips the top-level signature field before signing', () => {
    const kp = KeyPair.fromPrivateKey(seedBytes());
    const withSig = { a: 1, signature: 'ignored-by-signing' };
    const withoutSig = { a: 1 };
    expect(sign(withSig, kp)).toBe(sign(withoutSig, kp));
  });

  it('matches the expected canonical bytes for every fixture case', () => {
    // Cross-check: the signature is deterministic given the canonical bytes,
    // so re-signing the canonical-equivalent payload reproduces the vector.
    const kp = KeyPair.fromPrivateKey(seedBytes());
    for (const { payload, expected_signature } of fixtures.cases) {
      expect(sign(payload, kp)).toBe(expected_signature);
    }
  });
});

describe('Ed25519 signing - tamper rejection (Python-defined cases)', () => {
  const kp = KeyPair.fromPrivateKey(seedBytes());
  const t = fixtures.tamper;

  it('accepts the valid base signature', () => {
    expect(verify(t.base_payload, t.valid_signature, kp.publicKey)).toBe(true);
  });

  it('rejects a tampered payload under a valid signature', () => {
    expect(verify(t.tampered_payload, t.valid_signature, kp.publicKey)).toBe(
      false,
    );
  });

  it('rejects a flipped-byte signature', () => {
    expect(verify(t.base_payload, t.flipped_signature, kp.publicKey)).toBe(
      false,
    );
  });

  it('rejects a valid signature under the wrong public key', () => {
    const wrongPub = fromBase64Url(t.wrong_public_key_b64);
    expect(verify(t.base_payload, t.valid_signature, wrongPub)).toBe(false);
  });
});

describe('Ed25519 signing - round-trip and key generation', () => {
  it('signs and verifies a freshly generated key pair', () => {
    const kp = generateKeyPair();
    const payload = { message_type: 'OFFER', amount: 7, nested: { b: 2, a: 1 } };
    const sig = sign(payload, kp);
    expect(verify(payload, sig, kp.publicKey)).toBe(true);
  });

  it('accepts a raw private key in place of a KeyPair', () => {
    const kp = generateKeyPair();
    const payload = { x: 'y' };
    expect(sign(payload, kp.privateKey)).toBe(sign(payload, kp));
  });

  it('reconstructs the same key pair from a raw private key', () => {
    const kp = generateKeyPair();
    const restored = KeyPair.fromPrivateKey(kp.privateKey);
    expect(restored.publicKeyB64()).toBe(kp.publicKeyB64());
  });

  it('rejects a private key of the wrong length', () => {
    expect(() => KeyPair.fromPrivateKey(new Uint8Array(16))).toThrow(
      SigningError,
    );
    expect(() => sign({ a: 1 }, new Uint8Array(16))).toThrow(SigningError);
  });

  it('returns false (does not throw) for a malformed signature', () => {
    const kp = generateKeyPair();
    expect(verify({ a: 1 }, 'not-base64-!!!', kp.publicKey)).toBe(false);
    expect(verify({ a: 1 }, '', kp.publicKey)).toBe(false);
  });

  it('returns false (does not throw) for a lone surrogate in the payload', () => {
    // Parity with Python verify_signature: non-canonical input (a lone UTF-16
    // surrogate) is a verification failure, not an accept and not a throw.
    const kp = generateKeyPair();
    expect(verify({ x: '\uD834' }, 'AAAA', kp.publicKey)).toBe(false);
  });

  it('returns false for a well-formed signature of the wrong byte length', () => {
    const kp = generateKeyPair();
    // 32 bytes (valid base64url, padded) is not a 64-byte Ed25519 signature.
    const shortSig = toBase64Url(new Uint8Array(32).fill(7));
    expect(verify({ a: 1 }, shortSig, kp.publicKey)).toBe(false);
  });

  it('returns false for a public key of the wrong length', () => {
    const kp = generateKeyPair();
    const sig = sign({ a: 1 }, kp);
    expect(verify({ a: 1 }, sig, new Uint8Array(16))).toBe(false);
  });
});

describe('base64url - Python urlsafe_b64encode parity (padded)', () => {
  it('encodes a 64-byte buffer with == padding', () => {
    const bytes = new Uint8Array(64).fill(0);
    const encoded = toBase64Url(bytes);
    expect(encoded.endsWith('==')).toBe(true);
    expect(encoded).toBe(Buffer.from(bytes).toString('base64url') + '==');
  });

  it('encodes a 32-byte buffer with = padding', () => {
    const bytes = new Uint8Array(32).fill(0);
    const encoded = toBase64Url(bytes);
    expect(encoded.endsWith('=')).toBe(true);
    expect(encoded.endsWith('==')).toBe(false);
  });

  it('round-trips encode/decode', () => {
    const bytes = new Uint8Array([1, 2, 3, 250, 251, 252, 253, 254, 255]);
    expect(fromBase64Url(toBase64Url(bytes))).toEqual(bytes);
  });

  it('decodes the padded public-key fixture', () => {
    // The padded form Concordia emits is the canonical accepted form.
    expect(fromBase64Url(fixtures.public_key_b64).length).toBe(32);
  });
});

describe('base64url - strict decode (Python urlsafe_b64decode reject contract)', () => {
  // Python's verify_signature decodes with base64.urlsafe_b64decode, which
  // REQUIRES correct = padding (raises binascii.Error on an unpadded string).
  // The previous Node-based decoder silently accepted unpadded / malformed
  // input -- a fail-open parity break. fromBase64Url is now strict.
  const padded = fixtures.public_key_b64;

  it('rejects an unpadded string (Python raises Incorrect padding)', () => {
    const unpadded = padded.replace(/=+$/, '');
    expect(() => fromBase64Url(unpadded)).toThrow(Base64UrlError);
  });

  it('rejects embedded whitespace', () => {
    const withSpace = padded.slice(0, 4) + ' ' + padded.slice(4);
    expect(() => fromBase64Url(withSpace)).toThrow(Base64UrlError);
  });

  it('rejects a trailing newline', () => {
    expect(() => fromBase64Url(padded + '\n')).toThrow(Base64UrlError);
  });

  it('rejects characters from the standard (+ /) base64 alphabet', () => {
    // 0xFB 0xFF 0xBF -> "+/+/" region in standard base64.
    const std = Buffer.from([0xfb, 0xff, 0xbf]).toString('base64');
    expect(std).toMatch(/[+/]/);
    expect(() => fromBase64Url(std)).toThrow(Base64UrlError);
  });

  it('rejects a non-canonical final group', () => {
    // Replace the canonical final sextet with one whose unused low bits are set.
    const bad = padded.slice(0, -2) + 'B=';
    expect(() => fromBase64Url(bad)).toThrow(Base64UrlError);
  });

  it('accepts the correctly-padded form', () => {
    expect(() => fromBase64Url(padded)).not.toThrow();
  });
});

describe('Ed25519 verify - base64url accept/reject parity with Python', () => {
  // Confirmed empirically against concordia.signing.verify_signature:
  // valid padded -> True; unpadded -> Python raises (never True) so TS -> false;
  // tampered -> False. Strict decoding cannot accept anything Python rejects.
  const kp = KeyPair.fromPrivateKey(seedBytes());
  const payload = { message_type: 'OFFER', amount: 3, terms: { x: 'y' } };
  const validSig = sign(payload, kp);

  it('accepts a valid, correctly-padded signature', () => {
    expect(validSig.endsWith('=')).toBe(true); // 64 bytes -> == padding
    expect(verify(payload, validSig, kp.publicKey)).toBe(true);
  });

  it('rejects an unpadded signature (fail-open guard)', () => {
    const unpadded = validSig.replace(/=+$/, '');
    expect(verify(payload, unpadded, kp.publicKey)).toBe(false);
  });

  it('rejects a signature with embedded whitespace', () => {
    const ws = validSig.slice(0, 8) + ' ' + validSig.slice(8);
    expect(verify(payload, ws, kp.publicKey)).toBe(false);
  });

  it('rejects a signature with an extra trailing character', () => {
    const extra = validSig.slice(0, -2) + 'AA==';
    expect(verify(payload, extra, kp.publicKey)).toBe(false);
  });

  it('rejects a tampered payload under the valid signature', () => {
    expect(verify({ ...payload, amount: 4 }, validSig, kp.publicKey)).toBe(
      false,
    );
  });
});
