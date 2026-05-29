/**
 * Ed25519 message signing and verification over canonical JSON.
 *
 * Port of the EdDSA path of the Concordia Python reference
 * (`concordia/signing.py`). Cross-language signature parity is the
 * load-bearing property: a signature produced here MUST be byte-identical to,
 * and verifiable by, the Python implementation, and vice versa.
 *
 * Parity contract (verified against `concordia/signing.py`):
 * - Algorithm: Ed25519 (EdDSA). The raw 32-byte private key is the Ed25519
 *   seed, exactly as `Ed25519PrivateKey.from_private_bytes` / `private_bytes`
 *   treat it. `@noble/curves` `ed25519` uses the same convention.
 * - Signing payload: `canonicalizeJcs` of the message object with its
 *   top-level `signature` field removed (matches `sign_message`, which signs
 *   `{k: v for k, v in data.items() if k != "signature"}`).
 * - Signature encoding: URL-safe base64 WITH `=` padding (Python's
 *   `base64.urlsafe_b64encode`).
 * - Public key encoding: raw 32 bytes; `.b64` is URL-safe base64 with padding
 *   (Python's `KeyPair.public_key_b64`).
 *
 * ES256 (the secondary algorithm in the Python module) is out of scope for
 * this PR, which ports the Ed25519 signing layer only.
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { canonicalizeJcs } from '../canonical/canonicalize.js';
import { toBase64Url, fromBase64Url } from './base64url.js';

/** Error raised for malformed keys or signing inputs. */
export class SigningError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SigningError';
  }
}

const ED25519_KEY_LENGTH = 32;
const ED25519_SIGNATURE_LENGTH = 64;

/**
 * An Ed25519 key pair for signing and verifying Concordia messages.
 *
 * Mirrors `concordia.signing.KeyPair`. Both keys are stored as their raw
 * 32-byte forms; the private key is the Ed25519 seed.
 */
export class KeyPair {
  /** Raw 32-byte Ed25519 private key (seed). */
  readonly privateKey: Uint8Array;
  /** Raw 32-byte Ed25519 public key. */
  readonly publicKey: Uint8Array;

  private constructor(privateKey: Uint8Array, publicKey: Uint8Array) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  /** Generate a fresh Ed25519 key pair. */
  static generate(): KeyPair {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKey = ed25519.getPublicKey(privateKey);
    return new KeyPair(privateKey, publicKey);
  }

  /**
   * Reconstruct a key pair from a raw 32-byte private key (seed). The public
   * key is derived deterministically, matching Python's
   * `Ed25519PrivateKey.from_private_bytes(...).public_key()`.
   */
  static fromPrivateKey(privateKey: Uint8Array): KeyPair {
    if (privateKey.length !== ED25519_KEY_LENGTH) {
      throw new SigningError(
        `Ed25519 private key must be ${ED25519_KEY_LENGTH} bytes, got ${privateKey.length}`,
      );
    }
    const publicKey = ed25519.getPublicKey(privateKey);
    return new KeyPair(Uint8Array.from(privateKey), publicKey);
  }

  /** Raw 32-byte private key (seed). */
  privateKeyBytes(): Uint8Array {
    return this.privateKey;
  }

  /** Raw 32-byte public key. */
  publicKeyBytes(): Uint8Array {
    return this.publicKey;
  }

  /**
   * Public key as a URL-safe base64 string with padding. Byte-identical to
   * Python's `KeyPair.public_key_b64()`.
   */
  publicKeyB64(): string {
    return toBase64Url(this.publicKey);
  }
}

/**
 * Produce the canonical-JSON signing payload for a message object: the object
 * with its top-level `signature` field removed, canonicalized per RFC 8785.
 * Matches `concordia.signing.sign_message`/`verify_signature`, which both
 * sign/verify over `canonical_json({k: v for ... if k != "signature"})`.
 */
function signingPayload(data: Record<string, unknown>): Buffer {
  const { signature: _stripped, ...signable } = data;
  return canonicalizeJcs(signable);
}

/**
 * Sign a message object with Ed25519, returning a URL-safe base64 signature
 * (with padding). The top-level `signature` field, if present, is excluded
 * before signing.
 *
 * @param data The message object to sign.
 * @param privateKey Raw 32-byte Ed25519 private key (seed), or a {@link KeyPair}.
 */
export function sign(
  data: Record<string, unknown>,
  privateKey: Uint8Array | KeyPair,
): string {
  const seed = privateKey instanceof KeyPair ? privateKey.privateKey : privateKey;
  if (seed.length !== ED25519_KEY_LENGTH) {
    throw new SigningError(
      `Ed25519 private key must be ${ED25519_KEY_LENGTH} bytes, got ${seed.length}`,
    );
  }
  const payload = signingPayload(data);
  const rawSig = ed25519.sign(payload, seed);
  return toBase64Url(rawSig);
}

/**
 * Verify an Ed25519 signature over a message object. Returns `true` if valid,
 * `false` otherwise (never throws on a bad signature/key, matching Python's
 * `verify_signature`, which returns `False` on any verification failure).
 *
 * Accept/reject contract (matched against `concordia/signing.py`
 * `verify_signature`, confirmed empirically): the signature must be a strict,
 * correctly-PADDED URL-safe base64 string that decodes to exactly 64 bytes.
 * - An unpadded signature is rejected: Python's `base64.urlsafe_b64decode`
 *   raises `binascii.Error` on missing padding, so `verify_signature` never
 *   returns `True` for it. The previous TS decoder accepted unpadded input,
 *   which was a fail-open parity break.
 * - A signature decoding to anything other than 64 bytes is rejected (Python's
 *   Ed25519 `public_key.verify` fails on a wrong-length signature).
 * - Tampered payloads, flipped-byte signatures, and wrong public keys are
 *   rejected by the Ed25519 verify itself.
 *
 * Any decode/verify failure returns `false` (Python likewise never returns
 * `True` for these inputs). Where Python's `binascii` decoder happens to be
 * more lenient than the strict decoder used here (it silently discards
 * embedded whitespace and tolerates the standard `+`/`/` alphabet), this path
 * is stricter, never more lenient: it can only reject inputs Python would have
 * accepted, never accept inputs Python rejects. That keeps verification
 * fail-closed.
 *
 * @param data The message object that was signed.
 * @param signature Strict, correctly-padded URL-safe base64 signature
 *   (64 bytes decoded).
 * @param publicKey Raw 32-byte Ed25519 public key, or a {@link KeyPair}.
 */
export function verify(
  data: Record<string, unknown>,
  signature: string,
  publicKey: Uint8Array | KeyPair,
): boolean {
  try {
    const pub = publicKey instanceof KeyPair ? publicKey.publicKey : publicKey;
    if (pub.length !== ED25519_KEY_LENGTH) {
      return false;
    }
    const payload = signingPayload(data);
    // Strict base64url decode (throws on unpadded / malformed input, caught
    // below and turned into `false`).
    const rawSig = fromBase64Url(signature);
    if (rawSig.length !== ED25519_SIGNATURE_LENGTH) {
      return false;
    }
    return ed25519.verify(rawSig, payload, pub);
  } catch {
    return false;
  }
}

/** Generate a fresh Ed25519 key pair. Alias for {@link KeyPair.generate}. */
export function generateKeyPair(): KeyPair {
  return KeyPair.generate();
}
