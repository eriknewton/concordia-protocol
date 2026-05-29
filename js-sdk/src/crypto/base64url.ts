/**
 * Base64url encoding/decoding that matches Python's
 * `base64.urlsafe_b64encode` / `base64.urlsafe_b64decode` exactly.
 *
 * The Concordia Python reference (`concordia/signing.py`) encodes signatures
 * and public keys with `base64.urlsafe_b64encode(...).decode()`, which uses
 * the URL-safe alphabet (`-` and `_`) and RETAINS `=` padding. Node's built-in
 * `Buffer.toString('base64url')` uses the same alphabet but STRIPS padding, so
 * we re-pad on encode to stay byte-identical with Python.
 *
 * On decode, Node's `Buffer.from(value, 'base64url')` is dangerously lenient:
 * it accepts unpadded input, embedded whitespace, trailing junk, and even the
 * standard (`+` / `/`) alphabet, silently recovering bytes from malformed
 * strings. Python's `verify_signature` does NOT: it calls
 * `base64.urlsafe_b64decode(signature)`, which REQUIRES correct `=` padding and
 * raises `binascii.Error` on an unpadded string. A verifier that accepts an
 * unpadded signature Python rejects is a fail-open parity break, so this module
 * decodes strictly: correct base64url alphabet, correct length, correct
 * padding, no extraneous characters.
 */

/** Error raised when a base64url string is malformed (strict decode). */
export class Base64UrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'Base64UrlError';
  }
}

/** Encode bytes as URL-safe base64 WITH `=` padding (Python-compatible). */
export function toBase64Url(bytes: Uint8Array): string {
  const unpadded = Buffer.from(bytes).toString('base64url');
  const remainder = unpadded.length % 4;
  if (remainder === 0) return unpadded;
  return unpadded + '='.repeat(4 - remainder);
}

// Strict base64url shape: groups of 4 chars from the URL-safe alphabet, with an
// optional final group that may carry one or two `=` pad characters. This is
// the correctly-padded form Python's urlsafe_b64decode requires; unpadded
// strings, embedded whitespace, the standard (`+`/`/`) alphabet, and trailing
// junk are all rejected.
const STRICT_BASE64URL =
  /^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{2}==|[A-Za-z0-9_-]{3}=)?$/;

/**
 * Decode a correctly-PADDED URL-safe base64 string to bytes.
 *
 * Strict by design, to match the accept/reject contract of Python's
 * `base64.urlsafe_b64decode` as used in `concordia/signing.py`:
 * - requires `=` padding so the total length is a multiple of 4 (Python raises
 *   `binascii.Error: Incorrect padding` on an unpadded string, which makes
 *   `verify_signature` reject it);
 * - rejects any character outside the URL-safe alphabet (`A-Z a-z 0-9 - _`)
 *   and the `=` padding, including whitespace, newlines, and the standard
 *   (`+` / `/`) alphabet.
 *
 * Where Python's `binascii` decoder is *more* lenient than this (it silently
 * discards embedded whitespace and tolerates the standard alphabet), this
 * decoder is stricter, never more lenient: it can only reject inputs Python
 * would have accepted, never accept inputs Python would reject. That keeps the
 * verifier fail-closed.
 *
 * @throws {Base64UrlError} if the input is not strict, correctly-padded
 *   base64url.
 */
export function fromBase64Url(value: string): Uint8Array {
  if (typeof value !== 'string' || !STRICT_BASE64URL.test(value)) {
    throw new Base64UrlError(
      'Invalid base64url: expected correctly-padded URL-safe base64 ' +
        '(alphabet A-Za-z0-9-_ with = padding to a multiple of 4)',
    );
  }
  const decoded = new Uint8Array(Buffer.from(value, 'base64url'));
  // Re-encoding must reproduce the exact input. Node's decoder can absorb a few
  // malformed forms the regex does not catch (e.g. a non-canonical final
  // sextet); this round-trip rejects them.
  if (toBase64Url(decoded) !== value) {
    throw new Base64UrlError('Invalid base64url: non-canonical encoding');
  }
  return decoded;
}
