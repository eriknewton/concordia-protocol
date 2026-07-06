/**
 * Concordia message hash-chain helpers (SPEC §9.3).
 *
 * Port of the transcript-integrity slice of `concordia/message.py`: the
 * per-message SHA-256 hash (`compute_hash`), the genesis sentinel
 * (`GENESIS_HASH`), and the chain validator (`validate_chain`). These are the
 * only pieces of the message module the {@link Session} state machine strictly
 * depends on: `Session.prevHash` hashes the last transcript entry, and the
 * chain is what makes the transcript tamper-evident.
 *
 * The message *constructor* (`build_envelope`) is deliberately NOT ported here.
 * It is a separate concern (it assembles + signs a fresh envelope and is not
 * needed to drive the lifecycle), so it ships with the message-envelope PR.
 * Tests assemble signed envelopes directly via the merged Ed25519 `sign()`.
 *
 * Parity contract (verified against Python `concordia.message` via fixtures in
 * `tests/fixtures/session/session_vectors.json`):
 * - `computeHash` returns `sha256:<hex>` where `<hex>` is the lowercase hex
 *   SHA-256 digest of the RFC-8785 canonical bytes of the message, byte-identical
 *   to Python `compute_hash` (which hashes `canonical_json(message)`).
 *   Unlike the signing payload, the hash is over the FULL message INCLUDING its
 *   `signature` field (Python `compute_hash` does not strip it).
 * - `GENESIS_HASH` is `sha256:` followed by 64 zeros, matching Python exactly.
 * - `validateChain` returns `true` for an empty list, requires the first
 *   message's `prev_hash` to equal `GENESIS_HASH`, and requires each subsequent
 *   message's `prev_hash` to equal `computeHash` of its predecessor.
 */

import { createHash } from 'node:crypto';

import { canonicalizeJcs } from '../canonical/canonicalize.js';

/**
 * The genesis hash sentinel used as `prev_hash` for the first message in a
 * session. Byte-identical to Python `GENESIS_HASH` (`f"sha256:{'0' * 64}"`).
 */
export const GENESIS_HASH = `sha256:${'0'.repeat(64)}`;

/**
 * Compute the SHA-256 hash of a message for chain integrity (SPEC §9.3).
 * Returns the hash in the format `sha256:<hex>`.
 *
 * Mirrors Python `concordia.message.compute_hash`: it hashes the canonical-JSON
 * bytes of the WHOLE message (the `signature` field is NOT stripped, unlike the
 * signing payload). The digest is lowercase hex, matching `hashlib.sha256(...)
 * .hexdigest()`.
 */
export function computeHash(message: Record<string, unknown>): string {
  const payload = canonicalizeJcs(message);
  const digest = createHash('sha256').update(payload).digest('hex');
  return `sha256:${digest}`;
}

/**
 * Validate the hash chain of a message sequence. Mirrors Python
 * `concordia.message.validate_chain`.
 *
 * Each message's `prev_hash` must equal the SHA-256 hash of the preceding
 * message; the first message must reference {@link GENESIS_HASH}. An empty list
 * is vacuously valid (returns `true`).
 */
export function validateChain(messages: Array<Record<string, unknown>>): boolean {
  const first = messages[0];
  if (first === undefined) {
    return true;
  }
  if (first.prev_hash !== GENESIS_HASH) {
    return false;
  }
  for (let i = 1; i < messages.length; i += 1) {
    const prev = messages[i - 1];
    const curr = messages[i];
    if (prev === undefined || curr === undefined) {
      return false;
    }
    if (curr.prev_hash !== computeHash(prev)) {
      return false;
    }
  }
  return true;
}
