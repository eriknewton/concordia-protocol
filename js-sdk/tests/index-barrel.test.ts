import { describe, it, expect } from 'vitest';

// FORGE / PARITY finding 2: the C-H2 countersign primitives and the canonical
// cosign helpers must be reachable from the top-level package barrel
// (../src/index.js), not only from the submodule barrels. A downstream JS
// consumer importing from the package root must be able to mint and verify an
// attestation countersignature. This test imports ONLY from the package root.
import {
  KeyPair,
  generateKeyPair,
  countersignAttestation,
  verifyAttestationCountersignature,
  verifyReceiptSetBinding,
  canonicalCosignBytes,
  stripSignatures,
} from '../src/index.js';

describe('package barrel (../src/index.js) public surface', () => {
  it('re-exports the C-H2 countersign primitives and canonical cosign helpers', () => {
    expect(typeof countersignAttestation).toBe('function');
    expect(typeof verifyAttestationCountersignature).toBe('function');
    expect(typeof verifyReceiptSetBinding).toBe('function');
    expect(typeof canonicalCosignBytes).toBe('function');
    expect(typeof stripSignatures).toBe('function');
  });

  it('mints and verifies a countersignature using only package-root imports', () => {
    const kp: KeyPair = generateKeyPair();
    // Minimal attestation-shaped object; the countersign primitive signs the
    // canonical bytes of the object minus its countersignatures map.
    const attestation: Record<string, unknown> = {
      concordia_attestation: '0.2.0',
      attestation_id: 'att_barrel_test',
      session_id: 'sess_barrel_test',
      timestamp: '2026-06-18T00:00:00Z',
      outcome: { status: 'agreed', rounds: 2, duration_seconds: 90 },
      parties: [{ agent_id: 'agent_root', role: 'seller' }],
      meta: { category: 'electronics' },
      transcript_hash: 'sha256:deadbeef',
    };

    const sig = countersignAttestation(attestation, kp);
    expect(verifyAttestationCountersignature(attestation, sig, kp.publicKey)).toBe(true);

    // Tamper the outcome -> the countersignature must no longer verify.
    const tampered = {
      ...attestation,
      outcome: { status: 'rejected', rounds: 2, duration_seconds: 90 },
    };
    expect(verifyAttestationCountersignature(tampered, sig, kp.publicKey)).toBe(false);
  });

  it('stripSignatures and canonicalCosignBytes from the root behave consistently', () => {
    const obj = { a: 1, signature: 'zzz', nested: { b: 2, signature: 'yyy' } };
    const stripped = stripSignatures(obj) as Record<string, unknown>;
    expect('signature' in stripped).toBe(false);
    expect((stripped.nested as Record<string, unknown>).signature).toBeUndefined();
    // Cosign bytes are deterministic over the signature-stripped canonical form.
    const bytesA = canonicalCosignBytes(obj);
    const bytesB = canonicalCosignBytes({ a: 1, nested: { b: 2 } });
    expect(bytesA.equals(bytesB)).toBe(true);
  });
});
