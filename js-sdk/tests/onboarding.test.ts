import { describe, expect, it, vi } from 'vitest';

function quickstartPredicateInput(): Record<string, unknown> {
  return {
    predicate_id: 'urn:concordia:predicate:quickstart_authority',
    type: 'urn:concordia:predicate-type:authority_gate:v1',
    authority: 'urn:concordia:authority:procurement',
    issuer: 'did:web:issuer.example#key-1',
    subject: 'did:web:buyer.example#agent',
    condition: { result: 'satisfied' },
    issued_at: '2026-05-14T00:00:00Z',
    expires_at: '2126-06-14T00:00:00Z',
    references: [],
    algorithm: 'EdDSA',
    status: 'active',
    signature: '',
  };
}

describe('JS SDK onboarding fixes', () => {
  it('README quickstart signs and verifies an authority_gate predicate from a fresh import', async () => {
    vi.resetModules();
    const sdk = await import('../src/index.js');

    // Mirrors the README Quickstart snippet: generate keys -> signPredicate ->
    // verifyPredicate -> portable low-level verify() with only the public key.
    const keyPair = sdk.generateKeyPair();
    const signed = sdk.signPredicate(quickstartPredicateInput(), keyPair);

    const semanticResult = sdk.verifyPredicate(signed);
    expect(semanticResult.valid).toBe(true);

    const publicKey = keyPair.publicKeyBytes();
    const signatureOnly = sdk.verify(signed.toDict(), signed.signature, publicKey);
    expect(signatureOnly).toBe(true);
  });

  it('profile lookup hits full URNs and rejects bare shorthand with a URN hint', async () => {
    vi.resetModules();
    const sdk = await import('../src/index.js');

    const profile = sdk.getPredicateTypeProfile('urn:concordia:predicate-type:authority_gate:v1');
    expect(profile?.typeId).toBe('urn:concordia:predicate-type:authority_gate:v1');
    expect(sdk.BUILTIN_PREDICATE_TYPE_PROFILE_URNS).toContain(
      'urn:concordia:predicate-type:authority_gate:v1',
    );

    let thrown: unknown;
    try {
      sdk.getPredicateTypeProfile('authority_gate');
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(sdk.PredicateTypeProfileLookupError);
    expect((thrown as Error).message).toContain('urn:concordia:predicate-type:authority_gate:v1');
    expect((thrown as Error).message).toContain('full URN form');
  });

  it('verifyPredicate names unregistered profiles and the portable verify() alternative', async () => {
    vi.resetModules();
    const sdk = await import('../src/index.js');
    const keyPair = sdk.generateKeyPair();
    const unsigned = {
      ...quickstartPredicateInput(),
      predicate_id: 'urn:concordia:predicate:custom_profile',
      type: 'urn:concordia:predicate-type:custom_missing:v1',
      metadata: { issuer_public_key_b64: keyPair.publicKeyB64() },
    };
    const signature = sdk.sign(unsigned, keyPair);
    const signed = { ...unsigned, signature };

    const semanticResult = sdk.verifyPredicate(signed);
    expect(semanticResult.valid).toBe(false);
    expect(semanticResult.errors[0]).toContain('predicate type profile is unregistered');
    expect(semanticResult.errors[0]).toContain('verify()');
    expect(semanticResult.errors[0]).toContain('no process-local profile registration');

    expect(sdk.verify(signed, signature, keyPair.publicKeyBytes())).toBe(true);
  });
});
