import { describe, expect, it, vi } from 'vitest';

import type { PublicKey } from './types.js';

// `verify` wraps the underlying signer in a try/catch that fails closed to
// `false` (sign.ts). That catch is defense-in-depth: empirically, no signature
// byte-pattern makes @noble's `ml_dsa65.verify` throw — it returns `false` for
// every malformed signature (verified with 6000+ random/structured inputs, and
// confirmed by reading its source: length, bad-hint and norm failures all
// return `false`). So the only honest way to exercise the catch is to force the
// signer itself to throw and assert `verify` still resolves to `false` instead
// of leaking the error. This mock is scoped to this file so the real
// sign/verify roundtrip suite (sign.test.ts) is unaffected.
vi.mock('@noble/post-quantum/ml-dsa.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@noble/post-quantum/ml-dsa.js')>();
  return {
    ...actual,
    ml_dsa65: {
      ...actual.ml_dsa65,
      verify: () => {
        throw new Error('simulated signer failure');
      },
    },
  };
});

// Imported after vi.mock (hoisted) so it binds to the mocked signer.
const { pqc } = await import('./index.js');

describe('pqc.verify defense-in-depth catch path', () => {
  it('fails closed to false if the underlying signer throws', async () => {
    // A well-formed ML-DSA-65 public key (correct algorithm, use and 1952-byte
    // length) so it passes requireKey and reaches the signer call that throws.
    const publicKey: PublicKey<'ml-dsa-65'> = {
      algorithm: 'ml-dsa-65',
      use: 'public',
      bytes: new Uint8Array(1952),
    };

    await expect(pqc.verify('message', new Uint8Array(3309), publicKey)).resolves.toBe(false);
  });
});
