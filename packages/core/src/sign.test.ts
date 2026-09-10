import { describe, expect, it } from 'vitest';

import { pqc } from './index.js';

describe('pqc.sign / pqc.verify', () => {
  it('roundtrips signing and verification', async () => {
    const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
    const data = new TextEncoder().encode('important document');

    const signature = await pqc.sign(data, pair.secretKey);

    expect(signature).toHaveLength(3309);
    await expect(pqc.verify(data, signature, pair.publicKey)).resolves.toBe(true);
  });

  it('accepts strings as data', async () => {
    const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });

    const signature = await pqc.sign('hello', pair.secretKey);

    await expect(pqc.verify('hello', signature, pair.publicKey)).resolves.toBe(true);
    await expect(pqc.verify('hallo', signature, pair.publicKey)).resolves.toBe(false);
  });

  it('returns false if the message changed', async () => {
    const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
    const signature = await pqc.sign('original', pair.secretKey);

    await expect(pqc.verify('altered', signature, pair.publicKey)).resolves.toBe(false);
  });

  it('returns false if the signature was tampered with or is garbage', async () => {
    const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
    const signature = await pqc.sign('msg', pair.secretKey);

    const tampered = new Uint8Array(signature);
    tampered[0] = tampered[0]! ^ 0xff;

    await expect(pqc.verify('msg', tampered, pair.publicKey)).resolves.toBe(false);
    await expect(pqc.verify('msg', new Uint8Array(10), pair.publicKey)).resolves.toBe(false);
  });

  it('returns false with the public key of another pair', async () => {
    const a = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
    const b = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
    const signature = await pqc.sign('msg', a.secretKey);

    await expect(pqc.verify('msg', signature, b.publicKey)).resolves.toBe(false);
  });

  it('supports FIPS 204 context strings (empty by default)', async () => {
    const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
    const context = new TextEncoder().encode('app-v1');

    const signature = await pqc.sign('msg', pair.secretKey, { context });

    await expect(pqc.verify('msg', signature, pair.publicKey, { context })).resolves.toBe(true);
    await expect(pqc.verify('msg', signature, pair.publicKey)).resolves.toBe(false);
  });

  it('signs and verifies an empty message', async () => {
    const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });

    const signature = await pqc.sign(new Uint8Array(0), pair.secretKey);

    await expect(pqc.verify(new Uint8Array(0), signature, pair.publicKey)).resolves.toBe(true);
  });

  it('accepts a context of exactly 255 bytes (the FIPS 204 maximum)', async () => {
    const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
    const context = new Uint8Array(255).fill(7);

    const signature = await pqc.sign('msg', pair.secretKey, { context });

    await expect(pqc.verify('msg', signature, pair.publicKey, { context })).resolves.toBe(true);
  });

  it('rejects an oversized context with INVALID_CONTEXT from both sign and verify', async () => {
    const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
    const context = new Uint8Array(256).fill(1);

    await expect(pqc.sign('msg', pair.secretKey, { context })).rejects.toMatchObject({
      code: 'INVALID_CONTEXT',
    });
    await expect(
      pqc.verify('msg', new Uint8Array(3309), pair.publicKey, { context }),
    ).rejects.toMatchObject({ code: 'INVALID_CONTEXT' });
  });

  it('returns false (never throws) for a malformed signature of the wrong length', async () => {
    const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });

    // Malformed signatures must verify to `false`, never throw — whether @noble
    // rejects them by returning false or by throwing (verify's catch normalizes
    // the latter to false). A bad signature is not an exceptional condition.
    await expect(pqc.verify('msg', new Uint8Array(3), pair.publicKey)).resolves.toBe(false);
    await expect(pqc.verify('msg', new Uint8Array(3309).fill(0xff), pair.publicKey)).resolves.toBe(
      false,
    );
  });

  it('returns false (never throws) for a public key of the wrong length', async () => {
    const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
    const signature = await pqc.sign('msg', pair.secretKey);

    // FIPS 204 §3.6.2: "If an implementation of ML-DSA can accept inputs for σ or
    // pk of any other length, it shall return false whenever the lengths of either
    // of these inputs differ from their lengths specified in this standard."
    //
    // The σ half is covered by the test above. This is the pk half: `verify` must
    // answer `false`, not throw INVALID_KEY as every other operation does for a
    // malformed key. ML-DSA-65 public keys are 1952 bytes (FIPS 204 Table 2).
    const wrongLengths = [
      0, // empty
      1951, // one byte short
      1953, // one byte long
      1312, // a valid ML-DSA-44 public key length
      2592, // a valid ML-DSA-87 public key length
    ];

    for (const length of wrongLengths) {
      const malformed = {
        algorithm: 'ml-dsa-65',
        use: 'public',
        bytes: new Uint8Array(length),
      } as const;

      await expect(pqc.verify('msg', signature, malformed)).resolves.toBe(false);
    }
  });

  it('still throws for a malformed key that is not a length mismatch', async () => {
    // The §3.6.2 carve-out is scoped to length only. Wrong use and unknown algorithm
    // keep the SDK-wide convention of throwing, and a correct-length key still reaches
    // the signer rather than being short-circuited.
    const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
    const signature = await pqc.sign('msg', pair.secretKey);

    await expect(
      // @ts-expect-error secret key passed where a public key is required
      pqc.verify('msg', signature, { ...pair.secretKey }),
    ).rejects.toMatchObject({ code: 'WRONG_KEY_USE' });

    const unknownAlgorithm = {
      algorithm: 'ml-dsa-99',
      use: 'public',
      bytes: pair.publicKey.bytes,
    } as const;

    await expect(
      // Unknown algorithm on purpose: it must not be swallowed as a length mismatch.
      pqc.verify('msg', signature, unknownAlgorithm as never),
    ).rejects.toMatchObject({ code: 'UNSUPPORTED_ALGORITHM' });

    await expect(pqc.verify('msg', signature, pair.publicKey)).resolves.toBe(true);
  });

  it('rejects sign with a non-ML-DSA key', async () => {
    const pair = await pqc.keys.generate();

    // @ts-expect-error KEM key used for signing on purpose
    await expect(pqc.sign('x', pair.secretKey)).rejects.toMatchObject({
      code: 'WRONG_ALGORITHM',
    });
  });

  it('rejects verify with a non-ML-DSA public key', async () => {
    const dsa = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
    const kem = await pqc.keys.generate();
    const signature = await pqc.sign('x', dsa.secretKey);

    // @ts-expect-error KEM key used for verification on purpose
    await expect(pqc.verify('x', signature, kem.publicKey)).rejects.toMatchObject({
      code: 'WRONG_ALGORITHM',
    });
  });
});
