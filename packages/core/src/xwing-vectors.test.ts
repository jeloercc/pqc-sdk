import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';

import { KEM_ALGORITHMS } from './algorithms.js';
import { PqcError } from './errors.js';
import { generateKeyPairFromSeed } from './keys.js';
import { pqc } from './index.js';
import xwingVectors from './vectors/xwing-draft10.json';

/**
 * KAT gate for the X-Wing hybrid KEM (draft-connolly-cfrg-xwing-kem-10,
 * Appendix C) against the pinned @noble/post-quantum implementation. This
 * suite is the tripwire required by the hybrid-envelope plan: if a pin bump
 * ever changes the combiner, keygen expansion, or encodings, these vectors
 * fail before any envelope code can ship on top of them.
 */
describe('x-wing draft-10 Appendix C vectors', () => {
  const spec = KEM_ALGORITHMS['x-wing'];

  it('ships the expected number of vectors', () => {
    expect(xwingVectors.vectors.length).toBeGreaterThanOrEqual(3);
  });

  for (const [index, vector] of xwingVectors.vectors.entries()) {
    it(`vector ${index}: deterministic keygen derives the expected keys`, () => {
      const seed = hexToBytes(vector.seed);
      const { publicKey, secretKey } = spec.kem.keygen(seed);

      expect(bytesToHex(publicKey)).toBe(vector.pk);
      // The X-Wing decapsulation key is the seed itself (draft §5.2).
      expect(bytesToHex(secretKey)).toBe(vector.sk);
    });

    it(`vector ${index}: seeded encapsulation produces the expected ciphertext and secret`, () => {
      const { cipherText, sharedSecret } = spec.kem.encapsulate(
        hexToBytes(vector.pk),
        hexToBytes(vector.eseed),
      );

      expect(bytesToHex(cipherText)).toBe(vector.ct);
      expect(bytesToHex(sharedSecret)).toBe(vector.ss);
    });

    it(`vector ${index}: decapsulation recovers the expected shared secret`, () => {
      const sharedSecret = spec.kem.decapsulate(hexToBytes(vector.ct), hexToBytes(vector.seed));

      expect(bytesToHex(sharedSecret)).toBe(vector.ss);
    });

    it(`vector ${index}: a tampered ciphertext implicitly rejects to a different secret`, () => {
      const tampered = hexToBytes(vector.ct);
      tampered[0]! ^= 0x01;
      const sharedSecret = spec.kem.decapsulate(tampered, hexToBytes(vector.seed));

      // ML-KEM implicit rejection: no throw, but never the real secret.
      expect(bytesToHex(sharedSecret)).not.toBe(vector.ss);
    });
  }

  it('spec lengths match the draft-10 constants', () => {
    expect(spec.seedLength).toBe(32);
    expect(spec.publicKeyLength).toBe(1216);
    expect(spec.secretKeyLength).toBe(32);
    expect(spec.ciphertextLength).toBe(1120);
  });
});

describe('x-wing key plumbing (Day 1 surface)', () => {
  it('generates, serializes, and deserializes an x-wing pair', async () => {
    const pair = await pqc.keys.generate({ algorithm: 'x-wing' });

    expect(pair.publicKey.bytes.length).toBe(1216);
    expect(pair.secretKey.bytes.length).toBe(32);

    const token = pqc.keys.serialize(pair.publicKey);
    expect(token.startsWith('pqcv1.x-wing.public.')).toBe(true);
    const restored = pqc.keys.deserialize(token, { algorithm: 'x-wing', use: 'public' });
    expect(restored.bytes).toEqual(pair.publicKey.bytes);

    const secretToken = pqc.keys.serialize(pair.secretKey);
    expect(secretToken.startsWith('pqcv1.x-wing.secret.')).toBe(true);
    const restoredSecret = pqc.keys.deserialize(secretToken, {
      algorithm: 'x-wing',
      use: 'secret',
    });
    expect(restoredSecret.bytes).toEqual(pair.secretKey.bytes);
  });

  it('generateKeyPairFromSeed matches the draft vectors end to end', () => {
    const vector = xwingVectors.vectors[0]!;
    const pair = generateKeyPairFromSeed('x-wing', hexToBytes(vector.seed));

    expect(bytesToHex(pair.publicKey.bytes)).toBe(vector.pk);
    expect(bytesToHex(pair.secretKey.bytes)).toBe(vector.sk);
  });

  it('rejects a wrong-length x-wing seed', () => {
    let caught: unknown;
    try {
      generateKeyPairFromSeed('x-wing', new Uint8Array(64));
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(PqcError);
    expect((caught as PqcError).code).toBe('INVALID_KEY');
  });

  it('encrypt refuses an x-wing public key until the v2 envelope exists', async () => {
    const pair = await pqc.keys.generate({ algorithm: 'x-wing' });

    await expect(pqc.encrypt('data', pair.publicKey as never)).rejects.toMatchObject({
      name: 'PqcError',
      code: 'UNSUPPORTED_ALGORITHM',
    });
  });

  it('decrypt refuses an x-wing secret key until the v2 envelope exists', async () => {
    const pair = await pqc.keys.generate({ algorithm: 'x-wing' });

    await expect(pqc.decrypt(new Uint8Array(2000), pair.secretKey as never)).rejects.toMatchObject({
      name: 'PqcError',
      code: 'UNSUPPORTED_ALGORITHM',
    });
  });
});
