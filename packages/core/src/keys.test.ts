import { describe, expect, it } from 'vitest';

import { PqcError } from './errors.js';
import { pqc } from './index.js';

describe('pqc.keys.generate', () => {
  it('generates an ML-KEM-768 pair by default', async () => {
    const pair = await pqc.keys.generate();

    expect(pair.algorithm).toBe('ml-kem-768');
    expect(pair.publicKey.algorithm).toBe('ml-kem-768');
    expect(pair.publicKey.use).toBe('public');
    expect(pair.publicKey.bytes).toHaveLength(1184);
    expect(pair.secretKey.use).toBe('secret');
    expect(pair.secretKey.bytes).toHaveLength(2400);
  });

  it('generates an ML-DSA-65 pair when requested', async () => {
    const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });

    expect(pair.algorithm).toBe('ml-dsa-65');
    expect(pair.publicKey.bytes).toHaveLength(1952);
    expect(pair.secretKey.bytes).toHaveLength(4032);
  });

  it('generates a different pair on every call', async () => {
    const a = await pqc.keys.generate();
    const b = await pqc.keys.generate();

    expect(Buffer.from(a.publicKey.bytes).equals(Buffer.from(b.publicKey.bytes))).toBe(false);
  });

  it('rejects unknown algorithms', async () => {
    await expect(
      // @ts-expect-error invalid algorithm on purpose
      pqc.keys.generate({ algorithm: 'rsa-2048' }),
    ).rejects.toThrow(PqcError);
  });
});

describe('pqc.keys serialization', () => {
  it('serializes to base64url with algorithm and use metadata', async () => {
    const pair = await pqc.keys.generate();
    const serialized = pqc.keys.serialize(pair.publicKey);

    expect(serialized).toMatch(/^pqcv1\.ml-kem-768\.public\.[A-Za-z0-9_-]+$/);
  });

  it('serialize → deserialize roundtrip preserves the key', async () => {
    const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });

    for (const key of [pair.publicKey, pair.secretKey]) {
      const restored = pqc.keys.deserialize(pqc.keys.serialize(key));
      expect(restored.algorithm).toBe(key.algorithm);
      expect(restored.use).toBe(key.use);
      expect(Buffer.from(restored.bytes).equals(Buffer.from(key.bytes))).toBe(true);
    }
  });

  it('rejects strings with an invalid format', () => {
    for (const bad of [
      'not-a-key',
      'pqcv9.ml-kem-768.public.AAAA',
      'pqcv1.rsa-2048.public.AAAA',
      'pqcv1.ml-kem-768.banana.AAAA',
      'pqcv1.ml-kem-768.public.!!!!',
    ]) {
      expect(() => pqc.keys.deserialize(bad)).toThrow(PqcError);
    }
  });

  it('rejects keys with the wrong length for the algorithm', () => {
    expect(() => pqc.keys.deserialize('pqcv1.ml-kem-768.public.AAAA')).toThrow(PqcError);
  });
});
