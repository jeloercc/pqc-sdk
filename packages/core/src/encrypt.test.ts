import { describe, expect, it } from 'vitest';

import { PqcError } from './errors.js';
import { pqc } from './index.js';

describe('pqc.encrypt / pqc.decrypt', () => {
  it('roundtrips a Uint8Array', async () => {
    const pair = await pqc.keys.generate();
    const data = new TextEncoder().encode('secret message');

    const ciphertext = await pqc.encrypt(data, pair.publicKey);
    const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);

    expect(Buffer.from(plaintext).equals(Buffer.from(data))).toBe(true);
  });

  it('accepts strings and encrypts them as UTF-8', async () => {
    const pair = await pqc.keys.generate();

    const ciphertext = await pqc.encrypt('hello PQC ✓', pair.publicKey);
    const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);

    expect(new TextDecoder().decode(plaintext)).toBe('hello PQC ✓');
  });

  it('produces different ciphertexts for the same message', async () => {
    const pair = await pqc.keys.generate();

    const a = await pqc.encrypt('same message', pair.publicKey);
    const b = await pqc.encrypt('same message', pair.publicKey);

    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it('encrypts empty messages and large binaries', async () => {
    const pair = await pqc.keys.generate();
    const big = new Uint8Array(100_000).map((_, i) => i % 251);

    for (const data of [new Uint8Array(0), big]) {
      const plaintext = await pqc.decrypt(await pqc.encrypt(data, pair.publicKey), pair.secretKey);
      expect(Buffer.from(plaintext).equals(Buffer.from(data))).toBe(true);
    }
  });

  it(
    'roundtrips a multi-megabyte payload',
    async () => {
      const pair = await pqc.keys.generate();
      const big = new Uint8Array(3 * 1024 * 1024).map((_, i) => i % 251);

      const plaintext = await pqc.decrypt(await pqc.encrypt(big, pair.publicKey), pair.secretKey);

      expect(Buffer.from(plaintext).equals(Buffer.from(big))).toBe(true);
    },
    // ~2.5s solo, but `turbo run test` runs the core and cli suites concurrently
    // and v8 coverage instrumentation makes the 3 MB encrypt+decrypt several
    // times slower under that CPU contention. A generous fixed timeout keeps it
    // from flaking in CI; the default 5s is too tight for this one test.
    30_000,
  );

  it('rejects a key with the right algorithm and use but a wrong byte length', async () => {
    const malformed = {
      algorithm: 'ml-kem-768',
      use: 'public',
      bytes: new Uint8Array(10),
    } as const;

    await expect(
      // Hand-built / truncated-in-memory key reaching the operation entry point.
      pqc.encrypt('x', malformed as never),
    ).rejects.toMatchObject({ code: 'INVALID_KEY' });
  });

  it('rejects encrypt with a non-ML-KEM key', async () => {
    const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });

    // @ts-expect-error signing key used for encryption on purpose
    await expect(pqc.encrypt('x', pair.publicKey)).rejects.toMatchObject({
      code: 'WRONG_ALGORITHM',
    });
  });

  it('rejects encrypt with the secret key', async () => {
    const pair = await pqc.keys.generate();

    // @ts-expect-error secret key where the public key belongs, on purpose
    await expect(pqc.encrypt('x', pair.secretKey)).rejects.toThrow(PqcError);
  });

  it('fails with DECRYPTION_FAILED if the ciphertext was tampered with', async () => {
    const pair = await pqc.keys.generate();
    const ciphertext = await pqc.encrypt('intact data', pair.publicKey);

    const tampered = new Uint8Array(ciphertext);
    const lastByte = tampered.length - 1;
    tampered[lastByte] = tampered[lastByte]! ^ 0xff;

    await expect(pqc.decrypt(tampered, pair.secretKey)).rejects.toMatchObject({
      code: 'DECRYPTION_FAILED',
    });
  });

  it('fails with DECRYPTION_FAILED when using another secret key', async () => {
    const alice = await pqc.keys.generate();
    const eve = await pqc.keys.generate();
    const ciphertext = await pqc.encrypt('for alice only', alice.publicKey);

    await expect(pqc.decrypt(ciphertext, eve.secretKey)).rejects.toMatchObject({
      code: 'DECRYPTION_FAILED',
    });
  });

  it('roundtrips after the header is bound as AES-GCM additional data', async () => {
    const pair = await pqc.keys.generate();

    const ciphertext = await pqc.encrypt('header is authenticated', pair.publicKey);
    const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);

    expect(new TextDecoder().decode(plaintext)).toBe('header is authenticated');
  });

  it('fails with INVALID_CIPHERTEXT when a header byte is tampered with', async () => {
    const pair = await pqc.keys.generate();
    const ciphertext = await pqc.encrypt('intact data', pair.publicKey);

    // Both header bytes (FORMAT_VERSION at 0, headerId at 1) are rejected by the
    // fail-fast header check before AES-GCM ever runs.
    for (const index of [0, 1]) {
      const tampered = new Uint8Array(ciphertext);
      tampered[index] = tampered[index]! ^ 0xff;

      await expect(pqc.decrypt(tampered, pair.secretKey)).rejects.toMatchObject({
        code: 'INVALID_CIPHERTEXT',
      });
    }
  });

  it('fails with DECRYPTION_FAILED when a body byte is tampered with', async () => {
    const pair = await pqc.keys.generate();
    const ciphertext = await pqc.encrypt('intact data', pair.publicKey);

    // One byte inside each body region: KEM ciphertext, nonce and the sealed
    // AES-GCM output (header is 2 bytes, KEM ciphertext is 1088 bytes, nonce 12).
    const kemCiphertextByte = 2;
    const nonceByte = 2 + 1088;
    const sealedByte = 2 + 1088 + 12;
    for (const index of [kemCiphertextByte, nonceByte, sealedByte]) {
      const tampered = new Uint8Array(ciphertext);
      tampered[index] = tampered[index]! ^ 0xff;

      await expect(pqc.decrypt(tampered, pair.secretKey)).rejects.toMatchObject({
        code: 'DECRYPTION_FAILED',
      });
    }
  });

  it('rejects truncated ciphertexts or unknown headers', async () => {
    const pair = await pqc.keys.generate();

    await expect(pqc.decrypt(new Uint8Array([1, 1, 2, 3]), pair.secretKey)).rejects.toMatchObject({
      code: 'INVALID_CIPHERTEXT',
    });
    await expect(pqc.decrypt(new Uint8Array(2000), pair.secretKey)).rejects.toMatchObject({
      code: 'INVALID_CIPHERTEXT',
    });
  });
});
