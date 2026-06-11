import { describe, expect, it } from 'vitest';

import { PqcError } from './errors.js';
import { pqc } from './index.js';

describe('pqc.encrypt / pqc.decrypt', () => {
  it('roundtrip con Uint8Array', async () => {
    const pair = await pqc.keys.generate();
    const data = new TextEncoder().encode('mensaje secreto');

    const ciphertext = await pqc.encrypt(data, pair.publicKey);
    const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);

    expect(Buffer.from(plaintext).equals(Buffer.from(data))).toBe(true);
  });

  it('acepta strings y los cifra como UTF-8', async () => {
    const pair = await pqc.keys.generate();

    const ciphertext = await pqc.encrypt('hola PQC ✓', pair.publicKey);
    const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);

    expect(new TextDecoder().decode(plaintext)).toBe('hola PQC ✓');
  });

  it('produce ciphertexts distintos para el mismo mensaje', async () => {
    const pair = await pqc.keys.generate();

    const a = await pqc.encrypt('mismo mensaje', pair.publicKey);
    const b = await pqc.encrypt('mismo mensaje', pair.publicKey);

    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it('cifra mensajes vacíos y binarios grandes', async () => {
    const pair = await pqc.keys.generate();
    const big = new Uint8Array(100_000).map((_, i) => i % 251);

    for (const data of [new Uint8Array(0), big]) {
      const plaintext = await pqc.decrypt(await pqc.encrypt(data, pair.publicKey), pair.secretKey);
      expect(Buffer.from(plaintext).equals(Buffer.from(data))).toBe(true);
    }
  });

  it('rechaza encrypt con una key que no es ML-KEM', async () => {
    const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });

    // @ts-expect-error key de firma usada para cifrar a propósito
    await expect(pqc.encrypt('x', pair.publicKey)).rejects.toMatchObject({
      code: 'WRONG_ALGORITHM',
    });
  });

  it('rechaza encrypt con la secret key', async () => {
    const pair = await pqc.keys.generate();

    // @ts-expect-error secret key donde va public key a propósito
    await expect(pqc.encrypt('x', pair.secretKey)).rejects.toThrow(PqcError);
  });

  it('falla con DECRYPTION_FAILED si el ciphertext fue manipulado', async () => {
    const pair = await pqc.keys.generate();
    const ciphertext = await pqc.encrypt('dato íntegro', pair.publicKey);

    const tampered = new Uint8Array(ciphertext);
    const lastByte = tampered.length - 1;
    tampered[lastByte] = tampered[lastByte]! ^ 0xff;

    await expect(pqc.decrypt(tampered, pair.secretKey)).rejects.toMatchObject({
      code: 'DECRYPTION_FAILED',
    });
  });

  it('falla con DECRYPTION_FAILED si se usa otra secret key', async () => {
    const alice = await pqc.keys.generate();
    const eve = await pqc.keys.generate();
    const ciphertext = await pqc.encrypt('solo para alice', alice.publicKey);

    await expect(pqc.decrypt(ciphertext, eve.secretKey)).rejects.toMatchObject({
      code: 'DECRYPTION_FAILED',
    });
  });

  it('rechaza ciphertexts truncados o con header desconocido', async () => {
    const pair = await pqc.keys.generate();

    await expect(pqc.decrypt(new Uint8Array([1, 1, 2, 3]), pair.secretKey)).rejects.toMatchObject({
      code: 'INVALID_CIPHERTEXT',
    });
    await expect(pqc.decrypt(new Uint8Array(2000), pair.secretKey)).rejects.toMatchObject({
      code: 'INVALID_CIPHERTEXT',
    });
  });
});
