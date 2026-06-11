import { describe, expect, it } from 'vitest';

import { pqc } from './index.js';

describe('pqc.sign / pqc.verify', () => {
  it('roundtrip firma y verificación', async () => {
    const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
    const data = new TextEncoder().encode('documento importante');

    const signature = await pqc.sign(data, pair.secretKey);

    expect(signature).toHaveLength(3309);
    await expect(pqc.verify(data, signature, pair.publicKey)).resolves.toBe(true);
  });

  it('acepta strings como datos', async () => {
    const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });

    const signature = await pqc.sign('hola', pair.secretKey);

    await expect(pqc.verify('hola', signature, pair.publicKey)).resolves.toBe(true);
    await expect(pqc.verify('hole', signature, pair.publicKey)).resolves.toBe(false);
  });

  it('devuelve false si el mensaje cambió', async () => {
    const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
    const signature = await pqc.sign('original', pair.secretKey);

    await expect(pqc.verify('alterado', signature, pair.publicKey)).resolves.toBe(false);
  });

  it('devuelve false si la firma fue manipulada o es basura', async () => {
    const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
    const signature = await pqc.sign('msg', pair.secretKey);

    const tampered = new Uint8Array(signature);
    tampered[0] = tampered[0]! ^ 0xff;

    await expect(pqc.verify('msg', tampered, pair.publicKey)).resolves.toBe(false);
    await expect(pqc.verify('msg', new Uint8Array(10), pair.publicKey)).resolves.toBe(false);
  });

  it('devuelve false con la public key de otro par', async () => {
    const a = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
    const b = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
    const signature = await pqc.sign('msg', a.secretKey);

    await expect(pqc.verify('msg', signature, b.publicKey)).resolves.toBe(false);
  });

  it('soporta context strings de FIPS 204 (default vacío)', async () => {
    const pair = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
    const context = new TextEncoder().encode('app-v1');

    const signature = await pqc.sign('msg', pair.secretKey, { context });

    await expect(pqc.verify('msg', signature, pair.publicKey, { context })).resolves.toBe(true);
    await expect(pqc.verify('msg', signature, pair.publicKey)).resolves.toBe(false);
  });

  it('rechaza sign con una key que no es ML-DSA', async () => {
    const pair = await pqc.keys.generate();

    // @ts-expect-error key KEM usada para firmar a propósito
    await expect(pqc.sign('x', pair.secretKey)).rejects.toMatchObject({
      code: 'WRONG_ALGORITHM',
    });
  });

  it('rechaza verify con una public key que no es ML-DSA', async () => {
    const dsa = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
    const kem = await pqc.keys.generate();
    const signature = await pqc.sign('x', dsa.secretKey);

    // @ts-expect-error key KEM usada para verificar a propósito
    await expect(pqc.verify('x', signature, kem.publicKey)).rejects.toMatchObject({
      code: 'WRONG_ALGORITHM',
    });
  });
});
