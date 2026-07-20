import { describe, expect, it } from 'vitest';

import { PqcError } from './errors.js';
import { pqc } from './index.js';

/**
 * pqcenc.v2 envelope suite (docs/serialization-format.md §2.2): roundtrips,
 * the mutation matrix over every byte region, and cross-version key
 * confusion. Mirrors the v1 coverage in encrypt.test.ts; the crypto-review
 * rule requires every region to fail closed independently with the
 * documented PqcError code — never wrong plaintext, never a raw upstream
 * error.
 */

// v2 layout offsets (1150-byte overhead: 2 header + 1120 X-Wing ct + 12 nonce
// + 16 GCM tag).
const VERSION_BYTE = 0;
const HEADER_ID_BYTE = 1;
const CT_M_FIRST = 2;
const CT_M_LAST = 2 + 1088 - 1;
const CT_X_FIRST = 2 + 1088;
const CT_X_LAST = 2 + 1120 - 1;
const NONCE_FIRST = 2 + 1120;
const SEALED_FIRST = 2 + 1120 + 12;
const V2_OVERHEAD = 1150;

async function xwingPair() {
  return pqc.keys.generate({ algorithm: 'x-wing' });
}

async function expectDecryptCode(
  ciphertext: Uint8Array,
  secretKey: Parameters<typeof pqc.decrypt>[1],
  code: string,
): Promise<void> {
  const error = await pqc.decrypt(ciphertext, secretKey).then(
    () => {
      throw new Error('expected decrypt to throw');
    },
    (cause: unknown) => cause,
  );
  // instanceof pins the typed error: a raw @noble error leaking through fails
  // here even when it would have "failed" anyway.
  expect(error).toBeInstanceOf(PqcError);
  expect((error as PqcError).code).toBe(code);
}

describe('pqcenc.v2: roundtrips', () => {
  it('roundtrips strings, empty payloads and binaries with 1150-byte overhead', async () => {
    const pair = await xwingPair();
    const big = new Uint8Array(100_000).map((_, i) => i % 251);

    for (const data of [new Uint8Array(0), new TextEncoder().encode('hybrid ✓'), big]) {
      const ciphertext = await pqc.encrypt(data, pair.publicKey);
      expect(ciphertext.length).toBe(V2_OVERHEAD + data.length);
      expect(ciphertext[VERSION_BYTE]).toBe(0x02);
      expect(ciphertext[HEADER_ID_BYTE]).toBe(0x02);

      const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);
      expect(Buffer.from(plaintext).equals(Buffer.from(data))).toBe(true);
    }
  });

  it('produces different ciphertexts for the same message', async () => {
    const pair = await xwingPair();

    const a = await pqc.encrypt('same message', pair.publicKey);
    const b = await pqc.encrypt('same message', pair.publicKey);

    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it('fails with DECRYPTION_FAILED under another x-wing secret key', async () => {
    const alice = await xwingPair();
    const eve = await xwingPair();
    const ciphertext = await pqc.encrypt('for alice only', alice.publicKey);

    await expectDecryptCode(ciphertext, eve.secretKey, 'DECRYPTION_FAILED');
  });
});

describe('pqcenc.v2: mutation matrix — every region fails closed independently', () => {
  const headerRegions = [
    { name: 'version byte', index: VERSION_BYTE },
    { name: 'header id', index: HEADER_ID_BYTE },
  ];
  const bodyRegions = [
    { name: 'ct_M first byte', index: CT_M_FIRST },
    { name: 'ct_M last byte', index: CT_M_LAST },
    { name: 'ct_X first byte', index: CT_X_FIRST },
    { name: 'ct_X last byte', index: CT_X_LAST },
    { name: 'nonce', index: NONCE_FIRST },
    { name: 'sealed payload', index: SEALED_FIRST },
  ];

  it.each(headerRegions)('flipping the $name → INVALID_CIPHERTEXT', async ({ index }) => {
    const pair = await xwingPair();
    const tampered = Uint8Array.from(await pqc.encrypt('intact data', pair.publicKey));
    tampered[index] = tampered[index]! ^ 0xff;

    await expectDecryptCode(tampered, pair.secretKey, 'INVALID_CIPHERTEXT');
  });

  it.each(bodyRegions)('flipping the $name → DECRYPTION_FAILED', async ({ index }) => {
    // ct_M / ct_X tampering exercises X-Wing implicit rejection (a wrong
    // shared secret, no throw) followed by the GCM tag failure.
    const pair = await xwingPair();
    const tampered = Uint8Array.from(await pqc.encrypt('intact data', pair.publicKey));
    tampered[index] = tampered[index]! ^ 0xff;

    await expectDecryptCode(tampered, pair.secretKey, 'DECRYPTION_FAILED');
  });

  it('flipping the GCM tag (last byte) → DECRYPTION_FAILED', async () => {
    const pair = await xwingPair();
    const tampered = Uint8Array.from(await pqc.encrypt('intact data', pair.publicKey));
    tampered[tampered.length - 1] = tampered[tampered.length - 1]! ^ 0xff;

    await expectDecryptCode(tampered, pair.secretKey, 'DECRYPTION_FAILED');
  });

  it('rejects a v2 ciphertext truncated below the 1150-byte minimum', async () => {
    const pair = await xwingPair();
    const ciphertext = await pqc.encrypt('intact data', pair.publicKey);

    await expectDecryptCode(ciphertext.subarray(0, 1149), pair.secretKey, 'INVALID_CIPHERTEXT');
    await expectDecryptCode(ciphertext.subarray(0, 1), pair.secretKey, 'INVALID_CIPHERTEXT');
  });

  it('rejects an unknown future version byte (0x03) with INVALID_CIPHERTEXT', async () => {
    const pair = await xwingPair();
    const tampered = Uint8Array.from(await pqc.encrypt('intact data', pair.publicKey));
    tampered[VERSION_BYTE] = 0x03;

    await expectDecryptCode(tampered, pair.secretKey, 'INVALID_CIPHERTEXT');
  });
});

describe('pqcenc.v2: cross-version key confusion fails closed', () => {
  it('a v1 ciphertext offered to an x-wing key → INVALID_CIPHERTEXT', async () => {
    const kem = await pqc.keys.generate();
    const xwing = await xwingPair();
    const v1Ciphertext = await pqc.encrypt('v1 message', kem.publicKey);

    await expectDecryptCode(v1Ciphertext, xwing.secretKey, 'INVALID_CIPHERTEXT');
  });

  it('a v2 ciphertext offered to an ml-kem-768 key → INVALID_CIPHERTEXT', async () => {
    const kem = await pqc.keys.generate();
    const xwing = await xwingPair();
    const v2Ciphertext = await pqc.encrypt('v2 message', xwing.publicKey);

    await expectDecryptCode(v2Ciphertext, kem.secretKey, 'INVALID_CIPHERTEXT');
  });
});
