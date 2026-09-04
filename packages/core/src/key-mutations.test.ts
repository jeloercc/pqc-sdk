import { describe, expect, it } from 'vitest';

import type { KemAlgorithm } from './types.js';
import { PqcError } from './errors.js';
import { decrypt, encrypt } from './encrypt.js';
import { generate } from './keys.js';
import { collect, single } from './stream-test-helpers.js';
import { encryptStream } from './stream.js';

/**
 * Mutation matrix for the *public key* — the one input region the existing
 * suites never tampered. `stream-mutations.test.ts` covers every ciphertext
 * region (header, KEM ciphertext, nonce, sealed payload) and `keys.test.ts`
 * covers key length and token format, but nothing tampered public-key
 * *content*, so the X-Wing `pk_X` half had no coverage at all.
 *
 * That gap hid a real defect: a degenerate `pk_X` made `@noble/curves` throw
 * a raw `Error: invalid private or public key received` straight through
 * `encrypt`, violating the crypto-review rule that failures surface as a
 * documented `PqcError` and never as a raw upstream error.
 *
 * Two properties are asserted for every mutation:
 *
 * 1. **No raw upstream error ever escapes** — every throw is a `PqcError`.
 * 2. **A tampered public key never yields a usable ciphertext** — either
 *    encryption fails closed, or it succeeds and the genuine secret key
 *    fails to recover the plaintext. The second branch is not a defect: a
 *    flipped bit in `pk_M` can still encode a well-formed ML-KEM
 *    encapsulation key, and encrypting to a different valid key is expected
 *    to produce a ciphertext its owner cannot open.
 */

const utf8 = new TextEncoder();
const PLAINTEXT = utf8.encode('mutation matrix: public key regions');

// X-Wing public key layout (draft-connolly-cfrg-xwing-kem-10 §5.2):
// pk_M(1184) ‖ pk_X(32), total 1216.
const XWING_PK_X_OFFSET = 1184;

/**
 * X25519 u-coordinates whose shared secret is all-zero, so `@noble/curves`
 * rejects them. RFC 7748 §6.1 explicitly permits this check; X-Wing's own
 * §5.4/§5.5 do not mandate it — that divergence is tracked in issue #73 —
 * but rejecting is the fail-closed direction and is what our pinned stack
 * does. If upstream ever relaxes the check to match the draft, these tests
 * fail and send us back to that issue, which is the intent.
 */
const DEGENERATE_PK_X: readonly (readonly [string, string])[] = [
  ['all-zero', '0000000000000000000000000000000000000000000000000000000000000000'],
  ['one', '0100000000000000000000000000000000000000000000000000000000000000'],
  ['order-8 point', 'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800'],
  ['p-1', 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'],
];

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

describe('public-key mutation matrix: degenerate X-Wing pk_X', () => {
  for (const [name, hex] of DEGENERATE_PK_X) {
    it(`one-shot encrypt rejects a ${name} pk_X with INVALID_KEY, not a raw @noble error`, async () => {
      const pair = await generate({ algorithm: 'x-wing' });
      const publicKey = { ...pair.publicKey, bytes: Uint8Array.from(pair.publicKey.bytes) };
      publicKey.bytes.set(hexToBytes(hex), XWING_PK_X_OFFSET);

      const error = await encrypt(PLAINTEXT, publicKey).then(
        () => undefined,
        (caught: unknown) => caught,
      );

      expect(error).toBeInstanceOf(PqcError);
      expect((error as PqcError).code).toBe('INVALID_KEY');
      // Errors carry only algorithm names and key use — never key material.
      expect((error as PqcError).message).not.toContain(hex.slice(0, 16));
    });

    it(`encryptStream rejects a ${name} pk_X the same way, before yielding anything`, async () => {
      const pair = await generate({ algorithm: 'x-wing' });
      const publicKey = { ...pair.publicKey, bytes: Uint8Array.from(pair.publicKey.bytes) };
      publicKey.bytes.set(hexToBytes(hex), XWING_PK_X_OFFSET);

      const error = await collect(encryptStream(publicKey, single(PLAINTEXT))).then(
        () => undefined,
        (caught: unknown) => caught,
      );

      expect(error).toBeInstanceOf(PqcError);
      expect((error as PqcError).code).toBe('INVALID_KEY');
    });
  }
});

describe('public-key mutation matrix: single-byte tampering by region', () => {
  const regions: readonly {
    algorithm: KemAlgorithm;
    region: string;
    offset: (length: number) => number;
  }[] = [
    { algorithm: 'x-wing', region: 'pk_M (ML-KEM half)', offset: () => 0 },
    { algorithm: 'x-wing', region: 'pk_M (last byte)', offset: () => XWING_PK_X_OFFSET - 1 },
    { algorithm: 'x-wing', region: 'pk_X (X25519 half)', offset: () => XWING_PK_X_OFFSET },
    { algorithm: 'x-wing', region: 'pk_X (last byte)', offset: (length) => length - 1 },
    { algorithm: 'ml-kem-768', region: 'encapsulation key (first byte)', offset: () => 0 },
    { algorithm: 'ml-kem-768', region: 'encapsulation key (last byte)', offset: (l) => l - 1 },
  ];

  for (const { algorithm, region, offset } of regions) {
    it(`${algorithm}: flipping a bit in ${region} never yields a decryptable ciphertext`, async () => {
      const pair = await generate({ algorithm });
      const publicKey = { ...pair.publicKey, bytes: Uint8Array.from(pair.publicKey.bytes) };
      const index = offset(publicKey.bytes.length);
      const original = publicKey.bytes[index];
      expect(original).toBeDefined();
      publicKey.bytes[index] = (original as number) ^ 0x01;

      let ciphertext: Uint8Array | undefined;
      try {
        ciphertext = await encrypt(PLAINTEXT, publicKey);
      } catch (caught) {
        // Property 1: a throw is always a documented PqcError.
        expect(caught).toBeInstanceOf(PqcError);
        return;
      }

      // Property 2: it encrypted to a *different* key, so the genuine secret
      // key must not recover the plaintext.
      const error = await decrypt(ciphertext, pair.secretKey).then(
        () => undefined,
        (caught: unknown) => caught,
      );
      expect(error).toBeInstanceOf(PqcError);
      expect((error as PqcError).code).toBe('DECRYPTION_FAILED');
    });
  }
});

describe('public-key mutation matrix: an untampered key still works', () => {
  // Guards against the suite passing vacuously: if encrypt() threw for every
  // input, every case above would pass while proving nothing.
  for (const algorithm of ['ml-kem-768', 'x-wing'] as const) {
    it(`${algorithm}: the genuine public key round-trips`, async () => {
      const pair = await generate({ algorithm });
      const roundtrip = await decrypt(await encrypt(PLAINTEXT, pair.publicKey), pair.secretKey);
      expect(roundtrip).toEqual(PLAINTEXT);
    });
  }
});

describe('ciphertext mutation matrix: degenerate X-Wing ct_X on decapsulation', () => {
  // X-Wing ciphertext layout: ct_M(1088) ‖ ct_X(32), total 1120, sitting
  // after the 2-byte pqcenc.v2 header.
  const CT_X_OFFSET = 2 + 1088;

  for (const [name, hex] of DEGENERATE_PK_X) {
    it(`decrypt fails closed with DECRYPTION_FAILED for a ${name} ct_X`, async () => {
      const pair = await generate({ algorithm: 'x-wing' });
      const ciphertext = Uint8Array.from(await encrypt(PLAINTEXT, pair.publicKey));
      ciphertext.set(hexToBytes(hex), CT_X_OFFSET);

      const error = await decrypt(ciphertext, pair.secretKey).then(
        () => undefined,
        (caught: unknown) => caught,
      );

      expect(error).toBeInstanceOf(PqcError);
      expect((error as PqcError).code).toBe('DECRYPTION_FAILED');
    });
  }
});
