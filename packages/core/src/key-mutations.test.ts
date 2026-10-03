import { runInNewContext } from 'node:vm';

import { describe, expect, it } from 'vitest';

import type { KemAlgorithm } from './types.js';
import { PqcError } from './errors.js';
import { decrypt, encrypt } from './encrypt.js';
import { generate, serialize } from './keys.js';
import { sign, verify } from './sign.js';
import { collect, single } from './stream-test-helpers.js';
import { collectDecryptStream, encryptStream } from './stream.js';

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

/**
 * Malformed key *objects* — the shape, not the content. TypeScript rejects
 * these at compile time, but plain JavaScript callers, agents, and code that
 * builds keys by hand reach the runtime with them. Before the fix each one
 * escaped as a raw `TypeError` (e.g. "Cannot read properties of undefined
 * (reading 'length')") instead of a documented `PqcError`.
 */
// CPU-bound (keygen/sign per case). Under a loaded gate, where turbo runs
// several packages' suites at once, this can exceed vitest's 5 s default
// with nothing wrong; only the time budget is raised (trailing argument).
describe('malformed key objects fail with a PqcError, never a raw TypeError', () => {
  const MALFORMED: readonly (readonly [string, unknown])[] = [
    ['undefined', undefined],
    ['null', null],
    ['a string', 'pqcv1.x-wing.public.AAAA'],
    ['a number', 42],
    ['an empty object', {}],
    ['a key without bytes', { algorithm: 'x-wing', use: 'public' }],
    ['a key with non-byte bytes', { algorithm: 'x-wing', use: 'public', bytes: [1, 2, 3] }],
    [
      'a key with a non-string algorithm',
      { algorithm: 42, use: 'public', bytes: new Uint8Array(1216) },
    ],
    ['a key with a non-string use', { algorithm: 'x-wing', use: 1, bytes: new Uint8Array(1216) }],
  ];

  // Each entry points the malformed value at one key-taking entry point.
  const OPERATIONS: readonly (readonly [string, (key: never) => Promise<unknown>])[] = [
    ['encrypt', (key) => encrypt(PLAINTEXT, key)],
    ['decrypt', (key) => decrypt(new Uint8Array(1200), key)],
    ['encryptStream', (key) => collect(encryptStream(key, single(PLAINTEXT)))],
    ['collectDecryptStream', (key) => collectDecryptStream(key, single(new Uint8Array(1200)))],
    ['sign', (key) => sign(PLAINTEXT, key)],
    ['verify', (key) => verify(PLAINTEXT, new Uint8Array(3309), key)],
    ['serialize', (key) => Promise.resolve().then(() => serialize(key))],
  ];

  for (const [operation, run] of OPERATIONS) {
    for (const [label, value] of MALFORMED) {
      it(`${operation} rejects ${label} with INVALID_KEY`, async () => {
        const error = await run(value as never).then(
          () => undefined,
          (caught: unknown) => caught,
        );

        expect(error).toBeInstanceOf(PqcError);
        expect((error as PqcError).code).toBe('INVALID_KEY');
      });
    }
  }

  it('a well-shaped key with an unknown algorithm still reports UNSUPPORTED_ALGORITHM', async () => {
    const key = { algorithm: 'ml-kem-9999', use: 'public', bytes: new Uint8Array(1184) };
    const error = await encrypt(PLAINTEXT, key as never).then(
      () => undefined,
      (caught: unknown) => caught,
    );
    expect((error as PqcError).code).toBe('UNSUPPORTED_ALGORITHM');
  });

  it('a non-string algorithm name reports UNSUPPORTED_ALGORITHM, not a TypeError', async () => {
    // getAlgorithm echoes the name through truncateForError, which used to
    // call .length/.slice on whatever it was given.
    const error = await generate({ algorithm: 42 as never }).then(
      () => undefined,
      (caught: unknown) => caught,
    );
    expect(error).toBeInstanceOf(PqcError);
    expect((error as PqcError).code).toBe('UNSUPPORTED_ALGORITHM');
  });

  it('accepts key bytes that are a Uint8Array from another realm', async () => {
    // Jest+jsdom, iframes and node:vm hand out Uint8Arrays whose constructor
    // is not this realm's, so `instanceof Uint8Array` is false for them.
    // 0.11.0 accepted such keys; the shape check must keep accepting them.
    const pair = await generate({ algorithm: 'x-wing' });
    const foreign = runInNewContext('new Uint8Array(length)', {
      length: pair.publicKey.bytes.length,
    }) as Uint8Array;
    foreign.set(pair.publicKey.bytes);
    expect(foreign instanceof Uint8Array).toBe(false);

    const ciphertext = await encrypt(PLAINTEXT, { ...pair.publicKey, bytes: foreign });
    expect(await decrypt(ciphertext, pair.secretKey)).toEqual(PLAINTEXT);

    const signer = await generate({ algorithm: 'ml-dsa-65' });
    const signature = await sign(PLAINTEXT, signer.secretKey);
    const foreignPk = runInNewContext('new Uint8Array(length)', {
      length: signer.publicKey.bytes.length,
    }) as Uint8Array;
    foreignPk.set(signer.publicKey.bytes);
    expect(await verify(PLAINTEXT, signature, { ...signer.publicKey, bytes: foreignPk })).toBe(
      true,
    );
  });

  it('still rejects byte-like values that are not Uint8Arrays', async () => {
    for (const bytes of [
      new Uint16Array(608), // an ArrayBuffer view, but not bytes
      { constructor: { name: 'Uint8Array' }, length: 1216 }, // not a view at all
    ]) {
      const error = await encrypt(PLAINTEXT, {
        algorithm: 'x-wing',
        use: 'public',
        bytes,
      } as never).then(
        () => undefined,
        (caught: unknown) => caught,
      );
      expect((error as PqcError).code).toBe('INVALID_KEY');
    }
  });

  it('verify still returns false for a wrong-length ML-DSA public key (F204-08)', async () => {
    const signer = await generate({ algorithm: 'ml-dsa-65' });
    const signature = await sign(PLAINTEXT, signer.secretKey);
    const truncated = { ...signer.publicKey, bytes: signer.publicKey.bytes.subarray(1) };
    expect(await verify(PLAINTEXT, signature, truncated)).toBe(false);
  });
}, 30_000);
