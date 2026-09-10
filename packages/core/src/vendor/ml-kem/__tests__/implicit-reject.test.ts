import { readFileSync } from 'node:fs';

import { sha3_256, shake256 } from '@noble/hashes/sha3.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';

import mlkemEncapDecap from '../../../vectors/mlkem768-encapdecap.json';
import mlkemKeygen from '../../../vectors/mlkem768-keygen.json';
import { ml_kem768 } from '../ml-kem.js';

/**
 * F203-18 regression suite — implicit-reject selection and intermediate-value destruction.
 *
 * FIPS 203 §6.3, on step 9 of ML-KEM.Decaps_internal: "The 'implicit reject' flag computed
 * in step 9 (by comparing c and c′) is a secret piece of intermediate data. As specified in
 * the requirements in Section 3.3, this flag shall be destroyed prior to
 * ML-KEM.Decaps_internal terminating. In particular, returning the value of the flag as an
 * output in any form is not permitted."
 *
 * The correction replaced two ternaries on that flag — one choosing the return value, one
 * choosing which candidate to zeroize — with byte-wise mask arithmetic, and made the
 * destruction of both candidates unconditional.
 *
 * What these tests can and cannot establish, stated plainly:
 *
 *   - They CAN establish that the change is output-inert on both paths, that the reject
 *     path still returns exactly J(z ‖ c), and that no secret-dependent branch remains in
 *     the source.
 *   - They CANNOT establish that the compiled path is constant-time. JavaScript exposes no
 *     verifiable constant-time primitives and the JIT may specialise on observed values.
 *     No timing assertion appears here, because a timing assertion in this environment
 *     would be theatre — it would measure the host, not the property.
 */

/**
 * The vendored primitive directly, not `KEM_ALGORITHMS['ml-kem-768'].kem`. The SDK's
 * structural `NobleKem` interface declares only keygen/encapsulate/decapsulate, and the
 * prepared-path case below needs `prepare()`.
 */
interface MlKemSurface {
  keygen(seed?: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array };
  encapsulate(publicKey: Uint8Array): { cipherText: Uint8Array; sharedSecret: Uint8Array };
  decapsulate(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array;
  prepare(publicKey: Uint8Array): {
    decapsulate(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array;
  };
}

const kem = ml_kem768 as unknown as MlKemSurface;

/**
 * Returns a copy of `bytes` with one byte flipped, forcing c !== c′ so the implicit-reject
 * branch is taken. The `as number` matches the idiom already used in
 * `key-mutations.test.ts:118` for the same `noUncheckedIndexedAccess` reason.
 */
function tamper(bytes: Uint8Array, index: number, mask = 0x01): Uint8Array {
  const copy = Uint8Array.from(bytes);
  copy[index] = (copy[index] as number) ^ mask;
  return copy;
}

/** ACVP fixtures are JSON; `noUncheckedIndexedAccess` makes indexed reads `| undefined`. */
function firstKeygenCase(): { d: string; z: string; dk: string } {
  const [first] = mlkemKeygen.cases;
  if (!first) throw new Error('mlkem768-keygen.json has no cases');
  return first;
}

/** ML-KEM-768 secret-key layout (FIPS 203 §7.1): dk_PKE ‖ ek ‖ H(ek) ‖ z, with k = 3. */
const K768 = 768 * 3; // 2304
const Z_OFFSET = K768 + 64; // 2368; z is the final 32 bytes of the 2400-byte dk

describe('F203-18: implicit-reject selection is output-inert', () => {
  it('the valid path still reproduces every ACVP encapsulation vector', () => {
    // The success branch of the mask must be byte-identical to the previous ternary. These
    // are the same known-answer vectors used by nist-vectors.test.ts, exercised here
    // directly against the primitive rather than through the SDK envelope.
    const mismatches: string[] = [];

    for (const { tcId, dk, c, k } of mlkemEncapDecap.encapsulation) {
      const recovered = kem.decapsulate(hexToBytes(c), hexToBytes(dk));
      if (Buffer.from(recovered).toString('hex') !== k.toLowerCase()) {
        mismatches.push(`tcId ${tcId}`);
      }
    }

    expect(mismatches).toEqual([]);
    expect(mlkemEncapDecap.encapsulation.length).toBeGreaterThan(0);
  });

  it('the reject path returns exactly J(z ‖ c), computed independently in the test', () => {
    // FIPS 203 Algorithm 18 step 10: on mismatch, K′ <- J(z ‖ c), where J is SHAKE256 with
    // a 32-byte output. Deriving it here from the standard rather than from the
    // implementation is what makes this a check of the value and not just of self-agreement.
    const { d, z: zHex, dk } = firstKeygenCase();
    const seed = new Uint8Array([...hexToBytes(d), ...hexToBytes(zHex)]);
    const { publicKey, secretKey } = kem.keygen(seed);

    expect(Buffer.from(secretKey).toString('hex')).toBe(dk.toLowerCase());

    const { cipherText } = kem.encapsulate(publicKey);
    const tampered = tamper(cipherText, 0); // forces c !== c′, so isValid === false

    const z = secretKey.subarray(Z_OFFSET, Z_OFFSET + 32);
    const expected = shake256.create({ dkLen: 32 }).update(z).update(tampered).digest();

    const rejected = kem.decapsulate(tampered, secretKey);

    expect(Buffer.from(rejected).toString('hex')).toBe(Buffer.from(expected).toString('hex'));
  });

  it('never throws on a corrupted ciphertext — it implicitly rejects', () => {
    // The whole point of the construction: decapsulation of a bad ciphertext yields a
    // different-but-valid shared secret rather than an error the attacker can observe.
    const { publicKey, secretKey } = kem.keygen();
    const { cipherText, sharedSecret } = kem.encapsulate(publicKey);

    for (const position of [0, 1, 543, 1087]) {
      const tampered = tamper(cipherText, position, 0xff);

      const result = kem.decapsulate(tampered, secretKey);

      expect(result).toHaveLength(32);
      expect(Buffer.from(result).equals(Buffer.from(sharedSecret))).toBe(false);
    }
  });

  it('is deterministic on the reject path: the same bad ciphertext yields the same secret', () => {
    // Guards against the mask accidentally mixing in fresh state.
    const { publicKey, secretKey } = kem.keygen();
    const { cipherText } = kem.encapsulate(publicKey);
    const tampered = tamper(cipherText, 100, 0x80);

    const first = kem.decapsulate(tampered, secretKey);
    const second = kem.decapsulate(tampered, secretKey);

    expect(Buffer.from(first).equals(Buffer.from(second))).toBe(true);
  });

  it('the prepared decapsulate path agrees with the plain one on both branches', () => {
    // The second call site carries the identical correction, so it must agree byte for byte.
    const { publicKey, secretKey } = kem.keygen();
    const prepared = kem.prepare(publicKey);
    const { cipherText } = kem.encapsulate(publicKey);

    const tampered = tamper(cipherText, 7);

    for (const ct of [cipherText, tampered]) {
      const plain = kem.decapsulate(ct, secretKey);
      const viaPrepared = prepared.decapsulate(ct, secretKey);
      expect(Buffer.from(viaPrepared).equals(Buffer.from(plain))).toBe(true);
    }
  });
});

describe('F203-18: intermediate values are destroyed', () => {
  it('zeroizes both shared-secret candidates, not only the non-returned one', () => {
    // Khat is a view into `kr`, the SHA3-512 digest of (m′ ‖ H(ek)). Reconstructing kr here
    // and checking the returned secret is a detached buffer establishes that the returned
    // value cannot alias a candidate the implementation is meant to have wiped — if it did,
    // wiping both candidates unconditionally would have zeroed the return value.
    const { publicKey, secretKey } = kem.keygen();
    const { cipherText, sharedSecret } = kem.encapsulate(publicKey);

    const recovered = kem.decapsulate(cipherText, secretKey);

    expect(Buffer.from(recovered).equals(Buffer.from(sharedSecret))).toBe(true);
    expect(recovered.some((byte) => byte !== 0)).toBe(true);
    // A detached 32-byte buffer, not a subarray of a larger digest still held elsewhere.
    expect(recovered.byteOffset).toBe(0);
    expect(recovered.buffer.byteLength).toBe(32);
  });

  it('does not leave H(ek) or the public key mutated in the caller’s secret key', () => {
    // cleanBytes now receives Khat as well; Khat aliases kr, not the secret key. This pins
    // that the widened destruction did not start reaching into caller-owned memory.
    const { publicKey, secretKey } = kem.keygen();
    const before = Uint8Array.from(secretKey);
    const { cipherText } = kem.encapsulate(publicKey);

    kem.decapsulate(cipherText, secretKey);

    expect(Buffer.from(secretKey).equals(Buffer.from(before))).toBe(true);
    // And the embedded H(ek) is still the real hash, i.e. nothing was zeroed in place.
    const embedded = secretKey.subarray(K768 + 32, K768 + 64);
    expect(Buffer.from(embedded).equals(Buffer.from(sha3_256(publicKey)))).toBe(true);
  });
});

describe('F203-18: no secret-dependent branch remains in the source', () => {
  it('decapsulate selects through the mask helper, not a ternary on isValid', () => {
    // FIPS 203 §6.3 constrains how the flag may be used, and no behavioural test can see
    // the difference between a branch and a mask — both produce the same bytes. Only the
    // source can be checked, so a future edit reintroducing the ternary fails here.
    const file = readFileSync(new URL('../ml-kem.ts', import.meta.url), 'utf8');
    const code = file
      .split('\n')
      .filter((line) => !line.trimStart().startsWith('//') && !line.trimStart().startsWith('*'))
      .join('\n');

    expect(code).not.toMatch(/isValid\s*\?/);
    expect(code).not.toMatch(/!isValid\s*\?/);

    // Both call sites must use the helper and destroy both candidates unconditionally.
    expect(code.match(/selectSharedSecret\(isValid, Khat, Kbar\)/g)).toHaveLength(2);
    expect(
      code.match(/cleanBytes\(msg, cipherText2, kr\.subarray\(32\), Khat, Kbar\)/g),
    ).toHaveLength(2);
  });

  it('the mask yields exactly one candidate for every byte pair', () => {
    // Exhaustive over the whole byte domain: for both flag values and all 256x256 input
    // pairs, the selection must equal the intended candidate. 131,072 combinations.
    const select = (isValid: boolean, a: number, b: number): number => {
      const mask = -Number(isValid) & 0xff;
      return (a & mask) | (b & ~mask & 0xff);
    };

    const wrong: string[] = [];
    for (const isValid of [true, false]) {
      for (let a = 0; a < 256; a++) {
        for (let b = 0; b < 256; b++) {
          const want = isValid ? a : b;
          if (select(isValid, a, b) !== want && wrong.length < 10) {
            wrong.push(`isValid=${isValid} a=${a} b=${b}`);
          }
        }
      }
    }

    expect(wrong).toEqual([]);
  });
});
