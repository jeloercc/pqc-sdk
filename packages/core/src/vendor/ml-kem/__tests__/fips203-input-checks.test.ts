import { sha3_256 } from '@noble/hashes/sha3.js';
import { describe, expect, it } from 'vitest';

import { ml_kem768 } from '../ml-kem.js';

/**
 * FIPS 203 §7.2 modulus check (F203-05) and §7.3 dk hash check (F203-10).
 *
 * Both checks live in the vendored primitive. The compliance matrix
 * (docs/compliance/FIPS-203-MATRIX.md §3.3) recorded them as
 * CONFORMING (delegated) because source inspection confirmed the logic but no
 * repository test exercised it. A vendor version bump that silently removed
 * either check would still pass CI — the mutation-check rule requires that a
 * test guarding a cryptographic property fails when that property is broken.
 * These tests close that gap.
 *
 * --- F203-05 (§7.2 step 2): the modulus (ByteEncode12 ∘ ByteDecode12) round-trip ---
 *
 * FIPS 203 §7.2: "Perform the computation test ← ByteEncode12(ByteDecode12(ek[0:384k])).
 * If test ≠ ek[0:384k], then input checking failed."
 *
 * A coefficient ≥ q=3329 cannot survive the round-trip: ByteDecode12 interprets each
 * 12-bit word modulo q, so 3329 maps to 0. ByteEncode12 of 0 encodes differently from
 * ByteEncode12 of 3329 in 12-bit representation, so the check catches it.
 *
 * Construction: we produce a valid encapsulation key, then inject a coefficient
 * equal to q into the first polynomial element position (the low 12 bits of the
 * first two bytes encode the first coefficient in little-endian 12-bit packing).
 * q = 3329 = 0xD01, so in 12-bit LE: byte 0 = 0x01, byte 1 = (byte 1 & 0xF0) | 0x0D.
 * We then confirm encapsulate throws, and that it fails _before_ any ciphertext is
 * produced (i.e. throws rather than returning a result).
 *
 * --- F203-10 (§7.3 step 3): the dk embedded hash check ---
 *
 * FIPS 203 §7.3: "Perform the computation test ← H(dk[384k : 768k+32]). If test ≠
 * dk[768k+32 : 768k+64], then input checking has failed."
 *
 * For ML-KEM-768 (k=3): 384k=1152, 768k=2304. The embedded H(ek) is dk[1184:2336],
 * and the stored hash is dk[2336:2368]. We tamper the stored hash by flipping one bit
 * in dk[2336] and confirm decapsulate throws.
 */

const Q = 3329; // ML-KEM's prime modulus

describe('F203-05: §7.2 modulus check rejects a public key with a coefficient ≥ q', () => {
  // ML-KEM-768 k=3, so ek length = 384*3+32 = 1184 bytes. Coefficients are
  // encoded in little-endian 12-bit groups: bytes 0+1 share the first coefficient
  // as bits [0:11] (byte 0 holds bits [0:7], byte 1 holds bits [8:11] in its low nibble).
  // Inject q = 3329 = 0b110100000001 into coefficient 0.
  function injectCoeffOverQ(publicKey: Uint8Array): Uint8Array {
    const bad = Uint8Array.from(publicKey);
    // 12-bit little-endian: coefficient 0 spans bytes [0] (low 8 bits) and [1] (high 4 bits).
    // q = 3329 = 0xD01. Low byte = 0x01, high nibble of byte 1 = 0xD.
    bad[0] = Q & 0xff; // 0x01
    bad[1] = ((bad[1] as number) & 0xf0) | ((Q >> 8) & 0x0f); // preserve upper nibble, set lower to 0xD
    return bad;
  }

  it('encapsulate throws on a public key whose first coefficient equals q', () => {
    const { publicKey } = ml_kem768.keygen();
    const badKey = injectCoeffOverQ(publicKey);

    expect(() => ml_kem768.encapsulate(badKey)).toThrow();
  });

  it('encapsulate on a genuine public key succeeds (non-regression)', () => {
    const { publicKey } = ml_kem768.keygen();

    expect(() => ml_kem768.encapsulate(publicKey)).not.toThrow();
  });

  it('the genuine key still round-trips correctly after injecting the bad key is rejected', () => {
    const { publicKey, secretKey } = ml_kem768.keygen();
    const badKey = injectCoeffOverQ(publicKey);

    // Bad key is rejected.
    expect(() => ml_kem768.encapsulate(badKey)).toThrow();

    // Genuine key still works.
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
    const recovered = ml_kem768.decapsulate(cipherText, secretKey);
    expect(recovered).toEqual(sharedSecret);
  });
});

describe('F203-10: §7.3 dk hash check rejects a decapsulation key with a tampered H(ek)', () => {
  // ML-KEM-768 k=3 secret key layout (FIPS 203 §7.3):
  //   dkPKE : 384*k bytes     = 1152 bytes  [0     : 1152]
  //   ek    : 384*k+32 bytes  = 1184 bytes  [1152  : 2336]
  //   H(ek) : 32 bytes                      [2336  : 2368]
  //   z     : 32 bytes                      [2368  : 2400]
  // H(ek) = SHA3-256(ek) = SHA3-256(dk[1152:2336]).
  // The check: H(dk[1152:2336]) must equal dk[2336:2368].
  const DK_PKE_LEN = 384 * 3; // 1152
  const EK_LEN = 384 * 3 + 32; // 1184
  const H_EK_OFFSET = DK_PKE_LEN + EK_LEN; // 2336
  const H_EK_END = H_EK_OFFSET + 32; // 2368

  function tamperedHash(secretKey: Uint8Array): Uint8Array {
    const bad = Uint8Array.from(secretKey);
    // Flip a single bit in the stored H(ek) field.
    bad[H_EK_OFFSET] = (bad[H_EK_OFFSET] as number) ^ 0x01;
    return bad;
  }

  it('decapsulate throws when the stored H(ek) does not match H(ek computed from dk)', () => {
    const { publicKey, secretKey } = ml_kem768.keygen();
    const { cipherText } = ml_kem768.encapsulate(publicKey);
    const badSk = tamperedHash(secretKey);

    expect(() => ml_kem768.decapsulate(cipherText, badSk)).toThrow();
  });

  it('the stored H(ek) field matches SHA3-256(ek) in a genuine key', () => {
    const { publicKey, secretKey } = ml_kem768.keygen();

    // Re-derive H(ek) from the embedded ek to confirm the field is correctly populated.
    const ek = secretKey.subarray(DK_PKE_LEN, DK_PKE_LEN + EK_LEN);
    const expectedHash = sha3_256(ek);
    const storedHash = secretKey.subarray(H_EK_OFFSET, H_EK_END);

    expect(storedHash).toEqual(expectedHash);

    // And confirm the genuine key still decapsulates correctly.
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
    expect(ml_kem768.decapsulate(cipherText, secretKey)).toEqual(sharedSecret);
  });

  it('decapsulate with a genuine key works correctly (non-regression)', () => {
    const { publicKey, secretKey } = ml_kem768.keygen();
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);

    expect(() => ml_kem768.decapsulate(cipherText, secretKey)).not.toThrow();
    expect(ml_kem768.decapsulate(cipherText, secretKey)).toEqual(sharedSecret);
  });
});
