import { shake128, shake256 } from '@noble/hashes/sha3.js';
import { describe, expect, it } from 'vitest';

import { ml_dsa44, ml_dsa65, ml_dsa87 } from '../ml-dsa.js';

/**
 * F204-09 (intermediate-value zeroization) and F204-21 (SHAKE256/SHAKE128) tripwires.
 *
 * Both rows are CONFORMING (delegated) — meaning source inspection confirmed their
 * satisfaction but no repository test would fail if a provider version bump silently
 * removed the relevant code. These tests install those tripwires.
 *
 * --- F204-21 (SHAKE256/SHAKE128 from FIPS 202) ---
 *
 * FIPS 204 §3.7: "This standard makes use of the functions SHAKE256 and SHAKE128, as
 * defined in FIPS 202." The vendor file imports these from `@noble/hashes/sha3.js`.
 * A bump that renamed or replaced them without touching the vendor copy would be caught
 * here, because the tests use the same imports and cross-check against known vectors.
 *
 * We test the exact SHAKE256 and SHAKE128 behavior the vendor uses:
 *   - 512-bit (64-byte) SHAKE256 output — used for tr = H(pk, 512) and µ = H(tr || M, 512)
 *   - 256-bit (32-byte) SHAKE256 output — used for seed expansion
 *   - SHAKE256 with configurable dkLen — used for cTilde (lambda bits)
 *
 * The vectors are the NIST SHAKE test vectors (FIPS 202 Appendix A.2).
 *
 * --- F204-09 (intermediate zeroization) —  behavioral evidence via sign() ---
 *
 * FIPS 204 §3.6.3: "implementations of ML-DSA shall ensure that any potentially sensitive
 * intermediate data is destroyed as soon as it is no longer needed." The F204-10 suite
 * already covers the verification path (see verify-zeroization.test.ts). F204-09 is the
 * broader requirement for keygen and signing.
 *
 * We cannot directly observe heap state in JavaScript, but we can establish that the
 * keygen/sign operations complete without exposing raw key material through their return
 * value, and that repeated calls produce fresh outputs (evidencing that no intermediate
 * is reused or leaked across calls). This is behavioral evidence, not a memory probe.
 */

const utf8 = new TextEncoder();

describe('F204-21: SHAKE256/SHAKE128 are FIPS 202 functions (provider tripwire)', () => {
  // NIST SHAKE256 test vector (FIPS 202, Sample #1):
  // input: empty string, output length: 32 bytes
  // expected: 46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f
  it('shake256 with empty input matches the NIST FIPS 202 sample #1 (32-byte output)', () => {
    const result = shake256(new Uint8Array(0), { dkLen: 32 });
    expect(Buffer.from(result).toString('hex')).toBe(
      '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f',
    );
  });

  // NIST SHAKE128 test vector (FIPS 202, Sample #1):
  // input: empty string, output length: 32 bytes
  // expected: 7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26
  it('shake128 with empty input matches the NIST FIPS 202 sample #1 (32-byte output)', () => {
    const result = shake128(new Uint8Array(0), { dkLen: 32 });
    expect(Buffer.from(result).toString('hex')).toBe(
      '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26',
    );
  });

  it('shake256 produces distinct 64-byte outputs for distinct inputs (TR_BYTES = 64)', () => {
    const pk1 = new Uint8Array(1952).fill(0x01);
    const pk2 = new Uint8Array(1952).fill(0x02);

    const tr1 = shake256(pk1, { dkLen: 64 });
    const tr2 = shake256(pk2, { dkLen: 64 });

    expect(tr1).toHaveLength(64);
    expect(tr2).toHaveLength(64);
    expect(Buffer.from(tr1).equals(Buffer.from(tr2))).toBe(false);
  });

  it('shake256 is deterministic: same input always yields the same output', () => {
    const input = utf8.encode('deterministic input');
    const out1 = shake256(input, { dkLen: 64 });
    const out2 = shake256(input, { dkLen: 64 });

    expect(Buffer.from(out1).equals(Buffer.from(out2))).toBe(true);
  });
});

describe('F204-09: keygen and sign do not reuse or expose intermediate values across calls', () => {
  for (const [name, dsa] of [
    ['ml-dsa-44', ml_dsa44],
    ['ml-dsa-65', ml_dsa65],
    ['ml-dsa-87', ml_dsa87],
  ] as const) {
    it(`${name}: two keygens produce distinct key pairs`, () => {
      const { publicKey: pk1, secretKey: sk1 } = dsa.keygen();
      const { publicKey: pk2, secretKey: sk2 } = dsa.keygen();

      expect(Buffer.from(pk1).equals(Buffer.from(pk2))).toBe(false);
      expect(Buffer.from(sk1).equals(Buffer.from(sk2))).toBe(false);
    });

    it(`${name}: two signatures over the same message with the same key differ (hedged rnd)`, () => {
      const { publicKey, secretKey } = dsa.keygen();
      const msg = utf8.encode('same message');

      const sig1 = dsa.sign(msg, secretKey);
      const sig2 = dsa.sign(msg, secretKey);

      // Both must verify.
      expect(dsa.verify(sig1, msg, publicKey)).toBe(true);
      expect(dsa.verify(sig2, msg, publicKey)).toBe(true);
      // Must differ: rnd is fresh per Algorithm 2 step 6.
      expect(Buffer.from(sig1).equals(Buffer.from(sig2))).toBe(false);
    });

    it(`${name}: the return values of keygen do not alias each other's memory`, () => {
      const { publicKey, secretKey } = dsa.keygen();
      // If they aliased, mutating one would change the other.
      const pkCopy = Uint8Array.from(publicKey);
      secretKey[0] = (secretKey[0] as number) ^ 0xff;
      // publicKey must be unchanged.
      expect(publicKey[0]).toBe(pkCopy[0]);
    });
  }
});
