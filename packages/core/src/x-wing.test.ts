import { ml_kem768_x25519 as npmXWing } from '@noble/post-quantum/hybrid.js';
import { randomBytes } from '@noble/post-quantum/utils.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';

import { ml_kem768_x25519 as vendoredXWing } from './x-wing.js';

/**
 * Cross-check that repointing X-Wing at the vendored, FIPS-corrected `ml_kem768`
 * (F203-19, F203-18) changed method, not output. `npmXWing` is `@noble/post-quantum`'s
 * own preset, still built from its unpatched internal `ml_kem768`; `vendoredXWing` is
 * this SDK's reconstruction built from `vendor/ml-kem/ml-kem.ts`. If these two ever
 * disagree, X-Wing keys or ciphertexts produced before this change would stop
 * round-tripping after it — the failure this suite exists to catch.
 */
describe('X-Wing cross-check: vendored ML-KEM-768 vs npm ML-KEM-768 (F203-19, F203-18)', () => {
  it('reports identical component lengths', () => {
    expect(vendoredXWing.lengths).toEqual(npmXWing.lengths);
  });

  it('deterministic keygen produces identical keys under both presets', () => {
    const seed = randomBytes(vendoredXWing.lengths.seed);

    const npmPair = npmXWing.keygen(seed);
    const vendoredPair = vendoredXWing.keygen(seed);

    expect(bytesToHex(vendoredPair.publicKey)).toBe(bytesToHex(npmPair.publicKey));
    expect(bytesToHex(vendoredPair.secretKey)).toBe(bytesToHex(npmPair.secretKey));
  });

  it('seeded encapsulation produces identical ciphertext and shared secret under both presets', () => {
    const seed = randomBytes(vendoredXWing.lengths.seed);
    const { publicKey } = vendoredXWing.keygen(seed);
    const eseed = randomBytes(vendoredXWing.lengths.msgRand);

    const npmEnc = npmXWing.encapsulate(publicKey, eseed);
    const vendoredEnc = vendoredXWing.encapsulate(publicKey, eseed);

    expect(bytesToHex(vendoredEnc.cipherText)).toBe(bytesToHex(npmEnc.cipherText));
    expect(bytesToHex(vendoredEnc.sharedSecret)).toBe(bytesToHex(npmEnc.sharedSecret));
  });

  it('npm-backed encapsulation decapsulates correctly under the vendored preset', () => {
    const seed = randomBytes(vendoredXWing.lengths.seed);
    const { publicKey, secretKey } = vendoredXWing.keygen(seed);

    const { cipherText, sharedSecret } = npmXWing.encapsulate(publicKey);
    const recovered = vendoredXWing.decapsulate(cipherText, secretKey);

    expect(bytesToHex(recovered)).toBe(bytesToHex(sharedSecret));
  });

  it('vendored-backed encapsulation decapsulates correctly under the npm preset', () => {
    const seed = randomBytes(vendoredXWing.lengths.seed);
    const { publicKey, secretKey } = npmXWing.keygen(seed);

    const { cipherText, sharedSecret } = vendoredXWing.encapsulate(publicKey);
    const recovered = npmXWing.decapsulate(cipherText, secretKey);

    expect(bytesToHex(recovered)).toBe(bytesToHex(sharedSecret));
  });

  it('a tampered ciphertext implicitly rejects to the same secret under both presets', () => {
    const seed = randomBytes(vendoredXWing.lengths.seed);
    const { publicKey, secretKey } = vendoredXWing.keygen(seed);
    const { cipherText, sharedSecret } = vendoredXWing.encapsulate(publicKey);

    const tampered = cipherText.slice();
    tampered[0]! ^= 0x01;

    const npmRejected = npmXWing.decapsulate(tampered, secretKey);
    const vendoredRejected = vendoredXWing.decapsulate(tampered, secretKey);

    // ML-KEM implicit rejection: no throw, but never the real secret — and both
    // implementations must land on the same (wrong) secret as each other.
    expect(bytesToHex(vendoredRejected)).toBe(bytesToHex(npmRejected));
    expect(bytesToHex(vendoredRejected)).not.toBe(bytesToHex(sharedSecret));
  });
});
