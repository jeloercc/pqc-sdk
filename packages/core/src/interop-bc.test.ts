import { describe, expect, it } from 'vitest';

import { pqc } from './index.js';
import type { SecretKey, SignatureAlgorithm } from './types.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from './vendor/ml-dsa/ml-dsa.js';
import { ml_kem768 } from './vendor/ml-kem/ml-kem.js';
import bcMldsa from './vectors/interop/bc-mldsa.json';
import bcMlkem768 from './vectors/interop/bc-mlkem768.json';

const MLDSA_SIGNERS = { '44': ml_dsa44, '65': ml_dsa65, '87': ml_dsa87 } as const;

function mldsaPublicKey(set: string, token: string) {
  const algorithm = `ml-dsa-${set}` as SignatureAlgorithm;
  return pqc.keys.deserialize(token, { algorithm, use: 'public' });
}

function mldsaSignerFor(set: string) {
  const signer = MLDSA_SIGNERS[set as keyof typeof MLDSA_SIGNERS];
  if (!signer) throw new Error(`unknown ML-DSA set ${set}`);
  return signer;
}

const hexToBytes = (hex: string) => new Uint8Array(Buffer.from(hex, 'hex'));

/**
 * Cross-implementation interop regression guard — BouncyCastle (Java), a
 * second, independent counterpart alongside CIRCL (Go, see
 * interop-circl.test.ts). No X-Wing: BouncyCastle does not implement it.
 *
 * Same two-part scope as interop-circl.test.ts — read that file's header for
 * the full rationale, restated briefly here:
 *
 * **Part 1** re-verifies/re-decapsulates bytes already committed at
 * generation time (scripts/interop/generate-bc-vectors.mts). It never calls
 * sign() or encapsulate(), so a regression there means this SDK's
 * verify()/decapsulate() no longer agrees with what BC already validated.
 *
 * **Part 2 (round-trip)** calls pqc.sign()/encapsulate() fresh, every CI
 * run, against the same key material BC already cross-checked, and confirms
 * the freshly-produced output is still accepted by this SDK's own
 * verify()/decapsulate(). This does NOT call BC again — Java never runs in
 * CI — so it is self-consistency, not a repeated cross-implementation check;
 * it exists so a broken generator (see the ML-DSA sign() mutation test this
 * pattern was built to catch, described in interop-circl.test.ts's history)
 * fails loudly instead of shipping silently.
 */

describe('BouncyCastle interop: ML-DSA-44/65/87 signature generation', () => {
  it.each(bcMldsa.cases)(
    'ML-DSA-$set: the SDK still accepts both its own and BC-produced signature',
    async ({ set, publicKeyToken, message, sdkSignatureHex, bcSignatureHex }) => {
      const publicKey = mldsaPublicKey(set, publicKeyToken);

      await expect(pqc.verify(message, hexToBytes(sdkSignatureHex), publicKey)).resolves.toBe(true);
      await expect(pqc.verify(message, hexToBytes(bcSignatureHex), publicKey)).resolves.toBe(true);
    },
  );

  it("does not accept a BC signature under a different set's message", async () => {
    const [first, second] = bcMldsa.cases;
    if (!first || !second) throw new Error('expected at least two ML-DSA cases in the fixture');
    const publicKey = mldsaPublicKey(first.set, first.publicKeyToken);
    await expect(
      pqc.verify(second.message, hexToBytes(first.bcSignatureHex), publicKey),
    ).resolves.toBe(false);
  });

  // --- Round-trip (see module doc comment above) ---
  it.each(bcMldsa.cases)(
    'ML-DSA-$set round-trip: pqc.sign(), called fresh right now, still verifies against the BC-cross-checked public key',
    async ({ set, seedHex, publicKeyToken, message }) => {
      const signer = mldsaSignerFor(set);
      const seed = hexToBytes(seedHex);
      const { publicKey, secretKey } = signer.keygen(seed);

      const publicKeyFromToken = mldsaPublicKey(set, publicKeyToken);
      expect(Buffer.from(publicKey).toString('hex')).toBe(
        Buffer.from(publicKeyFromToken.bytes).toString('hex'),
      );

      const algorithm = `ml-dsa-${set}` as SignatureAlgorithm;
      const secretKeyObj: SecretKey<SignatureAlgorithm> = {
        algorithm,
        use: 'secret',
        bytes: secretKey,
      };

      const freshSignature = await pqc.sign(message, secretKeyObj);
      await expect(pqc.verify(message, freshSignature, publicKeyFromToken)).resolves.toBe(true);
    },
  );
});

describe('BouncyCastle interop: ML-KEM-768 bidirectional shared-secret cross-check', () => {
  const {
    publicKeyHex,
    secretKeyHex,
    sdkCiphertextHex,
    sdkSharedSecretHex,
    bcCiphertextHex,
    bcSharedSecretHex,
  } = bcMlkem768.case;
  const secretKey = hexToBytes(secretKeyHex);

  it('the SDK still decapsulates its own committed ciphertext to the committed shared secret', () => {
    const sharedSecret = ml_kem768.decapsulate(hexToBytes(sdkCiphertextHex), secretKey);
    expect(Buffer.from(sharedSecret).toString('hex')).toBe(sdkSharedSecretHex);
  });

  it("the SDK's decapsulate still agrees with BC's committed ciphertext and shared secret", () => {
    const sharedSecret = ml_kem768.decapsulate(hexToBytes(bcCiphertextHex), secretKey);
    expect(Buffer.from(sharedSecret).toString('hex')).toBe(bcSharedSecretHex);
  });

  it('a tampered BC ciphertext no longer reproduces the committed shared secret', () => {
    const tampered = hexToBytes(bcCiphertextHex);
    tampered[0] = (tampered[0] ?? 0) ^ 0xff;
    const sharedSecret = ml_kem768.decapsulate(tampered, secretKey);
    expect(Buffer.from(sharedSecret).toString('hex')).not.toBe(bcSharedSecretHex);
  });

  // --- Round-trip (see module doc comment above) ---
  it('round-trip: encapsulate(), called fresh right now, still decapsulates correctly against the BC-cross-checked key', () => {
    const publicKey = hexToBytes(publicKeyHex);
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
    const recovered = ml_kem768.decapsulate(cipherText, secretKey);
    expect(Buffer.from(recovered).toString('hex')).toBe(Buffer.from(sharedSecret).toString('hex'));
  });
});
