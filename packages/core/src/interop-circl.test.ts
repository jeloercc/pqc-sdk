import { describe, expect, it } from 'vitest';

import { pqc } from './index.js';
import type { SignatureAlgorithm } from './types.js';
import { ml_kem768 } from './vendor/ml-kem/ml-kem.js';
import circlMldsa from './vectors/interop/circl-mldsa.json';
import circlMlkem768 from './vectors/interop/circl-mlkem768.json';
import circlXwing from './vectors/interop/circl-xwing.json';
import { ml_kem768_x25519 } from './x-wing.js';

function mldsaPublicKey(set: string, token: string) {
  const algorithm = `ml-dsa-${set}` as SignatureAlgorithm;
  return pqc.keys.deserialize(token, { algorithm, use: 'public' });
}

/**
 * Cross-implementation interop regression guard.
 *
 * The vectors here were produced by scripts/interop/generate-circl-vectors.mts
 * cross-checking this SDK against Cloudflare's CIRCL (Go) — an independent
 * codebase, not the @noble/post-quantum family this SDK is built on. That
 * cross-check (does CIRCL accept what the SDK produced; does the SDK accept
 * what CIRCL produced) happened once, at generation time, and is not
 * repeated here: Go/CIRCL never runs in CI. What these tests actually assert
 * is narrower and CI-appropriate — that the SDK's own code still agrees with
 * the committed bytes, i.e. a regression in this SDK's sign/verify or
 * encapsulate/decapsulate would be caught here even though CIRCL is absent.
 * See each vector file's `meta` block for exactly what was cross-checked,
 * against which CIRCL version, and how to reproduce it.
 */

const hexToBytes = (hex: string) => new Uint8Array(Buffer.from(hex, 'hex'));

describe('CIRCL interop: ML-DSA-44/65/87 signature generation', () => {
  it.each(circlMldsa.cases)(
    'ML-DSA-$set: the SDK still accepts both its own and CIRCL-produced signature',
    async ({ set, publicKeyToken, message, sdkSignatureHex, circlSignatureHex }) => {
      const publicKey = mldsaPublicKey(set, publicKeyToken);

      await expect(pqc.verify(message, hexToBytes(sdkSignatureHex), publicKey)).resolves.toBe(true);
      await expect(pqc.verify(message, hexToBytes(circlSignatureHex), publicKey)).resolves.toBe(
        true,
      );
    },
  );

  it("does not accept a CIRCL signature under a different set's message", async () => {
    // Cheap mutation check: swapping the message must break verification of a
    // genuinely independent (CIRCL-produced) signature, same as any other.
    const [first, second] = circlMldsa.cases;
    if (!first || !second) throw new Error('expected at least two ML-DSA cases in the fixture');
    const publicKey = mldsaPublicKey(first.set, first.publicKeyToken);
    await expect(
      pqc.verify(second.message, hexToBytes(first.circlSignatureHex), publicKey),
    ).resolves.toBe(false);
  });
});

describe('CIRCL interop: X-Wing bidirectional shared-secret cross-check', () => {
  const {
    publicKeyHex,
    secretKeyHex,
    sdkCiphertextHex,
    sdkSharedSecretHex,
    circlCiphertextHex,
    circlSharedSecretHex,
  } = circlXwing.case;
  const secretKey = hexToBytes(secretKeyHex);

  it('the SDK still decapsulates its own committed ciphertext to the committed shared secret', () => {
    const sharedSecret = ml_kem768_x25519.decapsulate(hexToBytes(sdkCiphertextHex), secretKey);
    expect(Buffer.from(sharedSecret).toString('hex')).toBe(sdkSharedSecretHex);
  });

  it("the SDK's decapsulate still agrees with CIRCL's committed ciphertext and shared secret", () => {
    // This is the direction that matters most: CIRCL — a genuinely independent
    // codebase — produced this ciphertext once, at generation time. Every CI
    // run re-checks that this SDK's decapsulate() still processes it correctly.
    const sharedSecret = ml_kem768_x25519.decapsulate(hexToBytes(circlCiphertextHex), secretKey);
    expect(Buffer.from(sharedSecret).toString('hex')).toBe(circlSharedSecretHex);
  });

  it('a tampered CIRCL ciphertext no longer reproduces the committed shared secret', () => {
    const tampered = hexToBytes(circlCiphertextHex);
    tampered[0] = (tampered[0] ?? 0) ^ 0xff;
    const sharedSecret = ml_kem768_x25519.decapsulate(tampered, secretKey);
    expect(Buffer.from(sharedSecret).toString('hex')).not.toBe(circlSharedSecretHex);
  });

  void publicKeyHex; // recorded for provenance/reproducibility; not needed by these assertions.
});

describe('CIRCL interop: ML-KEM-768 bidirectional shared-secret cross-check', () => {
  const {
    secretKeyHex,
    sdkCiphertextHex,
    sdkSharedSecretHex,
    circlCiphertextHex,
    circlSharedSecretHex,
  } = circlMlkem768.case;
  const secretKey = hexToBytes(secretKeyHex);

  it('the SDK still decapsulates its own committed ciphertext to the committed shared secret', () => {
    const sharedSecret = ml_kem768.decapsulate(hexToBytes(sdkCiphertextHex), secretKey);
    expect(Buffer.from(sharedSecret).toString('hex')).toBe(sdkSharedSecretHex);
  });

  it("the SDK's decapsulate still agrees with CIRCL's committed ciphertext and shared secret", () => {
    const sharedSecret = ml_kem768.decapsulate(hexToBytes(circlCiphertextHex), secretKey);
    expect(Buffer.from(sharedSecret).toString('hex')).toBe(circlSharedSecretHex);
  });

  it('a tampered CIRCL ciphertext no longer reproduces the committed shared secret', () => {
    const tampered = hexToBytes(circlCiphertextHex);
    tampered[0] = (tampered[0] ?? 0) ^ 0xff;
    const sharedSecret = ml_kem768.decapsulate(tampered, secretKey);
    expect(Buffer.from(sharedSecret).toString('hex')).not.toBe(circlSharedSecretHex);
  });
});
