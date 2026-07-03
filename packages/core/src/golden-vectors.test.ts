import { hexToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';

import { PqcError } from './errors.js';
import { pqc } from './index.js';
import golden from './vectors/golden-serialization-v1.json';

/**
 * Golden serialization vectors — the cross-version stability lock.
 *
 * The fixture was generated with the published @pqc-sdk/core@0.3.8 (see
 * `meta.generatedWith`); these tests deserialize and USE its artifacts on
 * every run. If any of them fails, a change broke the serialized format for
 * every artifact produced by an already-published version: that is a breaking
 * change requiring a major version bump, a docs/serialization-format.md
 * update and regenerated vectors in the same PR — never "fix" these tests to
 * match new output without that acknowledgment (.claude/rules/crypto-review.md).
 */

const utf8 = new TextEncoder();

const kemPublicToken = golden.keys['ml-kem-768'].publicToken;
const kemSecretToken = golden.keys['ml-kem-768'].secretToken;
const dsaPublicToken = golden.keys['ml-dsa-65'].publicToken;
const dsaSecretToken = golden.keys['ml-dsa-65'].secretToken;

const expectPqcCode = (fn: () => unknown, code: string) => {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(PqcError);
    expect((error as PqcError).code).toBe(code);
    return;
  }
  expect.unreachable('expected the call to throw');
};

describe('golden vectors: key tokens from published 0.3.x', () => {
  const cases = [
    { token: kemPublicToken, algorithm: 'ml-kem-768', use: 'public', length: 1184 },
    { token: kemSecretToken, algorithm: 'ml-kem-768', use: 'secret', length: 2400 },
    { token: dsaPublicToken, algorithm: 'ml-dsa-65', use: 'public', length: 1952 },
    { token: dsaSecretToken, algorithm: 'ml-dsa-65', use: 'secret', length: 4032 },
  ] as const;

  it.each(cases)('deserializes the $algorithm $use token', ({ token, algorithm, use, length }) => {
    const key = pqc.keys.deserialize(token);
    expect(key.algorithm).toBe(algorithm);
    expect(key.use).toBe(use);
    expect(key.bytes.length).toBe(length);
  });

  it.each(cases)('round-trips the $algorithm $use token byte-for-byte', ({ token }) => {
    // serialize(deserialize(t)) === t locks the canonical encoding itself.
    expect(pqc.keys.serialize(pqc.keys.deserialize(token))).toBe(token);
  });
});

describe('golden vectors: artifacts from published 0.3.x still work', () => {
  it('decrypts the golden ciphertext to the exact expected plaintext', async () => {
    const secretKey = pqc.keys.deserialize(kemSecretToken, {
      algorithm: 'ml-kem-768',
      use: 'secret',
    });
    const plaintext = await pqc.decrypt(hexToBytes(golden.encryption.ciphertextHex), secretKey);
    expect(new TextDecoder().decode(plaintext)).toBe(golden.encryption.plaintextUtf8);
  });

  it('verifies the golden signature against the golden public key', async () => {
    const publicKey = pqc.keys.deserialize(dsaPublicToken, {
      algorithm: 'ml-dsa-65',
      use: 'public',
    });
    const signature = hexToBytes(golden.signature.signatureHex);
    await expect(pqc.verify(golden.signature.messageUtf8, signature, publicKey)).resolves.toBe(
      true,
    );
    // Mutation check: the same signature must NOT verify for a different message.
    await expect(pqc.verify('a different message', signature, publicKey)).resolves.toBe(false);
  });

  it('encrypts fresh data for the golden public key, decryptable by the golden secret key', async () => {
    const publicKey = pqc.keys.deserialize(kemPublicToken, {
      algorithm: 'ml-kem-768',
      use: 'public',
    });
    const secretKey = pqc.keys.deserialize(kemSecretToken, {
      algorithm: 'ml-kem-768',
      use: 'secret',
    });
    const roundtrip = await pqc.decrypt(await pqc.encrypt('fresh message', publicKey), secretKey);
    expect(new TextDecoder().decode(roundtrip)).toBe('fresh message');
  });

  it('signs fresh data with the golden secret key, verifiable by the golden public key', async () => {
    const publicKey = pqc.keys.deserialize(dsaPublicToken, {
      algorithm: 'ml-dsa-65',
      use: 'public',
    });
    const secretKey = pqc.keys.deserialize(dsaSecretToken, {
      algorithm: 'ml-dsa-65',
      use: 'secret',
    });
    const signature = await pqc.sign('fresh document', secretKey);
    await expect(pqc.verify('fresh document', signature, publicKey)).resolves.toBe(true);
  });
});

describe('forward-compatibility contract: unknown versions fail closed', () => {
  it('rejects a token with an unknown version prefix (pqcv2) with INVALID_SERIALIZED_KEY', () => {
    const v2Token = kemPublicToken.replace(/^pqcv1\./, 'pqcv2.');
    expectPqcCode(() => pqc.keys.deserialize(v2Token), 'INVALID_SERIALIZED_KEY');
  });

  it('rejects a token with an unknown algorithm segment with UNSUPPORTED_ALGORITHM', () => {
    const unknownAlgorithm = kemPublicToken.replace('.ml-kem-768.', '.ml-kem-1024.');
    expectPqcCode(() => pqc.keys.deserialize(unknownAlgorithm), 'UNSUPPORTED_ALGORITHM');
  });

  it('rejects a ciphertext with an unknown format version byte with INVALID_CIPHERTEXT', async () => {
    const secretKey = pqc.keys.deserialize(kemSecretToken, {
      algorithm: 'ml-kem-768',
      use: 'secret',
    });
    const tampered = hexToBytes(golden.encryption.ciphertextHex);
    tampered[0] = 2; // a future format version this parser does not know
    await expect(pqc.decrypt(tampered, secretKey)).rejects.toMatchObject({
      code: 'INVALID_CIPHERTEXT',
    });
  });

  it('rejects a ciphertext with an unknown algorithm header byte with INVALID_CIPHERTEXT', async () => {
    const secretKey = pqc.keys.deserialize(kemSecretToken, {
      algorithm: 'ml-kem-768',
      use: 'secret',
    });
    const tampered = hexToBytes(golden.encryption.ciphertextHex);
    tampered[1] = 2; // a future algorithm id this parser does not know
    await expect(pqc.decrypt(tampered, secretKey)).rejects.toMatchObject({
      code: 'INVALID_CIPHERTEXT',
    });
  });
});

describe('golden vectors: fixture integrity', () => {
  it('records the published version and the seeds that derive the keys', () => {
    expect(golden.meta.generatedWith).toMatch(/^@pqc-sdk\/core@0\.3\.\d+$/);
    expect(golden.meta.seeds['ml-kem-768']).toHaveLength(64 * 2);
    expect(golden.meta.seeds['ml-dsa-65']).toHaveLength(32 * 2);
  });

  it('sanity: the UTF-8 plaintext matches the ciphertext length (1118-byte overhead)', () => {
    const plaintextLength = utf8.encode(golden.encryption.plaintextUtf8).length;
    expect(golden.encryption.ciphertextHex.length / 2).toBe(1118 + plaintextLength);
  });
});
