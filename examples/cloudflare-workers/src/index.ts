import { pqc } from '@pqc-sdk/core';

const message = 'roundtrip on Cloudflare Workers';

export default {
  async fetch(): Promise<Response> {
    const pair = await pqc.keys.generate();
    const ciphertext = await pqc.encrypt(message, pair.publicKey);
    const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);
    const decoded = new TextDecoder().decode(plaintext);

    // Hybrid KEM (X25519 + ML-KEM-768, pqcenc.v2): same API, an x-wing key pair.
    const hybridPair = await pqc.keys.generate({ algorithm: 'x-wing' });
    const hybridCiphertext = await pqc.encrypt(message, hybridPair.publicKey);
    const hybridPlaintext = await pqc.decrypt(hybridCiphertext, hybridPair.secretKey);
    const hybridDecoded = new TextDecoder().decode(hybridPlaintext);

    return Response.json({
      ok: decoded === message,
      algorithm: pair.algorithm,
      ciphertextBytes: ciphertext.length,
      roundtrip: decoded,
      hybrid: {
        ok: hybridDecoded === message,
        algorithm: hybridPair.algorithm,
        ciphertextBytes: hybridCiphertext.length,
        roundtrip: hybridDecoded,
      },
    });
  },
};
