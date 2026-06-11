import { pqc } from '@pqc-sdk/core';

const message = 'roundtrip en Cloudflare Workers';

export default {
  async fetch(): Promise<Response> {
    const pair = await pqc.keys.generate();
    const ciphertext = await pqc.encrypt(message, pair.publicKey);
    const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);
    const decoded = new TextDecoder().decode(plaintext);

    return Response.json({
      ok: decoded === message,
      algorithm: pair.algorithm,
      ciphertextBytes: ciphertext.length,
      roundtrip: decoded,
    });
  },
};
