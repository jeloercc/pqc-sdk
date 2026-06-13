import { pqc } from '@pqc-sdk/core';

const message = 'roundtrip on Deno';

const pair = await pqc.keys.generate();
const ciphertext = await pqc.encrypt(message, pair.publicKey);
const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);
const decoded = new TextDecoder().decode(plaintext);

if (decoded !== message) {
  throw new Error(`roundtrip failed: ${decoded}`);
}
console.log('✅ Deno: generate → encrypt → decrypt OK');
console.log(`   algorithm: ${pair.algorithm}, ciphertext: ${ciphertext.length} bytes`);
