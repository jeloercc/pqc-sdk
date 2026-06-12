// Roundtrip del SDK sobre el engine Hermes standalone (sin simulador ni RN).
// Los shims van primero: cumplen el rol que en RN tiene
// react-native-get-random-values (ver shims.js).
import './shims.js';

import { pqc } from '@pqc-sdk/core';

// Hermes 0.12 no trae TextDecoder, así que se compara byte a byte.
const utf8 = new TextEncoder();

function assertBytesEqual(a, b, label) {
  if (a.length !== b.length) throw new Error(`${label}: longitudes distintas`);
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) throw new Error(`${label}: difieren en el byte ${i}`);
  }
}

async function main() {
  const message = 'roundtrip en Hermes standalone';

  let t = Date.now();
  const pair = await pqc.keys.generate();
  const tKeygen = Date.now() - t;

  t = Date.now();
  const ciphertext = await pqc.encrypt(message, pair.publicKey);
  const tEncrypt = Date.now() - t;

  t = Date.now();
  const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);
  const tDecrypt = Date.now() - t;

  assertBytesEqual(plaintext, utf8.encode(message), 'ML-KEM roundtrip');
  console.log('✅ Hermes: generate → encrypt → decrypt OK');
  console.log(`   algoritmo: ${pair.algorithm}, ciphertext: ${ciphertext.length} bytes`);
  console.log(`   keygen ${tKeygen} ms, encrypt ${tEncrypt} ms, decrypt ${tDecrypt} ms`);

  t = Date.now();
  const signer = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
  const signature = await pqc.sign(message, signer.secretKey);
  const valid = await pqc.verify(message, signature, signer.publicKey);
  if (!valid) throw new Error('ML-DSA: la firma no verificó');
  console.log(`✅ Hermes: sign → verify OK (${Date.now() - t} ms)`);
}

main().catch((error) => {
  console.error(String(error && error.stack ? error.stack : error));
  throw error;
});
