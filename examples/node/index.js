import assert from 'node:assert/strict';

import { pqc } from '@pqc-sdk/core';

const message = 'roundtrip on plain Node';

const pair = await pqc.keys.generate();
const ciphertext = await pqc.encrypt(message, pair.publicKey);
const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);
const decoded = new TextDecoder().decode(plaintext);

assert.equal(decoded, message);
console.log('✅ Node: generate → encrypt → decrypt OK (ml-kem-768)');
console.log(`   algorithm: ${pair.algorithm}, ciphertext: ${ciphertext.length} bytes`);

// Hybrid KEM (X25519 + ML-KEM-768, pqcenc.v2): same API, an x-wing key pair.
const hybridPair = await pqc.keys.generate({ algorithm: 'x-wing' });
const hybridCiphertext = await pqc.encrypt(message, hybridPair.publicKey);
const hybridPlaintext = await pqc.decrypt(hybridCiphertext, hybridPair.secretKey);
const hybridDecoded = new TextDecoder().decode(hybridPlaintext);

assert.equal(hybridDecoded, message);
console.log('✅ Node: generate → encrypt → decrypt OK (x-wing hybrid)');
console.log(`   algorithm: ${hybridPair.algorithm}, ciphertext: ${hybridCiphertext.length} bytes`);
