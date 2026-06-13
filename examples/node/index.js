import assert from 'node:assert/strict';

import { pqc } from '@pqc-sdk/core';

const message = 'roundtrip on plain Node';

const pair = await pqc.keys.generate();
const ciphertext = await pqc.encrypt(message, pair.publicKey);
const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);
const decoded = new TextDecoder().decode(plaintext);

assert.equal(decoded, message);
console.log('✅ Node: generate → encrypt → decrypt OK');
console.log(`   algorithm: ${pair.algorithm}, ciphertext: ${ciphertext.length} bytes`);
