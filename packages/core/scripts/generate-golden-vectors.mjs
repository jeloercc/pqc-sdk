#!/usr/bin/env node
/**
 * Regenerates the golden serialization vectors
 * (src/vectors/golden-serialization-v1.json).
 *
 * The vectors lock the serialized formats across versions: keys derive from
 * the fixed seeds below (via @noble/post-quantum, the SDK's pinned primitive
 * layer), and every serialized artifact — key tokens, hybrid ciphertext,
 * signature — is produced by the @pqc-sdk/core build this script imports.
 * Ciphertext and signature bytes are NOT seed-reproducible (fresh KEM
 * encapsulation, random nonce, hedged signing): the committed bytes are the
 * artifact under test, the seeds only make the keys reproducible.
 *
 * ONLY regenerate after a deliberate, acknowledged format change (a breaking
 * change requiring a major version bump) — see docs/serialization-format.md
 * and .claude/rules/crypto-review.md. Build first: the script imports the
 * package entry point (`pnpm --filter @pqc-sdk/core build`).
 *
 * Usage: node scripts/generate-golden-vectors.mjs [--out <file>]
 */

import console from 'node:console';
import { writeFileSync } from 'node:fs';
import process from 'node:process';
import { URL } from 'node:url';
import { TextDecoder } from 'node:util';

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { pqc, version } from '@pqc-sdk/core';

const OUT = (() => {
  const flagIndex = process.argv.indexOf('--out');
  return flagIndex === -1
    ? new URL('../src/vectors/golden-serialization-v1.json', import.meta.url)
    : process.argv[flagIndex + 1];
})();

const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');

// Fixed, obviously synthetic seeds (test fixtures only — never real keys).
const KEM_SEED = new Uint8Array(64).map((_, i) => i);
const DSA_SEED = new Uint8Array(32).map((_, i) => i);

const PLAINTEXT = 'golden vector v1: this exact message must decrypt forever';
const SIGNED_MESSAGE = 'golden vector v1: this exact message must verify forever';

const kemMaterial = ml_kem768.keygen(KEM_SEED);
const dsaMaterial = ml_dsa65.keygen(DSA_SEED);
const key = (algorithm, use, bytes) => ({ algorithm, use, bytes });

const kemPublic = key('ml-kem-768', 'public', kemMaterial.publicKey);
const kemSecret = key('ml-kem-768', 'secret', kemMaterial.secretKey);
const dsaPublic = key('ml-dsa-65', 'public', dsaMaterial.publicKey);
const dsaSecret = key('ml-dsa-65', 'secret', dsaMaterial.secretKey);

const ciphertext = await pqc.encrypt(PLAINTEXT, kemPublic);
const signature = await pqc.sign(SIGNED_MESSAGE, dsaSecret);

// Self-check before writing: the artifacts must round-trip with the very
// build that produced them, otherwise the fixture would be born broken.
const decrypted = new TextDecoder().decode(await pqc.decrypt(ciphertext, kemSecret));
if (decrypted !== PLAINTEXT) {
  console.error('generate-golden-vectors: self-check failed — decrypt mismatch.');
  process.exit(1);
}
if (!(await pqc.verify(SIGNED_MESSAGE, signature, dsaPublic))) {
  console.error('generate-golden-vectors: self-check failed — signature did not verify.');
  process.exit(1);
}

const vectors = {
  meta: {
    generatedWith: `@pqc-sdk/core@${version}`,
    generatedAt: new Date().toISOString(),
    seeds: { 'ml-kem-768': toHex(KEM_SEED), 'ml-dsa-65': toHex(DSA_SEED) },
    note:
      'Golden serialization vectors — see docs/serialization-format.md. ' +
      'Regenerating these is a breaking format change requiring a major bump.',
  },
  keys: {
    'ml-kem-768': {
      publicToken: pqc.keys.serialize(kemPublic),
      secretToken: pqc.keys.serialize(kemSecret),
    },
    'ml-dsa-65': {
      publicToken: pqc.keys.serialize(dsaPublic),
      secretToken: pqc.keys.serialize(dsaSecret),
    },
  },
  encryption: {
    plaintextUtf8: PLAINTEXT,
    ciphertextHex: toHex(ciphertext),
  },
  signature: {
    messageUtf8: SIGNED_MESSAGE,
    signatureHex: toHex(signature),
  },
};

writeFileSync(OUT, `${JSON.stringify(vectors, null, 2)}\n`);
console.log(
  `generate-golden-vectors: wrote ${String(OUT)} (generated with @pqc-sdk/core@${version}).`,
);
