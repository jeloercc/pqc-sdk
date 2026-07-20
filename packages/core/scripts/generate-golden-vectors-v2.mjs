#!/usr/bin/env node
/**
 * Generates the pqcenc.v2 golden serialization vectors
 * (src/vectors/golden-serialization-v2.json).
 *
 * Same procedure as generate-golden-vectors.mjs, for the artifacts envelope
 * v2 added: x-wing key tokens derive from the fixed seed below (via
 * @noble/post-quantum, the SDK's pinned primitive layer) and the v2 hybrid
 * ciphertext is produced by the @pqc-sdk/core build this script imports.
 * Ciphertext bytes are NOT seed-reproducible (fresh KEM encapsulation,
 * random nonce): the committed bytes are the artifact under test, the seed
 * only makes the keys reproducible. The v1 fixture
 * (golden-serialization-v1.json) is a separate file this script never
 * touches.
 *
 * ONLY regenerate after a deliberate, acknowledged format change (a breaking
 * change requiring a major version bump) — see docs/serialization-format.md
 * and .claude/rules/crypto-review.md. Build first: the script imports the
 * package entry point (`pnpm --filter @pqc-sdk/core build`).
 *
 * Usage: node scripts/generate-golden-vectors-v2.mjs [--out <file>]
 */

import console from 'node:console';
import { writeFileSync } from 'node:fs';
import process from 'node:process';
import { URL } from 'node:url';
import { TextDecoder } from 'node:util';

import { XWing } from '@noble/post-quantum/hybrid.js';
import { pqc, version } from '@pqc-sdk/core';

const OUT = (() => {
  const flagIndex = process.argv.indexOf('--out');
  return flagIndex === -1
    ? new URL('../src/vectors/golden-serialization-v2.json', import.meta.url)
    : process.argv[flagIndex + 1];
})();

const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');

// Fixed, obviously synthetic seed (test fixture only — never a real key).
const XWING_SEED = new Uint8Array(32).map((_, i) => i);

const PLAINTEXT = 'golden vector v2: this exact message must decrypt forever';

const xwingMaterial = XWing.keygen(XWING_SEED);
const key = (use, bytes) => ({ algorithm: 'x-wing', use, bytes });

const xwingPublic = key('public', xwingMaterial.publicKey);
const xwingSecret = key('secret', xwingMaterial.secretKey);

const ciphertext = await pqc.encrypt(PLAINTEXT, xwingPublic);

// Self-check before writing: the artifact must round-trip with the very
// build that produced it, otherwise the fixture would be born broken.
const decrypted = new TextDecoder().decode(await pqc.decrypt(ciphertext, xwingSecret));
if (decrypted !== PLAINTEXT) {
  console.error('generate-golden-vectors-v2: self-check failed — decrypt mismatch.');
  process.exit(1);
}
if (ciphertext[0] !== 0x02 || ciphertext[1] !== 0x02) {
  console.error('generate-golden-vectors-v2: self-check failed — not a v2 header.');
  process.exit(1);
}

const vectors = {
  meta: {
    generatedWith: `@pqc-sdk/core@${version}`,
    generatedAt: new Date().toISOString(),
    seeds: { 'x-wing': toHex(XWING_SEED) },
    note:
      'Golden serialization vectors for envelope v2 (x-wing) — see ' +
      'docs/serialization-format.md. Regenerating these is a breaking format ' +
      'change requiring a major bump.',
  },
  keys: {
    'x-wing': {
      publicToken: pqc.keys.serialize(xwingPublic),
      secretToken: pqc.keys.serialize(xwingSecret),
    },
  },
  encryption: {
    plaintextUtf8: PLAINTEXT,
    ciphertextHex: toHex(ciphertext),
  },
};

writeFileSync(OUT, `${JSON.stringify(vectors, null, 2)}\n`);
console.log(
  `generate-golden-vectors-v2: wrote ${String(OUT)} (generated with @pqc-sdk/core@${version}).`,
);
