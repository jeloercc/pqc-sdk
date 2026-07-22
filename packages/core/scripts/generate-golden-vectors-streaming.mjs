#!/usr/bin/env node
/**
 * Generates the streaming-envelope golden serialization vectors
 * (src/vectors/golden-serialization-streaming.json).
 *
 * Same procedure as generate-golden-vectors-v2.mjs, with one difference:
 * encryptStream/decryptStream are not yet part of the public @pqc-sdk/core
 * surface (docs/proposals/streaming-encryption.md Day 3 exports them), so
 * this script imports the compiled dist/stream.js directly by relative path
 * rather than the package name — see tsup.config.ts's second entry, added
 * only so this script has compiled JS to run (plain `node`, not vitest,
 * can't execute TS source directly).
 *
 * Uses a deliberately small chunkSize (8 bytes) so a multi-chunk fixture
 * stays compact and readable in the committed JSON. The production default
 * (2^16, 64 KiB) is exercised by stream.test.ts, not by this fixture.
 *
 * ml-kem-768 only on Day 1 — x-wing joins this fixture on Day 2, per the
 * sprint plan.
 *
 * ONLY regenerate after a deliberate, acknowledged format change (a breaking
 * change requiring a major version bump) — see docs/serialization-format.md
 * §9 and .claude/rules/crypto-review.md. Build first: the script imports the
 * package's compiled output (`pnpm --filter @pqc-sdk/core build`).
 *
 * Usage: node scripts/generate-golden-vectors-streaming.mjs [--out <file>]
 */

import console from 'node:console';
import { writeFileSync } from 'node:fs';
import process from 'node:process';
import { URL } from 'node:url';
import { TextDecoder, TextEncoder } from 'node:util';

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { pqc, version } from '@pqc-sdk/core';

import { decryptStream, encryptStream } from '../dist/stream.js';

const OUT = (() => {
  const flagIndex = process.argv.indexOf('--out');
  return flagIndex === -1
    ? new URL('../src/vectors/golden-serialization-streaming.json', import.meta.url)
    : process.argv[flagIndex + 1];
})();

const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');

// Fixed, obviously synthetic seed (test fixture only — never a real key).
const ML_KEM_SEED = new Uint8Array(64).map((_, i) => i);

const CHUNK_SIZE = 8;
// 20 bytes at chunkSize=8: chunks of 8, 8, 4 — exercises full non-final
// chunks and a genuinely short (not full-size) final chunk.
const PLAINTEXT = 'streaming golden vec';
if (PLAINTEXT.length !== 20) {
  console.error('generate-golden-vectors-streaming: fixture plaintext length drifted.');
  process.exit(1);
}

async function* singleChunk(data) {
  yield data;
}

async function collect(chunks) {
  const parts = [];
  let total = 0;
  for await (const chunk of chunks) {
    parts.push(chunk);
    total += chunk.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

const kemMaterial = ml_kem768.keygen(ML_KEM_SEED);
const key = (use, bytes) => ({ algorithm: 'ml-kem-768', use, bytes });
const publicKey = key('public', kemMaterial.publicKey);
const secretKey = key('secret', kemMaterial.secretKey);

const plaintextBytes = new TextEncoder().encode(PLAINTEXT);

const ciphertext = await collect(
  encryptStream(publicKey, singleChunk(plaintextBytes), { chunkSize: CHUNK_SIZE }),
);

// Self-check before writing: the artifact must round-trip with the very
// build that produced it, otherwise the fixture would be born broken.
const decrypted = new TextDecoder().decode(
  await collect(decryptStream(secretKey, singleChunk(ciphertext))),
);
if (decrypted !== PLAINTEXT) {
  console.error('generate-golden-vectors-streaming: self-check failed — decrypt mismatch.');
  process.exit(1);
}
if (ciphertext[0] !== 0x03 || ciphertext[1] !== 0x01) {
  console.error(
    'generate-golden-vectors-streaming: self-check failed — not a streaming ml-kem-768 header.',
  );
  process.exit(1);
}

const vectors = {
  meta: {
    generatedWith: `@pqc-sdk/core@${version}`,
    generatedAt: new Date().toISOString(),
    seeds: { 'ml-kem-768': toHex(ML_KEM_SEED) },
    chunkSize: CHUNK_SIZE,
    note:
      'Golden serialization vectors for the streaming envelope (docs/serialization-format.md §9) — ' +
      'ml-kem-768 only, Day 1 of docs/proposals/streaming-encryption.md. Regenerating these is a ' +
      'breaking format change requiring a major bump.',
  },
  keys: {
    'ml-kem-768': {
      publicToken: pqc.keys.serialize(publicKey),
      secretToken: pqc.keys.serialize(secretKey),
    },
  },
  streaming: {
    plaintextUtf8: PLAINTEXT,
    chunkSize: CHUNK_SIZE,
    ciphertextHex: toHex(ciphertext),
  },
};

writeFileSync(OUT, `${JSON.stringify(vectors, null, 2)}\n`);
console.log(
  `generate-golden-vectors-streaming: wrote ${String(OUT)} (generated with @pqc-sdk/core@${version}).`,
);
