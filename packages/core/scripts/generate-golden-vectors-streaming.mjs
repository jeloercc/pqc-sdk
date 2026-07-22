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
 * Covers both KEMs (ml-kem-768 and x-wing) in one file — unlike the v1/v2
 * split (separate files because v2 was a later, separate addition), both
 * streaming version bytes were introduced by the same sprint, Days 1-2, so
 * they share one fixture the same way golden-serialization-v1.json bundles
 * ml-kem-768 and ml-dsa-65.
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

import { XWing } from '@noble/post-quantum/hybrid.js';
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

// Fixed, obviously synthetic seeds (test fixtures only — never real keys).
const ML_KEM_SEED = new Uint8Array(64).map((_, i) => i);
const XWING_SEED = new Uint8Array(32).map((_, i) => i);

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

const plaintextBytes = new TextEncoder().encode(PLAINTEXT);

async function buildFixture(algorithm, publicKey, secretKey, expectedVersion, expectedHeaderId) {
  const ciphertext = await collect(
    encryptStream(publicKey, singleChunk(plaintextBytes), { chunkSize: CHUNK_SIZE }),
  );

  // Self-check before writing: the artifact must round-trip with the very
  // build that produced it, otherwise the fixture would be born broken.
  const decrypted = new TextDecoder().decode(
    await collect(decryptStream(secretKey, singleChunk(ciphertext))),
  );
  if (decrypted !== PLAINTEXT) {
    console.error(
      `generate-golden-vectors-streaming: self-check failed for ${algorithm} — decrypt mismatch.`,
    );
    process.exit(1);
  }
  if (ciphertext[0] !== expectedVersion || ciphertext[1] !== expectedHeaderId) {
    console.error(
      `generate-golden-vectors-streaming: self-check failed for ${algorithm} — unexpected header.`,
    );
    process.exit(1);
  }

  return {
    publicToken: pqc.keys.serialize(publicKey),
    secretToken: pqc.keys.serialize(secretKey),
    ciphertextHex: toHex(ciphertext),
  };
}

const kemMaterial = ml_kem768.keygen(ML_KEM_SEED);
const mlKemKey = (use, bytes) => ({ algorithm: 'ml-kem-768', use, bytes });
const mlKemFixture = await buildFixture(
  'ml-kem-768',
  mlKemKey('public', kemMaterial.publicKey),
  mlKemKey('secret', kemMaterial.secretKey),
  0x03,
  0x01,
);

const xwingMaterial = XWing.keygen(XWING_SEED);
const xwingKey = (use, bytes) => ({ algorithm: 'x-wing', use, bytes });
const xwingFixture = await buildFixture(
  'x-wing',
  xwingKey('public', xwingMaterial.publicKey),
  xwingKey('secret', xwingMaterial.secretKey),
  0x04,
  0x02,
);

const vectors = {
  meta: {
    generatedWith: `@pqc-sdk/core@${version}`,
    generatedAt: new Date().toISOString(),
    seeds: { 'ml-kem-768': toHex(ML_KEM_SEED), 'x-wing': toHex(XWING_SEED) },
    chunkSize: CHUNK_SIZE,
    note:
      'Golden serialization vectors for the streaming envelope (docs/serialization-format.md §9) — ' +
      'both KEMs, Days 1-2 of docs/proposals/streaming-encryption.md. Regenerating these is a ' +
      'breaking format change requiring a major bump.',
  },
  keys: {
    'ml-kem-768': {
      publicToken: mlKemFixture.publicToken,
      secretToken: mlKemFixture.secretToken,
    },
    'x-wing': {
      publicToken: xwingFixture.publicToken,
      secretToken: xwingFixture.secretToken,
    },
  },
  streaming: {
    plaintextUtf8: PLAINTEXT,
    chunkSize: CHUNK_SIZE,
    'ml-kem-768': { ciphertextHex: mlKemFixture.ciphertextHex },
    'x-wing': { ciphertextHex: xwingFixture.ciphertextHex },
  },
};

writeFileSync(OUT, `${JSON.stringify(vectors, null, 2)}\n`);
console.log(
  `generate-golden-vectors-streaming: wrote ${String(OUT)} (generated with @pqc-sdk/core@${version}).`,
);
