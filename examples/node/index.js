import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable, Writable } from 'node:stream';

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

// Streaming (pqcenc.v2 chunked envelope, docs/proposals/streaming-encryption.md):
// a real large file, piped through fs streams and the Web Streams adapters —
// never held fully in memory, unlike pqc.encrypt above.
const LARGE_FILE_BYTES = 8 * 1024 * 1024; // 8 MiB: large enough to span many
// chunks at the 64 KiB default, small enough to keep the example fast.

async function streamingRoundtrip(algorithm) {
  const dir = await mkdtemp(join(tmpdir(), 'pqc-streaming-'));
  const plainPath = join(dir, 'large-file.bin');
  const encPath = join(dir, 'large-file.bin.enc');
  const decPath = join(dir, 'large-file.bin.dec');

  try {
    // Write deterministic-size random content — this is the "multi-GB file"
    // scenario in miniature: too large to comfortably hold as one in-memory
    // Uint8Array in the general case, so the CLI's 1 GiB guard exists.
    await writeFile(plainPath, randomBytes(LARGE_FILE_BYTES));

    const streamPair = await pqc.keys.generate({ algorithm });

    await Readable.toWeb(createReadStream(plainPath))
      .pipeThrough(pqc.encryptWebStream(streamPair.publicKey))
      .pipeTo(Writable.toWeb(createWriteStream(encPath)));

    await Readable.toWeb(createReadStream(encPath))
      .pipeThrough(pqc.decryptWebStream(streamPair.secretKey))
      .pipeTo(Writable.toWeb(createWriteStream(decPath)));

    const [original, roundtripped] = await Promise.all([readFile(plainPath), readFile(decPath)]);
    assert.deepEqual(roundtripped, original);

    const { size: encSize } = await stat(encPath);
    console.log(`✅ Node: streaming encryptWebStream → decryptWebStream OK (${algorithm})`);
    console.log(
      `   plaintext: ${LARGE_FILE_BYTES} bytes, ciphertext: ${encSize} bytes, byte-for-byte match: true`,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

await streamingRoundtrip('ml-kem-768');
await streamingRoundtrip('x-wing');
