import { pqc } from '@pqc-sdk/core';

const message = 'roundtrip on Deno';

const pair = await pqc.keys.generate();
const ciphertext = await pqc.encrypt(message, pair.publicKey);
const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);
const decoded = new TextDecoder().decode(plaintext);

if (decoded !== message) {
  throw new Error(`roundtrip failed: ${decoded}`);
}
console.log('✅ Deno: generate → encrypt → decrypt OK (ml-kem-768)');
console.log(`   algorithm: ${pair.algorithm}, ciphertext: ${ciphertext.length} bytes`);

// Hybrid KEM (X25519 + ML-KEM-768, pqcenc.v2): same API, an x-wing key pair.
const hybridPair = await pqc.keys.generate({ algorithm: 'x-wing' });
const hybridCiphertext = await pqc.encrypt(message, hybridPair.publicKey);
const hybridPlaintext = await pqc.decrypt(hybridCiphertext, hybridPair.secretKey);
const hybridDecoded = new TextDecoder().decode(hybridPlaintext);

if (hybridDecoded !== message) {
  throw new Error(`hybrid roundtrip failed: ${hybridDecoded}`);
}
console.log('✅ Deno: generate → encrypt → decrypt OK (x-wing hybrid)');
console.log(`   algorithm: ${hybridPair.algorithm}, ciphertext: ${hybridCiphertext.length} bytes`);

// Streaming (pqcenc.v2 chunked envelope, docs/proposals/streaming-encryption.md):
// a real large file, piped through Deno's native file streams and the Web
// Streams adapters — never held fully in memory, unlike pqc.encrypt above.
// Deno.FsFile's `.readable`/`.writable` are already WHATWG streams, so no
// bridging layer is needed here (unlike Node's Readable.toWeb/Writable.toWeb).
const LARGE_FILE_BYTES = 8 * 1024 * 1024; // 8 MiB

async function streamingRoundtrip(algorithm: 'ml-kem-768' | 'x-wing') {
  const dir = await Deno.makeTempDir({ prefix: 'pqc-streaming-' });
  const plainPath = `${dir}/large-file.bin`;
  const encPath = `${dir}/large-file.bin.enc`;
  const decPath = `${dir}/large-file.bin.dec`;

  try {
    // crypto.getRandomValues caps out at 65536 bytes per call — fill in chunks.
    const content = new Uint8Array(LARGE_FILE_BYTES);
    const RANDOM_CHUNK = 65536;
    for (let offset = 0; offset < content.length; offset += RANDOM_CHUNK) {
      crypto.getRandomValues(content.subarray(offset, offset + RANDOM_CHUNK));
    }
    await Deno.writeFile(plainPath, content);

    const streamPair = await pqc.keys.generate({ algorithm });

    const plainFile = await Deno.open(plainPath, { read: true });
    const encFile = await Deno.open(encPath, { write: true, create: true });
    await plainFile.readable
      .pipeThrough(pqc.encryptWebStream(streamPair.publicKey))
      .pipeTo(encFile.writable);

    const encFileForRead = await Deno.open(encPath, { read: true });
    const decFile = await Deno.open(decPath, { write: true, create: true });
    await encFileForRead.readable
      .pipeThrough(pqc.decryptWebStream(streamPair.secretKey))
      .pipeTo(decFile.writable);

    const roundtripped = await Deno.readFile(decPath);
    if (roundtripped.length !== content.length) {
      throw new Error(`streaming roundtrip length mismatch: ${roundtripped.length}`);
    }
    for (let i = 0; i < content.length; i++) {
      if (roundtripped[i] !== content[i]) {
        throw new Error(`streaming roundtrip byte mismatch at offset ${i}`);
      }
    }

    const { size: encSize } = await Deno.stat(encPath);
    console.log(`✅ Deno: streaming encryptWebStream → decryptWebStream OK (${algorithm})`);
    console.log(
      `   plaintext: ${LARGE_FILE_BYTES} bytes, ciphertext: ${encSize} bytes, byte-for-byte match: true`,
    );
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
}

await streamingRoundtrip('ml-kem-768');
await streamingRoundtrip('x-wing');
