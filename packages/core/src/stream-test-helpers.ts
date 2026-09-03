/**
 * Shared async-iterable helpers for the streaming test suites
 * (stream.test.ts, stream-mutations.test.ts, stream-web.test.ts).
 * Deliberately not a `.test.ts` file: importing a `.test.ts` file for its
 * exports re-executes that file's own top-level `describe`/`it`
 * registrations as a side effect of module evaluation, silently
 * duplicating test runs across every file that imports it.
 */

// async is required to satisfy the AsyncIterable<Uint8Array> shape
// encryptStream/decryptStream take; nothing here genuinely needs to await.
// eslint-disable-next-line @typescript-eslint/require-await
export async function* single(data: Uint8Array): AsyncGenerator<Uint8Array> {
  yield data;
}

export async function collect(chunks: AsyncIterable<Uint8Array>): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
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

// eslint-disable-next-line @typescript-eslint/require-await -- see `single` above.
export async function* asChunks(
  data: Uint8Array,
  sourceChunkSize: number,
): AsyncGenerator<Uint8Array> {
  for (let i = 0; i < data.length; i += sourceChunkSize) {
    yield data.subarray(i, i + sourceChunkSize);
  }
}
