import { createReadStream, existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { Readable } from 'node:stream';

import { pqc } from '@pqc-sdk/core';
import { defineCommand } from 'citty';

import { friendlyRun, UsageError } from '../errors.js';
import { assertReadableInput, peekEnvelopeVersion } from '../input.js';
import { readKemKeyFile } from '../keyfiles.js';
import { pipeToOutput, writeOutput } from '../output.js';
import { item, ok, warn } from '../ui.js';

const STREAMING_VERSIONS = new Set([0x03, 0x04]);

export const decrypt = defineCommand({
  meta: {
    name: 'decrypt',
    description: 'Decrypt a file produced by `pqc encrypt` (or the SDK) with your secret key',
  },
  args: {
    input: {
      type: 'positional',
      description:
        'Encrypted file (a KEM + AES-256-GCM envelope, one-shot or streamed; any size, 1 TiB operational ceiling)',
      required: true,
    },
    key: {
      type: 'string',
      description: 'Your secret key file (.secret.pqc, from `pqc keygen`)',
      required: true,
    },
    out: {
      type: 'string',
      description: 'Output file (default: <input> without .enc, else <input>.dec)',
    },
    force: {
      type: 'boolean',
      description: 'Overwrite the output file if it exists',
      default: false,
    },
  },
  run: friendlyRun(async ({ args }) => {
    await assertReadableInput(args.input);
    const outPath =
      args.out ?? (args.input.endsWith('.enc') ? args.input.slice(0, -4) : `${args.input}.dec`);
    if (!args.force && existsSync(outPath)) {
      throw new UsageError(`${outPath} already exists. Use --force to overwrite it.`);
    }

    const secretKey = await readKemKeyFile(args.key, 'secret');

    // Dispatch on the envelope's own leading version byte
    // (docs/serialization-format.md §2, §9) — not file size. A streaming
    // envelope can be small (e.g. produced directly by the SDK), and a
    // one-shot envelope's size already tracks whatever the CLI's own
    // encrypt threshold decided, so peeking the actual format is the only
    // way to be correct rather than guessing.
    const version = await peekEnvelopeVersion(args.input);

    if (!STREAMING_VERSIONS.has(version)) {
      // A Buffer already is a Uint8Array: no defensive copy needed.
      const envelope = await readFile(args.input);
      const plaintext = await pqc.decrypt(envelope, secretKey);
      // Recovered plaintext is as sensitive as a secret key: owner-only
      // (0600), like `pqc keygen` does for .secret.pqc.
      await writeOutput(outPath, plaintext, { force: args.force, mode: 0o600 });

      ok(`Decrypted ${args.input}:`);
      item(`output: ${outPath} (${plaintext.length} bytes)`);
      warn('The decrypted file is plaintext now — handle and delete it with care.');
      return;
    }

    // Streaming envelope: pipe through decryptWebStream rather than
    // buffering the whole ciphertext (docs/proposals/streaming-encryption.md
    // §3). Same incremental-release caveat as decryptStream applies to the
    // output file: it is provisional until pipeTo's promise resolves —
    // pipeToOutput surfaces any mid-stream failure as a rejection, and the
    // partially-written file must not be treated as a valid result.
    const readable = Readable.toWeb(createReadStream(args.input)) as ReadableStream<Uint8Array>;
    await pipeToOutput(readable.pipeThrough(pqc.decryptWebStream(secretKey)), outPath, {
      force: args.force,
      mode: 0o600,
    });

    ok(`Decrypted ${args.input} (streamed):`);
    item(`output: ${outPath}`);
    warn('The decrypted file is plaintext now — handle and delete it with care.');
  }),
});
