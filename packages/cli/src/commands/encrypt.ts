import { createReadStream, existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { Readable } from 'node:stream';

import { pqc } from '@pqc-sdk/core';
import { defineCommand } from 'citty';

import { friendlyRun, UsageError } from '../errors.js';
import {
  assertReadableInput,
  MAX_SIZE_DESCRIPTION,
  sizeGuardOptions,
  STREAMING_THRESHOLD_BYTES,
} from '../input.js';
import { readKemKeyFile } from '../keyfiles.js';
import { pipeToOutput, writeOutput } from '../output.js';
import { item, ok, warn } from '../ui.js';

export const encrypt = defineCommand({
  meta: {
    name: 'encrypt',
    description: 'Encrypt a file for the holder of a KEM key pair (ml-kem-768 or x-wing)',
  },
  args: {
    input: {
      type: 'positional',
      description:
        'File to encrypt (any size: at or below 8 MiB loaded fully into memory, larger streamed; 1 TiB operational guard, raise with --max-size)',
      required: true,
    },
    key: {
      type: 'string',
      description: 'Recipient public key file (.public.pqc, from `pqc keygen`)',
      required: true,
    },
    out: {
      type: 'string',
      description: 'Output file (default: <input>.enc)',
    },
    force: {
      type: 'boolean',
      description: 'Overwrite the output file if it exists',
      default: false,
    },
    'max-size': {
      type: 'string',
      description: MAX_SIZE_DESCRIPTION,
    },
  },
  run: friendlyRun(async ({ args }) => {
    const size = await assertReadableInput(args.input, sizeGuardOptions(args['max-size'], warn));
    const outPath = args.out ?? `${args.input}.enc`;
    if (!args.force && existsSync(outPath)) {
      throw new UsageError(`${outPath} already exists. Use --force to overwrite it.`);
    }

    const publicKey = await readKemKeyFile(args.key, 'public');

    if (size <= STREAMING_THRESHOLD_BYTES) {
      // A Buffer already is a Uint8Array: no defensive copy (encrypt never
      // mutates its input).
      const plaintext = await readFile(args.input);
      const envelope = await pqc.encrypt(plaintext, publicKey);
      await writeOutput(outPath, envelope, { force: args.force });

      ok(`Encrypted ${args.input} (${plaintext.length} bytes):`);
      item(`output: ${outPath} (${envelope.length} bytes, ${publicKey.algorithm} + AES-256-GCM)`);
      item('only the matching secret key can decrypt it');
      return;
    }

    // Above the threshold: stream instead of holding the whole file in
    // memory (docs/proposals/streaming-encryption.md §3).
    const readable = Readable.toWeb(createReadStream(args.input)) as ReadableStream<Uint8Array>;
    await pipeToOutput(readable.pipeThrough(pqc.encryptWebStream(publicKey)), outPath, {
      force: args.force,
    });

    ok(`Encrypted ${args.input} (${size} bytes, streamed):`);
    item(`output: ${outPath} (${publicKey.algorithm} + AES-256-GCM, chunked envelope)`);
    item('only the matching secret key can decrypt it');
  }),
});
