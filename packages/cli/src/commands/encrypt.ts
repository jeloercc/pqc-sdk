import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';

import { pqc } from '@pqc-sdk/core';
import { defineCommand } from 'citty';

import { friendlyRun, UsageError } from '../errors.js';
import { assertReadableInput } from '../input.js';
import { readKemKeyFile } from '../keyfiles.js';
import { writeOutput } from '../output.js';
import { item, ok } from '../ui.js';

export const encrypt = defineCommand({
  meta: {
    name: 'encrypt',
    description: 'Encrypt a file for the holder of a KEM key pair (ml-kem-768 or x-wing)',
  },
  args: {
    input: {
      type: 'positional',
      description: 'File to encrypt (loaded fully into memory; 1 GiB maximum)',
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
  },
  run: friendlyRun(async ({ args }) => {
    await assertReadableInput(args.input);
    const outPath = args.out ?? `${args.input}.enc`;
    if (!args.force && existsSync(outPath)) {
      throw new UsageError(`${outPath} already exists. Use --force to overwrite it.`);
    }

    const publicKey = await readKemKeyFile(args.key, 'public');
    // A Buffer already is a Uint8Array: no defensive copy (the file can be
    // large, and encrypt never mutates its input).
    const plaintext = await readFile(args.input);
    const envelope = await pqc.encrypt(plaintext, publicKey);
    await writeOutput(outPath, envelope, { force: args.force });

    ok(`Encrypted ${args.input} (${plaintext.length} bytes):`);
    item(`output: ${outPath} (${envelope.length} bytes, ${publicKey.algorithm} + AES-256-GCM)`);
    item('only the matching secret key can decrypt it');
  }),
});
