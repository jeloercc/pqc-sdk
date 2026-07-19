import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';

import { pqc } from '@pqc-sdk/core';
import { defineCommand } from 'citty';

import { friendlyRun, UsageError } from '../errors.js';
import { readKeyFile } from '../keyfiles.js';
import { writeOutput } from '../output.js';
import { item, ok } from '../ui.js';

export const encrypt = defineCommand({
  meta: {
    name: 'encrypt',
    description: 'Encrypt a file for the holder of an ML-KEM-768 key pair',
  },
  args: {
    input: {
      type: 'positional',
      description: 'File to encrypt',
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
    if (!existsSync(args.input)) {
      throw new UsageError(`Input file not found: ${args.input}`);
    }
    const outPath = args.out ?? `${args.input}.enc`;
    if (!args.force && existsSync(outPath)) {
      throw new UsageError(`${outPath} already exists. Use --force to overwrite it.`);
    }

    const publicKey = await readKeyFile(args.key, {
      algorithm: 'ml-kem-768',
      use: 'public',
    });
    const plaintext = await readFile(args.input);
    const envelope = await pqc.encrypt(new Uint8Array(plaintext), publicKey);
    await writeOutput(outPath, envelope, { force: args.force });

    ok(`Encrypted ${args.input} (${plaintext.length} bytes):`);
    item(`output: ${outPath} (${envelope.length} bytes, ML-KEM-768 + AES-256-GCM)`);
    item('only the matching secret key can decrypt it');
  }),
});
