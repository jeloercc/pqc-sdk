import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';

import { pqc } from '@pqc-sdk/core';
import { defineCommand } from 'citty';

import { friendlyRun, UsageError } from '../errors.js';
import { readKeyFile } from '../keyfiles.js';
import { writeOutput } from '../output.js';
import { item, ok, warn } from '../ui.js';

export const decrypt = defineCommand({
  meta: {
    name: 'decrypt',
    description: 'Decrypt a file produced by `pqc encrypt` (or the SDK) with your secret key',
  },
  args: {
    input: {
      type: 'positional',
      description: 'Encrypted file (an ML-KEM-768 + AES-256-GCM envelope)',
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
    if (!existsSync(args.input)) {
      throw new UsageError(`Input file not found: ${args.input}`);
    }
    const outPath =
      args.out ?? (args.input.endsWith('.enc') ? args.input.slice(0, -4) : `${args.input}.dec`);
    if (!args.force && existsSync(outPath)) {
      throw new UsageError(`${outPath} already exists. Use --force to overwrite it.`);
    }

    const secretKey = await readKeyFile(args.key, {
      algorithm: 'ml-kem-768',
      use: 'secret',
    });
    const envelope = await readFile(args.input);
    const plaintext = await pqc.decrypt(new Uint8Array(envelope), secretKey);
    // Recovered plaintext is as sensitive as a secret key: owner-only (0600),
    // like `pqc keygen` does for .secret.pqc.
    await writeOutput(outPath, plaintext, { force: args.force, mode: 0o600 });

    ok(`Decrypted ${args.input}:`);
    item(`output: ${outPath} (${plaintext.length} bytes)`);
    warn('The decrypted file is plaintext now — handle and delete it with care.');
  }),
});
