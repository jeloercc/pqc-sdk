import { existsSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';

import { pqc } from '@pqc-sdk/core';
import { defineCommand } from 'citty';

import { readKeyFile } from '../keyfiles.js';
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
  async run({ args }) {
    const outPath =
      args.out ?? (args.input.endsWith('.enc') ? args.input.slice(0, -4) : `${args.input}.dec`);
    if (!args.force && existsSync(outPath)) {
      throw new Error(`${outPath} already exists. Use --force to overwrite it.`);
    }
    if (!existsSync(args.input)) {
      throw new Error(`Input file not found: ${args.input}`);
    }

    const secretKey = await readKeyFile(args.key, {
      algorithm: 'ml-kem-768',
      use: 'secret',
    });
    const envelope = await readFile(args.input);
    const plaintext = await pqc.decrypt(new Uint8Array(envelope), secretKey);
    await writeFile(outPath, plaintext);

    ok(`Decrypted ${args.input}:`);
    item(`output: ${outPath} (${plaintext.length} bytes)`);
    warn('The decrypted file is plaintext now — handle and delete it with care.');
  },
});
