import { existsSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';

import { pqc } from '@pqc-sdk/core';
import { defineCommand } from 'citty';

import { readKeyFile } from '../keyfiles.js';
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
  async run({ args }) {
    const outPath = args.out ?? `${args.input}.enc`;
    if (!args.force && existsSync(outPath)) {
      throw new Error(`${outPath} already exists. Use --force to overwrite it.`);
    }
    if (!existsSync(args.input)) {
      throw new Error(`Input file not found: ${args.input}`);
    }

    const publicKey = await readKeyFile(args.key, {
      algorithm: 'ml-kem-768',
      use: 'public',
    });
    const plaintext = await readFile(args.input);
    const envelope = await pqc.encrypt(new Uint8Array(plaintext), publicKey);
    await writeFile(outPath, envelope);

    ok(`Encrypted ${args.input} (${plaintext.length} bytes):`);
    item(`output: ${outPath} (${envelope.length} bytes, ML-KEM-768 + AES-256-GCM)`);
    item('only the matching secret key can decrypt it');
  },
});
