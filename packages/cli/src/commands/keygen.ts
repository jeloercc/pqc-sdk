import { defineCommand } from 'citty';

import {
  assertSafeName,
  assertSupportedAlgorithm,
  ensureKeysIgnored,
  writeKeyPair,
} from '../keyfiles.js';
import { item, ok, warn } from '../ui.js';

export const keygen = defineCommand({
  meta: {
    name: 'keygen',
    description: 'Generate a PQC key pair serialized as base64url',
  },
  args: {
    algorithm: {
      type: 'string',
      description: 'Algorithm of the pair (ml-kem-768 or ml-dsa-65)',
      default: 'ml-kem-768',
    },
    name: {
      type: 'string',
      description: 'Base file name for the key pair (default: the algorithm, e.g. ml-kem-768)',
    },
    out: {
      type: 'string',
      description: 'Output directory',
      default: 'keys',
    },
    force: {
      type: 'boolean',
      description: 'Overwrite existing keys',
      default: false,
    },
  },
  async run({ args }) {
    const algorithm = assertSupportedAlgorithm(args.algorithm);
    const baseName = args.name === undefined ? algorithm : assertSafeName(args.name);
    const keys = await writeKeyPair(args.out, baseName, algorithm, args.force);
    const ignored = await ensureKeysIgnored(process.cwd());

    ok(`${algorithm} pair generated:`);
    item(`public: ${keys.publicPath}`);
    item(`secret: ${keys.secretPath} (mode 0600)`);
    if (ignored.length > 0) {
      item(`.gitignore: added ${ignored.join(', ')} so secret keys are never committed`);
    }
    warn('The secret key must not be committed or leave this environment.');
  },
});
