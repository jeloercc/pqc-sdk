import { defineCommand } from 'citty';

import { assertSupportedAlgorithm, writeKeyPair } from '../keyfiles.js';
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
    const keys = await writeKeyPair(args.out, algorithm, algorithm, args.force);

    ok(`${algorithm} pair generated:`);
    item(`public: ${keys.publicPath}`);
    item(`secret: ${keys.secretPath} (mode 0600)`);
    warn('The secret key must not be committed or leave this environment.');
  },
});
