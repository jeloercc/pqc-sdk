import { defineCommand } from 'citty';

import { assertSupportedAlgorithm, writeKeyPair } from '../keyfiles.js';
import { item, ok, warn } from '../ui.js';

export const keygen = defineCommand({
  meta: {
    name: 'keygen',
    description: 'Genera un par de keys PQC serializadas en base64url',
  },
  args: {
    algorithm: {
      type: 'string',
      description: 'Algoritmo del par (ml-kem-768 o ml-dsa-65)',
      default: 'ml-kem-768',
    },
    out: {
      type: 'string',
      description: 'Directorio de salida',
      default: 'keys',
    },
    force: {
      type: 'boolean',
      description: 'Sobreescribir keys existentes',
      default: false,
    },
  },
  async run({ args }) {
    const algorithm = assertSupportedAlgorithm(args.algorithm);
    const keys = await writeKeyPair(args.out, algorithm, algorithm, args.force);

    ok(`Par ${algorithm} generado:`);
    item(`pública: ${keys.publicPath}`);
    item(`secreta: ${keys.secretPath} (modo 0600)`);
    warn('La key secreta no debe commitearse ni salir de este entorno.');
  },
});
