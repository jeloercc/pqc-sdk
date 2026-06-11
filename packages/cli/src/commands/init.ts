import { writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';

import { defineCommand } from 'citty';

import { writeKeyPair } from '../keyfiles.js';
import { heading, item, ok, warn } from '../ui.js';

const CONFIG_FILE = 'pqc.config.json';

const CONFIG = {
  defaultAlgorithm: 'ml-kem-768',
  keysDir: 'keys',
} as const;

const EXAMPLE = `import { pqc } from '@pqc-sdk/core';

// Roundtrip completo: generar keys, cifrar y descifrar.
const pair = await pqc.keys.generate(); // ML-KEM-768 por defecto
const ciphertext = await pqc.encrypt('hola post-quantum', pair.publicKey);
const plaintext = await pqc.decrypt(ciphertext, pair.secretKey);
console.log(new TextDecoder().decode(plaintext)); // "hola post-quantum"

// Firmas digitales (ML-DSA-65):
const signer = await pqc.keys.generate({ algorithm: 'ml-dsa-65' });
const signature = await pqc.sign('documento', signer.secretKey);
console.log(await pqc.verify('documento', signature, signer.publicKey)); // true

// Las keys se serializan a base64url con metadata, listas para persistir:
const token = pqc.keys.serialize(pair.publicKey);
console.log(token.slice(0, 48) + '…');

// Para cargar las keys de desarrollo que generó \`pqc init\`:
// import { readFile } from 'node:fs/promises';
// const publicKey = pqc.keys.deserialize(
//   (await readFile('keys/dev.public.pqc', 'utf8')).trim(),
// );
`;

export const init = defineCommand({
  meta: {
    name: 'init',
    description: 'Inicializa un proyecto: config, keys de desarrollo y ejemplo',
  },
  async run() {
    if (existsSync(CONFIG_FILE)) {
      throw new Error(`${CONFIG_FILE} ya existe: el proyecto ya está inicializado.`);
    }

    await writeFile(CONFIG_FILE, `${JSON.stringify(CONFIG, null, 2)}\n`);
    const keys = await writeKeyPair(CONFIG.keysDir, 'dev', CONFIG.defaultAlgorithm, false);
    await writeFile('example.ts', EXAMPLE);

    heading('Proyecto PQC inicializado:');
    item(`${CONFIG_FILE} — configuración con defaults seguros`);
    item(`${keys.publicPath} / ${keys.secretPath} — par ${keys.algorithm} de desarrollo`);
    item('example.ts — roundtrip completo listo para ejecutar');
    console.log();
    warn('Las keys de keys/dev.* son SOLO de desarrollo — NO usarlas en producción.');
    ok(`Siguiente paso: ejecutá example.ts (node --experimental-strip-types example.ts o tsx)`);
  },
});
