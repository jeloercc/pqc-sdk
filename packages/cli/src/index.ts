import { defineCommand, runMain } from 'citty';

import { audit } from './commands/audit.js';
import { init } from './commands/init.js';
import { keygen } from './commands/keygen.js';

// Inyectada por tsup (`define` en tsup.config.ts) desde el package.json en build time.
declare const __PQC_CLI_VERSION__: string;

const main = defineCommand({
  meta: {
    name: 'pqc',
    version: __PQC_CLI_VERSION__,
    description: 'CLI del SDK de criptografía post-cuántica (@pqc-sdk/core)',
  },
  subCommands: {
    init,
    keygen,
    audit,
  },
});

await runMain(main);
