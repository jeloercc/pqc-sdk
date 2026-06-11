import { defineCommand, runMain } from 'citty';

import { audit } from './commands/audit.js';
import { init } from './commands/init.js';
import { keygen } from './commands/keygen.js';

const main = defineCommand({
  meta: {
    name: 'pqc',
    version: '0.0.1',
    description: 'CLI del SDK de criptografía post-cuántica (@pqc-sdk/core)',
  },
  subCommands: {
    init,
    keygen,
    audit,
  },
});

await runMain(main);
