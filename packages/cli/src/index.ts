import { defineCommand, runMain } from 'citty';

import { audit } from './commands/audit.js';
import { decrypt } from './commands/decrypt.js';
import { encrypt } from './commands/encrypt.js';
import { init } from './commands/init.js';
import { keygen } from './commands/keygen.js';

// Injected by tsup (`define` in tsup.config.ts) from package.json at build time.
declare const __PQC_CLI_VERSION__: string;

const main = defineCommand({
  meta: {
    name: 'pqc',
    version: __PQC_CLI_VERSION__,
    description: 'CLI for the post-quantum cryptography SDK (@pqc-sdk/core)',
  },
  subCommands: {
    init,
    keygen,
    encrypt,
    decrypt,
    audit,
  },
});

await runMain(main);
