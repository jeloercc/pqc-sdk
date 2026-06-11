// Copia docs/compatibility.md (fuente de verdad del repo) a la página del sitio.
import { readFile, writeFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const source = join(here, '../../../docs/compatibility.md');
const target = join(here, '../compatibility.md');

const content = await readFile(source, 'utf8');
const banner =
  '<!-- GENERADO desde docs/compatibility.md por scripts/sync.mjs — no editar acá -->\n\n';
await writeFile(target, banner + content);
console.log('compatibility.md sincronizado');
