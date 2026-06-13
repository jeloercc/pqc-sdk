// Copies docs/compatibility.md (the repo's source of truth) to the site page.
import { readFile, writeFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const source = join(here, '../../../docs/compatibility.md');
const target = join(here, '../compatibility.md');

const content = await readFile(source, 'utf8');
const banner =
  '<!-- GENERATED from docs/compatibility.md by scripts/sync.mjs — do not edit here -->\n\n';
await writeFile(target, banner + content);
console.log('compatibility.md synced');
