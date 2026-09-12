// Copies docs/compatibility.md and the three FIPS compliance matrices — each repo file is
// the source of truth — to their site pages. Same mechanism for every file: read, prepend an
// HTML-comment banner naming the source, write; no other content transformation.
//
// The compliance pages additionally get one visible line under their H1 linking back to the
// GitHub source. The matrices cross-reference each other and NOTICE.md/SECURITY.md by
// backtick-quoted path only (no Markdown links), so there is nothing to rewrite there — but
// unlike compatibility.md, README.md links to these matrices as the canonical copy, so the
// site page says so too rather than reading as though it originated here.
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '../../..');

const REPO_BLOB_BASE = 'https://github.com/jeloercc/pqc-sdk/blob/main';

const files = [
  { source: 'docs/compatibility.md', target: 'compatibility.md' },
  {
    source: 'docs/compliance/FIPS-203-MATRIX.md',
    target: 'compliance/fips-203.md',
    visibleBacklink: true,
  },
  {
    source: 'docs/compliance/FIPS-204-MATRIX.md',
    target: 'compliance/fips-204.md',
    visibleBacklink: true,
  },
  {
    source: 'docs/compliance/FIPS-205-MATRIX.md',
    target: 'compliance/fips-205.md',
    visibleBacklink: true,
  },
];

for (const { source, target, visibleBacklink } of files) {
  const sourcePath = join(repoRoot, source);
  const targetPath = join(here, '..', target);
  const content = await readFile(sourcePath, 'utf8');
  const banner = `<!-- GENERATED from ${source} by scripts/sync.mjs — do not edit here -->\n\n`;

  const body = visibleBacklink
    ? content.replace(
        /^(# .+\n)/,
        `$1\n> Synced from [\`${source}\`](${REPO_BLOB_BASE}/${source}) — edit there, not here.\n`,
      )
    : content;

  await mkdir(dirname(targetPath), { recursive: true });
  await writeFile(targetPath, banner + body);
  console.log(`${target} synced`);
}
