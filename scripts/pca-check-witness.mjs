#!/usr/bin/env node
// Check-removal witness: for each entry of tools/pca-audit/check-witness.json, neutralise ONE security check in the package
// source (a literal find/replace), run the named tests, and require them to FAIL; then restore the file. A test that still
// passes means nothing pins that check (the manifest or the tests are wrong). Usage: node scripts/pca-check-witness.mjs <pkg-dir> [--list]
import { readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

const pkg = process.argv[2];
const entries = JSON.parse(readFileSync('tools/pca-audit/check-witness.json', 'utf8')).entries.filter((e) => e.package === pkg);
if (!pkg || entries.length === 0) { console.error(`no witness entries for ${pkg}`); process.exit(2); }
const bad = [];
for (const e of entries) {
  const file = join('packages', e.package, e.file);
  const orig = readFileSync(file, 'utf8');
  const parts = orig.split(e.find);
  const nth = e.nth ?? 1;
  if (parts.length - 1 < nth) { bad.push(`${e.id}: find string occurs ${parts.length - 1} time(s), need ${nth}`); continue; }
  const mutated = parts.slice(0, nth).join(e.find) + e.replace + parts.slice(nth).join(e.find);
  writeFileSync(file, mutated);
  try {
    const r = spawnSync('pnpm', ['exec', 'vitest', 'run', ...e.tests, '--testTimeout=20000'], { cwd: join('packages', e.package), encoding: 'utf8', timeout: 300000 });
    const failed = r.status !== 0;
    console.log(`${failed ? 'WITNESSED ' : 'NOT PINNED'} ${e.id}: ${e.what}`);
    if (!failed) bad.push(`${e.id}: tests still pass with the check removed (${e.what})`);
  } finally {
    writeFileSync(file, orig);
  }
}
if (bad.length) { console.error(bad.join('\n')); process.exit(1); }
console.log(`${entries.length} checks witnessed for ${pkg}`);
