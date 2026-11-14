// vectors.ts [--check] - write (or verify byte-identical) the shared action-kit conformance vectors under
// packages/pca-conformance/vectors/actions/ and the approval profile vectors under packages/pca-conformance/vectors/approval-profiles/.
// Run from the repo root: pnpm --filter @atlasauth/pca-actions exec tsx scripts/vectors.ts
import { existsSync, mkdirSync, readdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { generate, generateProfiles } from '../test/vectors-gen';

const check = process.argv.includes('--check');
const body = (c: unknown) => JSON.stringify(c) + '\n';
const sets = [
  { dir: resolve(__dirname, '../../pca-conformance/vectors/actions'), cases: generate() },
  { dir: resolve(__dirname, '../../pca-conformance/vectors/approval-profiles'), cases: generateProfiles() },
];
let bad = 0;
for (const { dir, cases } of sets) {
  if (check) {
    const want = new Set(cases.map((c) => `${c.id}.json`));
    for (const c of cases) {
      const f = join(dir, `${c.id}.json`);
      if (!existsSync(f) || readFileSync(f, 'utf8') !== body(c)) { console.error(`stale or missing: ${c.id}.json`); bad++; }
    }
    if (existsSync(dir)) for (const f of readdirSync(dir)) if (f.endsWith('.json') && !want.has(f)) { console.error(`unexpected: ${f}`); bad++; }
    if (!bad) console.log(`OK: ${cases.length} vectors in ${dir} are byte-identical to a fresh generation`);
  } else {
    mkdirSync(dir, { recursive: true });
    for (const f of readdirSync(dir)) if (f.endsWith('.json')) unlinkSync(join(dir, f));
    for (const c of cases) writeFileSync(join(dir, `${c.id}.json`), body(c));
    console.log(`wrote ${cases.length} vectors to ${dir}`);
  }
}
if (bad) { console.error(`${bad} vector file(s) differ from a fresh generation`); process.exit(1); }
