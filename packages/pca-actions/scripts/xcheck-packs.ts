// xcheck-packs.ts - agreement between the suggestion rules and the trait annotations of the catalog packs (track A6), whose traits come
// from separate per-pack rules. For every pack def the declared traits and the review state are removed, the def is run through
// `suggestWithRules`, and the traits the system would show a reviewer (importer facts + suggestions) are compared with the traits the pack
// carries.
//   tsx scripts/xcheck-packs.ts <packs-dir> [--out FILE]
// This is AGREEMENT between two heuristic labelers, not accuracy: neither side is a human reading each operation.
import { existsSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { TRAITS, loadPackDefs, packTraits, rulesTraits } from './lib/xcheck-core';

const dir = resolve(process.argv[2] ?? '');
if (!existsSync(dir)) { console.error(`packs directory not found: ${dir}`); process.exit(2); }

interface Cell { both: number; pack_only: number; rules_only: number; neither: number }
const empty = (): Cell => ({ both: 0, pack_only: 0, rules_only: 0, neither: 0 });
const cells = new Map<string, Cell>();
const perPack = new Map<string, Map<string, Cell>>();
let defs = 0;
for (const { pack, def } of loadPackDefs(dir)) {
  defs++;
  const theirs = packTraits(def), mine = rulesTraits(def);
  const pm = perPack.get(pack) ?? new Map<string, Cell>();
  perPack.set(pack, pm);
  for (const t of TRAITS) {
    const a = theirs.has(t), b = mine.has(t);
    for (const m of [cells, pm]) {
      const c = m.get(t) ?? empty();
      m.set(t, c);
      if (a && b) c.both++; else if (a) c.pack_only++; else if (b) c.rules_only++; else c.neither++;
    }
  }
}
const kappa = (c: Cell): number | null => {
  const n = c.both + c.pack_only + c.rules_only + c.neither;
  if (n === 0) return null;
  const po = (c.both + c.neither) / n;
  const pe = ((c.both + c.pack_only) / n) * ((c.both + c.rules_only) / n) + ((c.rules_only + c.neither) / n) * ((c.pack_only + c.neither) / n);
  return pe === 1 ? 1 : (po - pe) / (1 - pe);
};
const f = (x: number | null): string => (x === null ? '-' : (x * 100).toFixed(1) + '%');
const row = (t: string, c: Cell): string => {
  const a = c.both + c.pack_only, b = c.both + c.rules_only;
  return `| ${t.replace('pca.', '')} | ${a} | ${b} | ${c.both} | ${f(a === 0 ? null : c.both / a)} | ${f(b === 0 ? null : c.both / b)} | ${f(kappa(c))} |`;
};
const head = '| trait | pack carries | rules show | both | rules reach the pack | pack confirms the rules | kappa |\n|---|---:|---:|---:|---:|---:|---:|';
const lines = [
  `# Agreement with the catalog packs (${defs} defs)`, '',
  'Two heuristic labelers compared; neither is a human reading each operation. The rules see only names, bindings and parameter names and types: the pack\'s declared traits, roles, tags and effects are removed first (a write becomes a neutral update). "rules reach the pack": of the traits the pack carries, the share the rules also show. "pack confirms the rules": of the traits the rules show, the share the pack carries.',
  '', head, ...TRAITS.map((t) => row(t, cells.get(t) ?? empty())),
];
for (const [pack, m] of [...perPack].sort()) lines.push('', `## ${pack}`, '', head, ...TRAITS.filter((t) => { const c = m.get(t)!; return c.both + c.pack_only + c.rules_only > 0; }).map((t) => row(t, m.get(t)!)));
const md = lines.join('\n') + '\n';
console.log(md);
const o = process.argv.indexOf('--out');
if (o >= 0) writeFileSync(resolve(process.argv[o + 1] ?? 'xcheck.md'), md);
