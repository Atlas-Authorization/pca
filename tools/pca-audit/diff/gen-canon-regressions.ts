/**
 * Turn the audit fuzzer's JSON-text mutations into deterministic cross-language `canon` vectors for
 * scripts/pca-conformance-all.sh (packages/pca-conformance/adversarial/regressions/audit-*.json). The TypeScript strict
 * parser is the oracle; we keep a diverse, bounded subset (every distinct accept / reject class the fuzzer reaches, up
 * to --max), so the other seven verifiers are checked on the boundary inputs a coverage-blind mutator finds.
 *
 *   tsx gen-canon-regressions.ts [--seed 20261009] [--iters 60000] [--max 80] [--out <dir>]
 */
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { mulberry32, mutateText } from '../fuzz/lib';
import { strictParse } from '../../../packages/pca/src/strict-json';
import { hashCanonical } from '../../../packages/pca/src/hash';

const arg = (n: string, d: string) => (process.argv.includes(`--${n}`) ? process.argv[process.argv.indexOf(`--${n}`) + 1]! : d);
const SEED = Number(arg('seed', '20261009'));
const ITERS = Number(arg('iters', '60000'));
const MAX = Number(arg('max', '80'));
const OUT = resolve(arg('out', resolve(import.meta.dirname, '../../../packages/pca-conformance/adversarial/regressions')));
mkdirSync(OUT, { recursive: true });

const seeds = [
  '{"a":[1,2,{"b":null}],"c":"d\\u00e9","e":-1.5e-3}',
  '{"ver":2,"x":{"y":[true,false,null,0,-0,1e2,1.5]},"s":"\\ud83d\\ude00 \\u0000 /"}',
  '{"k":"v","k2":{"n":9007199254740991},"arr":[[],{},[[]]]}',
  '[1,2,3,{"a":"b"},"\\u00e9\\u0301"]',
  '{"__proto__":{"p":1},"constructor":{"prototype":{}},"z":"\\ud800"}',
  '"plain string with \\"escapes\\" and \\\\ backslash"',
  '{"dup":1,"dup":2}',
  '123456789012345678901234567890',
];
const rng = mulberry32(SEED);
const outcome = (t: string): string => {
  try {
    const v = strictParse(t);
    return 'accept:' + hashCanonical(v).slice(0, 6);
  } catch (e) {
    const m = (e instanceof Error ? e.message : String(e)).replace(/\d+/g, 'N').slice(0, 40);
    return 'reject:' + m;
  }
};
const classes = new Map<string, string[]>();
for (let i = 0; i < ITERS; i++) {
  const base = seeds[Math.floor(rng() * seeds.length)]!;
  let t = mutateText(rng, base);
  if (rng() < 0.4) t = mutateText(rng, t);
  if (t.length > 4000) continue;
  const oc = outcome(t).startsWith('accept') ? 'accept' : outcome(t);
  const arr = classes.get(oc) ?? [];
  if (arr.length < 12) arr.push(t);
  classes.set(oc, arr);
}
// round-robin over classes so rare rejection reasons are all represented, accepts capped
const picked: string[] = [];
const lists = [...classes.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([, v]) => v);
for (let round = 0; picked.length < MAX && lists.some((l) => l.length > round); round++) for (const l of lists) if (l[round] !== undefined && picked.length < MAX) picked.push(l[round]!);
for (const raw of picked) {
  const id = createHash('sha256').update(raw).digest('hex').slice(0, 12);
  writeFileSync(resolve(OUT, `audit-canon-${id}.json`), JSON.stringify({ name: `audit-canon-${id}`, kind: 'canon', raw, found: { by: 'pca-audit structure-aware mutator', seed: SEED } }, null, 1) + '\n');
}
console.log(`wrote ${picked.length} canon vectors (${classes.size} outcome classes) -> ${OUT}`);
for (const [k, v] of [...classes.entries()].sort()) console.log(`  ${String(v.length).padStart(2)}  ${k}`);
