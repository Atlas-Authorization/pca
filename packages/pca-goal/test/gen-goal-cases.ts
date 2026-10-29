// gen-goal-cases.ts --n N --seed S --out FILE : the deterministic differential corpus for formal/dafny/difftargets/GoalHarness.dfy.
// One case per line: `<op> <goal tape> | <ontology tape> | <action tape> | <history tape>` (tape syntax: kN iN s<hex>.<hex>).
import { writeFileSync } from 'node:fs';
import { encodeAct, encodeGoal, encodeHist, encodeOntology } from '../src/codec';
import { tapeToText } from '../../pca-verified-core/src/goal';
import { ONT, Rng, randAct, randGoal, randHist } from './fixtures';

const arg = (k: string, d: string): string => { const i = process.argv.indexOf(`--${k}`); return i > 0 ? process.argv[i + 1]! : d; };
const n = Number(arg('n', '2000')), seed = Number(arg('seed', '1')), out = arg('out', 'goal.cases');
const r = new Rng(seed);
const lines: string[] = [];
const ot = tapeToText(encodeOntology(ONT));
for (let i = 0; i < n; i++) {
  const g = randGoal(r);
  if (i % 7 === 0) g.holes = [{ hid: 'h1', q: 'qé\u{1F600}?', domain: ['a', ''], affects: ['g1'], global: i % 2 === 0 }];
  if (i % 11 === 0) g.principal = 'pé\u{1F600}\u0000x';
  const gt = tapeToText(encodeGoal(g));
  const a = randAct(r), h = randHist(r, g);
  const at = tapeToText(encodeAct(a)), ht = tapeToText(encodeHist(h));
  lines.push(`typecheck ${gt} | ${ot}`, `compile ${gt} | ${ot}`, `render ${gt}`, `decideg ${gt} | ${ot} | ${at} | ${ht}`, `decidep ${gt} | ${ot} | ${at} | ${ht}`);
}
lines.push('compile i1 | k510 i0 i0', 'render k480', 'decideg | |  |'); // malformed tapes must give the same rejection everywhere
writeFileSync(out, lines.join('\n') + '\n');
