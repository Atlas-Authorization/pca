// Vector corpus builder: one JSON file per case under packages/pca-conformance/vectors/goal/, plus index.json.
//   node --experimental-strip-types adversarial/src/vectors.ts [--check]
// `--check` regenerates in memory and fails on any difference with the committed files (determinism gate).
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canon, digest, goalDigest } from './canon.ts';
import { genCorpus } from './gen.ts';
import { wCorpus } from './wcases.ts';
import * as R from './ref.ts';

export const VECTOR_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'pca-conformance', 'vectors', 'goal');
const D = (s: string) => digest('t', s);
type Fn = { id: string; kind: 'fn'; fn: string; input: unknown; expect: unknown };
export function fnVectors(): Fn[] {
  const out: Fn[] = [];
  const add = (fn: string, name: string, input: unknown, expect: unknown) => out.push({ id: `fn-${fn}-${name}`, kind: 'fn', fn, input, expect });
  const canonIn: Array<[string, unknown]> = [['keys-sorted', { b: 1, a: [true, null, 'x'] }], ['unicode-key-order', { 'é': 1, z: 2, 'Ａ': 3, a: 4 }], ['escapes', { s: 'q"b\\n\n\t\u0001\u007fé\u{1F600}' }], ['ints', [0, -1, 9007199254740991, -9007199254740991]], ['nested', { a: { b: { c: [] } }, d: {} }]];
  for (const [n, v] of canonIn) add('canon', n, v, { canon: canon(v), digest: goalDigest(v) });
  const lit = (p: string, op: string, v: string) => ({ k: 'cmp', op, l: { k: 'param', path: p, ty: { k: 's' } }, r: { k: 'lit', v: { k: 's', s: v } } });
  const and = (a: unknown, b: unknown) => ({ k: 'and', a, b });
  const pol: Array<[string, unknown[], string[]]> = [
    ['clean', [lit('amount', 'eq', 'x')], []],
    ['class-eq', [lit('env.class.tone', 'eq', 'calm')], ['env.class.tone']],
    ['nested-ne', [and({ k: 'not', c: lit('env.judge.safe', 'ne', 'no') }, lit('x', 'eq', 'y'))], ['env.judge.safe']],
    ['prov-world', [lit('env.prov.src', 'eq', 'a'), lit('env.world.stock', 'eq', 'b')], ['env.prov.src', 'env.world.stock']],
    ['lookalike-prefix', [lit('env.classy', 'eq', 'a'), lit('env.clas', 'eq', 'a')], []],
  ];
  for (const [n, w, e] of pol) add('polarity', n, w, e);
  const U = (currency: string, exponent: number) => ({ currency, exponent });
  add('units', 'match', { schema: { amount: U('USD', 2) }, terms: { amount: U('USD', 2) } }, []);
  add('units', 'cents-vs-dollars', { schema: { amount: U('USD', 2) }, terms: { amount: U('USD', 0) } }, ['amount']);
  add('units', 'eur-vs-usd', { schema: { amount: U('EUR', 2) }, terms: { amount: U('USD', 2) } }, ['amount']);
  add('units', 'undeclared', { schema: {}, terms: { fee: U('USD', 2) } }, ['fee']);
  for (const d of ['allow', 'escalate', 'deny'] as const) for (const s of ['ok', 'escalate', 'deny'] as const) add('meet', `${d}-${s}`, { decision: d, signal: s }, R.meet(d, s));
  const a1 = { verb: 'refund', res: 'ch_1', params: {}, t: 1, sess: 's', prin: 'p', org: 'o', agent: 'a', depth: 0 };
  const a2 = { ...a1, res: 'ch_2' };
  const ctx = { policy_digest: D('pol'), action_digest: R.actionDigest(a1), history_head: D('h') };
  const ans = (o: object) => ({ policy_digest: ctx.policy_digest, action_digest: ctx.action_digest, history_head: ctx.history_head, valid: true, ...o });
  const pep: Array<[string, string, object | null]> = [['allow', 'allow', null], ['deny', 'deny', ans({})], ['escalate-none', 'escalate', null], ['escalate-ok', 'escalate', ans({})], ['escalate-invalid', 'escalate', ans({ valid: false })], ['escalate-other-action', 'escalate', ans({ action_digest: R.actionDigest(a2) })], ['escalate-other-policy', 'escalate', ans({ policy_digest: D('pol2') })], ['escalate-stale-head', 'escalate', ans({ history_head: D('h2') })]];
  for (const [n, d, a] of pep) add('pep', n, { decision: d, ctx, answer: a }, R.pepAdmit(d as 'allow', ctx, a as R.Answer | undefined));
  const cm = (g: string, p: string, s: string) => ({ goal_digest: g, policy_digest: p, salt: s });
  add('commit', 'basic', cm(D('g'), D('p'), 's1'), { commit: R.goalCommit(D('g'), D('p'), 's1'), opens_other_goal: false });
  add('commit', 'other-policy', cm(D('g'), D('p2'), 's1'), { commit: R.goalCommit(D('g'), D('p2'), 's1'), opens_other_goal: false });
  for (const [n, min, claim, replay] of [['lying-claim', 900000, 1000000, null], ['honest-low-replay', 900000, 950000, 100000], ['replay-ok', 900000, 0, 950000]] as const)
    for (const d of ['allow', 'escalate', 'deny'] as const) add('claim', `${n}-${d}`, { base: d, min_ppm: min, claimed_ppm: claim, replayed_ppm: replay }, R.claimGate(d, min, claim, replay ?? undefined));
  return out;
}
export function allFiles(): Map<string, string> {
  const files = new Map<string, string>();
  const ids: string[] = [];
  const all: Array<{ id: string; kind: string }> = [...genCorpus(), ...wCorpus(), ...fnVectors()];
  for (const c of all) { if (ids.includes(c.id)) throw new Error('dup id ' + c.id); ids.push(c.id); files.set(c.id + '.json', JSON.stringify(c) + '\n'); }
  const corpus_digest = createHash('sha256').update([...files.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, v]) => k + '\n' + v).join('')).digest('base64url');
  const counts: Record<string, number> = {};
  for (const c of all) counts[c.kind] = (counts[c.kind] ?? 0) + 1;
  files.set('index.json', JSON.stringify({ format: 'pca-goal-vectors/2', note: 'generated by packages/pca-goal/adversarial; policy_digest is the sha256 of the lowered policy computed by the oracle; the extracted compiler must reproduce it (CI)', counts, corpus_digest, cases: ids }) + '\n');
  return files;
}
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const files = allFiles();
  if (process.argv.includes('--check')) {
    const have = existsSync(VECTOR_DIR) ? readdirSync(VECTOR_DIR) : [];
    const bad = [...files.keys()].filter((k) => !have.includes(k) || readFileSync(join(VECTOR_DIR, k), 'utf8') !== files.get(k)).concat(have.filter((k) => !files.has(k)));
    if (bad.length) { console.error('vector drift:', bad.slice(0, 10).join(', '), `(${bad.length})`); process.exit(1); }
    console.log(`vectors up to date: ${files.size} files`);
  } else {
    rmSync(VECTOR_DIR, { recursive: true, force: true });
    mkdirSync(VECTOR_DIR, { recursive: true });
    for (const [k, v] of files) writeFileSync(join(VECTOR_DIR, k), v);
    console.log(`wrote ${files.size} files to ${VECTOR_DIR}`);
  }
}
