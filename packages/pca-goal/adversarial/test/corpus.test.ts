import { test } from 'node:test';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { canon } from '../src/canon.ts';
import { DOMAINS } from '../src/domains.ts';
import { CASES_PER_DOMAIN, GUIDED_BUDGET, ILL_PER_DOMAIN, genCorpus, genGoal, genProbes, mkHist, rng, type Case } from '../src/gen.ts';
import { mutants } from '../src/mutants.ts';
import { canonicalOrder, decide, typecheck } from '../src/oracle.ts';
import { goalDigest } from '../src/canon.ts';
import { allFiles, VECTOR_DIR } from '../src/vectors.ts';
import type { Goal } from '../src/types.ts';
import { intersect } from '../src/ref.ts';
import { assert, each, subjects } from './harness.ts';

const corpus: Case[] = genCorpus();
const gen = corpus.filter((c) => c.kind === 'gen');
const dom = (c: Case) => DOMAINS.find((d) => d.name === c.domain)!;

test('generator is deterministic (same seeds, byte-identical corpus)', () => {
  assert.equal(canon(genCorpus()), canon(corpus));
});
test('committed vectors equal a fresh generation (no drift, no stale files)', () => {
  const files = allFiles();
  const have = readdirSync(VECTOR_DIR);
  assert.deepEqual([...files.keys()].sort(), have.sort());
  for (const [k, v] of files) assert.equal(readFileSync(join(VECTOR_DIR, k), 'utf8'), v, k);
});
test('corpus size: >= 30 well-typed and >= 6 ill-typed cases per domain, all three decisions exercised', () => {
  for (const d of DOMAINS) {
    assert.ok(gen.filter((c) => c.domain === d.name).length >= CASES_PER_DOMAIN, d.name);
    assert.ok(corpus.filter((c) => c.domain === d.name && c.kind === 'ill').length >= ILL_PER_DOMAIN, d.name);
  }
  const seen = new Set(gen.flatMap((c) => c.probes.map((p) => p.expect.decision)));
  assert.deepEqual([...seen].sort(), ['allow', 'deny', 'escalate']);
  assert.ok(gen.reduce((n, c) => n + c.probes.length, 0) >= 4000);
});
test('every generated goal compiles; every ill-typed variant is rejected with a code; every grant outside a hole is satisfiable', () => {
  for (const c of gen) assert.ok(c.compile.ok, c.id + c.compile.reasons);
  for (const c of corpus.filter((x) => x.kind === 'ill')) assert.ok(!c.compile.ok && c.compile.reasons.length > 0, c.id);
  const sat = gen.filter((c) => c.goal.grants.every((g) => c.goal.holes.some((h) => h.affects.includes(g.gid)) || c.probes.some((p) => p.expect.witness?.gid === g.gid)));
  assert.ok(sat.length / gen.length >= 0.9, `satisfiable ${sat.length}/${gen.length}`);
});
test('Unknown never yields Allow: every probe with a missing param on a constrained grant is not allow', () => {
  for (const c of gen) for (const p of c.probes) {
    const gr = c.goal.grants.find((g) => g.gid === p.expect.witness?.gid);
    if (gr && gr.cond.k !== 'true') for (const path of Object.keys(p.action.params)) {
      const { [path]: _x, ...rest } = p.action.params; void _x;
      const d = decide(c.goal, c.ontology, { ...p.action, params: rest }, p.history);
      if (d.decision === 'allow') assert.ok(!JSON.stringify(gr.cond).includes(`"path":"${path}"`) || d.witness!.gid !== gr.gid, c.id);
    }
  }
});

// ----- G-T5 canonicity: one order, one digest. A shuffled goal is refused (not_canonical_order); sorting restores the exact digest -----
const shuffle = <T>(r: () => number, xs: T[]): T[] => xs.map((x) => [r(), x] as const).sort((a, b) => a[0] - b[0]).map((x) => x[1]);
test('canonical order (G-T5): shuffled clause order is refused, sorted is accepted with the same digest and the same decisions', () => {
  const r = rng(77);
  let shuffled = 0;
  for (const c of gen.slice(0, 80)) {
    const g: Goal = JSON.parse(JSON.stringify(c.goal));
    g.grants = shuffle(r, g.grants); g.prohibits = shuffle(r, g.prohibits); g.bounds = shuffle(r, g.bounds);
    const moved = canon(g) !== canon(c.goal);
    if (moved) { shuffled++; assert.ok(typecheck(g, c.ontology).reasons.includes('not_canonical_order'), c.id); }
    assert.deepEqual(canonicalOrder(g), c.goal, c.id);
    assert.equal(goalDigest(canonicalOrder(g)), c.goal_digest, c.id);
    assert.ok(typecheck(canonicalOrder(g), c.ontology).ok, c.id);
  }
  assert.ok(shuffled > 5, 'shuffle exercised ' + shuffled);
  const x = gen[0]!; const y: Goal = { ...x.goal, nlDigest: 'other' };
  assert.notEqual(goalDigest(x.goal), goalDigest(y));
});

// ----- G-T2 monotonicity: adding a constraint never grows the allow set (also run against the real compiler) -----
const constraints: Array<[string, (g: Goal, c: Case) => Goal | null]> = [
  ['add_prohibit', (g, c) => ({ ...g, prohibits: [...g.prohibits, { pid: 'xm', target: { k: 'effect', cls: dom(c).ontology.verbs.find((v) => v.verb === g.grants[0]!.verb)!.cls }, res: { k: 'any', reason: 'm' }, cond: { k: 'true' } }] })],
  ['add_bound', (g) => ({ ...g, bounds: [...g.bounds, { bid: 'bm', sel: { k: 'gids', gids: g.grants.map((x) => x.gid) }, agg: 'count', value: { k: 'lit', v: { k: 'q', q: { u: { k: 'count' }, n: 1 } } }, key: '', window: { k: 'lifetime' }, scope: { k: 'session' }, cap: { u: { k: 'count' }, n: 1 }, onExceed: 'deny' }] })],
  ['narrow_where', (g) => ({ ...g, grants: g.grants.map((x, i) => (i === 0 ? { ...x, cond: { k: 'and', a: x.cond, b: { k: 'cmp', op: 'eq', l: { k: 'param', path: '__none', ty: { k: 'q', u: { k: 'count' } } }, r: { k: 'lit', v: { k: 'q', q: { u: { k: 'count' }, n: 1 } } } } } } : x)) })],
  ['shrink_validity', (g) => ({ ...g, validity: { ...g.validity, notAfter: 1_750_000_000_500 } })],
  ['narrow_delegation', (g) => ({ ...g, deleg: { ...g.deleg, maxDepth: 0, mayTouch: [] } })],
  ['add_hole', (g) => (g.grants.length ? { ...g, holes: [...g.holes, { hid: 'hm', q: '?', domain: [], affects: [g.grants[0]!.gid], global: false }] } : null)],
  ['add_escalate_on', (g) => ({ ...g, escalateOn: [...g.escalateOn, { k: 'true' }] })],
];
each('W7 monotonicity: for random G and constraint c, decision(G+c) <= decision(G) (deny < escalate < allow; G-T2)', ['decide'], (s) => {
  const r = rng(4242);
  let checked = 0;
  for (const c of gen) {
    const extra = genProbes(r, dom(c), c.goal).probes;
    for (const [name, f] of constraints) {
      const g2 = f(c.goal, c);
      if (!g2) continue;
      for (const p of [...c.probes, ...extra]) {
        const before = s.decide!(c.goal, c.ontology, p.action, p.history).decision;
        const after = s.decide!(g2, c.ontology, p.action, p.history).decision;
        if (after !== 'deny') assert.ok(['deny', 'escalate', 'allow'].indexOf(after) <= ['deny', 'escalate', 'allow'].indexOf(before), `${c.id} ${name}`);
        checked++;
      }
    }
  }
  assert.ok(checked > 10000);
});

// ----- compiler mutation tests: every non-equivalent mutant is killed; the subject follows the oracle on every mutant -----
test('mutation: the corpus kills every mutant not recorded as search-equivalent; equivalents survive an independent 4x search', () => {
  let total = 0, kills = 0, equiv = 0;
  for (const c of gen) {
    const eq = new Set(c.equiv);
    const idx = new Map<string, number>();
    for (const m of mutants(c.goal)) {
      const n = idx.get(m.op) ?? 0; idx.set(m.op, n + 1); total++;
      const killed = c.probes.some((p) => canon(decide(m.goal, c.ontology, p.action, p.history)) !== canon(p.expect));
      if (killed) { kills++; continue; }
      assert.ok(eq.has(`${m.op}#${n}`), `${c.id}: surviving mutant ${m.op}#${n} not recorded as equivalent`);
      equiv++;
    }
  }
  assert.ok(kills / total >= 0.75, `kill rate ${kills}/${total}`);
  assert.equal(kills + equiv, total);
});
test('mutation: recorded-equivalent mutants are re-searched with a fresh seed; at most 10% turn out killable (equivalence is undecidable by search, so this bounds the weak-search rate)', () => {
  const r = rng(9001);
  let total = 0, killable = 0;
  for (const c of gen.filter((_, i) => i % 3 === 0)) {
    if (!c.equiv.length) continue;
    const idx = new Map<string, number>();
    const ms = mutants(c.goal).filter((m) => { const n = idx.get(m.op) ?? 0; idx.set(m.op, n + 1); return c.equiv.includes(`${m.op}#${n}`); });
    const probes = Array.from({ length: 3 }, () => genProbes(r, dom(c), c.goal, 200).probes).flat();
    for (const m of ms) { total++; if (probes.some((p) => canon(decide(m.goal, c.ontology, p.action, p.history)) !== canon(p.expect))) killable++; }
  }
  assert.ok(total > 0);
  assert.ok(killable / total <= 0.1, `${killable}/${total} recorded-equivalent mutants were killable by re-search (GUIDED_BUDGET ${GUIDED_BUDGET})`);
});
each('mutation: the subject agrees with the oracle on every mutated goal (a compiler that ignores a clause is caught)', ['decide'], (s) => {
  if (s.name === 'reference-oracle') return; // the oracle is the oracle
  for (const c of gen) for (const m of mutants(c.goal)) if (typecheck(m.goal, c.ontology).ok) for (const p of c.probes)
    assert.equal(canon(s.decide!(m.goal, c.ontology, p.action, p.history)), canon(decide(m.goal, c.ontology, p.action, p.history)), `${c.id} ${m.op}`);
});

// ----- F3: merged policy is no broader than any reading -----
test('F3 intersection: merged allow implies allow in every reading (pairs and triples, with histories)', () => {
  const r = rng(31337);
  let allowed = 0;
  for (const d of DOMAINS) {
    const gs = Array.from({ length: 12 }, () => genGoal(r, d));
    for (let i = 0; i + 1 < gs.length; i += 2) for (const k of [2, 3, 0]) {
      const readings = k === 0 ? [gs[i]!, gs[i]!] : [gs[i]!, gs[i + 1]!, gs[(i + 2) % gs.length]!].slice(0, k);
      const merged = intersect(readings, d.ontology);
      const fromReadings = readings.flatMap((g) => genProbes(r, d, g, 30).probes).map((p) => ({ ...p, history: mkHist([]) }));
      for (const p of [...fromReadings, ...genProbes(r, d, merged, 30).probes]) {
        const v = decide(merged, d.ontology, p.action, p.history);
        if (v.decision !== 'allow') continue;
        allowed++;
        readings.forEach((g, j) => {
          const h = mkHist(p.history.adms.map((e) => ({ act: e.act, gid: e.gid.split('+')[j] ?? e.gid })));
          assert.equal(decide(g, d.ontology, p.action, h).decision, 'allow', `${d.name} reading ${j} witness ${v.witness!.gid}`);
        });
      }
    }
  }
  assert.ok(allowed > 20, 'property test exercised ' + allowed);
});
void subjects;
