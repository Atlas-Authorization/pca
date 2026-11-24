import { hashCanonical } from '@atlasauth/pca';
import { describe, expect, it, vi } from 'vitest';
import {
  DOMAIN_ALPHA, LEVELS, MODELS, SIM_SPECS, caseSetDigest, compileWideningCount, completionsFrom, evalCase, generateCases, recordFixtures,
  requestOf, runDomain, simulateOutput, summarize, truthGoal, truthOnt, type BenchCase, type CaseOutcome,
} from '../src/bench';
import { allowsWitness, disambiguate, type Reading } from '../src/disambiguate';
import { boundaryExamples, reviewSet, type Example } from '../src/examples';
import { buildPrompt, llmInterpreter, promptKey, ruleInterpreter, type Completion, type Recordings } from '../src/interpret';
import type { Goal, Ontology } from '../src/ir';
import { nVersion, type NVersionResult } from '../src/nversion';
import { ALL_ONTOLOGIES } from '../src/ontologies';
import { instantiateTemplate, type SlotValue } from '../src/ontology';

// The tail of the cpUpper95 import the report summary uses can be pinned to exact values for the gate edges.
const hoisted = vi.hoisted(() => ({ override: undefined as ((k: number, n: number) => number) | undefined }));
vi.mock('../src/crc', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/crc')>();
  return { ...actual, cpUpper95: (k: number, n: number): number => (hoisted.override ? hoisted.override(k, n) : actual.cpUpper95(k, n)) };
});

// ---------------- an independent restatement of one case evaluation, split so single steps can be varied ----------------

interface Variant { noExtra?: boolean; andCap?: boolean; some?: boolean; clean?: (x: Reading) => boolean; deny?: boolean }
interface Probe { ex: Example; truthAllow: boolean }
interface Prep { truth: Goal; ont: Ontology; probes: Probe[]; readings: Reading[]; nv: NVersionResult; capOpt: number | undefined }
interface Entry { id: string; p: Prep; base: CaseOutcome; real: CaseOutcome }

const priorOf = (e: Example) => ({ act: e.act, prior: e.hist.adms.map((a) => a.act), rels: e.rels });

async function prepare(c: BenchCase, comps: Record<string, Completion>, opts: { reviewCap?: number; truth?: Goal }): Promise<Prep> {
  const o = ALL_ONTOLOGIES[c.domain]!;
  const truth = opts.truth ?? truthGoal(c);
  const ont = truthOnt(c, truth);
  const probes = boundaryExamples(truth, { ont, verbs: o.verbs.map((v) => v.id) }).examples.map((ex) => ({ ex, truthAllow: ex.decision === 'allow' }));
  const req = requestOf(c);
  const readings: Reading[] = [
    await ruleInterpreter('rule').interpret(req),
    ...(await Promise.all(MODELS.map((m) => llmInterpreter({ id: m.id, family: m.family, complete: comps[m.id]! }).interpret(req)))),
  ];
  return { truth, ont, probes, readings, nv: nVersion(readings, { ont }), capOpt: opts.reviewCap };
}

async function finish(p: Prep, id: string, v: Variant = {}): Promise<CaseOutcome> {
  const { truth, ont, probes, readings, nv } = p;
  const wid = (g: Goal): boolean => probes.some((q) => !q.truthAllow && allowsWitness(g, ont, priorOf(q.ex)));
  const over = (g: Goal): boolean => probes.some((q) => q.truthAllow && !allowsWitness(g, ont, priorOf(q.ex)));
  const A = readings[1]!;
  const accept0 = A.goal.holes.length === 0 && A.goal.grants.length > 0;
  const accept1 = nv.signable && nv.merged.grants.length > 0;
  let accept2 = false;
  if (accept1) {
    const cap = v.andCap ? (p.capOpt === undefined ? Number.POSITIVE_INFINITY : p.capOpt === 0 ? 0 : 12) : (p.capOpt ?? 12);
    const ex = reviewSet(boundaryExamples(nv.merged, { ont, ...(v.noExtra ? {} : { extra: [truth] }) }).examples, cap);
    const agrees = (e: Example): boolean => allowsWitness(truth, ont, priorOf(e)) === (e.decision === 'allow');
    accept2 = v.some ? ex.some(agrees) : ex.every(agrees);
  }
  const loss = [accept0 && wid(A.goal) ? 1 : 0, accept1 && wid(nv.merged) ? 1 : 0, accept2 && wid(nv.merged) ? 1 : 0, 0];
  const accepted = [accept0, accept1, accept2, false];
  const falseRestricted = [accept0 && over(A.goal), accept1 && over(nv.merged), accept2 && over(nv.merged), false];
  let questions = 0;
  const keep = v.clean ?? ((x: Reading): boolean => x.goal.holes.length === 0 && x.goal.grants.length > 0);
  const clean = readings.filter(keep);
  if (!accept1 && clean.length > 1) {
    const res = await disambiguate(clean, (q) => (v.deny ? 'deny' : allowsWitness(truth, ont, q) ? 'allow' : 'deny'), { ont });
    questions = res.asked.length;
  }
  return { id, loss, accepted, falseRestricted, questions, panelIssue: nv.panelIssues.length > 0 };
}

// ---------------- scenario pool ----------------

type Money = { ccy: string; minor: number };
const isMoney = (v: SlotValue): v is Money => typeof v === 'object' && !Array.isArray(v) && 'minor' in v;
const hasMoney = (c: BenchCase): boolean => Object.values(c.slots).some(isMoney);
const mapMoney = (c: BenchCase, f: (m: Money) => number): BenchCase => ({
  ...c, slots: Object.fromEntries(Object.entries(c.slots).map(([k, v]) => [k, isMoney(v) ? { ccy: v.ccy, minor: f(v) } : v])),
});
const narrowTruth = (c: BenchCase): Goal => truthGoal(mapMoney(c, (m) => Math.max(500, Math.round(m.minor / 2))));
const wideTruth = (c: BenchCase): Goal => truthGoal(mapMoney(c, (m) => m.minor * 2));
const widestTruth = (c: BenchCase): Goal => {
  const top = Math.max(...Object.values(c.slots).filter(isMoney).map((m) => m.minor));
  return truthGoal(mapMoney(c, () => top * 2));
};
const fixed = (a: string, b: string): Record<string, Completion> => ({ 'model-a': async () => a, 'model-b': async () => b });
const filled = (c: BenchCase, slots: Record<string, SlotValue>): string => JSON.stringify({ template: c.template, slots });

async function entry(id: string, c: BenchCase, comps: Record<string, Completion>, opts: { reviewCap?: number; truth?: Goal } = {}): Promise<Entry> {
  const p = await prepare(c, comps, opts);
  return { id, p, base: await finish(p, c.id), real: await evalCase(c, comps, opts) };
}

async function buildPool(): Promise<Entry[]> {
  const out: Entry[] = [];
  const mixed = Object.keys(DOMAIN_ALPHA).flatMap((d, i) => [
    ...generateCases(d, 8, 31 + i, { hostileEvery: 3 }),
    ...generateCases(d, 4, 61 + i, { hostileOnly: true }).map((c) => ({ ...c, id: `${c.id}h` })),
  ]);
  const comps = completionsFrom(recordFixtures(mixed));
  for (const c of mixed) out.push(await entry(`base ${c.id}`, c, comps));
  const money = mixed.filter(hasMoney).filter((_, i) => i % 3 === 0);
  for (const [i, c] of money.entries()) {
    out.push(await entry(`narrow ${c.id}`, c, comps, { truth: narrowTruth(c) }));
    out.push(await entry(`wide ${c.id}`, c, comps, { truth: wideTruth(c) }));
    out.push(await entry(`narrow cap0 ${c.id}`, c, comps, { truth: narrowTruth(c), reviewCap: 0 }));
    out.push(await entry(`wide cap0 ${c.id}`, c, comps, { truth: wideTruth(c), reviewCap: 0 }));
    if (i % 3 === 0) {
      out.push(await entry(`narrow cap3 ${c.id}`, c, comps, { truth: narrowTruth(c), reviewCap: 3 }));
      out.push(await entry(`wide cap3 ${c.id}`, c, comps, { truth: wideTruth(c), reviewCap: 3 }));
    }
  }
  // three distinct clean readings of one text (swapped and doubled limits), a partial reading, and an unusable one
  for (const c of generateCases('payments', 24, 77, {}).filter((x) => x.template === 'refund_customer_charges').slice(0, 4)) {
    const s = c.slots as Record<string, SlotValue>;
    const swap = fixed(filled(c, { ...s, max_per: s.max_total!, max_total: s.max_per! }), filled(c, { ...s, max_per: s.max_total! }));
    out.push(await entry(`swap ${c.id}`, c, swap));
    out.push(await entry(`swap widest ${c.id}`, c, swap, { truth: widestTruth(c) }));
    out.push(await entry(`broken ${c.id}`, c, fixed(filled(c, s), '{"template":"nope","slots":{}}')));
  }
  // a truth that also grants a verb the merged goal never mentions: only the truth's own literals expose it
  for (const c of mixed.filter((x) => x.domain === 'payments').slice(0, 6)) {
    const t = truthGoal(c);
    const extra: Goal = { ...t, grants: [...t.grants, { gid: 'zz-extra', verb: 'read_charge', res: { k: 'exact', id: 'ch_zzextra' }, cond: { k: 'true' } }] };
    out.push(await entry(`extra grant ${c.id}`, c, comps, { truth: extra, reviewCap: 1000 }));
  }
  // three readings that differ pairwise on some witness (limit of one, count default of another), and a truth that allows everything any of them allows
  let three = 0;
  for (const c of generateCases('payments', 120, 79, {})) {
    if (three === 3) break;
    const s = c.slots as Record<string, SlotValue>;
    const n = s.max_count;
    if (c.template !== 'refund_customer_charges' || n === undefined || typeof n !== 'object' || Array.isArray(n) || !('n' in n) || n.n === 5) continue;
    const per = s.max_per as Money, total = s.max_total as Money;
    // the sum cap already limits a single action to the smaller of the two, so only per < total makes the readings differ on single actions
    if (per.minor >= total.minor) continue;
    const { max_count: _m, ...noCount } = s;
    void _m;
    const trio = fixed(filled(c, noCount), filled(c, { ...s, max_per: total }));
    const p = await prepare(c, trio, {});
    if (!p.readings.every((r) => r.goal.holes.length === 0)) continue;
    const top = Math.max(per.minor, total.minor) * 2;
    const open = truthGoal({ ...mapMoney(c, () => top), slots: { ...mapMoney(c, () => top).slots, max_count: { n: 100 } } });
    out.push(await entry(`three ${c.id}`, c, trio, { truth: open }));
    for (const [i, r] of p.readings.entries()) out.push(await entry(`three truth ${i} ${c.id}`, c, trio, { truth: r.goal }));
    three++;
  }
  for (const c of generateCases('email', 15, 78, {}).filter((x) => x.template === 'reply_to_thread').slice(0, 3)) {
    const { domains: _d, ...rest } = c.slots;
    void _d;
    out.push(await entry(`partial ${c.id}`, c, fixed(filled(c, rest), filled(c, c.slots))));
    out.push(await entry(`broken ${c.id}`, c, fixed(filled(c, c.slots), '{"template":"nope","slots":{}}')));
  }
  return out;
}

let poolP: Promise<Entry[]> | undefined;
const getPool = (): Promise<Entry[]> => (poolP ??= buildPool());
const LONG = 900_000;

async function witness(v: Variant): Promise<boolean> {
  for (const e of await getPool()) if (JSON.stringify(await finish(e.p, e.base.id, v)) !== JSON.stringify(e.base)) return true;
  return false;
}

describe('evalCase against an independent restatement', () => {
  it('equals the restatement on every scenario, including other truths and review caps', async () => {
    const pool = await getPool();
    expect(pool.length).toBeGreaterThanOrEqual(104);
    expect(pool.some((e) => e.id.startsWith('three'))).toBe(true);
    for (const e of pool) expect(e.real, e.id).toStrictEqual(e.base);
  }, LONG);

  it('the scenarios reach every accept / widen / restrict / question outcome', async () => {
    const pool = (await getPool()).map((e) => e.base);
    expect(pool.some((o) => o.accepted[1] && o.accepted[2])).toBe(true);
    expect(pool.some((o) => !o.accepted[1])).toBe(true);
    expect(pool.some((o) => o.accepted[1] && !o.accepted[2])).toBe(true);
    expect(pool.some((o) => o.accepted[0] && o.loss[0] === 1)).toBe(true);
    expect(pool.some((o) => o.accepted[0] && o.loss[0] === 0)).toBe(true);
    expect(pool.some((o) => o.loss[1] === 1)).toBe(true);
    expect(pool.some((o) => o.loss[2] === 1)).toBe(true);
    expect(pool.some((o) => o.falseRestricted[0])).toBe(true);
    expect(pool.some((o) => o.falseRestricted[1])).toBe(true);
    expect(pool.some((o) => o.falseRestricted[2])).toBe(true);
    expect(pool.some((o) => o.questions > 0)).toBe(true);
    expect(pool.every((o) => !o.panelIssue && o.accepted.length === 4 && o.accepted[3] === false && o.loss[3] === 0)).toBe(true);
  }, LONG);

  it('merged examples are checked against the truth goal, over the first twelve by default and every example of all of them', async () => {
    expect(await witness({ noExtra: true })).toBe(true);
    expect(await witness({ andCap: true })).toBe(true);
    expect(await witness({ some: true })).toBe(true);
  }, LONG);

  it('only complete readings are asked about, and the answers come from the truth goal', async () => {
    expect(await witness({ clean: () => true })).toBe(true);
    expect(await witness({ clean: () => false })).toBe(true);
    expect(await witness({ clean: (x) => x.goal.grants.length > 0 })).toBe(true);
    expect(await witness({ clean: (x) => x.goal.holes.length !== 0 && x.goal.grants.length > 0 })).toBe(true);
    expect(await witness({ clean: (x) => x.goal.holes.length === 0 || x.goal.grants.length > 0 })).toBe(true);
    expect(await witness({ clean: (x) => x.goal.holes.length === 0 && x.goal.grants.length <= 0 })).toBe(true);
    expect(await witness({ deny: true })).toBe(true);
  }, LONG);

  it('a reading with no holes keeps every grant of its template, whatever a completion says (the shape the ledger relies on)', () => {
    for (const o of Object.values(ALL_ONTOLOGIES)) {
      for (const t of o.templates) {
        expect(t.grants.length, `${o.domain}/${t.id}`).toBeGreaterThan(0);
        const g = instantiateTemplate(o, t.id, t.example, { principal: 'p', nl: 'x' });
        expect(g.holes, `${o.domain}/${t.id}`).toStrictEqual([]);
        expect(g.grants.map((x) => x.gid).sort(), `${o.domain}/${t.id}`).toStrictEqual(t.grants.map((x) => x.gid).sort());
      }
    }
  });
});

describe('completionsFrom', () => {
  it('replays the recording of each simulated model under its own id', async () => {
    const c = generateCases('payments', 1, 4, {})[0]!;
    const comps = completionsFrom(recordFixtures([c]));
    expect(Object.keys(comps)).toStrictEqual(['model-a', 'model-b']);
    for (const spec of SIM_SPECS) expect(await comps[spec.id]!(buildPrompt(requestOf(c), false))).toBe(simulateOutput(c, spec));
  });
});

describe('summarize', () => {
  const row = (i: number): CaseOutcome => {
    if (i % 2 === 0) return { id: `r${i}`, loss: [0, 0, 0, 0], accepted: [true, true, true, false], falseRestricted: [false, false, false, false], questions: 0, panelIssue: false };
    const j = (i - 1) / 2;
    return { id: `r${i}`, loss: [j < 20 ? 1 : 0, 0, 0, 0], accepted: [j < 20, j < 30, j < 10, false], falseRestricted: [j < 7, false, false, false], questions: j % 3, panelIssue: false };
  };
  const rows = Array.from({ length: 100 }, (_, i) => row(i));
  const alpha = DOMAIN_ALPHA.payments!;
  const perLevel = (cp: number) => [
    { level: LEVELS[0]!, widening: { k: 20, n: 100, cpUpper95: cp }, escalationRate: 30 / 100 },
    { level: LEVELS[1]!, widening: { k: 0, n: 100, cpUpper95: cp }, escalationRate: 20 / 100 },
    { level: LEVELS[2]!, widening: { k: 0, n: 100, cpUpper95: cp }, escalationRate: 40 / 100 },
    { level: LEVELS[3]!, widening: { k: 0, n: 100, cpUpper95: cp }, escalationRate: 100 / 100 },
  ];

  it('calibrates on the even cases, tests on the odd ones, and passes a bound exactly at alpha / 2 and 0.01 under alpha', () => {
    hoisted.override = () => alpha / 2;
    try {
      const r = summarize('payments', rows, 'ms');
      expect(r).toStrictEqual({
        domain: 'payments', modelSet: 'ms', alpha, levels: LEVELS,
        calibration: { level: 0, n: 50, feasible: true, correctedRisk: 1 / 51, minN: 49, levelName: LEVELS[0]! },
        test: { n: 50, widening: { k: 20, rate: 20 / 50, cpUpper95: alpha / 2 }, escalationRate: 30 / 50, falseRestrictionRate: 7 / 50, meanQuestions: 49 / 50 },
        gatePassed: true,
        perLevel: perLevel(alpha / 2),
        compileWidening: { k: 0, n: 0 },
      });
    } finally { hoisted.override = undefined; }
  });

  it('a bound above alpha / 2 fails the calibration gate at every level and above alpha fails the report gate', () => {
    hoisted.override = () => 0.03;
    try {
      const r = summarize('payments', rows, 'ms', { k: 3, n: 9 });
      expect(r).toStrictEqual({
        domain: 'payments', modelSet: 'ms', alpha, levels: LEVELS,
        calibration: { level: 3, n: 50, feasible: false, correctedRisk: 1 / 51, minN: 49, levelName: LEVELS[3]! },
        test: { n: 50, widening: { k: 0, rate: 0 / 50, cpUpper95: 0.03 }, escalationRate: 50 / 50, falseRestrictionRate: 0 / 50, meanQuestions: 49 / 50 },
        gatePassed: false,
        perLevel: perLevel(0.03),
        compileWidening: { k: 3, n: 9 },
      });
    } finally { hoisted.override = undefined; }
  });

  it('a bound exactly at alpha passes the report gate but not the calibration gate', () => {
    hoisted.override = () => alpha;
    try {
      const r = summarize('payments', rows, 'ms');
      expect(r.gatePassed).toBe(true);
      expect(r.calibration.level).toBe(3);
      expect(r.test.widening.cpUpper95).toBe(alpha);
    } finally { hoisted.override = undefined; }
  });

  it('uses the real Clopper-Pearson bound for the gate', async () => {
    const real = await vi.importActual<typeof import('../src/crc')>('../src/crc');
    const r = summarize('payments', rows, 'ms');
    expect(r.calibration).toStrictEqual({ level: 3, n: 50, feasible: false, correctedRisk: 1 / 51, minN: 49, levelName: LEVELS[3]! });
    expect(r.test.widening.cpUpper95).toBe(real.cpUpper95(0, 50));
    expect(r.gatePassed).toBe(real.cpUpper95(0, 50) <= alpha);
    expect(r.perLevel[0]!.widening.cpUpper95).toBe(real.cpUpper95(20, 100));
  });
});

describe('compileWideningCount', () => {
  it('counts the boundary examples of every item and the compiled allows the reference does not make', () => {
    const items = [...generateCases('payments', 4, 3, {}), ...generateCases('email', 3, 3, {})].map((c) => { const goal = truthGoal(c); return { goal, ont: truthOnt(c, goal) }; });
    const all = items.flatMap(({ goal, ont }) => boundaryExamples(goal, { ont, verbs: [] }).examples);
    expect(compileWideningCount(items)).toStrictEqual({ k: 0, n: all.length });
    const notAllowed = all.filter((e) => e.decision !== 'allow').length;
    expect(notAllowed).toBeGreaterThan(0);
    expect(compileWideningCount(items, () => 'allow')).toStrictEqual({ k: notAllowed, n: all.length });
    expect(compileWideningCount(items, () => 'deny')).toStrictEqual({ k: 0, n: all.length });
  });
});

describe('boundary example options', () => {
  it('compile-widening decides the examples against the ontology: an effect-class prohibition resolves its verbs', () => {
    const c = generateCases('payments', 1, 3, {})[0]!;
    const base = truthGoal(c);
    const ont0 = truthOnt(c, base);
    const goal: Goal = { ...base, prohibits: [{ pid: 'eff', target: { k: 'effect', cls: ont0.verbs[0]!.cls }, res: { k: 'any', reason: 'r' }, cond: { k: 'true' } }] };
    const ont = truthOnt(c, goal);
    const n = boundaryExamples(goal, { ont, verbs: [] }).examples.length;
    expect(n).toBeGreaterThan(0);
    expect(compileWideningCount([{ goal, ont }])).toStrictEqual({ k: 0, n });
  });

  it('truth probes include the ontology verbs the truth never mentions, so a reading that grants one widens', async () => {
    const c = generateCases('payments', 24, 77, {}).find((x) => x.template === 'refund_customer_charges')!;
    const readOnly = JSON.stringify({ template: 'read_customer_charges', slots: { customer: c.slots.customer! } });
    const out = await evalCase(c, fixed(readOnly, filled(c, c.slots)));
    expect(out.accepted[0]).toBe(true);
    expect(out.loss[0]).toBe(1);
  });
});

describe('runDomain', () => {
  it('evaluates every case, defaults the model set and counts compile-widening over the first 25 cases only', async () => {
    const cases = generateCases('payments', 26, 5, { hostileEvery: 5 });
    const rec = recordFixtures(cases);
    const r = await runDomain('payments', cases, rec);
    const comps = completionsFrom(rec);
    const want: CaseOutcome[] = [];
    for (const c of cases) want.push(await evalCase(c, comps));
    expect(r.outcomes).toStrictEqual(want);
    const items = (cs: BenchCase[]) => cs.map((c) => { const goal = truthGoal(c); return { goal, ont: truthOnt(c, goal) }; });
    const first = compileWideningCount(items(cases.slice(0, 25)));
    expect(first.n).toBeLessThan(compileWideningCount(items(cases)).n);
    expect(r.report.compileWidening).toStrictEqual(first);
    expect(r.report.modelSet).toBe('recorded-fixtures');
    expect(r.report).toStrictEqual(summarize('payments', want, 'recorded-fixtures', first));
  }, LONG);

  it('hands the sources to the model interpreters only when asked', async () => {
    const cs = generateCases('payments', 6, 9, {}).map((c) => ({ ...c, sources: ['a forwarded note'] }));
    const rec: Recordings = {};
    for (const c of cs) for (const spec of SIM_SPECS) rec[promptKey(spec.id, buildPrompt(requestOf(c), true))] = simulateOutput(c, spec);
    const comps = completionsFrom(rec);
    const want: CaseOutcome[] = [];
    for (const c of cs) want.push(await evalCase(c, comps, { includeSources: true }));
    expect(want.some((o) => o.accepted[1])).toBe(true);
    const r = await runDomain('payments', cs, rec, 'ms', { includeSources: true });
    expect(r.outcomes).toStrictEqual(want);
    expect(r.report.modelSet).toBe('ms');
    const without = await runDomain('payments', cs, rec);
    expect(without.outcomes).not.toStrictEqual(want);
  }, LONG);
});

describe('caseSetDigest', () => {
  it('hashes each case with a null for a missing planted list', () => {
    const a: BenchCase = { id: 'x1', domain: 'payments', template: 't', slots: {}, text: 'x', sources: [], flags: [] };
    const b: BenchCase = { ...a, id: 'x2', planted: [{ ccy: 'USD', minor: 5 }] };
    expect(caseSetDigest([a, b])).toBe(hashCanonical([{ ...a, planted: null }, { ...b, planted: [{ ccy: 'USD', minor: 5 }] }]));
    expect(caseSetDigest([a, b])).not.toBe(hashCanonical([a, b]));
  });
});
