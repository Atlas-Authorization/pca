import { hashCanonical } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { EMPTY_HIST, MAX_CELLS, allowWitness, boundaryExamples, cells, mkAct, type Case, type Space } from '../src/examples';
import type { Bound, Cond, Goal, Grant, Ontology, Prohibit, Term, Unit, Value } from '../src/ir';
import { CNT, USD, baseGoal, ctrue, lteAmt, usd } from './fixtures';

const OV = '\u0000other-verb';
const OR = '\u0000other-resource';
const OTH = '\u0000other';
const sv = (s: string): Value => ({ k: 's', s });
const cnt = (n: number): Value => ({ k: 'q', q: { u: CNT, n } });
const ZZZ: Value = { k: 'q', q: { u: { k: 'money', ccy: 'ZZZ' }, n: 0 } };
const noSpace = { q: new Map<string, Map<string, number[]>>(), d: new Map<string, string[]>() };

describe('cells: complete grid', () => {
  it('enumerates verb x resource x relation bits in order, with the exact other-verb and other-resource representatives', () => {
    const sp: Space = { verbs: ['v1'], resources: ['r1'], rels: [{ rel: 'R', anchor: 'A' }], ...noSpace };
    const c = (verb: string, res: string, bit: number): Case => ({ act: mkAct(verb, res, {}), rels: [{ rel: 'R', anchor: 'A', members: bit ? [res] : [] }] });
    const expected: Case[] = [];
    for (const v of ['v1', OV]) for (const r of ['r1', OR]) for (const b of [0, 1]) expected.push(c(v, r, b));
    expect(cells(sp)).toEqual({ cases: expected, complete: true });
  });

  it('iterates the lexicographically first parameter fastest, even when the quantity key sorts after the discrete key', () => {
    const sp: Space = { verbs: [], resources: [], rels: [], q: new Map([['z', new Map([['count', [5]]])]]), d: new Map([['a', ['s:x']]]) };
    const zOpts: (Value | undefined)[] = [undefined, cnt(4), cnt(5), cnt(6)];
    const aOpts: (Value | undefined)[] = [undefined, sv('x'), sv(OTH)];
    const expected: Case[] = [];
    for (const z of zOpts) for (const a of aOpts) {
      const params: Record<string, Value> = {};
      if (a) params.a = a;
      if (z) params.z = z;
      expected.push({ act: mkAct(OV, OR, params), rels: [] });
    }
    expect(cells(sp)).toEqual({ cases: expected, complete: true });
  });

  it('is complete at exactly MAX_CELLS cells and enumerates every one', () => {
    expect(MAX_CELLS).toBe(40_000);
    const verbs = ['v0', 'v1', 'v2', 'v3', 'v4', 'v5', 'v6', 'v7'];
    const d = new Map<string, string[]>(['p0', 'p1', 'p2', 'p3'].map((p): [string, string[]] => [p, ['s:a', 's:b', 's:c']]));
    const sp: Space = { verbs, resources: [], rels: [{ rel: 'a', anchor: 'x' }, { rel: 'b', anchor: 'x' }, { rel: 'c', anchor: 'x' }], q: new Map(), d };
    // 8 verbs * 1 resource * 2^3 relation bits * 5^4 parameter options = 40000
    const r = cells(sp, { verbs });
    expect(r.complete).toBe(true);
    expect(r.cases).toHaveLength(40_000);
  });
});

describe('cells: subset when the grid exceeds MAX_CELLS', () => {
  const rels12 = Array.from({ length: 12 }, (_, i) => ({ rel: `r${i}`, anchor: 'x' }));
  // param a has two options (undefined, a unit-mismatch money 0); param d has three (undefined, 'x', other)
  const sp: Space = { verbs: ['v1'], resources: ['r1'], rels: rels12, q: new Map([['a', new Map([['money:USD', [] as number[]]])]]), d: new Map([['d', ['s:x']]]) };
  const sc = (verb: string, res: string, bits: number, params: Record<string, Value>): Case => ({
    act: mkAct(verb, res, params),
    rels: rels12.map((x, i) => ({ rel: x.rel, anchor: x.anchor, members: bits & (1 << i) ? [res] : [] })),
  });
  const defaults = { a: ZZZ, d: sv(OTH) };

  it('is incomplete and returns the all-defaults base plus the single-coordinate perturbations, in order', () => {
    // 2 verbs * 2 resources * 2^12 * (2 * 3) = 98304 > 40000
    const r = cells(sp);
    expect(r.complete).toBe(false);
    // per verb: base == (r1, bits 0); (r1, bits 1..4095); (other resource, bits 0..4095); a=undefined; d=undefined; d='x'
    expect(r.cases).toHaveLength(2 * 8195);
    expect(r.cases[0]).toEqual(sc('v1', 'r1', 0, defaults));
    expect(r.cases[1]).toEqual(sc('v1', 'r1', 1, defaults));
    expect(r.cases[4095]).toEqual(sc('v1', 'r1', 4095, defaults));
    expect(r.cases[4096]).toEqual(sc('v1', OR, 0, defaults));
    expect(r.cases[8191]).toEqual(sc('v1', OR, 4095, defaults));
    expect(r.cases[8192]).toEqual(sc('v1', 'r1', 0, { d: sv(OTH) }));
    expect(r.cases[8193]).toEqual(sc('v1', 'r1', 0, { a: ZZZ }));
    expect(r.cases[8194]).toEqual(sc('v1', 'r1', 0, { a: ZZZ, d: sv('x') }));
    expect(r.cases[8195]).toEqual(sc(OV, 'r1', 0, defaults));
    expect(r.cases[2 * 8195 - 1]).toEqual(sc(OV, 'r1', 0, { a: ZZZ, d: sv('x') }));
  });
});

// ---------------- allowWitness ----------------

const instant: Unit = { k: 'instant' };
const atTerm: Term = { k: 'param', path: 'at', ty: { k: 'q', u: instant } };
const atLit = (n: number): Term => ({ k: 'lit', v: { k: 'q', q: { u: instant, n } } });
const atCmp = (op: 'ne' | 'lte', n: number): Cond => ({ k: 'cmp', op, l: atTerm, r: atLit(n) });
const inst = (n: number): Value => ({ k: 'q', q: { u: instant, n } });
const anyRes = { k: 'any', reason: 'all' } as const;
const grant = (gid: string, verb: string, cond: Cond): Grant => ({ gid, verb, res: anyRes, cond });
const ONT0: Ontology = { verbs: [], rels: [] };

describe('allowWitness', () => {
  it('keeps the first of equal-magnitude Allow cells', () => {
    const gr = grant('g1', 'v', atCmp('ne', 0));
    const g = baseGoal({ grants: [gr] });
    // at = -1 and at = 1 both allow with magnitude 1; at = 0 denies
    expect(allowWitness(g, gr, ONT0)).toEqual({ act: mkAct('v', OR, { at: inst(-1) }), rels: [] });
  });

  it('picks a later cell of strictly smaller magnitude, measured by absolute value', () => {
    const gr = grant('g1', 'v', atCmp('lte', 0));
    const g = baseGoal({ grants: [gr] });
    // at = -1 (magnitude 1) is enumerated before at = 0 (magnitude 0); at = 1 denies
    expect(allowWitness(g, gr, ONT0)).toEqual({ act: mkAct('v', OR, { at: inst(0) }), rels: [] });
  });

  it('only counts Allow cells admitted by this very grant', () => {
    const g1 = grant('g1', 'v', ctrue);
    const g2 = grant('g2', 'v', ctrue);
    const g = baseGoal({ grants: [g1, g2] });
    expect(allowWitness(g, g1, ONT0)).toEqual({ act: mkAct('v', OR, {}), rels: [] });
    // g1 admits every cell first, so g2 is never the witness
    expect(allowWitness(g, g2, ONT0)).toBeUndefined();
  });
});

// ---------------- boundaryExamples ----------------

const amt: Term = { k: 'param', path: 'amount', ty: { k: 'q', u: USD } };
const eq5001: Cond = { k: 'cmp', op: 'eq', l: amt, r: { k: 'lit', v: { k: 'q', q: usd(5001) } } };
const p1: Prohibit = { pid: 'p1', target: { k: 'verb', verb: 'v' }, res: anyRes, cond: eq5001 };
const BG: Goal = baseGoal({ grants: [grant('g1', 'v', lteAmt(5000)), grant('g2', 'v', lteAmt(5000))], prohibits: [p1] });
const money = (n: number): Value => ({ k: 'q', q: usd(n) });

describe('boundaryExamples', () => {
  it('classifies each decision cell as prohibit_trigger, member or boundary with its exact reason, id and decision', () => {
    const { examples, complete } = boundaryExamples(BG, { ont: ONT0 });
    expect(complete).toBe(true);
    type Row = [string, string, string, Record<string, Value>, string];
    const rows: Row[] = [
      ['boundary', 'cell escalate', 'v', {}, 'escalate'],
      ['member', 'cell allow', 'v', { amount: money(4999) }, 'allow'],
      ['member', 'cell allow', 'v', { amount: money(5000) }, 'allow'],
      ['prohibit_trigger', 'cell deny', 'v', { amount: money(5001) }, 'deny'],
      ['boundary', 'cell deny', 'v', { amount: money(5002) }, 'deny'],
      ['boundary', 'cell escalate', 'v', { amount: ZZZ }, 'escalate'],
      ['boundary', 'cell deny', OV, {}, 'deny'],
      ['boundary', 'cell deny', OV, { amount: money(4999) }, 'deny'],
      ['boundary', 'cell deny', OV, { amount: money(5000) }, 'deny'],
      ['boundary', 'cell deny', OV, { amount: money(5001) }, 'deny'],
      ['boundary', 'cell deny', OV, { amount: money(5002) }, 'deny'],
      ['boundary', 'cell deny', OV, { amount: ZZZ }, 'deny'],
    ];
    expect(examples.slice(0, 12).map((e) => [e.kind, e.why, e.act.verb, e.act.params, e.decision])).toEqual(rows);
    for (const e of examples.slice(0, 12)) {
      expect(e.act.res).toBe(OR);
      expect(e.hist).toEqual(EMPTY_HIST);
      expect(e.rels).toEqual([]);
      expect(e.id).toBe(`${e.kind}:${hashCanonical({ act: e.act, hist: EMPTY_HIST, rels: [] }).slice(0, 12)}`);
      expect(e.id).toMatch(/^[a-z_]+:[A-Za-z0-9_-]{12}$/);
    }
  });

  it('adds a minimal Allow witness only for a grant that has one', () => {
    const { examples } = boundaryExamples(BG, { ont: ONT0 });
    const w = examples.filter((e) => e.kind === 'allow_witness');
    expect(w.map((e) => [e.why, e.act.verb, e.act.params, e.decision])).toEqual([
      ['minimal Allow witness of grant g1', 'v', { amount: money(4999) }, 'allow'],
    ]);
  });

  it('includes the extra verbs in the decision space, and none by default', () => {
    const verbsOf = (r: ReturnType<typeof boundaryExamples>): string[] => [...new Set(r.examples.map((e) => e.act.verb))].sort();
    expect(verbsOf(boundaryExamples(BG, { ont: ONT0 }))).toEqual([OV, 'v']);
    expect(verbsOf(boundaryExamples(BG, { ont: ONT0, verbs: ['w'] }))).toEqual([OV, 'v', 'w']);
  });

  it('never resolves an effect-class bound through the grant ids (no gids means no grant)', () => {
    // a grant whose gid equals the scratch string a mutated empty list would hold
    const gr = grant('Stryker was here', 'v', ctrue);
    const b: Bound = {
      bid: 'b1', sel: { k: 'effect', cls: 'x' }, agg: 'count', value: { k: 'lit', v: { k: 'q', q: { u: CNT, n: 1 } } }, key: '',
      window: { k: 'task' }, scope: { k: 'session' }, cap: { u: CNT, n: 3 }, onExceed: 'deny',
    };
    const g = baseGoal({ grants: [gr], bounds: [b] });
    const ont: Ontology = { verbs: [{ verb: 'v', cls: 'x', params: [] }], rels: [] };
    const { examples } = boundaryExamples(g, { ont });
    expect(examples.some((e) => e.kind === 'cap_sequence')).toBe(false);
    expect(examples.some((e) => e.kind === 'allow_witness')).toBe(true);
  });
});
