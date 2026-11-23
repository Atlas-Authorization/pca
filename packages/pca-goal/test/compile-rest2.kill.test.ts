import { describe, expect, it } from 'vitest';
import { calibrate } from '../src/crc';
import type { Act, Cond, Goal, Hist, Op, Ontology, Term, Value } from '../src/ir';
import { canonicalizeGoal, stable } from '../src/normalize';
import type { IntentOntology } from '../src/ontology';
import { refExplain } from '../src/refsem';
import { lexicalComparator } from '../src/roundtrip';

const U = { k: 'count' } as const;
const q = (n: number): Value => ({ k: 'q', q: { u: U, n } });
const str = (s: string): Value => ({ k: 's', s });
const lit = (v: Value): Term => ({ k: 'lit', v });
const param = (path: string): Term => ({ k: 'param', path, ty: { k: 'q', u: U } });
const any = { k: 'any', reason: 'x' } as const;
const ont: Ontology = { verbs: [{ verb: 'v', cls: 'c', params: [] }], rels: [] };
const act = (o: Partial<Act> = {}): Act => ({ verb: 'v', res: 'r', params: {}, t: 100, sess: 's', prin: 'p', org: 'o', agent: 'a1', depth: 0, ...o });
const none: Hist = { adms: [], last: -1, aggs: {} };
const goal = (o: Partial<Goal> = {}): Goal => ({
  v: 1, principal: 'p', ontDigest: 'o', nlDigest: 'n', sources: [],
  grants: [{ gid: 'g', verb: 'v', res: any, cond: { k: 'true' } }], prohibits: [],
  bounds: [], validity: { notBefore: 0, notAfter: 1_000_000, maxIdle: 0 }, deleg: { maxDepth: 1, narrowOnly: true, mayTouch: ['g'] },
  escalateOn: [], wildcardAck: [], holes: [], ...o,
});
const cmp = (op: Op, l: Term, r: Term): Cond => ({ k: 'cmp', op, l, r });
const withCond = (cond: Cond): Goal => goal({ grants: [{ gid: 'g', verb: 'v', res: any, cond }] });
const decide = (g: Goal, a: Act = act(), o: Ontology = ont): 0 | 1 | 2 => refExplain(g, o, a, none).d;

describe('stable', () => {
  it('scalars and null are plain JSON', () => {
    expect(stable(null)).toBe('null');
    expect(stable(5)).toBe('5');
    expect(stable('x')).toBe('"x"');
    expect(stable(true)).toBe('true');
  });
  it('arrays keep order and join with commas', () => {
    expect(stable([1, 'a', null])).toBe('[1,"a",null]');
    expect(stable([])).toBe('[]');
  });
  it('objects sort their keys, drop undefined values and recurse', () => {
    expect(stable({ b: [1, { d: 1, c: 2 }], a: null, z: undefined })).toBe('{"a":null,"b":[1,{"c":2,"d":1}]}');
    expect(stable({})).toBe('{}');
  });
});

describe('canonicalizeGoal', () => {
  const hole = (hid: string): Goal['holes'][number] => ({ hid, q: 'q', domain: [], affects: [], global: false });
  it('sorts holes, wildcard acknowledgements and mayTouch, and keeps duplicate ids in input order', () => {
    const out = canonicalizeGoal(goal({
      grants: [{ gid: 'g', verb: 'v1', res: any, cond: { k: 'true' } }, { gid: 'g', verb: 'v2', res: any, cond: { k: 'true' } }],
      holes: [hole('h2'), hole('h1')],
      wildcardAck: ['b', 'a', 'b'],
      deleg: { maxDepth: 2, narrowOnly: true, mayTouch: ['z', 'y', 'z'] },
    }));
    expect(out.grants.map((x) => x.verb)).toEqual(['v1', 'v2']);
    expect(out.holes.map((h) => h.hid)).toEqual(['h1', 'h2']);
    expect(out.wildcardAck).toEqual(['a', 'b']);
    expect(out.deleg).toEqual({ maxDepth: 2, narrowOnly: true, mayTouch: ['y', 'z'] });
  });
});

describe('calibrate', () => {
  it('rejects losses that are not nonincreasing, naming the case and level', () => {
    expect(() => calibrate([[0, 1]], { a: 1, b: 10 })).toThrow('loss is not nonincreasing in the threshold (case 0, level 1)');
  });
  it('accepts a level whose corrected risk equals alpha exactly', () => {
    const rows = Array.from({ length: 9 }, () => [0]);
    expect(calibrate(rows, { a: 1, b: 10 })).toEqual({ level: 0, n: 9, feasible: true, correctedRisk: 0.1, minN: 9 });
  });
});

describe('refsem string comparison and set membership', () => {
  it('text against a quantity is unknown whichever side the text is on', () => {
    expect(decide(withCond(cmp('eq', lit(str('a')), lit(q(1)))))).toBe(1);
  });
  it('two texts compare by value', () => {
    expect(decide(withCond(cmp('eq', lit(str('a')), lit(str('a')))))).toBe(2);
    expect(decide(withCond(cmp('eq', lit(str('a')), lit(str('b')))))).toBe(0);
    expect(decide(withCond(cmp('ne', lit(str('a')), lit(str('b')))))).toBe(2);
  });
  it('in and nin against something that is not a set are unknown', () => {
    expect(decide(withCond(cmp('in', lit(q(1)), lit(q(2)))))).toBe(1);
    expect(decide(withCond(cmp('nin', lit(q(1)), lit(q(2)))))).toBe(1);
  });
});

describe('refsem related selectors', () => {
  const o: Ontology = {
    verbs: ont.verbs,
    rels: [
      { rel: 'r1', anchor: 'a9', members: ['mq'] },
      { rel: 'r2', anchor: 'a1', members: ['mz'] },
      { rel: 'r1', anchor: 'a1', members: ['m1'] },
    ],
  };
  const g = goal({ grants: [{ gid: 'g', verb: 'v', res: { k: 'related', rel: 'r1', anchor: 'a1' }, cond: { k: 'true' } }] });
  it('uses the relation matching both the name and the anchor', () => {
    expect(decide(g, act({ res: 'm1' }), o)).toBe(2);
    expect(decide(g, act({ res: 'mq' }), o)).toBe(0);
    expect(decide(g, act({ res: 'mz' }), o)).toBe(0);
  });
});

describe('refsem prohibitions', () => {
  const proh = (target: Goal['prohibits'][number]['target'], cond: Cond): Goal => goal({ prohibits: [{ pid: 'p', target, res: any, cond }] });
  const t: Cond = { k: 'true' };
  it('a firing prohibition denies, by verb or by effect class, and hides the witness', () => {
    expect(refExplain(proh({ k: 'verb', verb: 'v' }, t), ont, act(), none)).toEqual({ d: 0, witness: null, prohibit: 0 });
    expect(refExplain(proh({ k: 'effect', cls: 'c' }, t), ont, act(), none)).toEqual({ d: 0, witness: null, prohibit: 0 });
  });
  it('an unknown prohibition makes the decision unknown', () => {
    expect(refExplain(proh({ k: 'verb', verb: 'v' }, cmp('eq', lit(q(1)), lit(str('a')))), ont, act(), none)).toEqual({ d: 1, witness: null, prohibit: 1 });
  });
  it('a prohibition that does not apply leaves the allow and its witness', () => {
    expect(refExplain(proh({ k: 'verb', verb: 'other' }, t), ont, act(), none)).toEqual({ d: 2, witness: 'g', prohibit: 2 });
    expect(refExplain(goal(), ont, act(), none)).toEqual({ d: 2, witness: 'g', prohibit: 2 });
  });
});

describe('refsem witness and bound values', () => {
  it('the witness is the first allowing grant', () => {
    const g = goal({ grants: [{ gid: 'g1', verb: 'v', res: any, cond: { k: 'true' } }, { gid: 'g2', verb: 'v', res: any, cond: { k: 'true' } }] });
    expect(refExplain(g, ont, act(), none)).toEqual({ d: 2, witness: 'g1', prohibit: 2 });
  });
  it('a sum bound over a non-quantity value is unknown, not a crash', () => {
    const g = goal({
      bounds: [{ bid: 'b', sel: { k: 'gids', gids: ['g'] }, agg: 'sum', value: param('amt'), key: '', window: { k: 'lifetime' }, scope: { k: 'session' }, cap: { u: U, n: 5 }, onExceed: 'deny' }],
    });
    expect(decide(g, act({ params: { amt: str('x') } }))).toBe(1);
  });
});

describe('lexicalComparator identity', () => {
  it('is named lexical, in the rule family', () => {
    const o: IntentOntology = { id: 't', version: 1, domain: 'd', types: [{ id: 'customer', id_prefix: 'cus_' }], units: {}, relations: [], verbs: [], aliases: {}, templates: [] };
    const c = lexicalComparator(o);
    expect(c.id).toBe('lexical');
    expect(c.family).toBe('rule');
  });
});
