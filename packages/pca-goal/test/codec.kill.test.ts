import { describe, expect, it } from 'vitest';
import type { Tape, Tok } from '@atlasauth/pca-verified-core';
import { IrError, TapeReader, decodeGoal, decodePolicy, encCond, encTerm, encUnit, encV, encodeAct, encodeGoal, encodeHist } from '../src/codec';
import type { Act, Cond, Goal, Grant, Hist, Policy, ProhTarget, Sel, Term, Ty, Unit, Value, Window, Scope } from '../src/ir';

const K = (n: number): Tok => ['k', n];
const I = (n: number): Tok => ['i', n];
const S = (s: string): Tok => ['s', s];
/** A value of the wrong shape, to drive the strict encoder's refusals. */
const bogus = <T>(x: unknown): T => x as T;
/** The IrError message a call throws; any other outcome (no throw, another error type) fails the test. */
const msg = (f: () => unknown): string => {
  try {
    f();
  } catch (e) {
    if (e instanceof IrError) return e.message;
    throw e;
  }
  return 'did not throw';
};

const usd: Unit = { k: 'money', ccy: 'USD' };
const cnt: Unit = { k: 'count' };
const litS = (s: string): Term => ({ k: 'lit', v: { k: 's', s } });

const baseGoal: Goal = {
  v: 1, principal: 'p', ontDigest: 'o', nlDigest: 'n', sources: ['s1'],
  grants: [{ gid: 'g', verb: 'v', res: { k: 'any', reason: 'r' }, cond: { k: 'true' } }],
  prohibits: [{ pid: 'x', target: { k: 'effect', cls: 'c' }, res: { k: 'exact', id: 'e' }, cond: { k: 'true' } }],
  bounds: [{ bid: 'b', sel: { k: 'effect', cls: 'c' }, agg: 'distinct', value: litS('q'), key: 'k', window: { k: 'task' }, scope: { k: 'principal' }, cap: { u: { k: 'instant' }, n: 5 }, onExceed: 'escalate' }],
  validity: { notBefore: 1, notAfter: 2, maxIdle: 3 }, deleg: { maxDepth: 2, narrowOnly: true, mayTouch: ['m'] },
  escalateOn: [], wildcardAck: [], holes: [],
};

const rich: Goal = {
  v: 2, principal: 'user:a', ontDigest: 'od', nlDigest: 'nd', sources: [],
  grants: [
    {
      gid: 'g1', verb: 'pay.refund', res: { k: 'oneof', ids: ['a', 'b'] },
      cond: {
        k: 'and',
        a: {
          k: 'or',
          a: { k: 'not', c: { k: 'true' } },
          b: { k: 'cmp', op: 'in', l: { k: 'param', path: 'a.b', ty: { k: 'q', u: usd } }, r: { k: 'lit', v: { k: 'set', items: [{ k: 'q', q: { u: { k: 'ratio' }, n: -2 } }, { k: 's', s: 'z' }] } } },
        },
        b: { k: 'cmp', op: 'ne', l: { k: 'param', path: 't', ty: { k: 's' } }, r: { k: 'hist', bid: 'b', u: { k: 'bytes' } } },
      },
    },
    { gid: 'g2', verb: 'x.y', res: { k: 'related', rel: 'rel', anchor: 'anc' }, cond: { k: 'true' } },
    { gid: 'g3', verb: 'x.z', res: { k: 'all_of', parts: [{ k: 'exact', id: 'e' }, { k: 'oneof', ids: ['q'] }, { k: 'related', rel: 'r', anchor: 'a' }] }, cond: { k: 'true' } },
  ],
  prohibits: [{ pid: 'p1', target: { k: 'verb', verb: 'pay.transfer' }, res: { k: 'any', reason: 'never' }, cond: { k: 'true' } }],
  bounds: [
    { bid: 'b1', sel: { k: 'gids', gids: ['g1', 'g2'] }, agg: 'count', value: { k: 'lit', v: { k: 'q', q: { u: cnt, n: 1 } } }, key: '', window: { k: 'lifetime' }, scope: { k: 'org' }, cap: { u: cnt, n: 3 }, onExceed: 'deny' },
    { bid: 'b2', sel: { k: 'effect', cls: 'c' }, agg: 'sum', value: litS('v'), key: '', window: { k: 'period', ms: 5, t0: 6 }, scope: { k: 'fleet', agents: ['a1'] }, cap: { u: { k: 'duration' }, n: 9 }, onExceed: 'escalate' },
    { bid: 'b3', sel: { k: 'gids', gids: [] }, agg: 'max', value: litS('v'), key: '', window: { k: 'sliding', ms: 7 }, scope: { k: 'session' }, cap: { u: usd, n: 1 }, onExceed: 'deny' },
  ],
  validity: { notBefore: 0, notAfter: 9, maxIdle: 4 }, deleg: { maxDepth: 0, narrowOnly: false, mayTouch: [] },
  escalateOn: [{ k: 'true' }, { k: 'not', c: { k: 'true' } }], wildcardAck: ['g9'],
  holes: [{ hid: 'h1', q: 'which?', domain: ['a'], affects: ['g1'], global: true }, { hid: 'h2', q: 'q', domain: [], affects: [], global: false }],
};

const VALIDITY: Tok[] = [K(460), I(0), I(0), I(0)];
const DELEG: Tok[] = [K(461), I(0), I(0), I(0)];
const goalTape = (o: { grants?: Tok[]; prohibits?: Tok[]; bounds?: Tok[]; validity?: Tok[]; deleg?: Tok[]; rest?: Tok[]; extra?: Tok[] } = {}): Tape => [
  K(480), I(1), S('p'), S('o'), S('n'), I(0),
  ...(o.grants ?? [I(0)]), ...(o.prohibits ?? [I(0)]), ...(o.bounds ?? [I(0)]),
  ...(o.validity ?? VALIDITY), ...(o.deleg ?? DELEG), ...(o.rest ?? [I(0), I(0), I(0)]), ...(o.extra ?? []),
];
const decG = (t: Tape): string => msg(() => decodeGoal(t));
/** A one-bound goal tape: after the aggregate tag, `rest` carries term, key, window, scope, cap and on_exceed. */
const bnd = (...rest: Tok[]): Tape => goalTape({ bounds: [I(1), K(451), S('b'), K(410), I(0), K(450), K(400), ...rest] });
const OK_REST: Tok[] = [K(341), K(331), S('v'), S(''), K(420), K(430), K(301), I(1), K(440)];

describe('IrError', () => {
  it('names itself and prefixes its message', () => {
    const e = new IrError('boom');
    expect(e.name).toBe('IrError');
    expect(e.message).toBe('pca-goal: boom');
  });
});

describe('encoder: exact tapes', () => {
  it('encodes every unit tag', () => {
    expect(encUnit(usd)).toEqual([K(300), S('USD')]);
    expect(encUnit(cnt)).toEqual([K(301)]);
    expect(encUnit({ k: 'duration' })).toEqual([K(302)]);
    expect(encUnit({ k: 'instant' })).toEqual([K(303)]);
    expect(encUnit({ k: 'bytes' })).toEqual([K(304)]);
    expect(encUnit({ k: 'ratio' })).toEqual([K(305)]);
  });
  it('encodes a set of a quantity and a string', () => {
    const v: Value = { k: 'set', items: [{ k: 'q', q: { u: cnt, n: 3 } }, { k: 's', s: 'x' }] };
    expect(encV(v)).toEqual([K(332), I(2), K(320), K(301), I(3), K(321), S('x')]);
  });
  it('encodes operator indices and typed params', () => {
    const lit: Term = litS('a');
    expect(encCond({ k: 'cmp', op: 'nin', l: lit, r: lit })).toEqual([K(361), K(357), K(341), K(331), S('a'), K(341), K(331), S('a')]);
    expect(encTerm({ k: 'param', path: 'p', ty: { k: 'q', u: cnt } })).toEqual([K(340), S('p'), K(310), K(301)]);
    expect(encTerm({ k: 'param', path: 'p', ty: { k: 's' } })).toEqual([K(340), S('p'), K(311)]);
  });
  it('encodes a whole goal tag for tag', () => {
    expect(encodeGoal(baseGoal)).toEqual([
      K(480), I(1), S('p'), S('o'), S('n'), I(1), S('s1'),
      I(1), K(380), S('g'), S('v'), K(373), S('r'), K(360),
      I(1), K(392), S('x'), K(391), S('c'), K(370), S('e'), K(360),
      I(1), K(451), S('b'), K(411), S('c'), K(450), K(403), K(341), K(331), S('q'), S('k'), K(420), K(431), K(303), I(5), K(441),
      K(460), I(1), I(2), I(3), K(461), I(2), I(1), I(1), S('m'), I(0), I(0), I(0),
    ]);
  });
  it('sorts act params and hist aggregates by key', () => {
    const one: Value = { k: 'q', q: { u: cnt, n: 1 } };
    const act: Act = { verb: 'v', res: 'r', params: { b: one, a: one }, t: 4, sess: 's', prin: 'p', org: 'o', agent: 'g', depth: 2 };
    expect(encodeAct(act)).toEqual([K(530), S('v'), S('r'), I(2), K(520), S('a'), K(330), K(301), I(1), K(520), S('b'), K(330), K(301), I(1), I(4), S('s'), S('p'), S('o'), S('g'), I(2)]);
    const hist: Hist = { adms: [], last: -1, aggs: { b: { u: cnt, n: 2 }, a: { u: usd, n: 1 } } };
    expect(encodeHist(hist)).toEqual([K(541), I(0), I(-1), I(2), K(540), S('a'), K(300), S('USD'), I(1), K(540), S('b'), K(301), I(2)]);
  });
});

describe('encoder: strict refusals', () => {
  it('refuses a non-string, a non-array and unknown discriminants with the exact message', () => {
    expect(msg(() => encV({ k: 's', s: bogus<string>(5) }))).toBe('pca-goal: string expected');
    expect(msg(() => encodeGoal({ ...baseGoal, grants: bogus<Grant[]>('x') }))).toBe('pca-goal: array expected');
    expect(msg(() => encV({ k: 'set', items: [bogus<Value>({ k: 'set', items: [] })] }))).toBe('pca-goal: unknown set member (sets hold quantities and strings only): {"k":"set","items":[]}');
    expect(msg(() => encTerm({ k: 'param', path: 'p', ty: bogus<Ty>({ k: 'z' }) }))).toBe('pca-goal: unknown type: {"k":"z"}');
    expect(msg(() => encCond({ k: 'cmp', op: bogus<'eq'>('zz'), l: litS('a'), r: litS('a') }))).toBe('pca-goal: unknown operator: "zz"');
    const target = bogus<ProhTarget>({ k: 'z' });
    expect(msg(() => encodeGoal({ ...baseGoal, prohibits: [{ pid: 'x', target, res: { k: 'exact', id: 'e' }, cond: { k: 'true' } }] }))).toBe('pca-goal: unknown prohibit target: {"k":"z"}');
    const b0 = baseGoal.bounds[0]!;
    const withBound = (o: Partial<typeof b0>): Goal => ({ ...baseGoal, bounds: [{ ...b0, ...o }] });
    expect(msg(() => encodeGoal(withBound({ sel: bogus<Sel>({ k: 'z' }) })))).toBe('pca-goal: unknown selection: {"k":"z"}');
    expect(msg(() => encodeGoal(withBound({ agg: bogus<'count'>('zz') })))).toBe('pca-goal: unknown aggregate: "zz"');
    expect(msg(() => encodeGoal(withBound({ onExceed: bogus<'deny'>('zz') })))).toBe('pca-goal: unknown on_exceed: "zz"');
  });
});

describe('tape reader', () => {
  it('refuses a truncated tape, wrong token kinds and a negative length', () => {
    expect(msg(() => new TapeReader([]).next())).toBe('pca-goal: truncated tape');
    expect(msg(() => new TapeReader([S('x')]).k())).toBe('pca-goal: keyword expected');
    expect(msg(() => new TapeReader([K(1)]).int())).toBe('pca-goal: integer expected');
    expect(msg(() => new TapeReader([K(1)]).str())).toBe('pca-goal: string expected');
    expect(msg(() => new TapeReader([I(-1)]).list(() => 1))).toBe('pca-goal: negative length');
  });
  it('reports done only at the end of the tape', () => {
    const r = new TapeReader([K(1)]);
    expect(r.done()).toBe(false);
    r.k();
    expect(r.done()).toBe(true);
    expect(new TapeReader([]).done()).toBe(true);
  });
});

describe('goal decoding', () => {
  it('round-trips an exact goal and a goal using every variant', () => {
    expect(decodeGoal(encodeGoal(baseGoal))).toEqual(baseGoal);
    expect(decodeGoal(encodeGoal(rich))).toEqual(rich);
  });
  it('decodes a minimal goal tape and refuses a trailing token', () => {
    expect(decG(goalTape({ extra: [I(0)] }))).toBe('pca-goal: trailing tokens after goal');
    expect(decodeGoal(goalTape()).deleg).toEqual({ maxDepth: 0, narrowOnly: false, mayTouch: [] });
  });
  it('names the expected section when a tag is wrong', () => {
    expect(decG([K(481)])).toBe('pca-goal: goal expected');
    expect(decG(goalTape({ grants: [I(1), K(381)] }))).toBe('pca-goal: grant expected');
    expect(decG(goalTape({ prohibits: [I(1), K(393)] }))).toBe('pca-goal: prohibit expected');
    expect(decG(goalTape({ bounds: [I(1), K(452)] }))).toBe('pca-goal: bound expected');
    expect(decG(goalTape({ bounds: [I(1), K(451), S('b'), K(410), I(0), K(451)] }))).toBe('pca-goal: bound core expected');
    expect(decG(goalTape({ validity: [K(461)] }))).toBe('pca-goal: validity expected');
    expect(decG(goalTape({ deleg: [K(460)] }))).toBe('pca-goal: delegation expected');
    expect(decG(goalTape({ rest: [I(0), I(0), I(1), K(471)] }))).toBe('pca-goal: hole expected');
  });
  it('refuses unknown tags with the tag in the message', () => {
    const g = (...rest: Tok[]): Tok[] => [I(1), K(380), S('g'), S('v'), ...rest];
    expect(decG(goalTape({ rest: [I(1), K(365), I(0), I(0)] }))).toBe('pca-goal: bad condition tag 365');
    expect(decG(goalTape({ grants: g(K(375)) }))).toBe('pca-goal: bad resource selector tag 375');
    expect(decG(goalTape({ grants: g(K(374), I(1), K(378)) }))).toBe('pca-goal: bad resource part tag 378');
    expect(decG(goalTape({ prohibits: [I(1), K(392), S('x'), K(393)] }))).toBe('pca-goal: bad prohibit target');
    expect(decG(goalTape({ bounds: [I(1), K(451), S('b'), K(412)] }))).toBe('pca-goal: bad selection');
    expect(decG(bnd(K(343)))).toBe('pca-goal: bad term tag 343');
    expect(decG(bnd(K(340), S('p'), K(312)))).toBe('pca-goal: bad type tag 312');
    expect(decG(bnd(K(341), K(333)))).toBe('pca-goal: bad value tag 333');
    expect(decG(bnd(K(341), K(332), I(1), K(322)))).toBe('pca-goal: bad atom tag 322');
    expect(decG(bnd(K(341), K(331), S('v'), S(''), K(424)))).toBe('pca-goal: bad window tag 424');
    expect(decG(bnd(K(341), K(331), S('v'), S(''), K(420), K(434)))).toBe('pca-goal: bad scope tag 434');
    expect(decG(bnd(K(341), K(331), S('v'), S(''), K(420), K(430), K(399)))).toBe('pca-goal: bad unit tag 399');
    expect(decG(bnd(...OK_REST.slice(0, -1), K(442)))).toBe('pca-goal: bad on_exceed');
    expect(decG(goalTape({ bounds: [I(1), K(451), S('b'), K(410), I(0), K(450), K(404)] }))).toBe('pca-goal: bad aggregate');
  });
  it('decodes every unit and both on_exceed values of a bound', () => {
    const tail = (u: Tok[], oe: number): Tape => bnd(K(341), K(331), S('v'), S(''), K(420), K(430), ...u, I(1), K(oe));
    const cap = (t: Tape): unknown => decodeGoal(t).bounds[0]?.cap;
    expect(cap(tail([K(300), S('EUR')], 440))).toEqual({ u: { k: 'money', ccy: 'EUR' }, n: 1 });
    for (const [tag, k] of [[301, 'count'], [302, 'duration'], [303, 'instant'], [304, 'bytes'], [305, 'ratio']] as const) {
      expect(cap(tail([K(tag)], 441))).toEqual({ u: { k }, n: 1 });
    }
    expect(decodeGoal(tail([K(301)], 440)).bounds[0]?.onExceed).toBe('deny');
    expect(decodeGoal(tail([K(301)], 441)).bounds[0]?.onExceed).toBe('escalate');
  });
});

describe('policy decoding', () => {
  const ZERO: Tok[] = [I(0)];
  const pol = (o: { preds?: Tok[]; prohs?: Tok[]; ceils?: Tok[]; escs?: Tok[]; extra?: Tok[] } = {}): Tape => [
    K(650), ...(o.preds ?? ZERO), ...(o.prohs ?? ZERO), ...(o.ceils ?? ZERO), ...(o.escs ?? ZERO), ...VALIDITY, ...DELEG, ...(o.extra ?? []),
  ];
  const atom: Tok[] = [K(602), K(352), K(340), S('x'), K(310), K(300), S('USD'), K(341), K(330), K(300), S('USD'), I(7)];
  const ceil = (oe: number, agg: number, window: Tok[], scope: Tok[], unit: number): Tok[] => [
    K(610), S('b1'), I(1), S('g1'), I(1), S('v1'), K(450), K(agg), K(341), K(331), S('val'), S('k'), ...window, ...scope, K(unit), I(9), K(oe),
  ];

  it('decodes an empty policy', () => {
    const empty: Policy = { preds: [], prohs: [], ceils: [], escs: [], validity: { notBefore: 0, notAfter: 0, maxIdle: 0 }, deleg: { maxDepth: 0, narrowOnly: false, mayTouch: [] } };
    expect(decodePolicy(pol())).toEqual(empty);
  });
  it('decodes predicates, prohibitions, ceilings and escalation conditions exactly', () => {
    const t = pol({
      preds: [I(1), K(620), S('g'), S('v'), K(630), K(603), K(601), K(604), K(600), ...atom],
      prohs: [I(1), K(640), S('p'), I(1), S('v'), K(631), I(1), S('r'), K(600)],
      ceils: [I(2),
        ...ceil(440, 402, [K(422), I(5), I(6)], [K(433), I(1), S('ag')], 305),
        ...ceil(441, 400, [K(421), I(3)], [K(432)], 304)],
      escs: [I(1), K(604), K(600), K(601)],
    });
    const atomC = {
      k: 'atom', op: 'lt',
      l: { k: 'param', path: 'x', ty: { k: 'q', u: { k: 'money', ccy: 'USD' } } },
      r: { k: 'lit', v: { k: 'q', q: { u: { k: 'money', ccy: 'USD' }, n: 7 } } },
    };
    const p = decodePolicy(t);
    expect(p.preds).toEqual([{ gid: 'g', verb: 'v', res: { k: 'star' }, cond: { k: 'and', a: { k: 'false' }, b: { k: 'or', a: { k: 'true' }, b: atomC } } }]);
    expect(p.prohs).toEqual([{ pid: 'p', verbs: ['v'], res: { k: 'set', ids: ['r'] }, cond: { k: 'true' } }]);
    const base = { bid: 'b1', selGids: ['g1'], selVerbs: ['v1'], key: 'k', value: litS('val') };
    expect(p.ceils).toEqual([
      { ...base, agg: 'max', window: { k: 'period', ms: 5, t0: 6 }, scope: { k: 'fleet', agents: ['ag'] }, cap: { u: { k: 'ratio' }, n: 9 }, onExceed: 'deny' },
      { ...base, agg: 'count', window: { k: 'sliding', ms: 3 }, scope: { k: 'org' }, cap: { u: { k: 'bytes' }, n: 9 }, onExceed: 'escalate' },
    ]);
    expect(p.escs).toEqual([{ k: 'or', a: { k: 'true' }, b: { k: 'false' } }]);
  });
  it('decodes narrowOnly from a one', () => {
    const t = pol({ extra: [] }).slice(0, -4);
    expect(decodePolicy([...t, K(461), I(3), I(1), I(1), S('m')]).deleg).toEqual({ maxDepth: 3, narrowOnly: true, mayTouch: ['m'] });
  });
  it('refuses a trailing token and unknown tags', () => {
    expect(msg(() => decodePolicy(pol({ extra: [I(0)] })))).toBe('pca-goal: trailing tokens after policy');
    expect(msg(() => decodePolicy(pol({ escs: [I(1), K(605)] })))).toBe('pca-goal: bad condition tag 605');
    expect(msg(() => decodePolicy(pol({ preds: [I(1), K(620), S('g'), S('v'), K(632)] })))).toBe('pca-goal: bad resource pattern tag 632');
    expect(msg(() => decodePolicy(pol({ ceils: [I(1), K(610), S('b'), I(0), I(0), K(450), K(404)] })))).toBe('pca-goal: bad aggregate');
    const oe = (n: number): Tok[] => [I(1), K(610), S('b'), I(0), I(0), K(450), K(400), K(341), K(331), S('v'), S(''), K(420), K(430), K(301), I(1), K(n)];
    expect(msg(() => decodePolicy(pol({ ceils: oe(442) })))).toBe('pca-goal: bad on_exceed');
  });
});

describe('exact messages of the default branches', () => {
  const z = { k: 'z' };
  const grantRes = (res: unknown): Goal => ({ ...baseGoal, grants: [{ gid: 'g', verb: 'v', res: bogus<Grant['res']>(res), cond: { k: 'true' } }] });
  const b0 = baseGoal.bounds[0]!;
  const withBound = (o: Partial<typeof b0>): Goal => ({ ...baseGoal, bounds: [{ ...b0, ...o }] });
  it('refuses an unknown discriminant with the exact word and value', () => {
    expect(msg(() => encUnit(bogus<Unit>(z)))).toBe('pca-goal: unknown unit: {"k":"z"}');
    expect(msg(() => encV(bogus<Value>(z)))).toBe('pca-goal: unknown value: {"k":"z"}');
    expect(msg(() => encTerm(bogus<Term>(z)))).toBe('pca-goal: unknown term: {"k":"z"}');
    expect(msg(() => encCond(bogus<Cond>(z)))).toBe('pca-goal: unknown condition: {"k":"z"}');
    expect(msg(() => encodeGoal(grantRes({ k: 'all_of', parts: [z] })))).toBe('pca-goal: unknown resource part: {"k":"z"}');
    expect(msg(() => encodeGoal(grantRes(z)))).toBe('pca-goal: unknown resource selector: {"k":"z"}');
    expect(msg(() => encodeGoal(withBound({ window: bogus<Window>(z) })))).toBe('pca-goal: unknown window: {"k":"z"}');
    expect(msg(() => encodeGoal(withBound({ scope: bogus<Scope>(z) })))).toBe('pca-goal: unknown scope: {"k":"z"}');
  });
  it('names the expected token when a tape is malformed', () => {
    expect(msg(() => decodeGoal(goalTape({ rest: [I(1), K(361), K(349)] })))).toBe('pca-goal: bad operator');
    expect(msg(() => decodePolicy([K(651)]))).toBe('pca-goal: policy expected');
    expect(msg(() => decodePolicy([K(650), I(1), K(621)]))).toBe('pca-goal: pred');
    expect(msg(() => decodePolicy([K(650), I(0), I(1), K(641)]))).toBe('pca-goal: prohibition');
    expect(msg(() => decodePolicy([K(650), I(0), I(0), I(1), K(611)]))).toBe('pca-goal: ceiling expected');
    expect(msg(() => decodePolicy([K(650), I(0), I(0), I(1), K(610), S('b'), I(0), I(0), K(451)]))).toBe('pca-goal: bound core expected');
    expect(msg(() => decodePolicy([K(650), I(0), I(0), I(0), I(0), K(461)]))).toBe('pca-goal: validity');
    expect(msg(() => decodePolicy([K(650), I(0), I(0), I(0), I(0), ...VALIDITY, K(460)]))).toBe('pca-goal: delegation');
  });
});
