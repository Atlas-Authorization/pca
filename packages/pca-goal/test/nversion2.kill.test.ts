import { describe, expect, it } from 'vitest';
import type { Reading } from '../src/disambiguate';
import type { Bound, Goal, Grant, Hole, Prohibit } from '../src/ir';
import { meet, meetGrants, nVersion } from '../src/nversion';
import { ONT, baseGoal, ctrue, lteAmt } from './fixtures';

const shell: Goal = {
  v: 1, principal: 'p', ontDigest: 'o', nlDigest: 'n', sources: [], grants: [], prohibits: [], bounds: [],
  validity: { notBefore: 0, notAfter: 1_000, maxIdle: 0 }, deleg: { maxDepth: 1, narrowOnly: true, mayTouch: [] },
  escalateOn: [], wildcardAck: [], holes: [],
};
const goal = (over: Partial<Goal>): Goal => ({ ...shell, ...over });
const grant = (gid: string, verb: string, res: Grant['res'], cond: Grant['cond'] = ctrue): Grant => ({ gid, verb, res, cond });
const exact = (id: string): Grant['res'] => ({ k: 'exact', id });
const wild = (reason: string): Grant['res'] => ({ k: 'any', reason });
const bound = (over: Partial<Bound> = {}): Bound => ({
  bid: 'b1', sel: { k: 'effect', cls: 'c' }, agg: 'count', value: { k: 'lit', v: { k: 'q', q: { u: { k: 'count' }, n: 1 } } }, key: '',
  window: { k: 'task' }, scope: { k: 'principal' }, cap: { u: { k: 'count' }, n: 1 }, onExceed: 'deny', ...over,
});
const one = (a: Grant, b: Grant): Grant[] => meetGrants([a], [b]);

describe('resource intersection and condition conjunction', () => {
  it('flattens an all_of operand, drops duplicates and unwraps a single remaining part', () => {
    const nested = grant('x', 'v', { k: 'all_of', parts: [{ k: 'exact', id: 'e1' }, { k: 'exact', id: 'e2' }] });
    expect(one(nested, grant('y', 'v', exact('e3')))[0]!.res).toStrictEqual({ k: 'all_of', parts: [{ k: 'exact', id: 'e1' }, { k: 'exact', id: 'e2' }, { k: 'exact', id: 'e3' }] });
    expect(one(grant('x', 'v', exact('e')), grant('y', 'v', exact('e')))[0]!.res).toStrictEqual({ k: 'exact', id: 'e' });
  });
  it('a wildcard operand yields the other operand unchanged', () => {
    const single = (): Grant['res'] => ({ k: 'all_of', parts: [{ k: 'exact', id: 'e' }] });
    expect(one(grant('x', 'v', wild('ra')), grant('y', 'v', single()))[0]!.res).toStrictEqual({ k: 'all_of', parts: [{ k: 'exact', id: 'e' }] });
    expect(one(grant('x', 'v', single()), grant('y', 'v', wild('rb')))[0]!.res).toStrictEqual({ k: 'all_of', parts: [{ k: 'exact', id: 'e' }] });
    expect(one(grant('x', 'v', wild('ra')), grant('y', 'v', wild('rb')))[0]!.res).toStrictEqual({ k: 'any', reason: 'rb' });
  });
  it('conjoins conditions, skipping a true operand on either side', () => {
    const l1 = lteAmt(1);
    const l2 = lteAmt(2);
    expect(one(grant('x', 'v', exact('e'), ctrue), grant('y', 'v', exact('e'), l2))[0]!.cond).toStrictEqual(l2);
    expect(one(grant('x', 'v', exact('e'), l1), grant('y', 'v', exact('e'), ctrue))[0]!.cond).toStrictEqual(l1);
    expect(one(grant('x', 'v', exact('e'), l1), grant('y', 'v', exact('e'), l2))[0]!.cond).toStrictEqual({ k: 'and', a: l1, b: l2 });
  });
});

describe('meet field kills', () => {
  it('a single reading is returned as is, not rebuilt', () => {
    const g = goal({ grants: [grant('g2', 'v', wild('r')), grant('g1', 'v', exact('e'))], wildcardAck: ['g2', 'g2'] });
    expect(meet([g])).toBe(g);
  });
  it('an identical prohibition in two readings is kept once', () => {
    const pr: Prohibit = { pid: 'p1', target: { k: 'verb', verb: 'a' }, res: wild('r'), cond: ctrue };
    expect(meet([goal({ prohibits: [pr] }), goal({ prohibits: [{ ...pr }] })]).prohibits).toStrictEqual([pr]);
  });
  it('a bound over derived grants lists them sorted; a bound with no derived grant is dropped', () => {
    const g0 = goal({ grants: [grant('g2', 'v', exact('e')), grant('g1', 'v', exact('e'))], bounds: [bound({ sel: { k: 'gids', gids: ['g1', 'g2'] } })] });
    const g1 = goal({ grants: [grant('h', 'v', exact('e'))] });
    expect(meet([g0, g1]).bounds).toStrictEqual([bound({ sel: { k: 'gids', gids: ['g1&h', 'g2&h'] } })]);
    const lone = goal({ grants: [grant('g1', 'v', exact('e'))], bounds: [bound({ sel: { k: 'gids', gids: ['g1'] } }), bound({ bid: 'b2', sel: { k: 'gids', gids: ['zz'] } })] });
    const other = goal({ grants: [grant('h', 'w', exact('e'))] });
    expect(meet([lone, other]).bounds).toStrictEqual([]);
  });
  it('equal caps keep the first reading cap object; a smaller cap replaces it', () => {
    const c0 = { u: { k: 'count' as const }, n: 2 };
    const m = meet([goal({ bounds: [bound({ cap: c0 })] }), goal({ bounds: [bound({ cap: { u: { k: 'count' }, n: 2 } })] })]);
    expect(m.bounds).toHaveLength(1);
    expect(m.bounds[0]!.cap).toBe(c0);
  });
  it('the exceed action is deny when any reading denies, else stays as is', () => {
    const exceed = (a: Bound['onExceed'], b: Bound['onExceed']): Bound['onExceed'] =>
      meet([goal({ bounds: [bound({ onExceed: a })] }), goal({ bounds: [bound({ onExceed: b })] })]).bounds[0]!.onExceed;
    expect(exceed('escalate', 'deny')).toBe('deny');
    expect(exceed('deny', 'escalate')).toBe('deny');
    expect(exceed('escalate', 'escalate')).toBe('escalate');
    expect(exceed('deny', 'deny')).toBe('deny');
  });
  it('bounds with different ids that count different things keep their ids', () => {
    const m = meet([goal({ bounds: [bound()] }), goal({ bounds: [bound({ bid: 'b2', agg: 'sum' })] })]);
    expect(m.bounds).toStrictEqual([bound(), bound({ bid: 'b2', agg: 'sum' })]);
  });
  it('escalation conditions are the union of the readings', () => {
    const l1 = lteAmt(1);
    const l2 = lteAmt(2);
    const l3 = lteAmt(3);
    expect(meet([goal({ escalateOn: [l1, l2] }), goal({ escalateOn: [l2, l3] })]).escalateOn).toStrictEqual([l1, l2, l3]);
  });
  it('the idle limit ignores readings with no limit', () => {
    const idle = (n: number): Goal => goal({ validity: { notBefore: 0, notAfter: 1_000, maxIdle: n } });
    expect(meet([idle(0), idle(10)]).validity.maxIdle).toBe(10);
    expect(meet([idle(10), idle(0)]).validity.maxIdle).toBe(10);
    expect(meet([idle(0), idle(0)]).validity.maxIdle).toBe(0);
  });
  it('validity, depth and sources combine strictly', () => {
    const a = goal({ sources: ['s1', 's2'], validity: { notBefore: 5, notAfter: 1_000, maxIdle: 0 }, deleg: { maxDepth: 1, narrowOnly: false, mayTouch: [] } });
    const b = goal({ sources: ['s2', 's3'], validity: { notBefore: 10, notAfter: 2_000, maxIdle: 0 }, deleg: { maxDepth: 3, narrowOnly: false, mayTouch: [] } });
    const m = meet([a, b]);
    expect(m.sources).toStrictEqual(['s1', 's2', 's3']);
    expect(m.validity).toStrictEqual({ notBefore: 10, notAfter: 1_000, maxIdle: 0 });
    expect(m.deleg).toStrictEqual({ maxDepth: 1, narrowOnly: true, mayTouch: [] });
  });
  it('a merged grant may be touched only when every reading allows touching its source', () => {
    const g0 = goal({ grants: [grant('a', 'v', exact('e')), grant('b', 'v', exact('e'))], deleg: { maxDepth: 1, narrowOnly: true, mayTouch: ['a'] } });
    const g1 = goal({ grants: [grant('c', 'v', exact('e')), grant('d', 'v', exact('e'))], deleg: { maxDepth: 1, narrowOnly: true, mayTouch: ['c'] } });
    expect(meet([g0, g1]).deleg.mayTouch).toStrictEqual(['a&c']);
  });
  it('a merged grant that is not a wildcard is never acknowledged', () => {
    const g0 = goal({ grants: [grant('a', 'v', wild('r'))], wildcardAck: ['a'] });
    const g1 = goal({ grants: [grant('b', 'v', exact('e'))], wildcardAck: [] });
    expect(meet([g0, g1]).wildcardAck).toStrictEqual([]);
  });
  it('holes merge by id: affected grants re-derived and sorted, global sticky, later text wins', () => {
    const hole = (hid: string, q: string, affects: string[], global: boolean, domain: string[] = []): Hole => ({ hid, q, domain, affects, global });
    const g0 = goal({
      grants: [grant('b', 'v', exact('e')), grant('a', 'v', exact('e'))],
      holes: [hole('h1', 'q1', ['a', 'b'], false, ['d']), hole('h2', 'q2', [], true), hole('h3', 'q3a', ['a'], true)],
    });
    const g1 = goal({ grants: [grant('c', 'v', exact('e'))], holes: [hole('h3', 'q3b', ['c'], false)] });
    expect(meet([g0, g1]).holes).toStrictEqual([
      hole('h1', 'q1', ['a&c', 'b&c'], false, ['d']),
      hole('h2', 'q2', [], true),
      hole('h3', 'q3b', ['a&c', 'b&c'], true),
    ]);
  });
});

describe('n-version disagreement holes', () => {
  const reading = (id: string, deterministic: boolean, g: Goal): Reading => ({ id, family: id, deterministic, goal: g, notes: [] });
  it('names, in sorted order, each verb only some readings allow', () => {
    const read = grant('g3', 'pay.read', wild('read anything'));
    const r1 = baseGoal({
      grants: [
        grant('g1', 'pay.transfer', { k: 'oneof', ids: ['ch_1'] }, lteAmt(100)),
        grant('g2', 'pay.refund', { k: 'related', rel: 'charges_of', anchor: 'C1' }, lteAmt(5000)),
        read,
      ],
      deleg: { maxDepth: 2, narrowOnly: true, mayTouch: [] }, wildcardAck: ['g3'],
    });
    const r2 = baseGoal({ grants: [read], deleg: { maxDepth: 2, narrowOnly: true, mayTouch: [] }, wildcardAck: ['g3'] });
    const out = nVersion([reading('a', true, r1), reading('b', false, r2)], { ont: ONT, massThreshold: 1 });
    const verbHole = (v: string): Hole => ({ hid: `nv:verb:${v}`, q: `Only some readings allow "${v}". Should it be allowed at all?`, domain: [], affects: [], global: false });
    expect(out.disagreementHoles).toStrictEqual([verbHole('pay.refund'), verbHole('pay.transfer')]);
    expect(out.merged.holes).toStrictEqual([verbHole('pay.refund'), verbHole('pay.transfer')]);
    expect(out.signable).toBe(false);
  });
});
