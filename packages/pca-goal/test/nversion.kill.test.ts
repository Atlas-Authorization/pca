import { describe, expect, it } from 'vitest';
import type { Reading } from '../src/disambiguate';
import type { Bound, Goal, Grant, Prohibit } from '../src/ir';
import { checkPanel, meet, meetGrants, nVersion } from '../src/nversion';
import { ONT, baseGoal, ctrue } from './fixtures';

const shell: Goal = {
  v: 1, principal: 'p', ontDigest: 'o', nlDigest: 'n', sources: [], grants: [], prohibits: [], bounds: [],
  validity: { notBefore: 0, notAfter: 1_000, maxIdle: 0 }, deleg: { maxDepth: 1, narrowOnly: true, mayTouch: [] },
  escalateOn: [], wildcardAck: [], holes: [],
};
const goal = (over: Partial<Goal>): Goal => ({ ...shell, ...over });
const grant = (gid: string, verb: string, res: Grant['res']): Grant => ({ gid, verb, res, cond: ctrue });
const wild: Grant['res'] = { k: 'any', reason: 'r' };
const exact = (id: string): Grant['res'] => ({ k: 'exact', id });
const reading = (id: string, family: string, deterministic: boolean, g: Goal = baseGoal()): Reading => ({ id, family, deterministic, goal: g, notes: [] });

describe('meet kills', () => {
  it('meetGrants crosses equal verbs, names the pair, intersects resources and conjoins conditions', () => {
    const a: Grant[] = [grant('x', 'v', exact('e')), grant('x2', 'w', wild)];
    const b: Grant[] = [grant('y', 'v', { k: 'oneof', ids: ['e', 'f'] })];
    expect(meetGrants(a, b)).toStrictEqual([{ gid: 'x&y', verb: 'v', res: { k: 'all_of', parts: [{ k: 'exact', id: 'e' }, { k: 'oneof', ids: ['e', 'f'] }] }, cond: { k: 'true' } }]);
  });
  it('refuses no goals and goals that differ in principal, ontology or text', () => {
    expect(() => meet([])).toThrow(new Error('meet: no goals'));
    const bad = 'meet: readings must share principal, ontology and text';
    expect(() => meet([shell, goal({ principal: 'q' })])).toThrow(new Error(bad));
    expect(() => meet([shell, goal({ ontDigest: 'q' })])).toThrow(new Error(bad));
    expect(() => meet([shell, goal({ nlDigest: 'q' })])).toThrow(new Error(bad));
  });
  it('renames a prohibition whose id is taken by a different prohibition', () => {
    const pr = (verb: string): Prohibit => ({ pid: 'p1', target: { k: 'verb', verb }, res: wild, cond: ctrue });
    const m = meet([goal({ prohibits: [pr('a')] }), goal({ prohibits: [pr('b')] })]);
    expect(m.prohibits).toStrictEqual([pr('a'), { ...pr('b'), pid: 'p1#1' }]);
  });
  it('renames a bound whose id is taken by a different bound', () => {
    const bd = (agg: Bound['agg']): Bound => ({
      bid: 'b1', sel: { k: 'effect', cls: 'c' }, agg, value: { k: 'lit', v: { k: 'q', q: { u: { k: 'count' }, n: 1 } } }, key: '', window: { k: 'task' },
      scope: { k: 'principal' }, cap: { u: { k: 'count' }, n: 1 }, onExceed: 'deny',
    });
    const m = meet([goal({ bounds: [bd('count')] }), goal({ bounds: [bd('sum')] })]);
    expect(m.bounds).toStrictEqual([bd('count'), { ...bd('sum'), bid: 'b1#1' }]);
  });
  it('the merged idle limit is the smallest positive one', () => {
    const m = meet([goal({ validity: { notBefore: 0, notAfter: 1_000, maxIdle: 10 } }), goal({ validity: { notBefore: 0, notAfter: 1_000, maxIdle: 30 } })]);
    expect(m.validity.maxIdle).toBe(10);
  });
  it('a merged wildcard needs every reading to acknowledge its wildcard', () => {
    const acked = (gid: string): Partial<Goal> => ({ grants: [grant(gid, 'v', wild)], wildcardAck: [gid] });
    expect(meet([goal(acked('ga')), goal(acked('gb'))]).wildcardAck).toStrictEqual(['ga&gb']);
    const second = goal({ grants: [grant('a0', 'w', exact('e')), grant('gb', 'v', wild)], wildcardAck: [] });
    expect(meet([goal(acked('ga')), second]).wildcardAck).toStrictEqual([]);
    // a reading that repeats a gid: the first grant of that gid is the one consulted, as written
    const dup = goal({ grants: [grant('g', 'v', exact('e')), grant('g', 'v', wild)], wildcardAck: [] });
    expect(meet([dup, goal(acked('h'))]).wildcardAck).toStrictEqual(['g&h']);
  });
});

describe('panel and n-version kills', () => {
  it('checkPanel names each missing requirement', () => {
    expect(checkPanel([])).toStrictEqual([
      { code: 'too_few', msg: 'need at least 3 interpreters' },
      { code: 'no_deterministic', msg: 'need at least one deterministic template interpreter' },
      { code: 'no_family_diversity', msg: 'need at least two distinct model families' },
    ]);
    expect(checkPanel([reading('a', 'x', true), reading('b', 'y', false), reading('c', 'z', false)])).toStrictEqual([]);
  });
  it('a panel with too few readings is not signable even with no hole', () => {
    const r = nVersion([reading('a', 'x', true), reading('b', 'y', false)], { ont: ONT });
    expect(r.disagreementHoles).toStrictEqual([]);
    expect(r.signable).toBe(false);
  });
  it('a split hole falls back to a generic question when no witness splits the readings', () => {
    const r = nVersion([reading('a', 'x', true), reading('b', 'y', false), reading('c', 'z', false)], { ont: ONT, massThreshold: -1 });
    expect(r.disagreementHoles).toStrictEqual([{ hid: 'nv:split', q: 'The readings disagree.', domain: [], affects: [], global: true }]);
  });
});
