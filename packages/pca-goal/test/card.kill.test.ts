import { describe, expect, it } from 'vitest';
import type { Bound, Cond, Goal, Hole, ResSel, Scope, Term, Unit, Value, Window } from '../src/ir';
import { boundLine, cond, delegationLine, holeLine, prohibitLine, renderCard, res, scope, term, value, win } from '../src/card';

const CNT: Unit = { k: 'count' };
const USD: Unit = { k: 'money', ccy: 'USD' };
const T: Cond = { k: 'true' };
const n = (x: number): Value => ({ k: 'q', q: { u: CNT, n: x } });
const s = (x: string): Value => ({ k: 's', s: x });

describe('value and term text', () => {
  it('prints quantities, strings and sets exactly', () => {
    expect(value(n(3))).toBe('3 count');
    expect(value(s('a'))).toBe('"a"');
    expect(value({ k: 'set', items: [n(1), s('x'), { k: 'set', items: [n(2)] }] })).toBe('{1 count, "x", {2 count}}');
  });
  it('prints each term kind', () => {
    expect(term({ k: 'param', path: 'amount', ty: { k: 'q', u: USD } })).toBe('param "amount" (USD minor units)');
    expect(term({ k: 'param', path: 'name', ty: { k: 's' } })).toBe('param "name" (text)');
    expect(term({ k: 'lit', v: s('x') })).toBe('"x"');
    expect(term({ k: 'hist', bid: 'b1', u: CNT })).toBe('running total of bound "b1" (count)');
  });
});

describe('cond text', () => {
  it('prints and, or and not with their keyword and parentheses', () => {
    expect(cond({ k: 'and', a: T, b: T })).toBe('(always) AND (always)');
    expect(cond({ k: 'or', a: T, b: T })).toBe('(always) OR (always)');
    expect(cond({ k: 'not', c: T })).toBe('NOT (always)');
    const l: Term = { k: 'lit', v: n(1) };
    expect(cond({ k: 'cmp', op: 'lte', l, r: l })).toBe('1 count <= 1 count');
  });
});

describe('selector, window and scope text', () => {
  it('prints resource selectors', () => {
    expect(res({ k: 'oneof', ids: ['a', 'b'] })).toBe('one of ["a", "b"]');
    expect(res({ k: 'all_of', parts: [{ k: 'exact', id: 'a' }, { k: 'related', rel: 'owner', anchor: 'z' }] })).toBe('ALL OF (exactly "a" AND owner of "z")');
    const any: ResSel = { k: 'any', reason: 'why' };
    expect(res(any)).toBe('ANY RESOURCE (reason: "why")');
  });
  it('prints every window kind', () => {
    const w = (x: Window): string => win(x);
    expect(w({ k: 'task' })).toBe('per task');
    expect(w({ k: 'lifetime' })).toBe('over the lifetime');
    expect(w({ k: 'sliding', ms: 5 })).toBe('in any 5 ms window');
    expect(w({ k: 'period', ms: 10, t0: 3 })).toBe('per 10 ms period starting at 3');
  });
  it('prints every scope kind', () => {
    const sc = (x: Scope): string => scope(x);
    expect(sc({ k: 'fleet', agents: ['a', 'b'] })).toBe('fleet ["a", "b"]');
    expect(sc({ k: 'session' })).toBe('session');
    expect(sc({ k: 'org' })).toBe('org');
  });
});

describe('clause lines', () => {
  it('prints both prohibition targets', () => {
    expect(prohibitLine({ pid: 'p1', target: { k: 'verb', verb: 'x' }, res: { k: 'exact', id: 'r' }, cond: T })).toBe('NEVER "p1": verb "x" on exactly "r" when always');
    expect(prohibitLine({ pid: 'p2', target: { k: 'effect', cls: 'money' }, res: { k: 'exact', id: 'r' }, cond: T })).toBe('NEVER "p2": every verb of effect class "money" on exactly "r" when always');
  });
  it('prints bounds by selector and aggregate', () => {
    const base: Bound = { bid: 'b1', sel: { k: 'gids', gids: ['g1'] }, agg: 'count', value: { k: 'lit', v: n(0) }, key: '', window: { k: 'task' }, scope: { k: 'session' }, cap: { u: CNT, n: 5 }, onExceed: 'deny' };
    expect(boundLine(base)).toBe('LIMIT "b1": count over grants ["g1"], per task, scope session, at most 5 count; beyond that: deny');
    expect(boundLine({ ...base, sel: { k: 'effect', cls: 'money' }, agg: 'distinct', key: 'k', onExceed: 'escalate' })).toBe('LIMIT "b1": distinct of "k" over effect class "money", per task, scope session, at most 5 count; beyond that: ask the principal');
    expect(boundLine({ ...base, agg: 'sum', value: { k: 'lit', v: n(2) } })).toBe('LIMIT "b1": sum of 2 count over grants ["g1"], per task, scope session, at most 5 count; beyond that: deny');
    expect(boundLine({ ...base, sel: { k: 'gids', gids: ['a', 'b'] } })).toContain('over grants ["a", "b"],');
  });
  it('prints delegation and holes', () => {
    expect(delegationLine({ maxDepth: 2, narrowOnly: true, mayTouch: ['a', 'b'] })).toBe('DELEGATION depth at most 2, narrow only true, delegates may use grants ["a", "b"]');
    const h: Hole = { hid: 'h1', q: 'Q?', domain: ['a', 'b'], affects: ['g1', 'g2'], global: false };
    expect(holeLine(h)).toBe('UNRESOLVED "h1": "Q?" options ["a", "b"] affects ["g1", "g2"]');
    expect(holeLine({ ...h, global: true })).toBe('UNRESOLVED "h1": "Q?" options ["a", "b"] affects everything');
  });
});

describe('renderCard', () => {
  const goal = (over: Partial<Goal>): Goal => ({
    v: 1, principal: 'p', ontDigest: 'o', nlDigest: 'n', sources: [], grants: [], prohibits: [], bounds: [],
    validity: { notBefore: 1, notAfter: 9, maxIdle: 0 }, deleg: { maxDepth: 2, narrowOnly: true, mayTouch: ['g1'] },
    escalateOn: [], wildcardAck: [], holes: [], ...over,
  });
  it('prints every clause in order with its warnings', () => {
    const g = goal({
      sources: ['s1'],
      grants: [{ gid: 'g1', verb: 'v', res: { k: 'exact', id: 'r1' }, cond: T }, { gid: 'g2', verb: 'w', res: { k: 'any', reason: 'why' }, cond: T }],
      prohibits: [{ pid: 'p1', target: { k: 'verb', verb: 'x' }, res: { k: 'exact', id: 'r2' }, cond: T }],
      bounds: [{ bid: 'b1', sel: { k: 'gids', gids: ['g1'] }, agg: 'count', value: { k: 'lit', v: n(0) }, key: '', window: { k: 'task' }, scope: { k: 'session' }, cap: { u: CNT, n: 5 }, onExceed: 'deny' }],
      escalateOn: [T], wildcardAck: ['g1'],
      holes: [{ hid: 'h1', q: 'Q?', domain: ['a', 'b'], affects: ['g1', 'g2'], global: false }],
    });
    expect(renderCard(g)).toEqual({
      lines: [
        'Goal v1 for principal "p"; ontology "o"; request text digest "n"',
        'Source "s1"',
        'ALLOW "g1": verb "v" on exactly "r1" when always',
        'ALLOW "g2": verb "w" on ANY RESOURCE (reason: "why") when always',
        'NEVER "p1": verb "x" on exactly "r2" when always',
        'LIMIT "b1": count over grants ["g1"], per task, scope session, at most 5 count; beyond that: deny',
        'VALID from 1 to 9; idle limit none',
        'DELEGATION depth at most 2, narrow only true, delegates may use grants ["g1"]',
        'ASK THE PRINCIPAL when always',
        'Wildcard acknowledged for "g1"',
        'UNRESOLVED "h1": "Q?" options ["a", "b"] affects ["g1", "g2"]',
      ],
      warnings: ['grant "g2" applies to every resource (NOT acknowledged)', 'this goal has unresolved questions and cannot be signed'],
    });
  });
  it('marks an acknowledged wildcard and warns of nothing else without holes or wildcards', () => {
    const acked = goal({ grants: [{ gid: 'g2', verb: 'w', res: { k: 'any', reason: 'why' }, cond: T }], wildcardAck: ['g2'] });
    expect(renderCard(acked).warnings).toEqual(['grant "g2" applies to every resource (acknowledged)']);
    const plain = goal({ grants: [{ gid: 'g1', verb: 'v', res: { k: 'exact', id: 'r1' }, cond: T }] });
    expect(renderCard(plain).warnings).toEqual([]);
  });
});
