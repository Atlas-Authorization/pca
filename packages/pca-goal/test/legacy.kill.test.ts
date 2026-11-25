import { describe, expect, it, vi } from 'vitest';
import { buildCatalog, defineAction } from '@atlasauth/pca/ext/research';
import { liftLegacy } from '../src/legacy';
import type { Bound, Grant, Term } from '../src/ir';

const USD = { k: 'money', ccy: 'USD' } as const;
const COUNT = { k: 'count' } as const;
const action = (name: string, over: { reversibility?: 'reversible' | 'rate_limited' | 'irreversible'; amountField?: string; resource?: string } = {}) =>
  defineAction({ connector: 'm', action: name, reversibility: over.reversibility ?? 'reversible', blastRadius: 0.2, description: 'd', ...(over.amountField ? { amountField: over.amountField } : {}), ...(over.resource ? { resource: over.resource } : {}) });
const catalog = buildCatalog([
  action('pay', { reversibility: 'irreversible', amountField: 'amount', resource: 'acct_1' }),
  action('buy', { amountField: 'total' }),
  action('send', { reversibility: 'rate_limited' }),
  action('cnt'),
  action('free'),
  action('glob', { resource: 'a*' }),
  action('q', { resource: 'b?' }),
  action('rx', { resource: 're:x' }),
  action('inner', { resource: 'xre:y' }),
]);
const amt = (path: string): Term => ({ k: 'param', path, ty: { k: 'q', u: USD } });
const usdCond = (path: string, minor: number): Grant['cond'] => ({
  k: 'and',
  a: { k: 'cmp', op: 'gte', l: amt(path), r: { k: 'lit', v: { k: 'q', q: { u: USD, n: 0 } } } },
  b: { k: 'cmp', op: 'lte', l: amt(path), r: { k: 'lit', v: { k: 'q', q: { u: USD, n: minor } } } },
});
const WILD = { k: 'any', reason: 'legacy default: no resource scope given' } as const;
const lift = (permissions: Record<string, string[]>, limits?: Record<string, string>) => liftLegacy({ permissions, ...(limits ? { limits } : {}), catalog, principal: 'P' });
const countBound = (verb: string, window: Bound['window'], n: number): Bound => ({
  bid: `b:m.${verb}`, sel: { k: 'gids', gids: [`g:m.${verb}`] }, agg: 'count', value: { k: 'lit', v: { k: 'q', q: { u: COUNT, n: 1 } } }, key: '',
  window, scope: { k: 'session' }, cap: { u: COUNT, n }, onExceed: 'deny',
});

describe('liftLegacy kills', () => {
  it('lifts every grant, bound and verb exactly, in code-unit order whatever the input order', () => {
    const { goal, ontology } = lift({ m: ['pay', 'buy', 'send', 'cnt', 'free'] }, { 'm.pay': '$12.5/day', buy: '$5', send: '3/hour', 'm.cnt': '2' });
    expect(goal).toStrictEqual({
      v: 1, principal: 'P', ontDigest: 'legacy-catalog', nlDigest: '', sources: [],
      grants: [
        { gid: 'g:m.buy', verb: 'm.buy', res: WILD, cond: usdCond('total', 500) },
        { gid: 'g:m.cnt', verb: 'm.cnt', res: WILD, cond: { k: 'true' } },
        { gid: 'g:m.free', verb: 'm.free', res: WILD, cond: { k: 'true' } },
        { gid: 'g:m.pay', verb: 'm.pay', res: { k: 'exact', id: 'acct_1' }, cond: usdCond('amount', 1250) },
        { gid: 'g:m.send', verb: 'm.send', res: WILD, cond: { k: 'true' } },
      ],
      prohibits: [],
      bounds: [
        countBound('cnt', { k: 'lifetime' }, 2),
        { bid: 'b:m.pay', sel: { k: 'gids', gids: ['g:m.pay'] }, agg: 'sum', value: amt('amount'), key: '', window: { k: 'sliding', ms: 86_400_000 }, scope: { k: 'session' }, cap: { u: USD, n: 1250 }, onExceed: 'deny' },
        countBound('send', { k: 'sliding', ms: 3_600_000 }, 3),
      ],
      validity: { notBefore: 0, notAfter: Number.MAX_SAFE_INTEGER, maxIdle: 0 },
      deleg: { maxDepth: 16, narrowOnly: true, mayTouch: ['g:m.buy', 'g:m.cnt', 'g:m.free', 'g:m.pay', 'g:m.send'] },
      escalateOn: [], wildcardAck: ['g:m.buy', 'g:m.cnt', 'g:m.free', 'g:m.send'], holes: [],
    });
    expect(ontology).toStrictEqual({
      verbs: [
        { verb: 'm.buy', cls: 'reversible', params: [{ path: 'total', ty: { k: 'q', u: USD } }] },
        { verb: 'm.cnt', cls: 'reversible', params: [] },
        { verb: 'm.free', cls: 'reversible', params: [] },
        { verb: 'm.pay', cls: 'irreversible', params: [{ path: 'amount', ty: { k: 'q', u: USD } }] },
        { verb: 'm.send', cls: 'rate_limited', params: [] },
      ],
      rels: [],
    });
  });

  it('orders by UTF-16 code unit: the three comparators return exactly -1, 1 and 0', () => {
    type Rec = { gid: string; bid: string; verb: string };
    type Cmp = (a: Rec, b: Rec) => number;
    const seen: Cmp[] = [];
    const real = Array.prototype.sort;
    const spy = vi.spyOn(Array.prototype, 'sort').mockImplementation(function (this: unknown[], cmp?: Cmp) {
      if (cmp) seen.push(cmp);
      return real.call(this, cmp);
    });
    try { lift({ m: ['pay', 'buy'] }); } finally { spy.mockRestore(); }
    const rec = (s: string): Rec => ({ gid: s, bid: s, verb: s });
    const mine = seen.slice(-3); // grants, bounds, verbs: the last three sorts of the lift
    expect(mine).toHaveLength(3);
    for (const c of mine) {
      expect(c(rec('a'), rec('b'))).toBe(-1);
      expect(c(rec('b'), rec('a'))).toBe(1);
      expect(c(rec('a'), rec('a'))).toBe(0);
    }
  });

  it('refuses a resource pattern it cannot express, and names it', () => {
    for (const [verb, res] of [['glob', 'a*'], ['q', 'b?'], ['rx', 're:x']] as const) {
      expect(() => lift({ m: [verb] })).toThrow(new Error(`liftLegacy: resource pattern '${res}' of m.${verb} is not expressible; name exact resources or acknowledge a wildcard`));
    }
  });
  it('a resource that merely contains re: after the start is an exact id', () => {
    expect(lift({ m: ['inner'] }).goal.grants[0]!.res).toStrictEqual({ k: 'exact', id: 'xre:y' });
  });

  it('refuses a $ limit that overflows the minor unit', () => {
    expect(() => lift({ m: ['buy'] }, { buy: '$99999999999999999999' })).toThrow(new Error('liftLegacy: limit for m.buy is out of range'));
  });
  it('refuses a fractional count limit', () => {
    expect(() => lift({ m: ['free'] }, { free: '2.5' })).toThrow(new Error('liftLegacy: count limit for m.free must be a whole number'));
  });
  it('refuses a duplicate grant, naming it', () => {
    expect(() => lift({ m: ['pay', 'pay'] })).toThrow(new Error('liftLegacy: duplicate grant g:m.pay'));
  });
});
