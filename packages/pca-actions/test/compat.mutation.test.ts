import { describe, expect, it } from 'vitest';
import { REV_RANK, blastExactOfFloat, blastOfFloat, fromCatalog, fromCatalogSpec, maxRevOf, type CatalogSpecLike, type Rev } from '../src';

const spec = (over: Partial<CatalogSpecLike> = {}): CatalogSpecLike => ({
  connector: 'acme', action: 'sync', verb: 'acme.sync', reversibility: 'reversible', blastRadius: 0.2, description: 'Sync things', ...over,
});

describe('maxRevOf picks the stricter class', () => {
  const revs: Rev[] = ['reversible', 'rate_limited', 'irreversible'];
  it('is the higher-ranked of every ordered pair', () => {
    for (const a of revs) for (const b of revs) expect(maxRevOf(a, b), `${a},${b}`).toBe(REV_RANK[a] >= REV_RANK[b] ? a : b);
    expect(maxRevOf('reversible', 'irreversible')).toBe('irreversible');
    expect(maxRevOf('irreversible', 'reversible')).toBe('irreversible');
    expect(maxRevOf('rate_limited', 'reversible')).toBe('rate_limited');
    expect(maxRevOf('reversible', 'rate_limited')).toBe('rate_limited');
  });
});

describe('blast floats', () => {
  it('blastOfFloat picks the smallest covering radius and clamps', () => {
    expect(blastOfFloat(0)).toEqual({ radius: 'one', ppm: 0 });
    expect(blastOfFloat(0.2)).toEqual({ radius: 'bounded', ppm: 200_000 });
    expect(blastOfFloat(0.1234567)).toEqual({ radius: 'bounded', ppm: 123_457 });
    expect(blastOfFloat(Number.NaN)).toEqual({ radius: 'global', ppm: 1_000_000 });
    expect(blastOfFloat(1.5)).toEqual({ radius: 'global', ppm: 1_000_000 });
    expect(blastOfFloat(-3)).toEqual({ radius: 'one', ppm: 0 });
  });
  it('blastExactOfFloat picks the largest radius not above the float, and falls back to the smallest below every default', () => {
    expect(blastExactOfFloat(0.01)).toEqual({ radius: 'one', ppm: 10_000 });
    expect(blastExactOfFloat(0)).toEqual({ radius: 'one', ppm: 0 });
    expect(blastExactOfFloat(-1)).toEqual({ radius: 'one', ppm: 0 });
    expect(blastExactOfFloat(0.05)).toEqual({ radius: 'one', ppm: 50_000 });
    expect(blastExactOfFloat(0.3)).toEqual({ radius: 'bounded', ppm: 300_000 });
    expect(blastExactOfFloat(0.5)).toEqual({ radius: 'bounded', ppm: 500_000 });
    expect(blastExactOfFloat(0.7)).toEqual({ radius: 'tenant', ppm: 700_000 });
    expect(blastExactOfFloat(Number.NaN)).toEqual({ radius: 'global', ppm: 1_000_000 });
    expect(blastExactOfFloat(2)).toEqual({ radius: 'global', ppm: 1_000_000 });
  });
});

describe('fromCatalogSpec builds the whole def', () => {
  it('a scoped non-money entry has no params and no idempotency', () => {
    const d = fromCatalogSpec(spec({ resource: 'acct' }));
    expect(d).toEqual({
      v: 1, kind: 'pca-action-def', verb: 'acme.sync', title: 'Sync things', description: 'Sync things', effects: ['update'],
      resource: { type: 'acme', id: { prefix: '', class: 'any_safe', len: [1, 128] }, scope: 'one' },
      params: {}, reversibility: 'reversible', blast: { radius: 'bounded', ppm: 200_000 }, review: { state: 'authored' },
    });
    expect(Object.keys(d.params)).toEqual([]);
    expect(d).not.toHaveProperty('idempotency');
  });
  it('an absent, "*" or empty resource: the first two are the wildcard set, the empty string is a scoped resource', () => {
    const wild = { type: 'acme', id: '*', scope: 'set' };
    expect(fromCatalogSpec(spec()).resource).toEqual(wild);
    expect(fromCatalogSpec(spec({ resource: '*' })).resource).toEqual(wild);
    expect(fromCatalogSpec(spec({ resource: '' })).resource).toEqual({ type: 'acme', id: { prefix: '', class: 'any_safe', len: [1, 128] }, scope: 'one' });
  });
  it('a money entry carries the bounded amount, the key param, defaults and options', () => {
    const d = fromCatalogSpec(spec({ action: 'get_and_delete_and_send', verb: 'acme.x', amountField: 'amount', reversibility: 'costly' }));
    expect(d.effects).toEqual(['pay', 'read', 'delete', 'send']);
    expect(d.params).toEqual({
      amount: { type: 'integer', role: 'money.amount', min: 0, max: 100_000_000_000, unit: { kind: 'money', ccy: 'USD', exp: 2 } },
      idempotency_key: { type: 'string', max_len: 128 },
    });
    expect(d.idempotency).toEqual({ mode: 'key_param', param: 'idempotency_key' });
    expect(d.reversibility).toBe('rate_limited');
    const o = fromCatalogSpec(spec({ amountField: 'amt' }), { ccy: 'EUR', exp: 0, maxAmount: 5 });
    expect(o.params.amt).toEqual({ type: 'integer', role: 'money.amount', min: 0, max: 5, unit: { kind: 'money', ccy: 'EUR', exp: 0 } });
  });
  it('the title is the description up to 120 characters and a 117-character cut with an ellipsis above', () => {
    for (const n of [5, 119, 120]) expect(fromCatalogSpec(spec({ description: 'x'.repeat(n) })).title).toBe('x'.repeat(n));
    const long = 'abcdefghij'.repeat(13);
    const t = fromCatalogSpec(spec({ description: long })).title;
    expect(t).toBe(`${long.slice(0, 117)}...`);
    expect(t).toHaveLength(120);
    expect(fromCatalogSpec(spec({ description: 'y'.repeat(121) })).description).toBe('y'.repeat(121));
  });
  it('fromCatalog converts every entry with the shared options', () => {
    const out = fromCatalog([spec({ amountField: 'a' }), spec({ action: 'x', verb: 'acme.x' })], { ccy: 'JPY', exp: 0 });
    expect(out.map((d) => d.verb)).toEqual(['acme.sync', 'acme.x']);
    expect(out[0]!.params.a).toMatchObject({ unit: { kind: 'money', ccy: 'JPY', exp: 0 } });
    expect(out[1]!.effects).toEqual(['update']);
    expect(fromCatalog([])).toEqual([]);
  });
});
