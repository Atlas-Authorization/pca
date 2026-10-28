import { describe, expect, it } from 'vitest';
import { b64u } from './hash';
import { publicKeyOf } from './keys';
import { AGGREGATE_DOMAIN, aggregateRead, detokenize, emptyAggregateState, memoryVault, redactReadWithVault, signAggregateGrant, type AggregateGrantBody, type AggregateInput } from './read-vault';
import { signReadGrant, type ReadGrantBody } from './readside';
import { signBody } from './workflow';

const P = new Uint8Array(32).fill(71);
const PK = b64u(publicKeyOf(P));
const X = b64u(publicKeyOf(new Uint8Array(32).fill(72)));
const NOW = 1_800_000_000_000;
const SALT = 'a-per-read-secret-salt';

const grantBody: ReadGrantBody = {
  v: 1, id: 'rg', principal: PK, issued_at: NOW - 1000, expires_at: NOW + 1000,
  reads: [{ verb: 'customers.get', resource_prefix: 'customers/', purposes: ['support'], modes: { ref: 'token', ssn: 'token' }, default_mode: 'drop' }],
  caps: {}, sinks: { payments: { allow: ['ref'], escalate: ['ssn'] }, email: { allow: [], escalate: [] } },
};
const grant = signReadGrant(P, grantBody);
const read = (store = memoryVault()) =>
  redactReadWithVault({ grant, principal: PK, now: NOW, verb: 'customers.get', resource: 'customers/1', purpose: 'support', schema: { fields: { cust: 'ref', tax: 'ssn' }, required: [] }, record: { cust: 'c_77', tax: '123-45' }, tighten: {}, salt: SALT, counts: {} }, store);

describe('tokenisation vault (C-315)', () => {
  it('detokenises only for a sink the grant allows the class to reach', () => {
    const store = memoryVault();
    const r = read(store);
    const tRef = r.view.cust as string;
    const tSsn = r.view.tax as string;
    const d = (token: string, sink: string, o: Record<string, unknown> = {}) => detokenize({ grant, principal: PK, now: NOW, sink, token, store, ...o });
    expect(d(tRef, 'payments')).toEqual({ decision: 'allow', code: null, value: 'c_77' });
    expect(d(tSsn, 'payments')).toEqual({ decision: 'escalate', code: 'label_escalate', value: null });
    expect(d(tSsn, 'email')).toEqual({ decision: 'deny', code: 'label_flow', value: null });
    expect(d(tRef, 'email')).toEqual({ decision: 'deny', code: 'label_flow', value: null });
    expect(d(tRef, 'billing')).toEqual({ decision: 'deny', code: 'unknown_sink', value: null });
    expect(d('tok_nope', 'payments')).toEqual({ decision: 'deny', code: 'unknown_token', value: null });
    expect(d(tRef, 'payments', { principal: X })).toEqual({ decision: 'deny', code: 'bad_signature', value: null });
    expect(d(tRef, 'payments', { now: NOW + 1000 })).toEqual({ decision: 'deny', code: 'expired', value: null });
    expect(d(tRef, 'payments', { now: null })).toEqual({ decision: 'deny', code: 'bad_request', value: null });
    expect(d(tRef, '__proto__')).toEqual({ decision: 'deny', code: 'unknown_sink', value: null });
  });
  it('a token minted under another grant is unknown', () => {
    const store = memoryVault();
    const t = read(store).view.cust as string;
    const other = signReadGrant(P, { ...grantBody, id: 'rg2' });
    expect(detokenize({ grant: other, principal: PK, now: NOW, sink: 'payments', token: t, store })).toEqual({ decision: 'deny', code: 'unknown_token', value: null });
  });
  it('a refused read mints no token', () => {
    const store = memoryVault();
    const r = redactReadWithVault({ grant, principal: X, now: NOW, verb: 'customers.get', resource: 'customers/1', purpose: 'support', schema: { fields: { cust: 'ref' }, required: [] }, record: { cust: 'c_77' }, tighten: {}, salt: SALT, counts: {} }, store);
    expect(r.decision).toBe('deny');
    expect(store.get('tok_x')).toBeUndefined();
  });
});

const aBody: AggregateGrantBody = {
  v: 1, id: 'ag', principal: PK, issued_at: NOW - 1000, expires_at: NOW + 1000,
  rules: [
    { verb: 'orders.stats', resource_prefix: 'orders/', purposes: ['analytics'], fns: ['count', 'sum'], min_group: 3, clamp: 100, epsilon_micro: 500_000, dp: true },
    { verb: 'orders.exact', resource_prefix: 'orders/', purposes: ['analytics'], fns: ['count'], min_group: 5, clamp: 0, epsilon_micro: 0, dp: false },
  ],
  epsilon_budget_micro: 1_000_000, max_queries: 3,
};
const ag = signAggregateGrant(P, aBody);
const q = (o: Partial<AggregateInput> = {}): AggregateInput => ({ grant: ag, principal: PK, now: NOW, verb: 'orders.stats', resource: 'orders/eu', purpose: 'analytics', fn: 'sum', values: [10, 20, 500, -900], salt: SALT, noise: 'seeded', state: emptyAggregateState(), ...o });

describe('aggregate read limits and epsilon accounting (C-316..C-319)', () => {
  it('charges epsilon, clamps each value, and refuses once the budget would be exceeded', () => {
    const a = aggregateRead(q({ values: [1, 2, 3], fn: 'count' }));
    expect(a).toMatchObject({ decision: 'allow', charged_micro: 500_000 });
    const b = aggregateRead(q({ state: a.state, values: [1, 2, 3, 4], fn: 'count' }));
    expect(b).toMatchObject({ decision: 'allow', charged_micro: 500_000 });
    expect(b.state.spent_micro).toBe(1_000_000);
    const c = aggregateRead(q({ state: b.state, values: [1, 2, 3, 4, 5], fn: 'count' }));
    expect(c).toMatchObject({ decision: 'deny', code: 'epsilon_exhausted', value: null, charged_micro: 0 });
    expect(c.state).toEqual(b.state); // a refusal changes nothing
  });
  it('a repeated identical query returns the same answer and is not charged again', () => {
    const a = aggregateRead(q());
    const again = aggregateRead(q({ state: a.state }));
    expect(again).toMatchObject({ decision: 'allow', value: a.value, charged_micro: 0 });
    expect(again.state).toEqual(a.state);
  });
  it('the noise is deterministic for a salt and differs across salts', () => {
    expect(aggregateRead(q()).value).toBe(aggregateRead(q()).value);
    expect(aggregateRead(q({ salt: 'another-per-read-salt' })).value).not.toBe(aggregateRead(q()).value);
  });
  it('a group below k is refused; clamping bounds the exact sum (non-dp rule counts exactly)', () => {
    expect(aggregateRead(q({ values: [1, 2] }))).toMatchObject({ decision: 'deny', code: 'group_too_small' });
    const e = aggregateRead(q({ verb: 'orders.exact', fn: 'count', values: [1, 2, 3, 4, 5, 6] }));
    expect(e).toMatchObject({ decision: 'allow', value: 6, charged_micro: 0 });
    expect(aggregateRead(q({ verb: 'orders.exact', fn: 'sum', values: [1, 2, 3, 4, 5, 6] }))).toMatchObject({ decision: 'deny', code: 'no_read_scope' });
  });
  it('the query count is capped even when no epsilon is spent', () => {
    let s = emptyAggregateState();
    for (let i = 0; i < 3; i++) {
      const r = aggregateRead(q({ verb: 'orders.exact', fn: 'count', state: s, values: Array.from({ length: 5 + i }, () => 1) }));
      expect(r.decision).toBe('allow');
      s = r.state;
    }
    expect(aggregateRead(q({ verb: 'orders.exact', fn: 'count', state: s, values: Array.from({ length: 9 }, () => 1) }))).toMatchObject({ decision: 'deny', code: 'query_cap' });
  });
  it('signature, pin, time and request errors deny and leave the state alone', () => {
    const st = aggregateRead(q({ fn: 'count', values: [1, 2, 3] })).state;
    const keep = (o: Partial<AggregateInput>, code: string) => expect(aggregateRead(q({ state: st, ...o }))).toMatchObject({ decision: 'deny', code, state: st });
    keep({ principal: X }, 'bad_signature');
    keep({ now: aBody.expires_at }, 'expired');
    keep({ now: aBody.issued_at - 1 }, 'not_yet');
    keep({ salt: 'short' }, 'bad_request');
    keep({ values: [1.5, 2, 3] }, 'bad_request');
    keep({ purpose: 'marketing' }, 'no_read_scope');
    keep({ grant: { body: aBody, sig: signBody(P, 'atlas-pca/other/v1\0', aBody) } }, 'bad_signature');
    keep({ grant: { body: { ...aBody, max_queries: 99 }, sig: ag.sig } }, 'bad_signature');
    void AGGREGATE_DOMAIN;
  });
});

import { discreteLaplace, secureDraws, seededDraws } from './read-vault';
describe('integer-exact discrete Laplace', () => {
  it('is a pure function of the seed (pinned values)', () => {
    const d = seededDraws('seed-1');
    expect(Array.from({ length: 12 }, () => discreteLaplace(d, 500_000, 1_000_000))).toMatchInlineSnapshot(`
      [
        2,
        0,
        1,
        0,
        1,
        3,
        3,
        0,
        -6,
        3,
        2,
        -6,
      ]
    `);
  });
  it('has the right spread: mean absolute value near the scale for many draws', () => {
    const d = seededDraws('spread');
    const xs = Array.from({ length: 4000 }, () => discreteLaplace(d, 1_000_000, 2_000_000)); // scale 2
    const mad = xs.reduce((a, x) => a + Math.abs(x), 0) / xs.length;
    expect(mad).toBeGreaterThan(1.7);
    expect(mad).toBeLessThan(2.3);
    expect(Math.abs(xs.reduce((a, x) => a + x, 0) / xs.length)).toBeLessThan(0.25);
  });
  it('secure draws differ between calls; seeded draws do not', () => {
    expect(secureDraws().uniform(2 ** 40)).not.toBe(secureDraws().uniform(2 ** 40));
    expect(seededDraws('x').uniform(1000)).toBe(seededDraws('x').uniform(1000));
  });
  it('rejects a bad bound', () => {
    expect(() => seededDraws('x').uniform(0)).toThrow('bad bound');
    expect(() => seededDraws('x').uniform(2 ** 47 + 1)).toThrow('bad bound');
  });
});
