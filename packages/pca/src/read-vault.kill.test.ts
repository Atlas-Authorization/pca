import { afterEach, describe, expect, it, vi } from 'vitest';
import { b64u } from './hash';
import { publicKeyOf } from './keys';
import {
  aggregateRead,
  detokenize,
  discreteLaplace,
  emptyAggregateState,
  redactReadWithVault,
  seededDraws,
  signAggregateGrant,
  validAggregateGrantBody,
  type AggregateGrantBody,
  type AggregateInput,
  type AggregateRule,
  type VaultEntry,
  type VaultStore,
} from './read-vault';
import { READ_GRANT_DOMAIN, readGrantDigest, signReadGrant, type ReadGrantBody } from './readside';
import { signBody } from './workflow';

const P = new Uint8Array(32).fill(71);
const PK = b64u(publicKeyOf(P));
const YPK = b64u(publicKeyOf(new Uint8Array(32).fill(72)));
const NOW = 1_800_000_000_000;
const SALT = 'a-per-read-secret-salt';

// ---- vault -----------------------------------------------------------------------------------------------------------------

const gBody: ReadGrantBody = {
  v: 1, id: 'rg', principal: PK, issued_at: NOW - 1000, expires_at: NOW + 1000,
  reads: [{ verb: 'customers.get', resource_prefix: 'customers/', purposes: ['support'], modes: { ref: 'token', pii: 'last4', hsh: 'hash', open: 'show' }, default_mode: 'drop' }],
  caps: {}, sinks: { payments: { allow: ['ref'], escalate: [] } },
};
const gGrant = signReadGrant(P, gBody);
const gDigest = readGrantDigest(gBody);
const recorder = () => {
  const puts: [string, VaultEntry][] = [];
  const store: VaultStore = { put: (t, e) => void puts.push([t, e]), get: () => undefined };
  return { puts, store };
};
const readInto = (store: VaultStore, o: Record<string, unknown> = {}) =>
  redactReadWithVault({
    grant: gGrant, principal: PK, now: NOW, verb: 'customers.get', resource: 'customers/1', purpose: 'support',
    schema: { fields: { a: 'ref', b: 'pii', c: 'hsh', d: 'open' }, required: [] }, record: { a: 'secret-ref', b: '12345678', c: 'h', d: 'o', e: 'unclassified' }, tighten: {}, salt: SALT, counts: {}, ...o,
  }, store);

describe('vault recording', () => {
  it('records a token and nothing else', () => {
    const { puts, store } = recorder();
    const r = readInto(store);
    expect(r.decision).toBe('allow');
    expect(puts).toEqual([[r.view.a as string, { cls: 'ref', value: 'secret-ref', grant: gDigest, exp: gBody.expires_at }]]);
  });
  it('a refused read returns the refusal untouched and records nothing', () => {
    const { puts, store } = recorder();
    const r = readInto(store, { grant: null });
    expect(r).toEqual({ decision: 'deny', code: 'bad_grant', view: {}, fields: {}, labels: [], counts: {} });
    expect(puts).toEqual([]);
  });
});

describe('detokenize', () => {
  const entry = (o: Partial<VaultEntry> = {}): VaultEntry => ({ cls: 'ref', value: 'v', grant: gDigest, exp: gBody.expires_at, ...o });
  const withEntry = (e: VaultEntry): VaultStore => ({ put: () => undefined, get: () => e });
  const run = (store: VaultStore, o: Record<string, unknown> = {}) => detokenize({ grant: gGrant, principal: PK, now: NOW, sink: 'payments', token: 'tok_x', store, ...o } as never);
  const no = (code: string) => ({ decision: 'deny', code, value: null });
  it('returns the value for the allowed class', () => {
    expect(run(withEntry(entry()))).toEqual({ decision: 'allow', code: null, value: 'v' });
  });
  it('refuses a request whose token or sink is not a string', () => {
    expect(run(withEntry(entry()), { token: 5 })).toEqual(no('bad_request'));
    expect(run(withEntry(entry()), { token: ['tok_x'] })).toEqual(no('bad_request'));
    expect(run(withEntry(entry()), { sink: ['payments'] })).toEqual(no('bad_request'));
    expect(run(withEntry(entry()), { principal: 'abc' })).toEqual(no('bad_request'));
  });
  it('names the exact refusal for each grant defect', () => {
    expect(run(withEntry(entry()), { grant: null })).toEqual(no('bad_grant'));
    expect(run(withEntry(entry()), { grant: { ...gGrant, extra: 1 } })).toEqual(no('bad_grant'));
    expect(run(withEntry(entry()), { grant: { body: { ...gBody, v: 2 }, sig: gGrant.sig } })).toEqual(no('bad_grant'));
    const named = { ...gBody, principal: YPK };
    expect(run(withEntry(entry()), { grant: { body: named, sig: signBody(P, READ_GRANT_DOMAIN, named) } })).toEqual(no('bad_signature'));
  });
  it('the grant window is [issued_at, expires_at) and the token has its own expiry', () => {
    expect(run(withEntry(entry()), { now: gBody.issued_at }).decision).toBe('allow');
    expect(run(withEntry(entry()), { now: gBody.issued_at - 1 })).toEqual(no('not_yet'));
    // the entry outlives the grant, so only the grant check can refuse
    expect(run(withEntry(entry({ exp: NOW + 5000 })), { now: gBody.expires_at })).toEqual(no('expired'));
    expect(run(withEntry(entry({ exp: NOW + 5000 })), { now: gBody.expires_at - 1 }).decision).toBe('allow');
    // the grant outlives the entry, so only the token check can refuse
    expect(run(withEntry(entry({ exp: NOW + 10 })), { now: NOW + 10 })).toEqual(no('expired'));
    expect(run(withEntry(entry({ exp: NOW + 10 })), { now: NOW + 9 }).decision).toBe('allow');
  });
  it('a throwing store or request is a bad_request refusal', () => {
    expect(detokenize(null as never)).toEqual(no('bad_request'));
    expect(run({ put: () => undefined, get: () => { throw new Error('x'); } })).toEqual(no('bad_request'));
  });
});

// ---- aggregates ------------------------------------------------------------------------------------------------------------

const rule: AggregateRule = { verb: 'orders.stats', resource_prefix: 'orders/', purposes: ['analytics'], fns: ['count', 'sum'], min_group: 3, clamp: 100, epsilon_micro: 500_000, dp: true };
const aBody: AggregateGrantBody = {
  v: 1, id: 'ag', principal: PK, issued_at: NOW - 1000, expires_at: NOW + 1000,
  rules: [rule, { ...rule, verb: 'orders.exact', fns: ['count'], min_group: 5, clamp: 0, epsilon_micro: 0, dp: false }],
  epsilon_budget_micro: 1_000_000, max_queries: 3,
};
const ag = signAggregateGrant(P, aBody);
const q = (o: Partial<AggregateInput> = {}): AggregateInput => ({ grant: ag, principal: PK, now: NOW, verb: 'orders.stats', resource: 'orders/eu', purpose: 'analytics', fn: 'sum', values: [10, 20, 500, -900], salt: SALT, noise: 'seeded', state: emptyAggregateState(), ...o });
const arrOf = (n: number) => Array.from({ length: n }, () => 1);

describe('aggregate grant shape', () => {
  const ok = (patch: Partial<AggregateRule>) => validAggregateGrantBody({ ...aBody, rules: [{ ...rule, ...patch }] });
  const top = (patch: Record<string, unknown>) => validAggregateGrantBody({ ...aBody, ...patch });
  const ps = (n: number) => Array.from({ length: n }, (_, i) => `p${String(i).padStart(2, '0')}`);
  it('accepts the base grant and every stated boundary', () => {
    expect(validAggregateGrantBody(aBody)).toBe(true);
    expect(ok({ min_group: 1, clamp: 1_000_000, epsilon_micro: 1_073_741_824 })).toBe(true);
    expect(ok({ dp: true, epsilon_micro: 1 })).toBe(true);
    expect(ok({ dp: false, epsilon_micro: 0, clamp: 0 })).toBe(true);
    expect(ok({ verb: 'v'.repeat(128), resource_prefix: 'p'.repeat(512), purposes: ps(16), fns: ['count'] })).toBe(true);
    expect(top({ rules: Array.from({ length: 16 }, () => rule) })).toBe(true);
  });
  it('rejects a rule that is not an exact object', () => {
    expect(top({ rules: [5] })).toBe(false);
    expect(top({ rules: [Object.assign([], rule)] })).toBe(false);
    expect(top({ rules: [{ ...rule, extra: 1 }] })).toBe(false);
    const { dp: _dp, ...noDp } = rule;
    void _dp;
    expect(top({ rules: [noDp] })).toBe(false);
  });
  it('rejects each bad rule operand on its own', () => {
    for (const verb of ['', 'v'.repeat(129)]) expect(ok({ verb })).toBe(false);
    for (const resource_prefix of ['', 'p'.repeat(513)]) expect(ok({ resource_prefix })).toBe(false);
    for (const purposes of [[], ['b', 'a'], ['a', 'a'], ['bad purpose'], ps(17)]) expect(ok({ purposes })).toBe(false);
    for (const fns of [[], ['sum', 'count'], ['count', 'count'], ['xcount'], ['countx'], ['avg'], ['count', 'sum', 'sum']]) expect(ok({ fns: fns as never })).toBe(false);
    for (const min_group of [0, -1, 1.5]) expect(ok({ min_group })).toBe(false);
    for (const clamp of [-1, 1.5, 1_000_001]) expect(ok({ clamp })).toBe(false);
    for (const epsilon_micro of [-1, 1.5, 1_073_741_825]) expect(ok({ epsilon_micro })).toBe(false);
    for (const dp of [1, 'true', null]) expect(ok({ dp: dp as never })).toBe(false);
    expect(ok({ dp: true, epsilon_micro: 0 })).toBe(false);
  });
  it('rejects each bad grant operand on its own', () => {
    expect(validAggregateGrantBody(null)).toBe(false);
    expect(validAggregateGrantBody(Object.assign([], aBody))).toBe(false);
    expect(top({ extra: 1 })).toBe(false);
    expect(top({ v: 2 })).toBe(false);
    for (const id of ['', 'a b', ['ag'], 5]) expect(top({ id })).toBe(false);
    for (const principal of ['abc', 5]) expect(top({ principal })).toBe(false);
    for (const t of [-1, 1.5, '5']) {
      expect(top({ issued_at: t })).toBe(false);
      expect(top({ expires_at: t })).toBe(false);
      expect(top({ epsilon_budget_micro: t })).toBe(false);
      expect(top({ max_queries: t })).toBe(false);
    }
    expect(top({ rules: [] })).toBe(false);
    expect(top({ rules: 'x' })).toBe(false);
    expect(top({ rules: Array.from({ length: 17 }, () => rule) })).toBe(false);
    expect(top({ rules: [rule, { ...rule, min_group: 0 }] })).toBe(false);
  });
  it('signAggregateGrant refuses a malformed body or a body for another key', () => {
    expect(() => signAggregateGrant(P, { ...aBody, v: 2 } as never)).toThrow(RangeError);
    expect(() => signAggregateGrant(P, { ...aBody, v: 2 } as never)).toThrow('signAggregateGrant: malformed grant');
    expect(() => signAggregateGrant(new Uint8Array(32).fill(72), aBody)).toThrow('signAggregateGrant: malformed grant');
  });
});

describe('aggregateRead checks', () => {
  const st = aggregateRead(q({ fn: 'count', values: [1, 2, 3] })).state;
  const keep = (o: Partial<AggregateInput>, code: string) => expect(aggregateRead(q({ state: st, ...o }))).toEqual({ decision: 'deny', code, value: null, state: st, charged_micro: 0 });
  const bare = { decision: 'deny', code: 'bad_request', value: null, state: emptyAggregateState(), charged_micro: 0 };
  it('refuses a malformed state with a bare bad_request refusal', () => {
    const base = { spent_micro: 0, queries: 0, answered: {} };
    for (const s of [Object.assign([], base), { ...base, spent_micro: -1 }, { ...base, spent_micro: 1.5 }, { ...base, queries: -1 }, { ...base, queries: 1.5 }, { ...base, answered: [] }, { ...base, answered: null }, { ...base, answered: { x: 1.5 } }, null]) {
      expect(aggregateRead(q({ state: s as never })), JSON.stringify(s)).toEqual(bare);
    }
  });
  it('a throwing request is a bare bad_request refusal', () => {
    expect(aggregateRead(null as never)).toEqual(bare);
  });
  it('refuses a bad principal or time and keeps the state', () => {
    keep({ principal: 'abc' }, 'bad_request');
    keep({ now: null as never }, 'bad_request');
    keep({ now: -1 }, 'bad_request');
  });
  it('names the exact refusal for each grant defect and keeps the state', () => {
    keep({ grant: null }, 'bad_grant');
    keep({ grant: { ...ag, extra: 1 } }, 'bad_grant');
    keep({ grant: { body: { ...aBody, v: 2 }, sig: ag.sig } }, 'bad_grant');
    const named = { ...aBody, principal: YPK };
    keep({ grant: { body: named, sig: signBody(P, 'atlas-pca/aggregate-grant/v1\0', named) } }, 'bad_signature');
    keep({ now: aBody.issued_at - 1 }, 'not_yet');
    keep({ now: aBody.expires_at }, 'expired');
  });
  it('the grant window starts at issued_at', () => {
    expect(aggregateRead(q({ now: aBody.issued_at })).decision).toBe('allow');
  });
  it('refuses each malformed request field on its own', () => {
    keep({ verb: '' }, 'bad_request');
    keep({ verb: 'v'.repeat(129) }, 'bad_request');
    keep({ resource: '' }, 'bad_request');
    keep({ resource: `orders/${'r'.repeat(506)}` }, 'bad_request');
    keep({ purpose: ['analytics'] as never }, 'bad_request');
    keep({ purpose: 'bad purpose' }, 'bad_request');
    keep({ fn: 'avg' as never }, 'bad_request');
    keep({ noise: 'bogus' as never }, 'bad_request');
    keep({ salt: 'short-salt-15ch' }, 'bad_request');
    keep({ salt: Array.from({ length: 16 }, () => 'a') as never }, 'bad_request');
    keep({ values: 'abc' as never }, 'bad_request');
    keep({ values: [1, 2, 3.5] }, 'bad_request');
    keep({ values: arrOf(1_000_001) }, 'bad_request');
  });
  it('accepts a salt of exactly 16 characters and 1,000,000 values', () => {
    expect(aggregateRead(q({ salt: 'exactly-16-chars' })).decision).toBe('allow');
    expect(aggregateRead(q({ fn: 'count', values: arrOf(1_000_000) })).decision).toBe('allow');
  });
});

describe('aggregate noise source', () => {
  afterEach(() => vi.restoreAllMocks());
  const spy = () => vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation(((a: Uint8Array) => {
    a.fill(7);
    return a;
  }) as never);
  it('secure mode draws from the system random source and nothing else', () => {
    const s = spy();
    const r = aggregateRead(q({ fn: 'count', values: [1, 2, 3], noise: 'secure' }));
    expect(s).toHaveBeenCalledTimes(1);
    expect(r.decision).toBe('allow');
    expect(r.value).toBe(3 + discreteLaplace(seededDraws(b64u(new Uint8Array(32).fill(7))), 500_000, 1_000_000));
  });
  it('seeded mode never touches the system random source', () => {
    const s = spy();
    expect(aggregateRead(q({ fn: 'count', values: [1, 2, 3], noise: 'seeded' })).decision).toBe('allow');
    expect(s).not.toHaveBeenCalled();
  });
});
