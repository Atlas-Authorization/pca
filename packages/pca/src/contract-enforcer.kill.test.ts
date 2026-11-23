import { describe, expect, it } from 'vitest';
import { ContractEnforcer, ContractEnforcerError, signContractReset } from './contract-enforcer';
import { CONTRACT_VERSION, signContract, type Clause } from './contracts';
import { createMemoryDurableKv, type DurableKv } from './durable-state';
import { encodeKey, generateKeyPair } from './keys';
import type { ActionContext } from './predicates';
import { emptyState } from './prohibitions';

const P = generateKeyPair();
const PRIN = encodeKey(P.publicKey);
const act = (verb: string): ActionContext => ({ action: { verb, resource: '/r' } });
const clauses: Clause[] = [
  { id: 'no-delete', kind: 'never', p: { verb: 'delete' } },
  { id: 'review-first', kind: 'precedes', p: { verb: 'review' }, q: { verb: 'deploy' } },
];
const sc = signContract({ version: CONTRACT_VERSION, principal: PRIN, clauses }, P.secretKey);
const KEY = `contract/${sc.id}`;
const T0 = 1_700_000_000_000;
const open = (kv: DurableKv, extra = {}) => ContractEnforcer.open(kv, sc, { principal: PRIN, now: () => T0, ...extra });
const STATE_ERR = { allow: false, reason: 'state-error', violated: [], reasons: ['<state>: stored state is corrupt or belongs to another contract'], seq: 0 };

describe('ContractEnforcerError', () => {
  it('carries its class name and prefixed message', () => {
    const e = new ContractEnforcerError('boom');
    expect(e.name).toBe('ContractEnforcerError');
    expect(e.message).toBe('ContractEnforcer: boom');
    expect(e).toBeInstanceOf(Error);
  });
});

describe('open: principal pin', () => {
  it('missing options object throws the typed error, not a TypeError', () => {
    expect(() => ContractEnforcer.open(createMemoryDurableKv(), sc, undefined as never)).toThrow(ContractEnforcerError);
    expect(() => ContractEnforcer.open(createMemoryDurableKv(), sc, undefined as never)).toThrow('ContractEnforcer: a pinned principal is required');
  });
  it('an empty principal string is refused before verification', () => {
    expect(() => ContractEnforcer.open(createMemoryDurableKv(), sc, { principal: '' })).toThrow('ContractEnforcer: a pinned principal is required');
  });
});

describe('stored document shape (isDoc)', () => {
  it('a null document is a state error (not a crash into store-error)', async () => {
    const kv = createMemoryDurableKv();
    await kv.set(KEY, null);
    const e = open(kv);
    expect(await e.check(act('review'))).toEqual(STATE_ERR);
    expect(await e.peek(act('review'))).toEqual(STATE_ERR);
    await expect(e.state()).rejects.toThrow('ContractEnforcer: stored state is corrupt or belongs to another contract');
  });
  it('a primitive document is refused even when its prototype carries doc-shaped fields', async () => {
    const kv = createMemoryDurableKv();
    await kv.set(KEY, 5);
    const e = open(kv);
    const proto = Number.prototype as unknown as Record<string, unknown>;
    const fields = { v: 1, contract_id: sc.id, state: emptyState(T0) };
    for (const [k, v] of Object.entries(fields)) Object.defineProperty(proto, k, { value: v, configurable: true, writable: true });
    try {
      await expect(e.state()).rejects.toThrow(ContractEnforcerError);
    } finally {
      for (const k of Object.keys(fields)) delete proto[k];
    }
  });
  it('a document of another version is refused', async () => {
    const kv = createMemoryDurableKv();
    const e = open(kv);
    await e.check(act('review'));
    const doc = (await kv.get(KEY)) as Record<string, unknown>;
    await kv.set(KEY, { ...doc, v: 2 });
    expect(await e.check(act('review'))).toEqual(STATE_ERR);
    await kv.set(KEY, { ...doc, v: 1 });
    expect(await e.check(act('review'))).toEqual({ allow: true, reason: 'ok', violated: [], reasons: [], seq: 2 });
  });
  it('a latch whose violated list holds a non-string is corrupt', async () => {
    const kv = createMemoryDurableKv();
    const e = open(kv);
    await e.check(act('delete'));
    const doc = (await kv.get(KEY)) as { latched: Record<string, unknown> };
    await kv.set(KEY, { ...doc, latched: { seq: 0, violated: ['no-delete', 5] } });
    expect(await e.check(act('review'))).toEqual(STATE_ERR);
    await kv.set(KEY, { ...doc, latched: { seq: 0, violated: ['no-delete', 'x'] } });
    expect(await e.check(act('review'))).toEqual({ allow: false, reason: 'latched', violated: ['no-delete', 'x'], reasons: ['<latched>: contract violated at seq 0'], seq: 0 });
  });
});

describe('check: exact results', () => {
  it('a store whose update never runs the callback reports store unavailable', async () => {
    const kv: DurableKv = { ...createMemoryDurableKv(), update: async () => undefined };
    expect(await open(kv).check(act('review'))).toEqual({ allow: false, reason: 'store-error', violated: [], reasons: ['store unavailable'], seq: 0 });
  });
  it('a throwing store reports store error (fail closed)', async () => {
    const kv: DurableKv = { ...createMemoryDurableKv(), update: async () => { throw new Error('down'); } };
    expect(await open(kv).check(act('review'))).toEqual({ allow: false, reason: 'store-error', violated: [], reasons: ['store error (fail closed)'], seq: 0 });
  });
  it('a non-finite clock with stored state is a state error at the stored seq', async () => {
    const kv = createMemoryDurableKv();
    await open(kv).check(act('review'));
    expect(await open(kv, { now: () => Number.NaN }).check(act('review'))).toEqual({ allow: false, reason: 'state-error', violated: [], reasons: ['<state>: clock is not finite'], seq: 1 });
  });
  it('a non-finite clock with no stored state reaches the contract advance and is refused there (not a store error)', async () => {
    const kv = createMemoryDurableKv();
    const e = open(kv, { now: () => Number.NaN });
    const r = await e.check(act('review'));
    expect(r).toMatchObject({ allow: false, reason: 'state-error', violated: [], seq: 0 });
    expect(r.reasons).toContain('<state>: advance failed: clock regression');
    expect(await e.state()).toBeUndefined();
  });
  it('the state clock advances to the later wall time', async () => {
    const kv = createMemoryDurableKv();
    let t = 1000;
    const e = open(kv, { now: () => t });
    await e.check(act('review'));
    expect((await e.state())?.state.now).toBe(1000);
    t = 5000;
    await e.check(act('review'));
    expect((await e.state())?.state.now).toBe(5000);
    t = 2000;
    await e.check(act('review'));
    expect((await e.state())?.state.now).toBe(5000);
  });
  it('a malformed action is a structural state-error that does not latch', async () => {
    const kv = createMemoryDurableKv();
    const e = open(kv);
    const bad = { action: { verb: 5, resource: '/r' } } as unknown as ActionContext;
    const r = await e.check(bad);
    expect(r.allow).toBe(false);
    expect(r.reason).toBe('state-error');
    expect(r.violated).toEqual([]);
    expect(r.seq).toBe(0);
    expect(await e.check(act('review'))).toEqual({ allow: true, reason: 'ok', violated: [], reasons: [], seq: 1 });
    expect((await e.state())?.latched).toBe(false);
  });
});

describe('peek: exact results', () => {
  it('ok, latched, and a throwing store', async () => {
    const kv = createMemoryDurableKv();
    const e = open(kv);
    expect(await e.peek(act('review'))).toEqual({ allow: true, reason: 'ok', violated: [], reasons: [], seq: 0 });
    await e.check(act('review'));
    expect(await e.peek(act('review'))).toEqual({ allow: true, reason: 'ok', violated: [], reasons: [], seq: 1 });
    await e.check(act('delete'));
    expect(await e.peek(act('review'))).toEqual({ allow: false, reason: 'latched', violated: ['no-delete'], reasons: ['<latched>: contract violated at seq 1'], seq: 1 });
    const broken: DurableKv = { ...createMemoryDurableKv(), get: async () => { throw new Error('down'); } };
    expect(await open(broken).peek(act('review'))).toEqual({ allow: false, reason: 'store-error', violated: [], reasons: ['store error (fail closed)'], seq: 0 });
  });
});

describe('reset: refusals', () => {
  it('a corrupt document that carries a latch is never cleared, even with a valid signature', async () => {
    const kv = createMemoryDurableKv();
    const e = open(kv);
    await e.check(act('delete'));
    const doc = (await kv.get(KEY)) as Record<string, unknown>;
    await kv.set(KEY, { ...doc, v: 2 });
    expect(await e.reset(signContractReset(P.secretKey, sc.id, 0))).toBe(false);
    expect(((await kv.get(KEY)) as Record<string, unknown>).latched).toEqual({ seq: 0, violated: ['no-delete'] });
  });
  it('an unlatched document is not reset', async () => {
    const kv = createMemoryDurableKv();
    const e = open(kv);
    await e.check(act('review'));
    expect(await e.reset(signContractReset(P.secretKey, sc.id, 0))).toBe(false);
  });
  it('a store that fails after the callback approved the reset reports false', async () => {
    const inner = createMemoryDurableKv();
    await open(inner).check(act('delete'));
    const kv: DurableKv = {
      ...inner,
      update: async (k, fn) => {
        fn(await inner.get(k));
        throw new Error('write failed');
      },
    };
    expect(await open(kv).reset(signContractReset(P.secretKey, sc.id, 0))).toBe(false);
  });
});
