/** Operation records at their edges: stores, stale settlement, races with a concurrent recovery, and the executor's replay path. */
import { describe, expect, it } from 'vitest';
import { mintGrant } from '../envelope';
import { hashCanonical } from '../hash';
import { encodeKey, generateKeyPair } from '../keys';
import { paramsDigest, type PlanNode } from '../merkle';
import { buildPCActn, encodePCActn, type PCActn } from '../pcactn';
import { type RiskPolicy } from '../risk';
import { createAuthorizer, type AuthorizeOptions, type AuthorizeResult } from './authorize';
import {
  createExecutor,
  durableOperationStore,
  executeAuthorized,
  memoryOperationStore,
  recoverOperation,
  recoverOperations,
  resolveOperation,
  type ExecutionHandle,
  type ExecutorOutcome,
  type OperationRecord,
  type OperationStore,
} from './operations';
import { memoryAtomicKv, type PlanRegistry } from './plan-lifecycle';
import { atomicMemoryPcaStore, type AtomicKv } from './require-pca';
import type { PcaOperation } from './verify';
import { principalDirect } from '../test-support/provenance';

const NOW = Date.UTC(2026, 9, 25, 12, 0, 0);
const AUD = 'payments-rs';
const VERB = 'payments.send';
const RES = 'payments';
const ZERO: RiskPolicy = { weights: { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 }, theta1: 1, theta2: 1, kappa: 100, lambda: 0, rho: 0.5, bMax: 1_000_000 };
const T = 60_000;

function setup() {
  const principal = generateKeyPair();
  const holder = generateKeyPair();
  const { grant } = mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: encodeKey(principal.publicKey),
    holder: encodeKey(holder.publicKey),
    goal: 'pay invoices',
    envelope: { predicates: [{ verb: VERB, resource: '*', where: [{ field: 'action.params.amount', op: 'lte', value: 100 }] }], caveats: [], agent_binding: {}, risk_policy: ZERO },
  });
  let counter = 0;
  const sign = (params: Record<string, unknown>, cls = 'irreversible'): PCActn => {
    const node: PlanNode = { id: 'n1', verb: VERB, resource: RES, params_digest: paramsDigest(params), reversibility_class: cls };
    return buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n1', params, counter: ++counter, signerSecret: holder.secretKey, aud: AUD, now: NOW });
  };
  return { grant, sign };
}

const op = (amount: number): PcaOperation & { params: Record<string, unknown> } => ({ verb: VERB, resource: RES, params: { payee: 'acme', amount } });
const world = () => ({ t: NOW, revoked: false });

function azOptions(grant: { id: string }, w: ReturnType<typeof world>, over: Partial<AuthorizeOptions> = {}): AuthorizeOptions {
  return {
    provenance: principalDirect(),
    audience: AUD,
    resolveGrant: async (ref) => (ref === grant.id ? (grant as never) : null),
    budgetStore: atomicMemoryPcaStore(),
    hooks: { revocation: () => ({ enforced: true, ok: !w.revoked, ...(w.revoked ? { reason: 'revoked' } : {}) }) },
    plan: 'single-step',
    now: () => w.t,
    ...over,
  };
}

function counted<V>(value: V) {
  const s = { runs: 0 };
  const fn = async (_h: ExecutionHandle): Promise<V> => {
    s.runs++;
    return value;
  };
  return { s, fn };
}

const allowOk = () => ({ ok: true }) as const;

const failedChecks = (o: ExecutorOutcome<unknown>): string[] => (o.status === 'denied' ? Object.entries(o.authorization.verdict.checks).filter(([, s]) => s === 'fail').map(([k]) => k) : []);

async function authorized(): Promise<{ r: Extract<AuthorizeResult, { allow: true }>; w: ReturnType<typeof world> }> {
  const { grant, sign } = setup();
  const w = world();
  const r = await createAuthorizer(azOptions(grant, w))({ pcactn: sign(op(50).params), operation: op(50) });
  if (!r.allow) throw new Error(`fixture: not allowed: ${r.reason}`);
  return { r, w };
}

const base = { verb: VERB, resource: RES, params_digest: 'd', reversibility: 'irreversible' as const };
const recOf = (id: string, over: Partial<OperationRecord> = {}): OperationRecord => ({ id, state: 'pending', startedAt: NOW, ...base, ...over });

/** The record for `r` as executeAuthorized would claim it, put in the store first (state as given). */
async function seed(store: OperationStore, r: Extract<AuthorizeResult, { allow: true }>, over: Partial<OperationRecord>): Promise<void> {
  await store.create({ id: r.operation.id, state: 'pending', verb: VERB, resource: RES, params_digest: r.operation.params_digest, reversibility: 'irreversible', startedAt: NOW, ...over } as OperationRecord);
}

describe('memoryOperationStore', () => {
  it('transition is a compare-and-set: a wrong state or a missing id answers false and changes nothing', async () => {
    const s = memoryOperationStore();
    await s.create(recOf('a'));
    expect(await s.transition('a', 'executing', recOf('a', { state: 'committed' }))).toBe(false);
    expect(await s.get('a')).toEqual(recOf('a'));
    expect(await s.transition('missing', 'pending', recOf('missing', { state: 'executing' }))).toBe(false);
    expect(await s.get('missing')).toBeUndefined();
    expect(await s.transition('a', 'pending', recOf('a', { state: 'executing' }))).toBe(true);
  });
  it('listOpen returns only pending and executing records', async () => {
    const s = memoryOperationStore();
    await s.create(recOf('p'));
    await s.create(recOf('e'));
    await s.transition('e', 'pending', recOf('e', { state: 'executing' }));
    await s.create(recOf('c'));
    await s.transition('c', 'pending', recOf('c', { state: 'committed' }));
    const open = await s.listOpen!();
    expect(open.map((x) => `${x.id}:${x.state}`).sort()).toEqual(['e:executing', 'p:pending']);
  });
});

describe('durableOperationStore', () => {
  it('reads only well-formed records: null, a non-object, a missing id or a missing state is "no record"', async () => {
    const kv = memoryAtomicKv();
    const s = durableOperationStore(kv);
    await kv.set('pca-op:n', null);
    await kv.set('pca-op:j', 'junk');
    await kv.set('pca-op:i', { state: 'pending' });
    await kv.set('pca-op:t', { id: 't' });
    await kv.set('pca-op:ok', recOf('ok'));
    expect(await s.get('n')).toBeUndefined();
    expect(await s.get('j')).toBeUndefined();
    expect(await s.get('i')).toBeUndefined();
    expect(await s.get('t')).toBeUndefined();
    expect(await s.get('ok')).toEqual(recOf('ok'));
  });
  it('keys default to the pca-op: prefix; a given prefix replaces it', async () => {
    const kv = memoryAtomicKv();
    await durableOperationStore(kv).create(recOf('x'));
    expect(await kv.get('pca-op:x')).toEqual(recOf('x'));
    const kv2 = memoryAtomicKv();
    await durableOperationStore(kv2, { prefix: 'p/' }).create(recOf('x'));
    expect(await kv2.get('p/x')).toEqual(recOf('x'));
    expect(await kv2.get('pca-op:x')).toBeUndefined();
  });
  it('scope defaults to shared; a given scope is kept', () => {
    expect(durableOperationStore(memoryAtomicKv()).scope).toBe('shared');
    expect(durableOperationStore(memoryAtomicKv(), { scope: 'process' }).scope).toBe('process');
  });
  it('a key/value store that never applies the update reports the transition as not done', async () => {
    const kv: AtomicKv = { get: async () => undefined, set: async () => undefined, update: async () => undefined };
    expect(await durableOperationStore(kv).transition('x', 'pending', recOf('x', { state: 'executing' }))).toBe(false);
  });
});

describe('settling stale records (recoverOperation)', () => {
  it('a pending record exactly olderThanMs old is not stale yet', async () => {
    const s = memoryOperationStore();
    await s.create(recOf('a'));
    expect(await recoverOperation(s, 'a', { olderThanMs: T, now: () => NOW + T })).toEqual(recOf('a'));
    expect(await recoverOperation(s, 'a', { olderThanMs: T, now: () => NOW + T + 1 })).toEqual(
      recOf('a', { state: 'aborted', error: `not started within ${T} ms of the claim: the side effect never ran`, finishedAt: NOW + T + 1 }),
    );
  });
  it('an executing record is aged from executingAt, not from startedAt', async () => {
    const s = memoryOperationStore();
    const running = recOf('e', { state: 'executing', executingAt: NOW + 50 });
    await s.create(recOf('e'));
    await s.transition('e', 'pending', running);
    expect(await recoverOperation(s, 'e', { olderThanMs: T, now: () => NOW + T + 10 })).toEqual(running);
    expect(await recoverOperation(s, 'e', { olderThanMs: T, now: () => NOW + 50 + T + 1 })).toEqual({
      ...running,
      state: 'uncertain',
      error: `no outcome recorded within ${T} ms of the start: the side effect may or may not have happened`,
      finishedAt: NOW + 50 + T + 1,
    });
  });
  it('an executing record without executingAt is aged from startedAt', async () => {
    const s = memoryOperationStore();
    await s.create(recOf('e'));
    await s.transition('e', 'pending', recOf('e', { state: 'executing' }));
    expect((await recoverOperation(s, 'e', { olderThanMs: T, now: () => NOW + T + 1 }))?.state).toBe('uncertain');
  });
  it('a pending record is aged from startedAt even when it carries an executingAt', async () => {
    const s = memoryOperationStore();
    await s.create(recOf('p', { executingAt: NOW + 1000 }));
    expect((await recoverOperation(s, 'p', { olderThanMs: T, now: () => NOW + T + 1 }))?.state).toBe('aborted');
  });
  it('when the original execution finishes first, the stored record is returned, not the attempted settlement', async () => {
    const inner = memoryOperationStore();
    const s: OperationStore = {
      ...inner,
      async transition(id, from, next) {
        if (next.state === 'aborted') await inner.transition(id, 'pending', recOf(id, { state: 'committed', result: 'won' }));
        return inner.transition(id, from, next);
      },
    };
    await inner.create(recOf('r'));
    expect(await recoverOperation(s, 'r', { olderThanMs: T, now: () => NOW + T + 1 })).toEqual(recOf('r', { state: 'committed', result: 'won' }));
  });
  it('recoverOperations without listOpen throws its own message', async () => {
    let msg = '';
    try {
      await recoverOperations(durableOperationStore(memoryAtomicKv()));
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).toBe('recoverOperations: the store has no listOpen (recover by id with recoverOperation)');
  });
});

describe('executeAuthorized: what counts as an allowed authorization', () => {
  const REFUSED = { status: 'refused', reason: 'executeAuthorized: the authorization did not allow an operation' };
  it('null and a primitive are refused (no throw)', async () => {
    const { w } = await authorized();
    const c = counted(1);
    const o = { store: memoryOperationStore(), recheck: allowOk, now: () => w.t };
    expect(await executeAuthorized(null as never, c.fn, o)).toEqual(REFUSED);
    expect(await executeAuthorized('allow' as never, c.fn, o)).toEqual(REFUSED);
    expect(c.s.runs).toBe(0);
  });
  it('ok: false refuses even with an allowed verdict, a PCActn and an operation', async () => {
    const { r, w } = await authorized();
    const c = counted(1);
    expect(await executeAuthorized({ ok: false, verdict: r.verdict, pcactn: r.pcactn, operation: r.operation } as never, c.fn, { store: memoryOperationStore(), recheck: allowOk, now: () => w.t })).toEqual(REFUSED);
    expect(c.s.runs).toBe(0);
  });
  it('allow: true is refused when the verdict is missing or does not allow', async () => {
    const { r, w } = await authorized();
    const c = counted(1);
    const o = () => ({ store: memoryOperationStore(), recheck: allowOk, now: () => w.t });
    expect(await executeAuthorized({ allow: true, verdict: { ...r.verdict, allow: false }, pcactn: r.pcactn, operation: r.operation } as never, c.fn, o())).toEqual(REFUSED);
    expect(await executeAuthorized({ allow: true, pcactn: r.pcactn, operation: r.operation } as never, c.fn, o())).toEqual(REFUSED);
    expect(c.s.runs).toBe(0);
  });
  it('an attached result without a verdict is refused (no throw)', async () => {
    const { r, w } = await authorized();
    const c = counted(1);
    expect(await executeAuthorized({ pcactn: r.pcactn, operation: r.operation } as never, c.fn, { store: memoryOperationStore(), recheck: allowOk, now: () => w.t })).toEqual(REFUSED);
    expect(c.s.runs).toBe(0);
  });
  it('the verdict is re-read for the final decision: one that stops allowing is refused', async () => {
    const { r, w } = await authorized();
    const c = counted(1);
    let reads = 0;
    const flaky = {
      pcactn: r.pcactn,
      operation: r.operation,
      get verdict() {
        reads++;
        return reads === 1 ? r.verdict : { ...r.verdict, allow: false };
      },
    };
    expect(await executeAuthorized(flaky as never, c.fn, { store: memoryOperationStore(), recheck: allowOk, now: () => w.t })).toEqual(REFUSED);
    expect(c.s.runs).toBe(0);
  });
  it('an empty operation id is refused', async () => {
    const { r, w } = await authorized();
    const c = counted(1);
    expect(await executeAuthorized({ ...r, operation: { ...r.operation, id: '' } }, c.fn, { store: memoryOperationStore(), recheck: allowOk, now: () => w.t })).toEqual(REFUSED);
    expect(c.s.runs).toBe(0);
  });
});

describe('executeAuthorized: configuration', () => {
  const NO_STORE = { status: 'refused', reason: 'executeAuthorized: missing required component: store (fail closed)' };
  it('no options at all, or a store missing any one method, is refused', async () => {
    const { r, w } = await authorized();
    const c = counted(1);
    expect(await executeAuthorized(r, c.fn, undefined as never)).toEqual(NO_STORE);
    const full = memoryOperationStore();
    const { create: _c, ...noCreate } = full;
    const { get: _g, ...noGet } = full;
    const { transition: _t, ...noTransition } = full;
    void _c;
    void _g;
    void _t;
    for (const store of [noCreate, noGet, noTransition]) {
      expect(await executeAuthorized(r, c.fn, { store: store as OperationStore, recheck: allowOk, now: () => w.t })).toEqual(NO_STORE);
    }
    expect(c.s.runs).toBe(0);
  });
  it('a PCActn without an action counts as irreversible (needs a recheck)', async () => {
    const { r, w } = await authorized();
    const c = counted(1);
    const attached = { verdict: r.verdict, pcactn: { ...r.pcactn, action: undefined } as unknown as PCActn, operation: r.operation };
    expect(await executeAuthorized(attached, c.fn, { store: memoryOperationStore(), now: () => w.t })).toEqual({
      status: 'refused',
      reason: 'executeAuthorized: a irreversible operation needs a recheck (revocation, expiry, approval) before it runs (fail closed)',
    });
  });
  it('a given pendingTimeoutMs settles an older claim; the default is 5 minutes', async () => {
    const { r } = await authorized();
    const c = counted(1);
    const s1 = memoryOperationStore();
    await seed(s1, r, {});
    expect(await executeAuthorized(r, c.fn, { store: s1, recheck: allowOk, pendingTimeoutMs: 1000, now: () => NOW + 1001 })).toEqual({
      status: 'aborted',
      operationId: r.operation.id,
      reason: 'not started within 1000 ms of the claim: the side effect never ran',
      replayed: true,
    });
    const s2 = memoryOperationStore();
    await seed(s2, r, {});
    expect(await executeAuthorized(r, c.fn, { store: s2, recheck: allowOk, now: () => NOW + 300_001 })).toEqual({
      status: 'aborted',
      operationId: r.operation.id,
      reason: 'not started within 300000 ms of the claim: the side effect never ran',
      replayed: true,
    });
    expect(c.s.runs).toBe(0);
  });
});

describe('executeAuthorized: answers from an existing record never run fn', () => {
  it('a claim that is still pending answers pending (fn and the recheck do not run)', async () => {
    const { r, w } = await authorized();
    const c = counted(1);
    let rechecks = 0;
    const s = memoryOperationStore();
    await seed(s, r, { startedAt: w.t });
    const out = await executeAuthorized(r, c.fn, { store: s, recheck: () => (rechecks++, { ok: true }), now: () => w.t });
    expect(out).toEqual({ status: 'pending', operationId: r.operation.id, replayed: true });
    expect([c.s.runs, rechecks]).toEqual([0, 0]);
  });
  it('a stored record without an error gets the default text per state; an unknown state is uncertain', async () => {
    const { r, w } = await authorized();
    const c = counted(1);
    const answer = async (over: Partial<OperationRecord>) => {
      const s = memoryOperationStore();
      await seed(s, r, over);
      return executeAuthorized(r, c.fn, { store: s, recheck: allowOk, now: () => w.t });
    };
    const id = r.operation.id;
    expect(await answer({ state: 'failed' })).toEqual({ status: 'failed', operationId: id, error: 'failed', replayed: true });
    expect(await answer({ state: 'aborted' })).toEqual({ status: 'aborted', operationId: id, reason: 'aborted', replayed: true });
    expect(await answer({ state: 'uncertain' })).toEqual({ status: 'uncertain', operationId: id, reason: 'outcome unknown', replayed: true });
    expect(await answer({ state: 'weird' as never })).toEqual({ status: 'uncertain', operationId: id, reason: "unknown record state 'weird'", replayed: true });
    expect(c.s.runs).toBe(0);
  });
});

describe('executeAuthorized: the recheck and the expiry', () => {
  it('an expiry given as a string is not a number: it is not compared', async () => {
    const { r, w } = await authorized();
    const c = counted('ran');
    const attached = { verdict: r.verdict, pcactn: { ...r.pcactn, exp: '1' } as unknown as PCActn, operation: r.operation };
    expect((await executeAuthorized(attached, c.fn, { store: memoryOperationStore(), recheck: allowOk, now: () => w.t })).status).toBe('committed');
    expect(c.s.runs).toBe(1);
  });
  it('executing exactly at exp is still allowed', async () => {
    const { r } = await authorized();
    const c = counted('ran');
    expect((await executeAuthorized(r, c.fn, { store: memoryOperationStore(), recheck: allowOk, now: () => r.pcactn.exp })).status).toBe('committed');
  });
  it('a recheck answering nothing, ok: false without a reason, or a non-boolean ok is a plain refusal', async () => {
    const { r, w } = await authorized();
    const c = counted(1);
    const run = (recheck: () => unknown) => executeAuthorized(r, c.fn, { store: memoryOperationStore(), recheck: recheck as never, now: () => w.t });
    const refused = { status: 'aborted', operationId: r.operation.id, reason: 'recheck: refused', replayed: false };
    expect(await run(() => undefined)).toEqual(refused);
    expect(await run(() => ({ ok: false }))).toEqual(refused);
    expect(await run(() => ({ ok: 'no', reason: 'x' }))).toEqual(refused);
    expect(c.s.runs).toBe(0);
  });
});

describe('executeAuthorized: a concurrent recovery or writer', () => {
  it('a recovery that settled the running execution as uncertain is overwritten by the real outcome', async () => {
    const { r, w } = await authorized();
    const s = memoryOperationStore();
    const fn = async () => {
      const cur = (await s.get(r.operation.id)) as OperationRecord;
      expect(await s.transition(cur.id, 'executing', { ...cur, state: 'uncertain', error: 'slow' })).toBe(true);
      return 'done';
    };
    expect(await executeAuthorized(r, fn, { store: s, recheck: allowOk, now: () => w.t })).toEqual({ status: 'committed', operationId: r.operation.id, result: 'done', replayed: false, recorded: true });
    expect((await s.get(r.operation.id))?.state).toBe('committed');
  });
  it('a record moved to another final state meanwhile is not overwritten (recorded: false)', async () => {
    const { r, w } = await authorized();
    const s = memoryOperationStore();
    const fn = async () => {
      const cur = (await s.get(r.operation.id)) as OperationRecord;
      expect(await s.transition(cur.id, 'executing', { ...cur, state: 'failed', error: 'elsewhere' })).toBe(true);
      return 'done';
    };
    expect(await executeAuthorized(r, fn, { store: s, recheck: allowOk, now: () => w.t })).toEqual({ status: 'committed', operationId: r.operation.id, result: 'done', replayed: false, recorded: false });
    expect(await s.get(r.operation.id)).toMatchObject({ state: 'failed', error: 'elsewhere' });
  });
  it('a refused recheck whose claim was settled meanwhile answers from the stored record', async () => {
    const { r, w } = await authorized();
    const s = memoryOperationStore();
    const recheck = async () => {
      const cur = (await s.get(r.operation.id)) as OperationRecord;
      await s.transition(cur.id, 'pending', { ...cur, state: 'uncertain', error: 'settled elsewhere' });
      return { ok: false as const, reason: 'no' };
    };
    expect(await executeAuthorized(r, counted(1).fn, { store: s, recheck, now: () => w.t })).toEqual({ status: 'uncertain', operationId: r.operation.id, reason: 'settled elsewhere', replayed: true });
    expect((await s.get(r.operation.id))?.state).toBe('uncertain');
  });
  it('a record that disappeared after the claim is reported as such', async () => {
    const { r, w } = await authorized();
    const s: OperationStore = { create: async () => ({ created: true }), get: async () => undefined, transition: async () => false };
    const c = counted(1);
    expect(await executeAuthorized(r, c.fn, { store: s, recheck: allowOk, now: () => w.t })).toEqual({
      status: 'uncertain',
      operationId: r.operation.id,
      reason: 'the operation record disappeared',
      replayed: true,
    });
    expect(c.s.runs).toBe(0);
  });
});

describe('resolveOperation', () => {
  it('settles an uncertain record as failed with the given clock, and as committed with it', async () => {
    const s = memoryOperationStore();
    const u = recOf('u', { state: 'uncertain', error: 'slow' });
    await s.create(u);
    expect(await resolveOperation(s, 'u', { state: 'failed', error: 'never applied' }, { now: () => 777 })).toBe(true);
    expect(await s.get('u')).toEqual({ ...u, state: 'failed', error: 'never applied', finishedAt: 777 });
    const s2 = memoryOperationStore();
    await s2.create(u);
    expect(await resolveOperation(s2, 'u', { state: 'committed', result: 'r' }, { now: () => 778 })).toBe(true);
    expect(await s2.get('u')).toEqual({ ...u, state: 'committed', result: 'r', finishedAt: 778 });
  });
  it('a missing record, or one that was not uncertain when read, is not resolved', async () => {
    const inner = memoryOperationStore();
    expect(await resolveOperation(inner, 'missing', { state: 'failed', error: 'x' })).toBe(false);
    // the record becomes uncertain right after it was read as executing: the decision stands on what was read
    const s: OperationStore = {
      ...inner,
      async get(id) {
        const cur = await inner.get(id);
        if (cur?.state === 'executing') await inner.transition(id, 'executing', { ...cur, state: 'uncertain' });
        return cur;
      },
    };
    await inner.create(recOf('e'));
    await inner.transition('e', 'pending', recOf('e', { state: 'executing' }));
    expect(await resolveOperation(s, 'e', { state: 'committed', result: 1 }, { now: () => 1 })).toBe(false);
    expect((await inner.get('e'))?.state).toBe('uncertain');
  });
});

describe('createExecutor', () => {
  /** A store that runs `onCreate` when the claim is made (after authorize, before the recheck). */
  const armed = (onCreate: () => void): OperationStore => {
    const inner = memoryOperationStore();
    return {
      ...inner,
      async create(rec) {
        onCreate();
        return inner.create(rec);
      },
    };
  };

  it('an operations store missing any one method is refused', async () => {
    const { grant, sign } = setup();
    const w = world();
    const full = memoryOperationStore();
    const { create: _c, ...noCreate } = full;
    const { get: _g, ...noGet } = full;
    const { transition: _t, ...noTransition } = full;
    void _c;
    void _g;
    void _t;
    for (const operations of [noCreate, noGet, noTransition]) {
      const ex = createExecutor({ ...azOptions(grant, w), operations: operations as OperationStore });
      expect(await ex({ pcactn: sign(op(50).params), operation: op(50) }, counted(1).fn)).toEqual({
        status: 'refused',
        reason: 'createExecutor: missing required component: operations (fail closed)',
      });
    }
  });

  it('a grant that is gone by execution time aborts', async () => {
    const { grant, sign } = setup();
    const w = world();
    let gone = false;
    const c = counted(1);
    const ex = createExecutor({ ...azOptions(grant, w), resolveGrant: async (ref) => (!gone && ref === grant.id ? (grant as never) : null), operations: armed(() => (gone = true)) });
    const out = await ex({ pcactn: sign(op(50).params), operation: op(50) }, c.fn);
    expect(out).toMatchObject({ status: 'aborted', reason: 'recheck: the grant is no longer known', replayed: false });
    expect(c.s.runs).toBe(0);
  });

  it('the revocation re-check receives the PCActn, the grant and the clock', async () => {
    const { grant, sign } = setup();
    const w = world();
    const seen: unknown[] = [];
    const c = counted('ran');
    const ex = createExecutor({
      ...azOptions(grant, w),
      hooks: {
        revocation: (a: { pcactn?: unknown; grant?: { id?: string }; nowEpoch?: number }) => {
          seen.push(a);
          const ok = !!a.pcactn && a.grant?.id === grant.id && a.nowEpoch === w.t;
          return ok ? { enforced: true, ok: true } : { enforced: true, ok: false, reason: 'bad hook input' };
        },
      } as never,
      operations: memoryOperationStore(),
    });
    expect((await ex({ pcactn: sign(op(50).params), operation: op(50) }, c.fn)).status).toBe('committed');
    expect([c.s.runs, seen.length]).toEqual([1, 2]);
  });

  it('a revocation without a reason, and an unenforced revocation, abort with the default texts', async () => {
    const { grant, sign } = setup();
    const w = world();
    let mode: 'ok' | 'revoked' | 'unenforced' = 'ok';
    const hooks = { revocation: () => (mode === 'ok' ? { enforced: true, ok: true } : mode === 'revoked' ? { enforced: true, ok: false } : { enforced: false, ok: true }) } as never;
    const ex1 = createExecutor({ ...azOptions(grant, w), hooks, operations: armed(() => (mode = 'revoked')) });
    expect(await ex1({ pcactn: sign(op(50).params), operation: op(50) }, counted(1).fn)).toMatchObject({ status: 'aborted', reason: 'recheck: the grant has been revoked' });
    mode = 'ok';
    const ex2 = createExecutor({ ...azOptions(grant, w), hooks, operations: armed(() => (mode = 'unenforced')) });
    expect(await ex2({ pcactn: sign(op(50).params), operation: op(50) }, counted(1).fn)).toMatchObject({ status: 'aborted', reason: 'recheck: revocation could not be checked' });
  });

  describe('a registered plan is re-checked', () => {
    const plansWith = (check: (g: string, root: string, o?: { nodeId?: string; now?: number }) => unknown): PlanRegistry =>
      ({ context: async () => undefined, get: async () => ({ state: 'authorized' }), check: async (g: string, root: string, o?: { nodeId?: string; now?: number }) => check(g, root, o) }) as unknown as PlanRegistry;

    it('with the node id and the clock; an executable plan runs', async () => {
      const { grant, sign } = setup();
      const w = world();
      const c = counted('ran');
      const plans = plansWith((_g, _r, o) => (o?.nodeId === 'n1' && o?.now === w.t ? { state: 'authorized', executable: true } : { state: 'stale', executable: false }));
      const ex = createExecutor({ ...azOptions(grant, w), plans, operations: memoryOperationStore() });
      expect((await ex({ pcactn: sign(op(50).params), operation: op(50) }, c.fn)).status).toBe('committed');
      expect(c.s.runs).toBe(1);
    });
    it('a plan that is no longer executable aborts with its reason, or its state', async () => {
      const { grant, sign } = setup();
      const w = world();
      const ex1 = createExecutor({ ...azOptions(grant, w), plans: plansWith(() => ({ state: 'revoked', executable: false })), operations: memoryOperationStore() });
      expect(await ex1({ pcactn: sign(op(50).params), operation: op(50) }, counted(1).fn)).toMatchObject({ status: 'aborted', reason: 'recheck: plan is revoked' });
      const ex2 = createExecutor({ ...azOptions(grant, w), plans: plansWith(() => ({ state: 'revoked', executable: false, reason: 'withdrawn' })), operations: memoryOperationStore() });
      expect(await ex2({ pcactn: sign(op(50).params), operation: op(50) }, counted(1).fn)).toMatchObject({ status: 'aborted', reason: 'recheck: withdrawn' });
    });
    it('a PCActn that no longer carries a plan is not looked up (and does not throw)', async () => {
      const { grant, sign } = setup();
      const w = world();
      let calls = 0;
      const c = counted('ran');
      const ex = createExecutor({
        ...azOptions(grant, w),
        plans: plansWith(() => ({ state: 'revoked', executable: false })),
        hooks: {
          revocation: (a: { pcactn: { plan?: unknown } }) => {
            if (++calls === 2) delete a.pcactn.plan;
            return { enforced: true, ok: true };
          },
        } as never,
        operations: memoryOperationStore(),
      });
      expect((await ex({ pcactn: sign(op(50).params), operation: op(50) }, c.fn)).status).toBe('committed');
      expect([c.s.runs, calls]).toEqual([1, 2]);
    });
  });

  it('an absent input is a denial (no throw)', async () => {
    const { grant } = setup();
    const w = world();
    const out = await createExecutor({ ...azOptions(grant, w), operations: memoryOperationStore(), reversibilityClassOf: () => 'irreversible' })(undefined as never, counted(1).fn);
    expect([out.status, failedChecks(out)]).toEqual(['denied', ['operation']]);
  });

  it("recheckFor: 'always' re-checks a reversible operation", async () => {
    const { grant, sign } = setup();
    const w = world();
    const c = counted(1);
    const ex = createExecutor({ ...azOptions(grant, w), operations: memoryOperationStore(), recheckFor: 'always', recheck: () => ({ ok: false, reason: 'approval withdrawn' }) });
    expect(await ex({ pcactn: sign(op(10).params, 'reversible'), operation: op(10) }, c.fn)).toMatchObject({ status: 'aborted', reason: 'recheck: approval withdrawn' });
    expect(c.s.runs).toBe(0);
  });

  it("the server's catalog class raises a signed reversible operation to irreversible (re-checked)", async () => {
    const { grant, sign } = setup();
    const w = world();
    const c = counted(1);
    const ex = createExecutor({ ...azOptions(grant, w), operations: memoryOperationStore(), reversibilityClassOf: () => 'irreversible', recheck: () => ({ ok: false, reason: 'approval withdrawn' }) });
    expect(await ex({ pcactn: sign(op(10).params, 'reversible'), operation: op(10) }, c.fn)).toMatchObject({ status: 'aborted', reason: 'recheck: approval withdrawn' });
    expect(c.s.runs).toBe(0);
  });

  describe('the replay path', () => {
    const seeded = async (store: OperationStore, id: string, o: ReturnType<typeof op>, over: Partial<OperationRecord> = {}) =>
      store.create({ id, state: 'committed', verb: o.verb, resource: o.resource, params_digest: hashCanonical(o.params), reversibility: 'irreversible', startedAt: NOW, result: 'seeded', ...over } as OperationRecord);

    it('a denial that is not a replay is never answered from a record, even one under its id', async () => {
      const { grant, sign } = setup();
      const w = world();
      const store = memoryOperationStore();
      const p = sign(op(400).params);
      await seeded(store, hashCanonical(p), op(400));
      const out = await createExecutor({ ...azOptions(grant, w), operations: store })({ pcactn: p, operation: op(400) }, counted(1).fn);
      expect([out.status, failedChecks(out)]).toEqual(['denied', ['policy']]);
    });

    it('a replay that also fails another check is not answered from the record', async () => {
      const { grant, sign } = setup();
      const w = world();
      const store = memoryOperationStore();
      const budgetStore = atomicMemoryPcaStore();
      const p = sign(op(50).params);
      expect((await createExecutor({ ...azOptions(grant, w, { budgetStore }), operations: store })({ pcactn: p, operation: op(50) }, counted('r1').fn)).status).toBe('committed');
      const strict = createExecutor({ ...azOptions(grant, w, { budgetStore }), requireVerifiedPrincipal: true, operations: store });
      const out = await strict({ pcactn: p, operation: op(50) }, counted(1).fn);
      expect([out.status, failedChecks(out)]).toEqual(['denied', ['replay', 'principal']]);
    });

    it('reads the replayed proof from the request with the configured extractor', async () => {
      const { grant, sign } = setup();
      const w = world();
      const enc = encodePCActn(sign(op(50).params));
      const ex = createExecutor({ ...azOptions(grant, w), extract: (req) => (req.headers as Record<string, string | undefined>)['x-proof'] ?? null, operations: memoryOperationStore() });
      const request = { headers: { 'x-proof': enc } };
      expect((await ex({ request, operation: op(50) }, counted('r1').fn)).status).toBe('committed');
      expect(await ex({ request, operation: op(50) }, counted('r2').fn)).toMatchObject({ status: 'committed', result: 'r1', replayed: true });
    });

    it('without a request, the extractor gets an empty headers object', async () => {
      const { grant, sign } = setup();
      const w = world();
      const enc = encodePCActn(sign(op(50).params));
      const ex = createExecutor({ ...azOptions(grant, w), extract: (req) => (req.headers ? enc : null), operations: memoryOperationStore() });
      expect((await ex({ operation: op(50) }, counted('r1').fn)).status).toBe('committed');
      expect(await ex({ operation: op(50) }, counted('r2').fn)).toMatchObject({ status: 'committed', result: 'r1', replayed: true });
    });

    /** An extractor that hands the proof to authorize, then `third` to the replay lookup of the second call. */
    async function replayWith(third: () => unknown, seedNull = false) {
      const { grant, sign } = setup();
      const w = world();
      const enc = encodePCActn(sign(op(50).params));
      const store = memoryOperationStore();
      if (seedNull) await seeded(store, hashCanonical(null), op(50));
      let calls = 0;
      const ex = createExecutor({
        ...azOptions(grant, w),
        extract: () => {
          calls++;
          return (calls === 3 ? third() : enc) as string;
        },
        operations: store,
      });
      expect((await ex({ request: { headers: {} }, operation: op(50) }, counted('r1').fn)).status).toBe('committed');
      const out = await ex({ request: { headers: {} }, operation: op(50) }, counted('r2').fn);
      expect(calls).toBe(3);
      return out;
    }

    it('no proof at the replay lookup (null or undefined) keeps the replay denial', async () => {
      for (const [third, seedNull] of [[() => null, true], [() => undefined, false]] as const) {
        const out = await replayWith(third, seedNull);
        expect([out.status, failedChecks(out)]).toEqual(['denied', ['replay']]);
        expect((out as { authorization?: { allow: boolean } }).authorization?.allow).toBe(false);
      }
    });

    it('an unreadable proof at the replay lookup keeps the replay denial', async () => {
      const out = await replayWith(() => {
        throw new Error('unreadable');
      });
      expect([out.status, failedChecks(out)]).toEqual(['denied', ['replay']]);
      expect((out as { authorization?: { allow: boolean } }).authorization?.allow).toBe(false);
    });

    it('a record for another verb or another resource under the same id is never returned', async () => {
      for (const field of ['verb', 'resource'] as const) {
        const { grant, sign } = setup();
        const w = world();
        const store = memoryOperationStore();
        const ex = createExecutor({ ...azOptions(grant, w), operations: store });
        const p = sign(op(50).params);
        expect((await ex({ pcactn: p, operation: op(50) }, counted('r1').fn)).status).toBe('committed');
        const id = hashCanonical(p);
        const rec = (await store.get(id)) as OperationRecord;
        expect(await store.transition(id, 'committed', { ...rec, [field]: 'other' })).toBe(true);
        const out = await ex({ pcactn: p, operation: op(50) }, counted('r2').fn);
        expect([out.status, failedChecks(out)]).toEqual(['denied', ['replay']]);
      }
    });
  });
});
