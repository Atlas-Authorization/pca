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
  type ExecuteOutcome,
  type ExecutionHandle,
  type ExecutorOutcome,
  type OperationRecord,
  type OperationStore,
} from './operations';
import { memoryAtomicKv } from './plan-lifecycle';
import { atomicMemoryPcaStore } from './require-pca';
import type { PcaOperation } from './verify';
import { principalDirect } from '../test-support/provenance';

const NOW = Date.UTC(2026, 9, 25, 12, 0, 0);
const AUD = 'payments-rs';
const VERB = 'payments.send';
const RES = 'payments';
const ZERO: RiskPolicy = { weights: { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 }, theta1: 1, theta2: 1, kappa: 100, lambda: 0, rho: 0.5, bMax: 1_000_000 };
const TIMEOUT = 60_000;

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

/** A clock the test moves; a revocation switch the test flips. */
const world = () => ({ t: NOW, revoked: false, revocationCalls: 0 });

function azOptions(grant: { id: string }, w: ReturnType<typeof world>, over: Partial<AuthorizeOptions> = {}): AuthorizeOptions {
  return {
    provenance: principalDirect(),
    audience: AUD,
    resolveGrant: async (ref) => (ref === grant.id ? (grant as never) : null),
    budgetStore: atomicMemoryPcaStore(),
    hooks: {
      revocation: () => {
        w.revocationCalls++;
        return { enforced: true, ok: !w.revoked, ...(w.revoked ? { reason: 'revocation: the grant is revoked' } : {}) };
      },
    },
    plan: 'single-step',
    now: () => w.t,
    ...over,
  };
}

/** A side effect that counts its runs; `gate` holds it until released. */
function sideEffect<T>(value: T) {
  const s = { runs: 0, keys: [] as string[], release: () => {}, gate: undefined as Promise<void> | undefined };
  const hold = () => {
    s.gate = new Promise<void>((r) => (s.release = r));
  };
  const fn = async (h: ExecutionHandle): Promise<T> => {
    s.runs++;
    s.keys.push(h.idempotencyKey);
    if (s.gate) await s.gate;
    return value;
  };
  return { s, hold, fn };
}

const allowOk = () => ({ ok: true }) as const;

/** The outcome without the operation id (compared separately). */
const settle = (o: ExecuteOutcome<unknown> | ExecutorOutcome<unknown>) => {
  if (o.status === 'denied') return { status: o.status, failed: Object.entries(o.authorization.verdict.checks).filter(([, s]) => s === 'fail').map(([k]) => k).sort() };
  const { operationId: _id, ...rest } = o as ExecuteOutcome<unknown> & { operationId?: string };
  return rest;
};

async function authorized(): Promise<{ r: Extract<AuthorizeResult, { allow: true }>; grant: { id: string }; w: ReturnType<typeof world>; p: PCActn; sign: ReturnType<typeof setup>['sign'] }> {
  const { grant, sign } = setup();
  const w = world();
  const p = sign(op(50).params);
  const r = await createAuthorizer(azOptions(grant, w))({ pcactn: p, operation: op(50) });
  if (!r.allow) throw new Error(`fixture: not allowed: ${r.reason}`);
  return { r, grant, w, p, sign };
}

describe('executeAuthorized: one execution per operation id, recorded', () => {
  it('runs fn once with the operation id as idempotency key, records committed, and answers a second execution from the record', async () => {
    const { r, w } = await authorized();
    const store = memoryOperationStore();
    const se = sideEffect({ charge: 'ch_1' });
    const o = { store, recheck: allowOk, now: () => w.t };
    const first = await executeAuthorized(r, se.fn, o);
    expect(first).toEqual({ status: 'committed', operationId: r.operation.id, result: { charge: 'ch_1' }, replayed: false, recorded: true });
    expect(se.s.keys).toEqual([r.operation.id]);
    expect(r.operation.id).toBe(hashCanonical(r.pcactn));
    const rec = await store.get(r.operation.id);
    expect(rec).toEqual({
      id: r.operation.id,
      state: 'committed',
      verb: VERB,
      resource: RES,
      params_digest: paramsDigest(op(50).params),
      reversibility: 'irreversible',
      startedAt: NOW,
      executingAt: NOW,
      finishedAt: NOW,
      result: { charge: 'ch_1' },
    });
    const second = await executeAuthorized(r, se.fn, o);
    expect(second).toEqual({ status: 'committed', operationId: r.operation.id, result: { charge: 'ch_1' }, replayed: true, recorded: true });
    expect(se.s.runs).toBe(1);
  });

  it('refuses (and records nothing) without a store, for a denied authorization, and for another operation', async () => {
    const { r, w } = await authorized();
    const store = memoryOperationStore();
    const se = sideEffect(1);
    expect(await executeAuthorized(r, se.fn, { store: undefined as unknown as OperationStore, recheck: allowOk })).toEqual({
      status: 'refused',
      reason: 'executeAuthorized: missing required component: store (fail closed)',
    });
    const denied = { ...r, allow: false } as unknown as AuthorizeResult;
    expect(await executeAuthorized(denied, se.fn, { store, recheck: allowOk })).toEqual({ status: 'refused', reason: 'executeAuthorized: the authorization did not allow an operation' });
    expect(await executeAuthorized(r, se.fn, { store, recheck: allowOk, operation: op(400), now: () => w.t })).toEqual({
      status: 'refused',
      reason: 'executeAuthorized: the authorization is not for this operation (verb, resource or params differ)',
    });
    expect([se.s.runs, await store.get(r.operation.id)]).toEqual([0, undefined]);
    // the same operation passes the binding
    expect((await executeAuthorized(r, se.fn, { store, recheck: allowOk, operation: op(50), now: () => w.t })).status).toBe('committed');
  });

  it('accepts what the adapters attach ({ verdict, pcactn, operation }) and a guard result; refuses one without an allowed verdict or operation', async () => {
    const { r, w } = await authorized();
    const se = sideEffect('ok');
    const o = { recheck: allowOk, now: () => w.t };
    const attached = { verdict: r.verdict, pcactn: r.pcactn, operation: r.operation };
    expect(settle(await executeAuthorized(attached, se.fn, { store: memoryOperationStore(), ...o }))).toEqual({ status: 'committed', result: 'ok', replayed: false, recorded: true });
    expect(settle(await executeAuthorized({ ok: true, ...attached }, se.fn, { store: memoryOperationStore(), ...o }))).toEqual({ status: 'committed', result: 'ok', replayed: false, recorded: true });
    const refused = { status: 'refused', reason: 'executeAuthorized: the authorization did not allow an operation' };
    expect(await executeAuthorized({ ...attached, verdict: { ...r.verdict, allow: false } }, se.fn, { store: memoryOperationStore(), ...o })).toEqual(refused);
    expect(await executeAuthorized({ verdict: r.verdict, pcactn: r.pcactn }, se.fn, { store: memoryOperationStore(), ...o })).toEqual(refused);
    expect(await executeAuthorized({ ok: false, status: 403, verdict: r.verdict }, se.fn, { store: memoryOperationStore(), ...o })).toEqual(refused);
    expect(se.s.runs).toBe(2);
  });

  it('an irreversible operation without a recheck is refused (fail closed); a reversible one runs without it', async () => {
    const { r, w } = await authorized();
    const store = memoryOperationStore();
    const se = sideEffect(1);
    expect(await executeAuthorized(r, se.fn, { store, now: () => w.t })).toEqual({
      status: 'refused',
      reason: 'executeAuthorized: a irreversible operation needs a recheck (revocation, expiry, approval) before it runs (fail closed)',
    });
    // the server's catalog class cannot lower the signed irreversible class
    expect((await executeAuthorized(r, se.fn, { store, reversibilityClass: 'reversible', now: () => w.t })).status).toBe('refused');
    expect([se.s.runs, await store.get(r.operation.id)]).toEqual([0, undefined]);

    const { grant, sign } = setup();
    const w2 = world();
    const rev = await createAuthorizer(azOptions(grant, w2))({ pcactn: sign(op(10).params, 'reversible'), operation: op(10) });
    expect((await executeAuthorized(rev, se.fn, { store, now: () => w2.t })).status).toBe('committed');
    // recheckFor 'always' requires it for every class
    const rev2 = await createAuthorizer(azOptions(grant, w2))({ pcactn: sign(op(10).params, 'reversible'), operation: op(10) });
    expect((await executeAuthorized(rev2, se.fn, { store, recheckFor: 'always', now: () => w2.t })).status).toBe('refused');
    expect(se.s.runs).toBe(1);
  });

  it('a failed recheck (revoked between authorize and execute) aborts: fn never runs, the record says aborted', async () => {
    const { r, w } = await authorized();
    const store = memoryOperationStore();
    const se = sideEffect(1);
    const recheck = () => (w.revoked ? { ok: false as const, reason: 'the grant has been revoked' } : { ok: true as const });
    w.revoked = true;
    const out = await executeAuthorized(r, se.fn, { store, recheck, now: () => w.t });
    expect(settle(out)).toEqual({ status: 'aborted', reason: 'recheck: the grant has been revoked', replayed: false });
    expect([se.s.runs, (await store.get(r.operation.id))?.state]).toEqual([0, 'aborted']);
    // un-revoking does not resurrect the operation
    w.revoked = false;
    expect(settle(await executeAuthorized(r, se.fn, { store, recheck, now: () => w.t }))).toEqual({ status: 'aborted', reason: 'recheck: the grant has been revoked', replayed: true });
    expect(se.s.runs).toBe(0);
  });

  it('the PCActn expiry is re-checked at execution; a throwing recheck refuses', async () => {
    const { r, w } = await authorized();
    const se = sideEffect(1);
    w.t = r.pcactn.exp + 1;
    const late = await executeAuthorized(r, se.fn, { store: memoryOperationStore(), recheck: allowOk, now: () => w.t });
    expect(settle(late)).toEqual({ status: 'aborted', reason: `recheck: the PCActn expired at ${r.pcactn.exp}`, replayed: false });
    w.t = NOW;
    const thrown = await executeAuthorized(r, se.fn, {
      store: memoryOperationStore(),
      recheck: () => {
        throw new Error('approval service down');
      },
      now: () => w.t,
    });
    expect(settle(thrown)).toEqual({ status: 'aborted', reason: 'recheck: recheck error (fail closed): approval service down', replayed: false });
    expect(se.s.runs).toBe(0);
  });

  it('a throwing fn is recorded failed and never re-run', async () => {
    const { r, w } = await authorized();
    const store = memoryOperationStore();
    let runs = 0;
    const fn = async () => {
      runs++;
      throw new Error('card declined');
    };
    expect(settle(await executeAuthorized(r, fn, { store, recheck: allowOk, now: () => w.t }))).toEqual({ status: 'failed', error: 'card declined', replayed: false });
    expect(settle(await executeAuthorized(r, fn, { store, recheck: allowOk, now: () => w.t }))).toEqual({ status: 'failed', error: 'card declined', replayed: true });
    expect([runs, (await store.get(r.operation.id))?.state]).toEqual([1, 'failed']);
  });
});

/** A store that "crashes" (throws, as the process dying there would leave it) at one step. */
function crashing(inner: OperationStore, at: 'after-create' | 'before-commit'): OperationStore {
  let armed = true;
  return {
    ...inner,
    async create(rec) {
      const r = await inner.create(rec);
      if (at === 'after-create' && armed && r.created) {
        armed = false;
        throw new Error('process crashed after the claim');
      }
      return r;
    },
    async transition(id, from, next) {
      if (at === 'before-commit' && armed && next.state === 'committed') {
        armed = false;
        throw new Error('process crashed before the commit');
      }
      return inner.transition(id, from, next);
    },
  };
}

describe('crash and retry (createExecutor: a retry of the same PCActn is answered from the record)', () => {
  function executor(over: Partial<Parameters<typeof createExecutor>[0]> = {}) {
    const { grant, sign } = setup();
    const w = world();
    const store = memoryOperationStore();
    const ex = createExecutor({ ...azOptions(grant, w), operations: store, pendingTimeoutMs: TIMEOUT, ...over });
    return { grant, sign, w, store, ex };
  }

  it('crash after the claim, before execution: the retry is pending, then aborted (never ran); nothing runs twice', async () => {
    const base = memoryOperationStore();
    const { sign, w, ex } = executor({ operations: crashing(base, 'after-create') });
    const se = sideEffect('done');
    const signed = sign(op(50).params);
    const p = encodePCActn(signed);
    await expect(ex({ pcactn: p, operation: op(50) }, se.fn)).rejects.toThrow('process crashed after the claim');
    const id = hashCanonical(signed);
    expect((await base.get(id))?.state).toBe('pending');
    // the client retries the same PCActn: authorize refuses the replay, the record answers
    w.t += 1_000;
    expect(settle(await ex({ pcactn: p, operation: op(50) }, se.fn))).toEqual({ status: 'pending', replayed: true });
    w.t += TIMEOUT;
    expect(settle(await ex({ pcactn: p, operation: op(50) }, se.fn))).toEqual({
      status: 'aborted',
      reason: `not started within ${TIMEOUT} ms of the claim: the side effect never ran`,
      replayed: true,
    });
    expect(se.s.runs).toBe(0);
  });

  it('crash after execution, before the commit: the retry is pending, then uncertain; reconciliation settles it; never re-run', async () => {
    const base = memoryOperationStore();
    const { sign, w, ex } = executor({ operations: crashing(base, 'before-commit') });
    const se = sideEffect({ charge: 'ch_9' });
    const p = sign(op(50).params);
    const id = hashCanonical(p);
    const first = await ex({ pcactn: p, operation: op(50) }, se.fn);
    // the side effect ran; the record could not be written (in a real crash nobody would even see this answer)
    expect(settle(first)).toEqual({ status: 'committed', result: { charge: 'ch_9' }, replayed: false, recorded: false });
    expect((await base.get(id))?.state).toBe('executing');
    expect(settle(await ex({ pcactn: p, operation: op(50) }, se.fn))).toEqual({ status: 'pending', replayed: true });
    w.t += TIMEOUT + 1;
    expect(settle(await ex({ pcactn: p, operation: op(50) }, se.fn))).toEqual({
      status: 'uncertain',
      reason: `no outcome recorded within ${TIMEOUT} ms of the start: the side effect may or may not have happened`,
      replayed: true,
    });
    expect(se.s.runs).toBe(1);
    // an operator looks the idempotency key up downstream and settles it
    expect(se.s.keys).toEqual([id]);
    expect(await resolveOperation(base, id, { state: 'committed', result: { charge: 'ch_9' } }, { now: () => w.t })).toBe(true);
    expect(await resolveOperation(base, id, { state: 'failed', error: 'x' })).toBe(false);
    expect(settle(await ex({ pcactn: p, operation: op(50) }, se.fn))).toEqual({ status: 'committed', result: { charge: 'ch_9' }, replayed: true, recorded: true });
    expect(se.s.runs).toBe(1);
  });

  it('retry after a client timeout: while the first execution runs the retry is pending; afterwards it gets the result', async () => {
    const { sign, ex } = executor();
    const se = sideEffect('ok');
    se.hold();
    const p = sign(op(50).params);
    const first = ex({ pcactn: p, operation: op(50) }, se.fn);
    // let the first call reach fn
    for (let i = 0; i < 50 && se.s.runs === 0; i++) await new Promise((r) => setImmediate(r));
    expect(se.s.runs).toBe(1);
    expect(settle(await ex({ pcactn: p, operation: op(50) }, se.fn))).toEqual({ status: 'pending', replayed: true });
    se.s.release();
    expect(settle(await first)).toEqual({ status: 'committed', result: 'ok', replayed: false, recorded: true });
    expect(settle(await ex({ pcactn: p, operation: op(50) }, se.fn))).toEqual({ status: 'committed', result: 'ok', replayed: true, recorded: true });
    expect(se.s.runs).toBe(1);
  });

  it('concurrent executions of the same authorization: exactly one runs fn', async () => {
    const { r, w } = await authorized();
    const store = memoryOperationStore();
    const se = sideEffect('once');
    se.hold();
    const all = Array.from({ length: 12 }, () => executeAuthorized(r, se.fn, { store, recheck: allowOk, now: () => w.t }));
    for (let i = 0; i < 50 && se.s.runs === 0; i++) await new Promise((res) => setImmediate(res));
    se.s.release();
    const out = (await Promise.all(all)).map(settle);
    expect(se.s.runs).toBe(1);
    expect(out.filter((o) => o.status === 'committed')).toEqual([{ status: 'committed', result: 'once', replayed: false, recorded: true }]);
    expect(out.filter((o) => o.status !== 'committed')).toEqual(Array.from({ length: 11 }, () => ({ status: 'pending', replayed: true })));
  });

  it('concurrent presentations of one PCActn through the executor: one execution, the rest pending or a replay denial', async () => {
    const { sign, ex } = executor();
    const se = sideEffect('once');
    se.hold();
    const p = sign(op(50).params);
    const all = Array.from({ length: 8 }, () => ex({ pcactn: p, operation: op(50) }, se.fn));
    for (let i = 0; i < 50 && se.s.runs === 0; i++) await new Promise((res) => setImmediate(res));
    se.s.release();
    const out = (await Promise.all(all)).map(settle);
    expect(se.s.runs).toBe(1);
    expect(out.filter((o) => o.status === 'committed' && !(o as { replayed: boolean }).replayed)).toHaveLength(1);
    for (const o of out.filter((x) => !(x.status === 'committed' && !(x as { replayed: boolean }).replayed))) {
      expect([{ status: 'pending', replayed: true }, { status: 'denied', failed: ['replay'] }]).toContainEqual(o);
    }
  });

  it('a retry is answered from the record only while every other check still passes, and only for the same operation', async () => {
    const { sign, w, ex, store } = executor();
    const se = sideEffect('r1');
    const p = sign(op(50).params);
    expect((await ex({ pcactn: p, operation: op(50) }, se.fn)).status).toBe('committed');
    // the same proof for other params: denied by the binding, not answered
    expect(settle(await ex({ pcactn: p, operation: op(60) }, se.fn))).toEqual({ status: 'denied', failed: ['operation', 'params_digest', 'plan_root_authorized', 'replay'] });
    // revoked since: the record is not handed out
    w.revoked = true;
    expect(settle(await ex({ pcactn: p, operation: op(50) }, se.fn))).toEqual({ status: 'denied', failed: ['replay', 'revocation'] });
    w.revoked = false;
    expect(settle(await ex({ pcactn: p, operation: op(50) }, se.fn))).toEqual({ status: 'committed', result: 'r1', replayed: true, recorded: true });
    // a record for a different operation under the same id is never returned
    const id = hashCanonical(p);
    const rec = (await store.get(id)) as OperationRecord;
    expect(await store.transition(id, 'committed', { ...rec, params_digest: 'other' })).toBe(true);
    expect(settle(await ex({ pcactn: p, operation: op(50) }, se.fn))).toEqual({ status: 'denied', failed: ['replay'] });
    expect(se.s.runs).toBe(1);
  });

  it('a replay with no record (the first attempt never reached execution) stays a replay denial', async () => {
    const { grant, sign } = setup();
    const w = world();
    const budgetStore = atomicMemoryPcaStore();
    const p = sign(op(50).params);
    // the first presentation was authorized elsewhere (e.g. the process died right after authorize)
    expect((await createAuthorizer(azOptions(grant, w, { budgetStore }))({ pcactn: p, operation: op(50) })).allow).toBe(true);
    const ex = createExecutor({ ...azOptions(grant, w, { budgetStore }), operations: memoryOperationStore() });
    const se = sideEffect(1);
    expect(settle(await ex({ pcactn: p, operation: op(50) }, se.fn))).toEqual({ status: 'denied', failed: ['replay'] });
    expect(se.s.runs).toBe(0);
  });

  it('the executor re-runs revocation immediately before an irreversible side effect (revoked after authorize -> aborted)', async () => {
    const { grant, sign } = setup();
    const w = world();
    const store = memoryOperationStore();
    const base = azOptions(grant, w);
    // revoked between the authorize decision (1st revocation call) and the execution (2nd call)
    const ex = createExecutor({
      ...base,
      hooks: {
        revocation: () => {
          w.revocationCalls++;
          return w.revocationCalls >= 2 ? { enforced: true, ok: false, reason: 'revoked by the principal' } : { enforced: true, ok: true };
        },
      },
      operations: store,
    });
    const se = sideEffect(1);
    expect(settle(await ex({ pcactn: sign(op(50).params), operation: op(50) }, se.fn))).toEqual({ status: 'aborted', reason: 'recheck: revoked by the principal', replayed: false });
    expect([se.s.runs, w.revocationCalls]).toEqual([0, 2]);
    // an extra recheck (e.g. a step-up approval) is honoured too
    const w2 = world();
    const ex2 = createExecutor({ ...azOptions(grant, w2), operations: memoryOperationStore(), recheck: () => ({ ok: false, reason: 'step-up approval withdrawn' }) });
    expect(settle(await ex2({ pcactn: sign(op(50).params), operation: op(50) }, se.fn))).toEqual({ status: 'aborted', reason: 'recheck: step-up approval withdrawn', replayed: false });
    expect(se.s.runs).toBe(0);
  });

  it('the executor refuses without an operation store, and denies what authorize denies', async () => {
    const { grant, sign } = setup();
    const w = world();
    const se = sideEffect(1);
    const ex = createExecutor({ ...azOptions(grant, w), operations: undefined as unknown as OperationStore });
    expect(await ex({ pcactn: sign(op(50).params), operation: op(50) }, se.fn)).toEqual({ status: 'refused', reason: 'createExecutor: missing required component: operations (fail closed)' });
    const ex2 = createExecutor({ ...azOptions(grant, w), operations: memoryOperationStore() });
    expect(settle(await ex2({ pcactn: sign(op(400).params), operation: op(400) }, se.fn))).toEqual({ status: 'denied', failed: ['policy'] });
    expect(se.s.runs).toBe(0);
  });
});

describe('recovery', () => {
  it('recoverOperations settles stale open records: pending -> aborted, executing -> uncertain; fresh ones stay', async () => {
    const store = memoryOperationStore();
    const base = { verb: VERB, resource: RES, params_digest: 'd', reversibility: 'irreversible' as const };
    await store.create({ id: 'a', state: 'pending', startedAt: NOW, ...base });
    await store.create({ id: 'b', state: 'pending', startedAt: NOW, ...base });
    expect(await store.transition('b', 'pending', { id: 'b', state: 'executing', startedAt: NOW, executingAt: NOW, ...base })).toBe(true);
    await store.create({ id: 'c', state: 'pending', startedAt: NOW + TIMEOUT, ...base });
    const settled = await recoverOperations(store, { olderThanMs: TIMEOUT, now: () => NOW + TIMEOUT + 1 });
    expect(settled.map((r) => [r.id, r.state]).sort()).toEqual([
      ['a', 'aborted'],
      ['b', 'uncertain'],
    ]);
    expect((await store.get('c'))?.state).toBe('pending');
    expect(await recoverOperation(store, 'missing')).toBeUndefined();
    // without listOpen: by id only
    await expect(recoverOperations(durableOperationStore(memoryAtomicKv()))).rejects.toThrow(/listOpen/);
  });
});

describe('durableOperationStore', () => {
  it('create is create-if-absent and transition is a compare-and-set on the state', async () => {
    const store = durableOperationStore(memoryAtomicKv());
    const rec: OperationRecord = { id: 'x', state: 'pending', verb: VERB, resource: RES, params_digest: 'd', reversibility: 'costly', startedAt: NOW };
    expect(await store.create(rec)).toEqual({ created: true });
    expect(await store.create({ ...rec, startedAt: NOW + 5 })).toEqual({ created: false, record: rec });
    expect(await store.transition('x', 'executing', { ...rec, state: 'committed' })).toBe(false);
    expect(await store.transition('x', 'pending', { ...rec, state: 'executing' })).toBe(true);
    expect(await store.transition('x', 'pending', { ...rec, state: 'aborted' })).toBe(false);
    expect((await store.get('x'))?.state).toBe('executing');
    expect(await store.transition('nope', 'pending', { ...rec, id: 'nope' })).toBe(false);
  });

  it('executeAuthorized over it: one run for concurrent executions', async () => {
    const { r, w } = await authorized();
    const store = durableOperationStore(memoryAtomicKv());
    const se = sideEffect(7);
    const out = (await Promise.all(Array.from({ length: 5 }, () => executeAuthorized(r, se.fn, { store, recheck: allowOk, now: () => w.t })))).map(settle);
    expect(se.s.runs).toBe(1);
    expect(out).toEqual([{ status: 'committed', result: 7, replayed: false, recorded: true }, ...Array.from({ length: 4 }, () => ({ status: 'pending', replayed: true }))]);
    expect((await store.get(r.operation.id))?.state).toBe('committed');
  });
});

describe('memoryOperationStore isolation', () => {
  it('returns copies: editing a returned record does not change the store', async () => {
    const store = memoryOperationStore();
    const rec: OperationRecord = { id: 'i', state: 'pending', verb: VERB, resource: RES, params_digest: 'd', reversibility: 'reversible', startedAt: NOW };
    await store.create(rec);
    const got = (await store.get('i')) as OperationRecord;
    got.state = 'committed';
    expect((await store.get('i'))?.state).toBe('pending');
    // a store that only this process holds says so
    expect(store.scope).toBe('process');
  });
});
