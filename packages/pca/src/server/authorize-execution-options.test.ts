// 0.5 merge follow-up: `enforce`, `multiInstance`, `replayScope` and `claimRetries` reach `authorize` through
// `authorizeExecution` (and so through the gateway and the agent-framework guards, which spread these options).
import { describe, expect, it } from 'vitest';
import { agent } from '../facade';
import { generateKeyPair } from '../keys';
import { authorizeExecution, type AuthorizeExecutionOptions } from './authorize-execution';
import { memoryAtomicKv } from './plan-lifecycle';
import { atomicMemoryPcaStore, durablePcaStateStore, memoryPcaStore, pcaStateKey, type AtomicPcaStateStore } from './require-pca';
import { principalDirect } from '../test-support/provenance';

const AUD = 'rs-w1';
const VERB = 'stripe.refund';

function world(over: Partial<AuthorizeExecutionOptions> = {}) {
  const a = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$100/day' }, aud: AUD });
  const opts: AuthorizeExecutionOptions = { provenance: principalDirect(), audience: AUD, grant: a.grant, state: memoryPcaStore(), isRevoked: () => false, ...over };
  const sign = (amount: number) => {
    const params = { charge: 'ch_1', amount };
    return { params, pcactn: a.act(VERB, 'charge:ch_1', params).pcactn };
  };
  return { a, opts, sign };
}

const run = async (w: ReturnType<typeof world>, amount = 10) => {
  const { params, pcactn } = w.sign(amount);
  return authorizeExecution(pcactn, { verb: VERB, resource: 'charge:ch_1', params }, w.opts);
};

const outcome = (d: Awaited<ReturnType<typeof authorizeExecution>>) => (d.allow ? { allow: true } : { allow: false, kind: d.kind, reason: d.reason });

describe('authorizeExecution forwards the 0.5 state options to authorize', () => {
  it('multiInstance: a process-local store denies every call with the reason; a shared atomic store is accepted', async () => {
    expect(outcome(await run(world({ multiInstance: true })))).toEqual({
      allow: false,
      kind: 'policy',
      reason:
        'authorization error (fail closed): requirePCA: multiInstance needs a budgetStore with `claim` (AtomicPcaStateStore) or `withKeyLock`; the in-process lock is correct for one process only (multiInstance is on unless the store declares `scope: \'process\'`; pass multiInstance: false to run this store in one process on purpose)',
    });
    expect(outcome(await run(world({ multiInstance: true, state: atomicMemoryPcaStore() })))).toEqual({
      allow: false,
      kind: 'policy',
      reason: 'authorization error (fail closed): requirePCA: multiInstance with a process-local budgetStore (its state is not shared between instances)',
    });
    expect(outcome(await run(world({ multiInstance: true, state: durablePcaStateStore(memoryAtomicKv()) })))).toEqual({ allow: true });
    // without the option the process-local store still works (default unchanged)
    expect(outcome(await run(world()))).toEqual({ allow: true });
  });

  it("replayScope 'audience-grant-holder': the counter stream is stored under the audience-scoped key", async () => {
    const state = memoryPcaStore();
    const w = world({ state, replayScope: 'audience-grant-holder' });
    const { params, pcactn } = w.sign(10);
    expect((await authorizeExecution(pcactn, { verb: VERB, params }, w.opts)).allow).toBe(true);
    const holder = pcactn.cap_chain[pcactn.cap_chain.length - 1]!.holder;
    expect([
      (await state.get(pcaStateKey(w.a.grant.id, holder, 'audience-grant-holder', AUD)))?.lastCounter,
      (await state.get(pcaStateKey(w.a.grant.id, holder)))?.lastCounter,
    ]).toEqual([pcactn.counter, undefined]);
  });

  it('claimRetries: a claim that keeps conflicting is retried exactly that many times, then denied', async () => {
    const counting = () => {
      const inner = atomicMemoryPcaStore();
      const s = { claims: 0 };
      const store: AtomicPcaStateStore = { ...inner, claim: async () => (s.claims++, { ok: false, reason: 'conflict' }) };
      return { s, store };
    };
    const zero = counting();
    const d0 = await run(world({ state: zero.store, claimRetries: 0 }));
    expect([outcome(d0), zero.s.claims]).toEqual([{ allow: false, kind: 'replay', reason: 'replay: concurrent state update for this holder kept conflicting (fail closed, retry the request)' }, 1]);
    const dflt = counting();
    await run(world({ state: dflt.store }));
    expect(dflt.s.claims).toBe(4);
    const two = counting();
    await run(world({ state: two.store, claimRetries: 2 }));
    expect(two.s.claims).toBe(3);
  });

  it('enforce: a core gate set here is applied (a stub freshness anchor is refused)', async () => {
    const d = await run(world({ enforce: { freshness: { maxAgeMs: 60_000 } } }));
    expect(d.allow === false && { kind: d.kind, freshness: d.checks?.['freshness'] }).toEqual({ kind: 'policy', freshness: 'fail' });
    expect((await run(world())).allow).toBe(true);
  });
});
