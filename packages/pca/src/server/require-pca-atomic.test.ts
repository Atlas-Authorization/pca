/**
 * T2 (0.5): the atomic claim path behind requirePCA. One action id (grant, leaf holder, counter) goes unconsumed ->
 * consumed at most once, across guards (instances) that share a store, without relying on the in-process lock.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createMemoryDurableKv, openDurableState } from '../durable-state';
import {
  atomicMemoryPcaStore,
  durablePcaStateStore,
  isAtomicPcaStateStore,
  memoryPcaStore,
  pcaStateKey,
  requirePCA as requirePCA05,
  type AtomicPcaStateStore,
  type PcaClaimResult,
  type PcaGuardResult,
  type PcaHolderState,
  type PcaStateClaim,
  type PcaStateStore,
} from './require-pca';
import { AUD, NOW, setup } from './fixture.test-util';
const requirePCA = (o: Parameters<typeof requirePCA05>[0]): ReturnType<typeof requirePCA05> => requirePCA05({ insecureAllowUnboundOperation: true, multiInstance: false, ...o }); // unbound and single-instance on purpose: these tests are not about operation binding or store scope (see breaking-05.test.ts)


const s = setup();
const revocation = () => ({ enforced: true, ok: true });
const guardOn = (budgetStore: PcaStateStore | undefined, extra: Record<string, unknown> = {}) =>
  requirePCA({
    resolveGrant: async (ref: string) => (ref === s.grant.id ? s.grant : null),
    now: () => NOW,
    audience: AUD,
    context: () => ({ plan: s.plan, planAuthorized: true, risk: s.lowRisk }),
    hooks: { revocation },
    ...(budgetStore ? { budgetStore } : {}),
    ...extra,
  });
const req = (counter: number, extra?: Record<string, unknown>) => ({ headers: {}, body: { pcactn: s.mk(s.plan[0]!, { counter, ...(extra ? { extra } : {}) }) } });
/** status per result: 'ok' or the deny status, plus the counter check of each deny. */
const outcome = (r: PcaGuardResult) => (r.ok ? 'ok' : `${r.status}:${String(r.verdict.checks.replay)}`);
const tally = (rs: PcaGuardResult[]) => rs.map(outcome).reduce<Record<string, number>>((m, k) => ({ ...m, [k]: (m[k] ?? 0) + 1 }), {});
const holderKey = () => pcaStateKey(s.grant.id, s.aPub, undefined, AUD); // the default key carries the audience (0.5)
const legacyKey = () => pcaStateKey(s.grant.id, s.aPub, 'grant-holder');
const tick = () => new Promise<void>((r) => setImmediate(r));

/** A store whose `claim` is split into read, await, write: what the atomic contract forbids (positive control). */
function nonAtomicClaimStore(): AtomicPcaStateStore {
  const m = new Map<string, PcaHolderState>();
  return {
    get: async (k) => m.get(k),
    put: async (k, v) => void m.set(k, v),
    async claim(k, c) {
      const cur = m.get(k);
      await tick();
      if (cur?.lastCounter !== undefined && !(c.counter > cur.lastCounter)) return { ok: false, reason: 'replay', lastCounter: cur.lastCounter };
      m.set(k, { budget: c.budgetAfter ?? cur?.budget, lastCounter: c.counter });
      return { ok: true };
    },
    async raisePin() {},
  };
}

describe('atomic claim path (T2)', () => {
  it('a store with claim + raisePin is atomic; the guard reports its state mode', () => {
    expect(isAtomicPcaStateStore(atomicMemoryPcaStore())).toBe(true);
    expect(isAtomicPcaStateStore(memoryPcaStore())).toBe(false);
    expect(isAtomicPcaStateStore({ ...memoryPcaStore(), claim: async () => ({ ok: true }) } as PcaStateStore)).toBe(false);
    expect(guardOn(atomicMemoryPcaStore()).stateMode).toBe('atomic-claim');
    expect(guardOn(memoryPcaStore()).stateMode).toBe('process-lock');
    expect(guardOn({ ...memoryPcaStore(), withKeyLock: (_k, fn) => fn() }).stateMode).toBe('shared-lock');
    expect(guardOn(undefined).stateMode).toBe('none');
  });

  it('20 concurrent copies of one proof to ONE instance: exactly one admitted, 19 replays', async () => {
    const g = guardOn(atomicMemoryPcaStore());
    const rs = await Promise.all(Array.from({ length: 20 }, () => g(req(5))));
    expect(tally(rs)).toEqual({ ok: 1, '403:fail': 19 });
  });

  it('20 concurrent copies spread over 4 instances sharing a durable kv: exactly one admitted', async () => {
    const kv = createMemoryDurableKv();
    const guards = Array.from({ length: 4 }, () => guardOn(durablePcaStateStore(kv)));
    const rs = await Promise.all(Array.from({ length: 20 }, (_, i) => guards[i % 4]!(req(5))));
    expect(tally(rs)).toEqual({ ok: 1, '403:fail': 19 });
    expect(((await kv.get(`pca-state:${holderKey()}`)) as PcaHolderState).lastCounter).toBe(5);
  });

  it('the claim, not the lock, decides: a read-then-write claim admits the same proof more than once (positive control)', async () => {
    const g = guardOn(nonAtomicClaimStore());
    const rs = await Promise.all(Array.from({ length: 8 }, () => g(req(5))));
    expect(rs.filter((r) => r.ok).length).toBe(8);
  });

  it('a replay of an already-claimed counter is denied with the last counter in the reason', async () => {
    const st = atomicMemoryPcaStore();
    const g = guardOn(st);
    expect(outcome(await g(req(5)))).toBe('ok');
    // a second instance that has not read the state yet: the claim, not the pre-read, catches it
    const raced: AtomicPcaStateStore = { ...st, get: async () => undefined };
    const r = await guardOn(raced)(req(5));
    expect(outcome(r)).toBe('403:fail');
    expect(!r.ok && r.verdict.reasons.at(-1)).toBe('replay: 5 is not greater than last seen 5 (replay)');
    expect(outcome(await g(req(6)))).toBe('ok');
  });

  it('a budget conflict re-reads and re-verifies, up to claimRetries, then denies (fail closed)', async () => {
    const mkStore = (conflicts: number) => {
      const inner = atomicMemoryPcaStore();
      const claims: PcaStateClaim[] = [];
      const st: AtomicPcaStateStore = {
        ...inner,
        async claim(k, c): Promise<PcaClaimResult> {
          claims.push(c);
          return claims.length <= conflicts ? { ok: false, reason: 'conflict' } : inner.claim(k, c);
        },
      };
      return { st, claims };
    };
    const a = mkStore(3);
    expect(outcome(await guardOn(a.st)(req(1)))).toBe('ok');
    expect(a.claims.length).toBe(4);
    const b = mkStore(4);
    const r = await guardOn(b.st)(req(1));
    expect(b.claims.length).toBe(4);
    expect(!r.ok && [r.status, r.verdict.reasons]).toEqual([403, ['replay: concurrent state update for this holder kept conflicting (fail closed, retry the request)']]);
    const c = mkStore(1);
    expect(outcome(await guardOn(c.st, { claimRetries: 0 })(req(1)))).toBe('403:fail');
    expect(c.claims.length).toBe(1);
    expect(() => guardOn(atomicMemoryPcaStore(), { claimRetries: -1 })).toThrow(/claimRetries/);
    expect(() => guardOn(atomicMemoryPcaStore(), { claimRetries: 1.5 })).toThrow(/claimRetries/);
  });

  it('concurrent DIFFERENT counters of one holder under a real budget: every one admitted exactly once, budget debited per action', async () => {
    const st = atomicMemoryPcaStore();
    // seed a budget so every decision reads and writes it (budgetBefore / budgetAfter are compared)
    await st.put(holderKey(), { budget: { B: 10, tau: NOW, asOf: NOW } });
    const g = guardOn(st, { context: () => ({ plan: s.plan, planAuthorized: true, risk: { ...s.lowRisk, blastRadius: 0.05 } }) });
    const rs = await Promise.all([1, 2, 3, 4].map((c) => g(req(c))));
    const after = rs.flatMap((r) => (r.ok ? [r.verdict.budget!.B] : []));
    const final = (await st.get(holderKey()))!;
    expect(final.lastCounter).toBe(4);
    // every admitted decision was computed from a DIFFERENT starting budget (no two spends of one balance) and the stored
    // budget is the last of them: no debit was lost
    expect(after.length).toBeGreaterThanOrEqual(2);
    expect(new Set(after).size).toBe(after.length);
    expect(Math.max(...after)).toBeLessThan(10);
    expect(final.budget!.B).toBe(Math.min(...after));
  });

  it('crash after claim: the action is burned (at most once); after a restart the same proof is denied, the next counter admitted', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pca-t2-crash-'));
    try {
      const st1 = durablePcaStateStore(await openDurableState({ dir }));
      // the guard admits (claim committed) and the process dies before the handler runs: nothing else to do here
      expect(outcome(await guardOn(st1)(req(9)))).toBe('ok');
      // restart: a new process opens the same directory
      const st2 = durablePcaStateStore(await openDurableState({ dir }));
      const g2 = guardOn(st2);
      expect(outcome(await g2(req(9)))).toBe('403:fail');
      expect(outcome(await g2(req(10)))).toBe('ok');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('retry after a timeout: a claim that committed but whose answer was lost denies, and the retry is a replay (zero admissions, never two)', async () => {
    const inner = atomicMemoryPcaStore();
    let lose = true;
    const st: AtomicPcaStateStore = {
      ...inner,
      async claim(k, c) {
        const r = await inner.claim(k, c);
        if (lose) {
          lose = false;
          throw new Error('timeout waiting for the store');
        }
        return r;
      },
    };
    const g = guardOn(st);
    const first = await g(req(3));
    expect(!first.ok && [first.status, first.verdict.reasons]).toEqual([403, ['guard error (fail closed): timeout waiting for the store']]);
    expect(outcome(await g(req(3)))).toBe('403:fail');
    expect(outcome(await g(req(4)))).toBe('ok');
  });

  it('retry after a timeout while the first claim is still in flight on another instance: exactly one admitted', async () => {
    const kv = createMemoryDurableKv();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const slow = durablePcaStateStore(kv);
    const slowStore: AtomicPcaStateStore = { ...slow, claim: async (k, c) => (await gate, slow.claim(k, c)) };
    const first = guardOn(slowStore)(req(7)); // the caller gives up waiting on this one...
    const retry = await guardOn(durablePcaStateStore(kv))(req(7)); // ...and retries on another instance
    release();
    expect([outcome(retry), outcome(await first)]).toEqual(['ok', '403:fail']);
  });

  it('epoch / beacon pins on the atomic path are raised monotonically, never lowered', async () => {
    const st = atomicMemoryPcaStore();
    await st.raisePin('g:epoch', 'lastEpoch', 4);
    await st.raisePin('g:epoch', 'lastEpoch', 2);
    expect(await st.get('g:epoch')).toEqual({ lastEpoch: 4 });
    await st.raisePin('g:epoch', 'lastEpoch', 6);
    expect(await st.get('g:epoch')).toEqual({ lastEpoch: 6 });
    const d = durablePcaStateStore(createMemoryDurableKv());
    await d.raisePin('g:beacon', 'lastBeaconSeq', 9);
    await d.raisePin('g:beacon', 'lastBeaconSeq', 3);
    expect(await d.get('g:beacon')).toEqual({ lastBeaconSeq: 9 });
  });
});

describe('multi-instance mode refuses the in-process lock (T2)', () => {
  it('throws at construction for a store with neither claim nor withKeyLock, or a process-local store', () => {
    expect(() => guardOn(memoryPcaStore(), { multiInstance: true })).toThrow(/multiInstance needs a budgetStore with `claim`/);
    const plain: PcaStateStore = { get: async () => undefined, put: async () => undefined };
    expect(() => guardOn(plain, { multiInstance: true })).toThrow(/in-process lock is correct for one process only/);
    expect(() => guardOn(atomicMemoryPcaStore(), { multiInstance: true })).toThrow(/process-local budgetStore/);
    expect(() => guardOn({ ...memoryPcaStore(), withKeyLock: (_k, fn) => fn() }, { multiInstance: true })).toThrow(/process-local/);
  });

  it('accepts a shared atomic store or a shared lock', () => {
    expect(guardOn(durablePcaStateStore(createMemoryDurableKv()), { multiInstance: true }).stateMode).toBe('atomic-claim');
    const plain: PcaStateStore = { get: async () => undefined, put: async () => undefined, withKeyLock: (_k, fn) => fn() };
    expect(guardOn(plain, { multiInstance: true }).stateMode).toBe('shared-lock');
  });

  it('default (single instance) is unchanged: the process-local store still works and is flagged as process-lock', async () => {
    const g = guardOn(memoryPcaStore());
    expect(g.stateMode).toBe('process-lock');
    expect(outcome(await g(req(1)))).toBe('ok');
  });
});

describe('replay scope option (T2)', () => {
  const other = 'rs-other';
  it("replayScope: 'grant-holder' (the 0.4 key): two audiences sharing a store interfere", async () => {
    const st = atomicMemoryPcaStore();
    expect(outcome(await guardOn(st, { replayScope: 'grant-holder' })(req(5)))).toBe('ok');
    expect(outcome(await guardOn(st, { audience: other, replayScope: 'grant-holder' })(req(1, { aud: other })))).toBe('403:fail');
  });

  it('the default scope is audience-grant-holder: two audiences sharing a store keep separate streams', async () => {
    const st = atomicMemoryPcaStore();
    expect(outcome(await guardOn(st)(req(5)))).toBe('ok');
    expect(outcome(await guardOn(st, { audience: other })(req(1, { aud: other })))).toBe('ok');
    expect(outcome(await guardOn(st)(req(5)))).toBe('403:fail');
    expect((await st.get(holderKey()))?.lastCounter).toBe(5);
    expect(await st.get(legacyKey())).toBeUndefined();
  });

  it('audience-grant-holder scope: separate counter streams per audience, replay within one still denied', async () => {
    const st = atomicMemoryPcaStore();
    const a = guardOn(st, { replayScope: 'audience-grant-holder' });
    const b = guardOn(st, { audience: other, replayScope: 'audience-grant-holder' });
    expect(outcome(await a(req(5)))).toBe('ok');
    expect(outcome(await b(req(1, { aud: other })))).toBe('ok');
    expect(outcome(await a(req(5)))).toBe('403:fail');
    expect(outcome(await b(req(1, { aud: other })))).toBe('403:fail');
    expect((await st.get(pcaStateKey(s.grant.id, s.aPub, 'audience-grant-holder', AUD)))?.lastCounter).toBe(5);
    expect(pcaStateKey('g', 'h', 'audience-grant-holder', 'a:b')).toBe('aud:a%3Ab:g:h');
    expect(pcaStateKey('g', 'h')).toBe('g:h');
  });

  it('the legacy lock path honours the scope too', async () => {
    const st = memoryPcaStore();
    expect(outcome(await guardOn(st, { replayScope: 'audience-grant-holder' })(req(5)))).toBe('ok');
    expect((await st.get(pcaStateKey(s.grant.id, s.aPub, 'audience-grant-holder', AUD)))?.lastCounter).toBe(5);
    expect(await st.get(legacyKey())).toBeUndefined();
  });

  it('rejects an unknown scope and an audience scope without an audience', () => {
    expect(() => guardOn(memoryPcaStore(), { replayScope: 'grant' })).toThrow(/unknown replayScope/);
    expect(() => guardOn(memoryPcaStore(), { audience: undefined, insecureAllowUnenforced: true, replayScope: 'audience-grant-holder' })).toThrow(/needs `audience`/);
  });
});

