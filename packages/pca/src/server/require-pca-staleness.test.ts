/**
 * T9 (0.5) through requirePCA: class-dependent maximum age of the signed revocation epoch, and irreversible actions
 * denied without verifiable (signed, dated) revocation state. Scenarios: grant revoked mid-run, stale root, revocation
 * source unavailable, restart with cached state.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { openDurableState } from '../durable-state';
import { encodeKey, generateKeyPair } from '../keys';
import { createRevocationChecker, RevocationSet, signRevocationEpoch, type RevocationEpoch, type RevocationStalenessPolicy } from '../revocation';
import { atomicMemoryPcaStore, durablePcaStateStore, memoryPcaStore, requirePCA as requirePCA05, type PcaGuardResult, type PcaStateStore } from './require-pca';
import { AUD, NOW, setup } from './fixture.test-util';
const requirePCA = (o: Parameters<typeof requirePCA05>[0]): ReturnType<typeof requirePCA05> => requirePCA05({ insecureAllowUnboundOperation: true, multiInstance: false, ...o }); // unbound and single-instance on purpose: these tests are not about operation binding or store scope (see breaking-05.test.ts)


const s = setup();
const G = generateKeyPair();
const guardianPublic = encodeKey(G.publicKey);
const REVERSIBLE = s.plan[0]!;
const IRREVERSIBLE = s.plan[1]!;
const taskCapId = () => s.mk(REVERSIBLE).cap_chain[1]!.id;
/** The RS context: the plaintext params of whichever plan step the PCActn is for. */
const rsContext = (_req: unknown, pc: { action: { verb: string } }) => ({
  plan: s.plan, planAuthorized: true, risk: s.lowRisk, params: pc.action.verb === IRREVERSIBLE.verb ? s.params : {},
});

/** The guardian: a revocation set, an epoch counter and a clock; `current()` is what GET /revocations/epoch would serve. */
function guardian() {
  const set = new RevocationSet();
  let epoch = 0;
  let signed = sign(NOW);
  function sign(at: number): RevocationEpoch {
    return signRevocationEpoch(G.secretKey, { instance_id: 'i', grant_ref: s.grant.id, epoch, set_size: set.size, root: set.root, issued_at: at, not_after: at + 300_000 });
  }
  return {
    current: () => signed,
    revoke(id: string, at: number) {
      set.revoke(id);
      epoch += 1;
      signed = sign(at);
    },
    resign: (at: number) => (signed = sign(at)),
    proofFor: (id: string) => (set.has(id) ? undefined : set.nonMembershipProof(id)),
  };
}

interface GuardOpts {
  served: () => RevocationEpoch | null;
  proofFor: (id: string) => ReturnType<RevocationSet['nonMembershipProof']> | undefined;
  clock: () => number;
  store?: PcaStateStore;
  staleness?: RevocationStalenessPolicy;
  extra?: Record<string, unknown>;
}
const guardOf = (o: GuardOpts) =>
  requirePCA({
    resolveGrant: async (ref: string) => (ref === s.grant.id ? s.grant : null),
    now: o.clock,
    audience: AUD,
    context: rsContext,
    budgetStore: o.store ?? memoryPcaStore(),
    revocationEpoch: async () => {
      const e = o.served();
      return e ? { epoch: e, guardianPublic } : null;
    },
    // non-membership against the root of the SAME served epoch (what the verifier was handed)
    hooks: { revocation: createRevocationChecker({ root: () => o.served()?.root, proofFor: (id) => o.proofFor(id) }) },
    ...(o.staleness ? { revocationStaleness: o.staleness } : {}),
    ...o.extra,
  });
// freshness.epoch 50: the agent's action postdates every epoch these tests serve
const call = (node: typeof REVERSIBLE, counter: number) => ({
  headers: {},
  body: { pcactn: s.mk(node, { counter, extra: { freshness: { beacon_ref: '', epoch: 50, accumulator_witness: '' } } }) },
});
// the `budget:` note is informational (no budget seeded in these tests), never the reason for a deny here
const res = (r: PcaGuardResult) => (r.ok ? 'ok' : `${r.status} ${r.verdict.reasons.filter((x) => !x.startsWith('budget: no budget supplied')).join(' | ')}`);

describe('requirePCA revocationStaleness', () => {
  it('fresh epoch: reversible and irreversible both admitted', async () => {
    const g = guardian();
    const guard = guardOf({ served: g.current, proofFor: g.proofFor, clock: () => NOW + 1000, staleness: {} });
    expect(res(await guard(call(REVERSIBLE, 1)))).toBe('ok');
    expect(res(await guard(call(IRREVERSIBLE, 2)))).toBe('ok');
  });

  it('stale root: the same 150 s old epoch admits a reversible action and denies an irreversible one; without the policy both pass', async () => {
    const g = guardian();
    const at = () => NOW + 150_000;
    const on = guardOf({ served: g.current, proofFor: g.proofFor, clock: at, staleness: {} });
    expect(res(await on(call(REVERSIBLE, 1)))).toBe('ok');
    expect(res(await on(call(IRREVERSIBLE, 2)))).toBe("403 freshness: revocation epoch is 150000 ms old, over the verifier's maximum of 120000 ms (stale revocation state)");
    const off = guardOf({ served: g.current, proofFor: g.proofFor, clock: at });
    expect(res(await off(call(IRREVERSIBLE, 1)))).toBe('ok');
  });

  it('a stricter configured window and the catalog class apply', async () => {
    const g = guardian();
    const at = () => NOW + 30_000;
    const strict = guardOf({ served: g.current, proofFor: g.proofFor, clock: at, staleness: { staleness: { irreversible: 20_000 } } });
    expect(res(await strict(call(IRREVERSIBLE, 1)))).toMatch(/^403 freshness: revocation epoch is 30000 ms old, over the verifier's maximum of 20000 ms/);
    // the server's catalog says the reversible-signed verb is irreversible: the stricter window applies
    const catalog = guardOf({
      served: g.current, proofFor: g.proofFor, clock: () => NOW + 150_000, staleness: {},
      extra: { context: (q: unknown, pc: { action: { verb: string } }) => ({ ...rsContext(q, pc), reversibilityClass: 'irreversible' }) },
    });
    const r = await catalog(call(REVERSIBLE, 1));
    expect(!r.ok && r.verdict.checks.freshness).toBe('fail');
  });

  it('grant revoked mid-run: the next call is denied, and a captured pre-revocation epoch replayed later is refused for an irreversible action', async () => {
    const g = guardian();
    let t = NOW + 1000;
    let served: () => RevocationEpoch | null = g.current;
    const mk = (staleness?: RevocationStalenessPolicy) => guardOf({ served: () => served(), proofFor: g.proofFor, clock: () => t, store: memoryPcaStore(), ...(staleness ? { staleness } : {}) });
    const on = mk({});
    const off = mk();
    expect(res(await on(call(IRREVERSIBLE, 1)))).toBe('ok');
    expect(res(await off(call(IRREVERSIBLE, 1)))).toBe('ok');
    const captured = g.current(); // epoch 0, root without the revocation
    t = NOW + 30_000;
    g.revoke(taskCapId(), t);
    expect(res(await on(call(IRREVERSIBLE, 2)))).toMatch(/^403 .*revoked|^403 .*no non-membership proof/);
    // an attacker (or a stale cache) serves the captured epoch 0 at t = 150 s: still inside its signed not_after
    t = NOW + 150_000;
    served = () => captured;
    const proofsFromOldSet = new RevocationSet().nonMembershipProof(taskCapId());
    const replayOn = guardOf({ served, proofFor: () => proofsFromOldSet, clock: () => t, staleness: {} });
    const replayOff = guardOf({ served, proofFor: () => proofsFromOldSet, clock: () => t });
    // without the policy the stale state admits the revoked agent (the gap this closes); with it, denied
    expect(res(await replayOff(call(IRREVERSIBLE, 3)))).toBe('ok');
    expect(res(await replayOn(call(IRREVERSIBLE, 3)))).toMatch(/^403 freshness: revocation epoch is 150000 ms old/);
  });

  it('revocation source unavailable: a throwing source fails closed; a missing epoch denies an irreversible action even when freshness is not in `require`', async () => {
    const g = guardian();
    const throwing = requirePCA({
      resolveGrant: async () => s.grant, now: () => NOW, audience: AUD, budgetStore: memoryPcaStore(),
      context: rsContext,
      hooks: { revocation: () => ({ enforced: true, ok: true }) },
      revocationEpoch: async () => {
        throw new Error('guardian unreachable');
      },
      revocationStaleness: {},
    });
    expect(res(await throwing(call(REVERSIBLE, 1)))).toBe('403 guard error (fail closed): guardian unreachable');
    // the integrator dropped `freshness` from `require` (e.g. a custom profile): T9 still refuses the irreversible action
    const require = ['counter', 'revocation', 'plan_root_authorized', 'audience', 'validity', 'grant_ref_bound'];
    const down = guardOf({ served: () => null, proofFor: g.proofFor, clock: () => NOW, staleness: {}, extra: { require, hooks: { revocation: () => ({ enforced: true, ok: true }) } } });
    expect(res(await down(call(REVERSIBLE, 1)))).toBe('ok');
    const r = await down(call(IRREVERSIBLE, 2));
    expect(res(r)).toBe('403 freshness: no verifiable (guardian-signed) revocation state for an irreversible action');
    expect(!r.ok && r.verdict.checks.freshness).toBe('fail');
    // explicitly allowed: the (undated) hook answer is accepted
    const allowed = guardOf({
      served: () => null, proofFor: g.proofFor, clock: () => NOW, staleness: { allowUnsignedRootForIrreversible: true },
      extra: { require, hooks: { revocation: () => ({ enforced: true, ok: true }) } },
    });
    expect(res(await allowed(call(IRREVERSIBLE, 1)))).toBe('ok');
    // no revocationEpoch option at all (hook only): same rule
    const hookOnly = requirePCA({
      resolveGrant: async () => s.grant, now: () => NOW, audience: AUD, budgetStore: memoryPcaStore(),
      context: rsContext,
      hooks: { revocation: () => ({ enforced: true, ok: true }) },
      revocationStaleness: {},
    });
    expect(res(await hookOnly(call(REVERSIBLE, 1)))).toBe('ok');
    expect(res(await hookOnly(call(IRREVERSIBLE, 2)))).toBe('403 freshness: no verifiable (guardian-signed) revocation state for an irreversible action');
  });

  it('restart with cached state: the pinned epoch survives, a cached epoch past the irreversible window is refused, a fresh one admits', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pca-t9-restart-'));
    try {
      const g = guardian();
      g.revoke('someone-else', NOW); // epoch 1
      const st1 = durablePcaStateStore(await openDurableState({ dir }));
      const before = guardOf({ served: g.current, proofFor: g.proofFor, clock: () => NOW + 1000, store: st1, staleness: {} });
      expect(res(await before(call(IRREVERSIBLE, 1)))).toBe('ok');
      const cached = g.current();
      // restart 200 s later: a new process, the same durable state, the epoch it had cached before the restart
      const st2 = durablePcaStateStore(await openDurableState({ dir }));
      expect((await st2.get(`${s.grant.id}:epoch`))?.lastEpoch).toBe(1);
      const t = NOW + 200_000;
      const after = guardOf({ served: () => cached, proofFor: g.proofFor, clock: () => t, store: st2, staleness: {} });
      expect(res(await after(call(REVERSIBLE, 2)))).toBe('ok');
      expect(res(await after(call(IRREVERSIBLE, 3)))).toMatch(/^403 freshness: revocation epoch is 200000 ms old/);
      // an even older epoch (0) from some other cache is a rollback against the persisted pin
      const epoch0 = signRevocationEpoch(G.secretKey, { instance_id: 'i', grant_ref: s.grant.id, epoch: 0, set_size: 0, root: new RevocationSet().root, issued_at: t, not_after: t + 300_000 });
      const rolled = guardOf({ served: () => epoch0, proofFor: (id) => new RevocationSet().nonMembershipProof(id), clock: () => t, store: st2, staleness: {} });
      expect(res(await rolled(call(REVERSIBLE, 4)))).toBe('403 freshness: revocation epoch 0 is older than the last accepted 1 (rollback)');
      // the guardian re-signs: fresh state admits the irreversible action again
      g.resign(t);
      const refreshed = guardOf({ served: g.current, proofFor: g.proofFor, clock: () => t, store: st2, staleness: {} });
      expect(res(await refreshed(call(IRREVERSIBLE, 5)))).toBe('ok');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('the atomic path pins accepted epochs (raisePin) like the lock path', async () => {
    const g = guardian();
    g.revoke('x', NOW); // epoch 1
    const st = atomicMemoryPcaStore();
    const guard = guardOf({ served: g.current, proofFor: g.proofFor, clock: () => NOW, store: st });
    expect(res(await guard(call(REVERSIBLE, 1)))).toBe('ok');
    expect(await st.get(`${s.grant.id}:epoch`)).toEqual({ lastEpoch: 1 });
  });

  it('a malformed policy is refused at construction', () => {
    const g = guardian();
    expect(() => guardOf({ served: g.current, proofFor: g.proofFor, clock: () => NOW, staleness: { maxRevocationAgeMs: -5 } })).toThrow(/maxRevocationAgeMs/);
  });
});
