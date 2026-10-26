/**
 * 0.5 breaking defaults for the server verifier (B2, B7): each test pins the NEW default and shows the old unsafe
 * default now refuses.
 */
import { describe, expect, it } from 'vitest';
import { decodePCActn } from '../pcactn';
import { missingAuthorizeComponents } from './authorize';
import { atomicMemoryPcaStore, memoryPcaStore, pcaStateKey, requirePCA, type PcaHolderState, type PcaStateStore } from './require-pca';
import { DEFAULT_REQUIRED_CHECKS, verifyPCActn } from './verify';
import { AUD, NOW, setup } from './fixture.test-util';

const s = setup();
const node = s.plan[0]!;
const revocation = () => ({ enforced: true, ok: true });
const ctx = () => ({ plan: s.plan, planAuthorized: true, risk: s.lowRisk });
const operation = () => ({ verb: node.verb, resource: node.resource, params: {} });
const base = { resolveGrant: async (ref: string) => (ref === s.grant.id ? s.grant : null), now: () => NOW, audience: AUD, context: ctx, hooks: { revocation }, operation };
const req = (counter: number) => ({ headers: {}, body: { pcactn: s.mk(node, { counter }) } });

describe('B2: verifyPCActn requires DEFAULT_REQUIRED_CHECKS by default', () => {
  const verify = (opts: Record<string, unknown> = {}) => verifyPCActn(s.mk(node), { grant: s.grant, audience: AUD, now: NOW, context: ctx(), ...opts });
  it('a bare call denies: revocation is not enforced, so it is not a pass', async () => {
    const v = await verify();
    expect({ allow: v.allow, revocation: v.checks.revocation, reasons: v.reasons.filter((r) => r.startsWith('revocation')) }).toEqual({
      allow: false,
      revocation: 'fail',
      reasons: ['revocation: required check is not-enforced (default-deny: not enforced by this resource server)'],
    });
    expect(DEFAULT_REQUIRED_CHECKS).toContain('revocation');
  });
  it('supplying the revocation check allows it', async () => {
    expect((await verify({ hooks: { revocation } })).allow).toBe(true);
  });
  it('require: [] is the explicit opt-out (the 0.4 report-only behaviour)', async () => {
    const v = await verify({ require: [] });
    expect({ allow: v.allow, revocation: v.checks.revocation }).toEqual({ allow: true, revocation: 'not-enforced' });
  });
  it('a custom require list replaces the default', async () => {
    expect((await verify({ require: ['audience'] })).allow).toBe(true);
    expect((await verify({ require: ['audience', 'revocation'] })).allow).toBe(false);
  });
});

describe('B2: requirePCA binds the proof to an operation', () => {
  it('refuses to be built without `operation` (the unbound guard accepted a proof for any operation)', () => {
    const { operation: _o, ...unbound } = base;
    expect(() => requirePCA(unbound)).toThrow(/`operation` is required/);
  });
  it('the unbound guard is an explicit, loudly named opt-in', async () => {
    const { operation: _o, ...unbound } = base;
    const g = requirePCA({ ...unbound, budgetStore: memoryPcaStore(), insecureAllowUnboundOperation: true });
    expect((await g(req(1))).ok).toBe(true);
  });
  it('insecureAllowUnenforced (dev mode) also builds without it', () => {
    const { operation: _o, ...unbound } = base;
    expect(() => requirePCA({ ...unbound, insecureAllowUnenforced: true })).not.toThrow();
  });
  it('with `operation` a proof for another operation is refused', async () => {
    const g = requirePCA({ ...base, operation: () => ({ verb: 'rotate_recovery_keys', resource: 'account:me', params: {} }) });
    const r = await g(req(1));
    expect({ ok: r.ok, operation: r.verdict.checks.operation }).toEqual({ ok: false, operation: 'fail' });
  });
});

describe('B2: authorize never runs unbound', () => {
  it('insecureAllowUnboundOperation is not accepted (it names the missing/forbidden component)', () => {
    expect(missingAuthorizeComponents({ audience: AUD, resolveGrant: base.resolveGrant, budgetStore: memoryPcaStore(), hooks: { revocation }, insecureAllowUnboundOperation: true })).toEqual([
      'insecureAllowUnboundOperation is not accepted by authorize',
    ]);
  });
});

describe('B2: multiInstance defaults to true unless the store is process-local', () => {
  const plain = (): PcaStateStore => {
    const m = new Map<string, PcaHolderState>();
    return { get: async (k) => m.get(k), put: async (k, v) => void m.set(k, v) };
  };
  it('a get/put store with neither claim nor withKeyLock is refused', () => {
    expect(() => requirePCA({ ...base, budgetStore: plain() })).toThrow(/multiInstance needs a budgetStore with `claim`/);
  });
  it('multiInstance: false runs a plain store in one process on purpose', async () => {
    const g = requirePCA({ ...base, budgetStore: plain(), multiInstance: false });
    expect(g.stateMode).toBe('process-lock');
    expect((await g(req(1))).ok).toBe(true);
  });
  it('a store that declares scope: process is accepted without the flag', () => {
    expect(requirePCA({ ...base, budgetStore: memoryPcaStore() }).stateMode).toBe('process-lock');
  });
  it('a store with withKeyLock or claim is accepted', () => {
    expect(requirePCA({ ...base, budgetStore: { ...plain(), withKeyLock: (_k, fn) => fn() } }).stateMode).toBe('shared-lock');
    expect(requirePCA({ ...base, budgetStore: { ...atomicMemoryPcaStore(), scope: 'shared' } }).stateMode).toBe('atomic-claim');
  });
  it('no store: nothing to serialise', () => {
    expect(requirePCA(base).stateMode).toBe('none');
  });
});

describe('B2: the replay key carries the audience by default', () => {
  const writes = (inner: PcaStateStore) => {
    const keys: string[] = [];
    return { keys, store: { ...inner, put: async (k: string, v: PcaHolderState) => (keys.push(k), inner.put(k, v)) } as PcaStateStore };
  };
  it('state is written under the audience-scoped key, not the 0.4 key', async () => {
    const w = writes(memoryPcaStore());
    expect((await requirePCA({ ...base, budgetStore: w.store })(req(1))).ok).toBe(true);
    expect(w.keys).toEqual([`aud:${encodeURIComponent(AUD)}:${s.grant.id}:${s.aPub}`]);
    expect(pcaStateKey(s.grant.id, s.aPub, undefined, AUD)).toBe(w.keys[0]);
    expect(pcaStateKey(s.grant.id, s.aPub)).toBe(`${s.grant.id}:${s.aPub}`);
  });
  it('two audiences sharing one store keep separate counter streams', async () => {
    const store = memoryPcaStore();
    const a = requirePCA({ ...base, budgetStore: store, audience: AUD });
    const b = requirePCA({ ...base, budgetStore: store, audience: 'rs-other' });
    const forB = (counter: number) => ({ headers: {}, body: { pcactn: s.mk(node, { counter, extra: { aud: 'rs-other' } }) } });
    expect((await a(req(1))).ok).toBe(true);
    // counter 1 again, for the other resource server: its own stream (under the 0.4 key this was refused as a replay)
    expect((await b(forB(1))).ok).toBe(true);
    expect((await a(req(1))).ok).toBe(false);
    expect((await b(forB(1))).ok).toBe(false);
  });
  it('replayScope: grant-holder keeps the 0.4 key', async () => {
    const w = writes(memoryPcaStore());
    await requirePCA({ ...base, budgetStore: w.store, replayScope: 'grant-holder' })(req(1));
    expect(w.keys).toEqual([`${s.grant.id}:${s.aPub}`]);
  });
  for (const [label, mk] of [['get/put store', () => memoryPcaStore()], ['atomic store', () => atomicMemoryPcaStore()]] as const) {
    it(`upgrading a live store (${label}): a counter already spent under the 0.4 key stays spent`, async () => {
      const store = mk();
      await store.put(`${s.grant.id}:${s.aPub}`, { lastCounter: 5, budget: { B: 7, tau: NOW, asOf: NOW } });
      const g = requirePCA({ ...base, budgetStore: store });
      const replay = await g(req(5));
      expect({ ok: replay.ok, counter: replay.verdict.checks.replay }).toEqual({ ok: false, counter: 'fail' });
      expect((await g(req(6))).ok).toBe(true);
      // the carried state moved to the new key; the old key is never written again
      expect((await store.get(`${s.grant.id}:${s.aPub}`))?.lastCounter).toBe(5);
      expect((await store.get(pcaStateKey(s.grant.id, s.aPub, undefined, AUD)))?.lastCounter).toBe(6);
      expect((await g(req(6))).ok).toBe(false);
    });
  }
});

describe('B7: a feature the verifier does not implement is `unsupported`, never a pass', () => {
  const bonded = () => s.mk(node, { extra: { bond_ref: 'bond-1' } });
  const verify = (opts: Record<string, unknown> = {}) => verifyPCActn(bonded(), { grant: s.grant, audience: AUD, now: NOW, context: ctx(), hooks: { revocation }, ...opts });
  it('checks.bond is unsupported and the default verifier denies', async () => {
    const v = await verify();
    expect({ allow: v.allow, bond: v.checks.bond, reason: v.reasons.find((r) => r.startsWith('bond')) }).toEqual({
      allow: false,
      bond: 'unsupported',
      reason: 'bond: unsupported: the PCActn carries a feature this verifier does not implement (list it in allowUnsupported to accept it)',
    });
  });
  it('allowUnsupported accepts it explicitly, and the status stays unsupported', async () => {
    const v = await verify({ allowUnsupported: ['bond'] });
    expect({ allow: v.allow, bond: v.checks.bond }).toEqual({ allow: true, bond: 'unsupported' });
  });
  it('a required unsupported check is named as unsupported', async () => {
    const v = await verify({ allowUnsupported: ['bond'], require: ['bond'] });
    expect({ allow: v.allow, bond: v.checks.bond, reason: v.reasons.find((r) => r.startsWith('bond')) }).toEqual({
      allow: false,
      bond: 'fail',
      reason: 'bond: required check is unsupported (default-deny: not enforced by this resource server)',
    });
  });
  it('the assurance report agrees', async () => {
    const v = await verify({ allowUnsupported: ['bond'], assurance: true });
    expect(v.assurance?.bond).toEqual({ outcome: 'unsupported', reason: 'bond verification is not implemented by this verifier' });
  });
  it('a proof without bond_ref has no bond check', async () => {
    const v = await verifyPCActn(s.mk(node), { grant: s.grant, audience: AUD, now: NOW, context: ctx(), hooks: { revocation } });
    expect(v.checks.bond).toBeUndefined();
    expect(v.allow).toBe(true);
    expect(decodePCActn).toBeTypeOf('function');
  });
});
