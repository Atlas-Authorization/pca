/**
 * Mutation kills for the 0.5.0 flagship gate survivors in immune.ts: the range checks of a stored state (inclusive upper
 * bound, a numeric string, non-object state and baseline, mean and m2 messages), the fail-closed assessment of a bad state,
 * assertNoWiden on a non-widening policy, every applyTightening refusal the earlier suites reached only indirectly (a
 * function as a proposal, non-string sig / guardian, an invalid base or proposal policy, a NaN clock, the max-age bound,
 * both halves of the state recompute, a throwing proposal) and the durable store (empty get, the epoch key, an update that
 * never runs its callback).
 */
import { describe, expect, it } from 'vitest';
import { createMemoryDurableKv, type DurableKv } from './durable-state';
import { b64u, canonicalBytesLenient, hashCanonicalLenient, utf8 } from './hash';
import {
  applyTightening,
  assertNoWiden,
  assess,
  createImmuneStore,
  INITIAL_IMMUNE_STATE,
  issueTighteningProposal,
  policyDigest,
  TIGHTENING_DOMAIN,
  validateImmuneState,
  type TighteningClaim,
  type TighteningProposal,
} from './immune';
import { generateKeyPair, publicKeyOf, sign } from './keys';
import { DEFAULT_RISK_POLICY, type RiskPolicy } from './risk';

const base: RiskPolicy = { ...DEFAULT_RISK_POLICY, kappa: 100, theta1: 0.5, theta2: 0.8 };
const g = generateKeyPair();
const gpk = b64u(publicKeyOf(g.secretKey));
const NOW = 1_000_000;
const opts = { guardian: gpk, lastEpoch: 0, now: NOW, maxAgeMs: 1000 };
const issue = () => issueTighteningProposal({ base, state: INITIAL_IMMUNE_STATE, epoch: 1, now: NOW, guardianSecret: g.secretKey });
const signClaim = (c: TighteningClaim): TighteningProposal => {
  const pre = utf8(TIGHTENING_DOMAIN);
  const body = canonicalBytesLenient(c);
  const m = new Uint8Array(pre.length + body.length);
  m.set(pre);
  m.set(body, pre.length);
  return { ...c, sig: b64u(sign(g.secretKey, m)) };
};
const claim = (o: Partial<TighteningClaim> = {}): TighteningClaim => ({ v: 1, base_digest: policyDigest(base), state_digest: hashCanonicalLenient(INITIAL_IMMUNE_STATE), epoch: 1, issued_at: NOW, policy: base, rationale: 'r', guardian: gpk, ...o });
const st = (baseline: object) => ({ ...INITIAL_IMMUNE_STATE, baseline });

describe('immune.ts: validateImmuneState', () => {
  it('the upper bound of a range is inclusive', () => {
    expect(validateImmuneState(st({ n: 1, mean: 1, m2: 0 }))).toBeNull();
    expect(validateImmuneState({ ...INITIAL_IMMUNE_STATE, ewma: 1 })).toBeNull();
  });
  it('a numeric string, an out-of-range mean and a negative m2 are refused by name', () => {
    expect(validateImmuneState(st({ n: 0, mean: '0.5', m2: 0 }))).toBe('baseline.mean must be in [0, 1]');
    expect(validateImmuneState(st({ n: 0, mean: 2, m2: 0 }))).toBe('baseline.mean must be in [0, 1]');
    expect(validateImmuneState(st({ n: 0, mean: 0, m2: -1 }))).toBe('baseline.m2 must be finite and >= 0');
  });
  it('a non-object state and a truthy non-object baseline', () => {
    expect(validateImmuneState(5)).toBe('state must be an object');
    expect(validateImmuneState(st(5 as never))).toBe('baseline missing');
  });
});

describe('immune.ts: assess and assertNoWiden', () => {
  it('a bad state is the worst case with the reason', () => {
    expect(assess(5 as never)).toEqual({ level: 'high', score: 1, signals: ['invalid immune state: state must be an object'], components: { drift: 1, volatility: 1, violation: 1 } });
  });
  it('a policy that only tightens passes; a widening one throws', () => {
    expect(() => assertNoWiden(base, base)).not.toThrow();
    expect(() => assertNoWiden(base, { ...base, kappa: 1 })).toThrow('immune: adaptation widens the policy (kappa decreased)');
  });
});

describe('immune.ts: applyTightening', () => {
  it('the issued proposal applies', () => {
    expect(applyTightening(base, issue(), opts)).toEqual({ ok: true, policy: base, epoch: 1 });
  });
  it('a function carrying every proposal member is malformed', () => {
    const f = Object.assign(() => undefined, issue());
    expect(applyTightening(base, f as never, opts)).toEqual({ ok: false, reason: 'malformed' });
  });
  it('a non-string sig or guardian is malformed', () => {
    expect(applyTightening(base, { ...issue(), sig: 5 } as never, opts)).toEqual({ ok: false, reason: 'malformed' });
    expect(applyTightening(base, { ...issue(), guardian: 5 } as never, opts)).toEqual({ ok: false, reason: 'malformed' });
  });
  it('an invalid base or an invalid signed policy is invalid-policy', () => {
    expect(applyTightening({ ...base, kappa: -1 }, issue(), opts)).toEqual({ ok: false, reason: 'invalid-policy' });
    expect(applyTightening(base, signClaim(claim({ policy: { ...base, kappa: -1 } })), opts)).toEqual({ ok: false, reason: 'invalid-policy' });
  });
  it('a NaN clock is stale; an age of exactly maxAgeMs is still fresh', () => {
    expect(applyTightening(base, issue(), { ...opts, now: Number.NaN })).toEqual({ ok: false, reason: 'stale' });
    expect(applyTightening(base, issue(), { ...opts, now: NOW + 1000 })).toEqual({ ok: true, policy: base, epoch: 1 });
    expect(applyTightening(base, issue(), { ...opts, now: NOW + 1001 })).toEqual({ ok: false, reason: 'stale' });
  });
  it('the state recompute checks the state digest and the derived policy separately', () => {
    // another calm state derives the same policy but has another digest
    expect(applyTightening(base, issue(), { ...opts, state: { ...INITIAL_IMMUNE_STATE, lastAt: 5 } })).toEqual({ ok: false, reason: 'state-mismatch' });
    // the right state digest with a tighter policy than that state derives
    const tighter = signClaim(claim({ policy: { ...base, kappa: 200 } }));
    expect(applyTightening(base, tighter, opts)).toEqual({ ok: true, policy: { ...base, kappa: 200 }, epoch: 1 });
    expect(applyTightening(base, tighter, { ...opts, state: INITIAL_IMMUNE_STATE })).toEqual({ ok: false, reason: 'state-mismatch' });
  });
  it('a throwing proposal is malformed', () => {
    const p = { get v(): never { throw new Error('boom'); } };
    expect(applyTightening(base, p as never, opts)).toEqual({ ok: false, reason: 'malformed' });
  });
});

describe('immune.ts: createImmuneStore', () => {
  it('an empty store reads the initial state', async () => {
    expect(await createImmuneStore(createMemoryDurableKv(), 's').get()).toEqual(INITIAL_IMMUNE_STATE);
  });
  it('the epoch floor lives under immune/epoch/<subject>', async () => {
    const kv = createMemoryDurableKv();
    await kv.set('immune/epoch/s', 7);
    expect(await createImmuneStore(kv, 's').lastEpoch()).toBe(7);
  });
  it('an update that never runs its callback leaves the malformed refusal', async () => {
    const kv: DurableKv = { get: async () => undefined, set: async () => undefined, update: async () => undefined, keys: async () => [] };
    expect(await createImmuneStore(kv, 's').apply(base, issue(), { guardian: gpk, now: NOW, maxAgeMs: 1000 })).toEqual({ ok: false, reason: 'malformed' });
  });
});
