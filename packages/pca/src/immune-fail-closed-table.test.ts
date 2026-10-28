/** Exact-outcome table for the immune layer: missing or malformed X gives Y. Fails closed everywhere. */
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { runImmuneEpoch } from './test-support/flow-immune-epoch';
import { createMemoryDurableKv } from './durable-state';
import {
  INITIAL_IMMUNE_STATE, adapt, applyTightening, assertNoWiden, assess, createImmuneStore,
  issueTighteningProposal, noWidenViolation, observe, validateImmuneState, type ImmuneState,
} from './immune';
import { encodeKey, generateKeyPair } from './keys';
import { DEFAULT_RISK_POLICY as BASE, type RiskPolicy } from './risk';
import type { ActivityEvent } from './console';

const G = generateKeyPair();
const GK = encodeKey(G.publicKey);
const NOW = 1_000_000;
const hot: ImmuneState = { ...INITIAL_IMMUNE_STATE, stepUps: 10, denies: 10, seeded: true, lastAt: 5, ewma: 1 };
const opts = { guardian: GK, lastEpoch: 0, now: NOW, maxAgeMs: 1000 };
const prop = (over: Partial<Parameters<typeof issueTighteningProposal>[0]> = {}) =>
  issueTighteningProposal({ base: BASE, state: hot, epoch: 1, now: NOW, guardianSecret: G.secretKey, ...over });

describe('validateImmuneState', () => {
  const bad: Array<[string, unknown, string]> = [
    ['null', null, 'state must be an object'],
    ['no baseline', { ...INITIAL_IMMUNE_STATE, baseline: undefined }, 'baseline missing'],
    ['NaN ewma', { ...INITIAL_IMMUNE_STATE, ewma: NaN }, 'ewma must be in [0, 1]'],
    ['ewma > 1', { ...INITIAL_IMMUNE_STATE, ewma: 2 }, 'ewma must be in [0, 1]'],
    ['negative stepUps', { ...INITIAL_IMMUNE_STATE, stepUps: -1 }, 'stepUps must be finite and >= 0'],
    ['over-bound denies', { ...INITIAL_IMMUNE_STATE, denies: 1e12 }, 'denies must be finite and >= 0'],
    ['fractional n', { ...INITIAL_IMMUNE_STATE, baseline: { n: 1.5, mean: 0, m2: 0 } }, 'baseline.n must be an integer in [0, 1e9]'],
    ['Infinity lastAt', { ...INITIAL_IMMUNE_STATE, lastAt: Infinity }, 'lastAt must be a finite non-negative time'],
    ['seeded not bool', { ...INITIAL_IMMUNE_STATE, seeded: 1 }, 'seeded must be a boolean'],
  ];
  it.each(bad)('%s -> reason, and assess() reads it as high threat (never calm)', (_n, s, reason) => {
    expect(validateImmuneState(s)).toBe(reason);
    const a = assess(s as ImmuneState);
    expect(a.level).toBe('high');
    expect(a.score).toBe(1);
  });
  it('the initial state is valid', () => expect(validateImmuneState(INITIAL_IMMUNE_STATE)).toBeNull());
});

describe('adapt fail-closed', () => {
  it('NaN score is the worst case, not calm', () => {
    const a = adapt(BASE, { level: 'calm', score: NaN, signals: [], components: { drift: 0, volatility: 0, violation: 0 } });
    expect(a.changed).toBe(true);
    expect(a.policy.kappa).toBe(BASE.kappa * 3);
  });
  it('a loosening config is rejected and the base is kept', () => {
    const a = adapt(BASE, assess(hot), { maxKappaMult: 0.5, minThetaMult: 0.4 });
    expect(a.changed).toBe(false);
    expect(a.rationale).toBe('adaptation rejected (kappa decreased) — kept baseline');
  });
  it('a theta-raising config is rejected', () => {
    const a = adapt(BASE, assess(hot), { maxKappaMult: 3, minThetaMult: 2 });
    expect(a.rationale).toContain('theta');
    expect(a.policy).toBe(BASE);
  });
  it('score 0 returns the base exactly', () => {
    expect(adapt(BASE, { level: 'calm', score: 0, signals: [], components: { drift: 0, volatility: 0, violation: 0 } }).policy).toBe(BASE);
  });
});

describe('noWidenViolation / assertNoWiden', () => {
  const p = (o: Partial<RiskPolicy>): RiskPolicy => ({ ...BASE, ...o });
  it.each([
    [{ kappa: 0.5 }, 'kappa decreased'],
    [{ theta1: 0.3 }, 'theta1 increased'],
    [{ theta2: 0.7 }, 'theta2 increased'],
    [{ bMax: 2 }, 'bMax changed'],
    [{ rho: 9 }, 'rho changed'],
    [{ lambda: 1 }, 'lambda changed'],
    [{ weights: { ...BASE.weights, alpha: 0 } }, 'weights.alpha changed'],
  ])('%j -> %s', (o, why) => {
    expect(noWidenViolation(BASE, p(o))).toBe(why);
    expect(() => assertNoWiden(BASE, p(o))).toThrow(why);
  });
  it('tightening and identity pass', () => {
    expect(noWidenViolation(BASE, p({ kappa: 2, theta1: 0.1 }))).toBeNull();
    expect(noWidenViolation(BASE, BASE)).toBeNull();
  });
});

describe('applyTightening outcomes', () => {
  it('valid proposal applies', () => {
    const r = applyTightening(BASE, prop(), opts);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.policy.kappa).toBeGreaterThan(BASE.kappa);
  });
  it('re-derives against the state when given', () => {
    expect(applyTightening(BASE, prop(), { ...opts, state: hot }).ok).toBe(true);
    expect(applyTightening(BASE, prop(), { ...opts, state: INITIAL_IMMUNE_STATE })).toEqual({ ok: false, reason: 'state-mismatch' });
  });
  const cases: Array<[string, () => unknown, Partial<typeof opts>, string]> = [
    ['unpinned guardian', () => prop(), { guardian: encodeKey(generateKeyPair().publicKey) }, 'guardian'],
    ['tampered policy', () => ({ ...prop(), policy: { ...prop().policy, kappa: 99 } }), {}, 'signature'],
    ['tampered epoch', () => ({ ...prop(), epoch: 9 }), {}, 'signature'],
    ['stale', () => prop({ now: NOW - 5000 }), {}, 'stale'],
    ['future-dated', () => prop({ now: NOW + 5000 }), {}, 'stale'],
    ['replayed epoch', () => prop({ epoch: 3 }), { lastEpoch: 3 }, 'replayed-epoch'],
    ['lower epoch', () => prop({ epoch: 2 }), { lastEpoch: 3 }, 'replayed-epoch'],
    ['not an object', () => null, {}, 'malformed'],
    ['wrong version', () => ({ ...prop(), v: 2 }), {}, 'malformed'],
  ];
  it.each(cases)('%s -> %s', (_n, mk, o, reason) => {
    expect(applyTightening(BASE, mk() as never, { ...opts, ...o })).toEqual({ ok: false, reason });
  });
  it('another base policy is refused', () => {
    expect(applyTightening({ ...BASE, kappa: 2 }, prop(), opts)).toEqual({ ok: false, reason: 'base' });
  });
  it('a correctly signed but widening proposal is refused', async () => {
    const { sign } = await import('./keys');
    const { b64u, canonicalBytesLenient, utf8 } = await import('./hash');
    const { TIGHTENING_DOMAIN, policyDigest } = await import('./immune');
    const { sig: _s, ...c } = prop();
    const claim = { ...c, policy: { ...BASE, kappa: 0.5 }, base_digest: policyDigest(BASE) };
    const body = canonicalBytesLenient(claim);
    const pre = utf8(TIGHTENING_DOMAIN);
    const m = new Uint8Array(pre.length + body.length);
    m.set(pre);
    m.set(body, pre.length);
    expect(applyTightening(BASE, { ...claim, sig: b64u(sign(G.secretKey, m)) }, opts)).toEqual({ ok: false, reason: 'widens' });
  });
  it('issue refuses a bad epoch, base, or clock', () => {
    expect(() => prop({ epoch: 0 })).toThrow('epoch');
    expect(() => prop({ now: NaN })).toThrow('now');
    expect(() => prop({ base: { ...BASE, kappa: -1 } })).toThrow('kappa');
  });
});

describe('ImmuneStore (durable)', () => {
  it('keeps state across handles and refuses a replayed epoch; refuses to fold into corrupt state', async () => {
    const kv = createMemoryDurableKv();
    const a = createImmuneStore(kv, 's');
    await a.observe({ r: 0.9, at: 1, denied: true });
    const b = createImmuneStore(kv, 's');
    expect((await b.get()).denies).toBe(1);
    const p = prop({ state: await b.get() });
    expect((await b.apply(BASE, p, { guardian: GK, now: NOW, maxAgeMs: 1000 })).ok).toBe(true);
    expect(await a.lastEpoch()).toBe(1);
    expect(await a.apply(BASE, p, { guardian: GK, now: NOW, maxAgeMs: 1000 })).toEqual({ ok: false, reason: 'replayed-epoch' });
    await kv.set('immune/state/s', { nonsense: true });
    await expect(a.observe({ r: 0, at: 2 })).rejects.toThrow('stored state invalid');
  });
});

describe('properties', () => {
  const obs = fc.array(fc.record({ r: fc.double({ min: 0, max: 1, noNaN: true }), stepUp: fc.boolean(), denied: fc.boolean() }), { maxLength: 40 });
  it('adapt never widens, never NaN, and reversal at score 0 is the base', () => {
    fc.assert(
      fc.property(obs, (xs) => {
        let s = INITIAL_IMMUNE_STATE;
        xs.forEach((o, i) => (s = observe(s, { ...o, at: i * 1000 })));
        const ad = adapt(BASE, assess(s));
        expect(noWidenViolation(BASE, ad.policy)).toBeNull();
        for (const v of [ad.policy.kappa, ad.policy.theta1, ad.policy.theta2]) expect(Number.isFinite(v)).toBe(true);
        expect(adapt(BASE, { ...assess(s), score: 0 }).policy).toBe(BASE);
      }),
      { numRuns: 100 },
    );
  });
  it('a higher score is never looser', () => {
    fc.assert(
      fc.property(fc.double({ min: 0, max: 1, noNaN: true }), fc.double({ min: 0, max: 1, noNaN: true }), (a, b) => {
        const [lo, hi] = a <= b ? [a, b] : [b, a];
        const m = (score: number) => adapt(BASE, { level: 'calm', score, signals: [], components: { drift: 0, volatility: 0, violation: 0 } }).policy;
        expect(m(hi).kappa).toBeGreaterThanOrEqual(m(lo).kappa);
        expect(m(hi).theta1).toBeLessThanOrEqual(m(lo).theta1);
        expect(m(hi).theta2).toBeLessThanOrEqual(m(lo).theta2);
      }),
      { numRuns: 100 },
    );
  });
});

describe('example: activity -> signed tightening -> stricter threshold', () => {
  it('a denial burst moves a probe action from auto (t=1) to a higher tier, and a replay is refused', async () => {
    const events: ActivityEvent[] = Array.from({ length: 6 }, (_, i) => ({
      at: i * 1000, agent: 'a', verb: 'pay', resource: 'x', outcome: 'deny', r: 0.9,
    }));
    const r = await runImmuneEpoch(events, NOW);
    expect(r.applied.ok).toBe(true);
    expect(r.before).toBe(1);
    expect(r.after).toBeGreaterThan(1);
    expect(r.replay).toEqual({ ok: false, reason: 'replayed-epoch' });
  });
});
