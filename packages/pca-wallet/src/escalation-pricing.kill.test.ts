import { describe, expect, it } from 'vitest';
import { encodeKey, generateKeyPair } from '@atlasauth/pca';
import {
  applyAutonomyRaise,
  decideEscalation,
  freshCalibration,
  pricingConfigError,
  PPM,
  signAnswer,
  signAutonomyRaise,
  signPricingConfig,
  updateCalibration,
  type ActionRisk,
  type AnswerBody,
  type PricingConfigBody,
  type SignedPricingConfig,
} from './escalation-pricing';

const P = generateKeyPair();
const O = generateKeyPair();
const principal = encodeKey(P.publicKey);
const otherPrincipal = encodeKey(O.publicKey);
const body = (over: Partial<PricingConfigBody> = {}): PricingConfigBody => ({
  v: 1, principal, currency: 'USD', interruptionCost: 100, maxInterruptionCost: 1000, hardCeilingLoss: 100_000, tightenStepPpm: 500_000, epoch: 1, ...over,
});
const cfg = signPricingConfig(body(), P.secretKey);
const num = (x: number) => x as unknown as string;

describe('pricingConfigError', () => {
  it('memoizes a verified config but never a failure', () => {
    const good = signPricingConfig(body({ interruptionCost: 999, epoch: 0 }), P.secretKey);
    // -0 serializes like 0 but cannot be re-verified (strict canonical form refuses it): a cache hit is the only way it passes.
    const probe = (c: SignedPricingConfig) => pricingConfigError({ ...c, epoch: -0 }) === null;
    expect(probe(good)).toBe(false);
    expect(pricingConfigError(good)).toBeNull();
    expect(probe(good)).toBe(true);
    const forged = signPricingConfig(body({ interruptionCost: 8 }), O.secretKey);
    expect(pricingConfigError(forged)).toBe('config_signature_invalid');
    expect(pricingConfigError(forged)).toBe('config_signature_invalid');
  });
  it('evicts the whole memo when it reaches 64 entries', () => {
    const mk = (i: number) => signPricingConfig(body({ interruptionCost: i, epoch: 0 }), P.secretKey);
    const probe = (c: SignedPricingConfig) => pricingConfigError({ ...c, epoch: -0 }) === null;
    const first = mk(500);
    pricingConfigError(first);
    let i = 0;
    while (probe(first) && i < 300) pricingConfigError(mk(i++));
    expect(i).toBeLessThan(300); // the first entry was evicted by a clear
    // The memo now holds exactly the config added at that clear.
    const anchor = mk(i - 1);
    expect(probe(anchor)).toBe(true);
    for (let j = 0; j < 63; j++) pricingConfigError(mk(i + j));
    expect(probe(anchor)).toBe(true); // 64 entries: still full, not yet cleared
    pricingConfigError(mk(i + 63)); // the 65th add clears first
    expect(probe(anchor)).toBe(false);
    expect(probe(mk(i + 63))).toBe(true);
  });
  it('anything that is not a plain config object is malformed', () => {
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    expect(pricingConfigError(circular)).toBe('config_malformed');
    expect(pricingConfigError(Object.assign(() => undefined, cfg))).toBe('config_malformed');
    for (const c of [null, undefined, 5, 'x', [], { ...cfg, v: 2 }]) expect(pricingConfigError(c)).toBe('config_malformed');
  });
  it('a member of the wrong type is malformed', () => {
    expect(pricingConfigError({ ...cfg, principal: 5 })).toBe('config_malformed');
    expect(pricingConfigError({ ...cfg, sig: 5 })).toBe('config_malformed');
    expect(pricingConfigError(signPricingConfig(body({ currency: num(5) }), P.secretKey))).toBe('config_malformed');
  });
  it('undecodable key or signature material is malformed, not a crash', () => {
    expect(pricingConfigError({ ...cfg, sig: '!!!' })).toBe('config_malformed');
    expect(pricingConfigError({ ...cfg, principal: '!!!' })).toBe('config_malformed');
  });
  it('each amount field is checked on its own', () => {
    for (const k of ['interruptionCost', 'maxInterruptionCost', 'hardCeilingLoss', 'epoch'] as const) {
      expect(pricingConfigError(signPricingConfig({ ...body(), [k]: -1 } as PricingConfigBody, P.secretKey))).toBe('config_amounts_invalid');
      expect(pricingConfigError(signPricingConfig({ ...body(), [k]: 1.5 } as PricingConfigBody, P.secretKey))).toBe('config_amounts_invalid');
    }
    expect(pricingConfigError(signPricingConfig(body({ interruptionCost: 1001 }), P.secretKey))).toBe('config_cost_above_max');
  });
});

describe('decideEscalation', () => {
  it('asks, rather than crashing, when the risk is missing', () => {
    expect(decideEscalation(cfg, freshCalibration(), undefined as unknown as ActionRisk)).toEqual({ ask: true, reason: 'currency_mismatch' });
    expect(decideEscalation(cfg, freshCalibration(), null as unknown as ActionRisk)).toEqual({ ask: true, reason: 'currency_mismatch' });
  });
});

describe('updateCalibration', () => {
  const risk: ActionRisk = { currency: 'USD', loss: 1, pBadUpperPpm: 0 }; // auto-approved
  const risks = new Map<string, ActionRisk>([['d1', risk]]);
  let n = 0;
  const answer = (over: Partial<AnswerBody> = {}, secret = P.secretKey) =>
    signAnswer({ v: 1, principal, nonce: `nonce-${++n}-xxxxxxxx`, action_digest: 'd1', answer: 'deny', ...over }, secret);
  const fresh = freshCalibration();

  it('a deny of an auto-approved action tightens by the step and records the nonce; a replay changes nothing', () => {
    const a = answer();
    expect(updateCalibration(cfg, fresh, [a], risks)).toEqual({ multiplierPpm: PPM + 500_000, seen: [a.nonce] });
    expect(updateCalibration(cfg, fresh, [a, a], risks)).toEqual({ multiplierPpm: PPM + 500_000, seen: [a.nonce] });
  });
  it('an approve, an unknown action and an already-asked deny leave the multiplier alone', () => {
    const ap = answer({ answer: 'approve' });
    const unknown = answer({ action_digest: 'other' });
    const asked = answer({ action_digest: 'd2' });
    const r = updateCalibration(cfg, fresh, [ap, unknown, asked], new Map<string, ActionRisk>([['d1', risk], ['d2', { currency: 'USD', loss: 100_000, pBadUpperPpm: PPM }]]));
    expect(r).toEqual({ multiplierPpm: PPM, seen: [ap.nonce, unknown.nonce, asked.nonce] });
  });
  it('invalid answers are skipped entirely: not tightening, not recorded', () => {
    const wrongPrincipal = answer({ principal: otherPrincipal }); // signed by the real principal, but names another
    const numericNonce = answer({ nonce: 12345678 as unknown as string });
    const shortNonce = answer({ nonce: 'short' });
    const numericDigest = answer({ action_digest: 5 as unknown as string });
    const badVerb = answer({ answer: 'maybe' as unknown as 'deny' });
    const wrongKey = answer({}, O.secretKey);
    const garbageSig = { ...answer(), sig: '!!!' };
    const badVersion = answer({ v: 2 as unknown as 1 });
    for (const a of [wrongPrincipal, numericNonce, shortNonce, numericDigest, badVerb, wrongKey, garbageSig, badVersion]) {
      expect(updateCalibration(cfg, fresh, [a], new Map<string, ActionRisk>([['d1', risk], [5 as unknown as string, risk]]))).toEqual({ multiplierPpm: PPM, seen: [] });
    }
  });
  it('an unverifiable config leaves the calibration untouched (same object)', () => {
    const forged = signPricingConfig(body(), O.secretKey);
    expect(updateCalibration(forged, fresh, [answer()], risks)).toBe(fresh);
  });
});

describe('applyAutonomyRaise', () => {
  const raiseBody = { v: 1 as const, principal, epoch: 2, newInterruptionCost: 200 };
  it('applies a signed, newer, in-range raise and re-signs the config', () => {
    const next = applyAutonomyRaise(cfg, signAutonomyRaise(raiseBody, P.secretKey), P.secretKey);
    expect(next).toMatchObject({ interruptionCost: 200, epoch: 2, principal, maxInterruptionCost: 1000 });
    expect(pricingConfigError(next)).toBeNull();
  });
  it('refuses an undecodable signature', () => {
    expect(() => applyAutonomyRaise(cfg, { ...signAutonomyRaise(raiseBody, P.secretKey), sig: '!!!' }, P.secretKey)).toThrow('applyAutonomyRaise: signature or principal invalid');
  });
  it('refuses a wrong version, even when correctly signed', () => {
    expect(() => applyAutonomyRaise(cfg, signAutonomyRaise({ ...raiseBody, v: 2 as unknown as 1 }, P.secretKey), P.secretKey)).toThrow('signature or principal invalid');
  });
  it('refuses a raise naming another principal, even when signed by the real one', () => {
    expect(() => applyAutonomyRaise(cfg, signAutonomyRaise({ ...raiseBody, principal: otherPrincipal }, P.secretKey), P.secretKey)).toThrow('signature or principal invalid');
  });
  it('refuses a raise signed by someone else', () => {
    expect(() => applyAutonomyRaise(cfg, signAutonomyRaise(raiseBody, O.secretKey), P.secretKey)).toThrow('signature or principal invalid');
  });
});
