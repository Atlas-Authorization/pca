import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { generateKeyPair, encodeKey } from '@atlasauth/pca';
import {
  applyAutonomyRaise, decideEscalation, pricingConfigError, freshCalibration, PPM, signAnswer, signAutonomyRaise, signPricingConfig, updateCalibration,
  type ActionRisk, type AnswerBody, type Calibration,
} from './escalation-pricing';

const p = generateKeyPair();
const other = generateKeyPair();
const principal = encodeKey(p.publicKey);
const cfg = signPricingConfig({ v: 1, principal, currency: 'USD', interruptionCost: 100, maxInterruptionCost: 500, hardCeilingLoss: 100_000, tightenStepPpm: 500_000, epoch: 1 }, p.secretKey);
const risk = (loss: number, pBadUpperPpm: number): ActionRisk => ({ currency: 'USD', loss, pBadUpperPpm });
let n = 0;
const ans = (d: string, a: 'approve' | 'deny', secret = p.secretKey, pr = principal) => signAnswer({ v: 1, principal: pr, nonce: `nonce-${++n}-xxxxxxxx`, action_digest: d, answer: a } as AnswerBody, secret);

describe('escalation pricing decision (C-284)', () => {
  it('asks exactly when p * loss > cost (boundary exact, integer math)', () => {
    expect(decideEscalation(cfg, freshCalibration(), risk(1000, 100_000))).toMatchObject({ ask: false }); // 100 == 100: not strictly greater
    expect(decideEscalation(cfg, freshCalibration(), risk(1001, 100_000))).toMatchObject({ ask: true, reason: 'expected_loss_exceeds_interruption_cost' });
    expect(decideEscalation(cfg, freshCalibration(), risk(50, 0))).toMatchObject({ ask: false });
  });
  it('fails strict: bad signature, tampered cost, currency, out-of-range inputs, ceiling', () => {
    expect(decideEscalation({ ...cfg, interruptionCost: 1_000_000 - 1 }, freshCalibration(), risk(1, 0)).ask).toBe(true);
    const forged = signPricingConfig({ ...cfg, principal }, other.secretKey);
    expect(decideEscalation(forged, freshCalibration(), risk(1, 0))).toEqual({ ask: true, reason: 'config_signature_invalid' });
    expect(decideEscalation(cfg, freshCalibration(), { ...risk(1, 0), currency: 'EUR' }).reason).toBe('currency_mismatch');
    expect(decideEscalation(cfg, freshCalibration(), risk(1.5, 0)).reason).toBe('risk_input_invalid');
    expect(decideEscalation(cfg, freshCalibration(), risk(1, PPM + 1)).reason).toBe('risk_input_invalid');
    expect(decideEscalation(cfg, freshCalibration(), risk(100_001, 0)).reason).toBe('above_hard_ceiling');
    expect(decideEscalation(cfg, { multiplierPpm: 1, seen: [] }, risk(1, 0)).reason).toBe('calibration_invalid');
  });
  it('is deterministic', () => {
    const a = decideEscalation(cfg, freshCalibration(), risk(5000, 30_000));
    for (let i = 0; i < 5; i++) expect(decideEscalation(cfg, freshCalibration(), risk(5000, 30_000))).toEqual(a);
  });
});

describe('calibration only tightens (C-285, C-286)', () => {
  it('a signed deny of an auto-approved action raises the multiplier; approve / replay / forged / unknown change nothing', () => {
    const r = risk(1000, 100_000);
    const risks = new Map([['d1', r], ['d2', r]]);
    const deny = ans('d1', 'deny');
    const c1 = updateCalibration(cfg, freshCalibration(), [deny, deny, ans('d2', 'approve'), ans('d2', 'deny', other.secretKey), ans('unknown', 'deny')], risks);
    expect(c1.multiplierPpm).toBe(PPM + 500_000);
    expect(decideEscalation(cfg, c1, r).ask).toBe(true);
    // an answer by another principal's key under this principal's name is rejected
    expect(updateCalibration(cfg, freshCalibration(), [ans('d1', 'deny', other.secretKey)], risks).multiplierPpm).toBe(PPM);
  });
  it('PROPERTY: no sequence of answers ever makes any action go from ask to no-ask', () => {
    let s = 12345;
    const rnd = (m: number) => { s = (Math.imul(s, 1103515245) + 12345) >>> 0; return s % m; };
    const probes: ActionRisk[] = [];
    for (let i = 0; i < 40; i++) probes.push(risk(rnd(120_000), rnd(PPM + 1)));
    const risks = new Map(probes.map((r, i) => [`d${i}`, r] as const));
    const pool = Array.from({ length: 120 }, (_, i) => ans(`d${i % 45}`, i % 2 === 0 ? 'approve' : 'deny', i % 5 === 0 ? other.secretKey : p.secretKey));
    for (let trial = 0; trial < 30; trial++) {
      let cal: Calibration = freshCalibration();
      for (let step = 0; step < 15; step++) {
        const batch = Array.from({ length: 1 + rnd(4) }, () => pool[rnd(pool.length)]!);
        const next = updateCalibration(cfg, cal, batch, risks);
        expect(next.multiplierPpm).toBeGreaterThanOrEqual(cal.multiplierPpm);
        for (const r of probes) if (decideEscalation(cfg, cal, r).ask) expect(decideEscalation(cfg, next, r).ask).toBe(true);
        cal = next;
      }
    }
  });
  it('a corrupt config makes the learner a no-op', () => {
    const bad = { ...cfg, sig: 'AAAA' };
    expect(updateCalibration(bad, freshCalibration(), [ans('d', 'deny')], new Map([['d', risk(1, 0)]])).multiplierPpm).toBe(PPM);
  });
});

describe('asking less needs the principal (C-287)', () => {
  it('a signed raise within the maximum lowers the ask rate; above the max, wrong key, stale epoch are refused', () => {
    const r = risk(1001, 100_000);
    const raised = applyAutonomyRaise(cfg, signAutonomyRaise({ v: 1, principal, epoch: 2, newInterruptionCost: 200 }, p.secretKey), p.secretKey);
    expect(decideEscalation(cfg, freshCalibration(), r).ask).toBe(true);
    expect(decideEscalation(raised, freshCalibration(), r).ask).toBe(false);
    expect(() => applyAutonomyRaise(cfg, signAutonomyRaise({ v: 1, principal, epoch: 2, newInterruptionCost: 501 }, p.secretKey), p.secretKey)).toThrow(/maximum/);
    expect(() => applyAutonomyRaise(cfg, signAutonomyRaise({ v: 1, principal, epoch: 2, newInterruptionCost: 200 }, other.secretKey), p.secretKey)).toThrow(/signature/);
    expect(() => applyAutonomyRaise(cfg, signAutonomyRaise({ v: 1, principal, epoch: 1, newInterruptionCost: 200 }, p.secretKey), p.secretKey)).toThrow(/epoch/);
  });
});

describe('shared decision vectors (T-703)', () => {
  it('replays conformance/k4-vectors.json (decisions, config cases, calibration)', () => {
    const v = JSON.parse(readFileSync(join(__dirname, '../../pca/conformance/k4-vectors.json'), 'utf8')).escalation;
    expect(v.decisions.length).toBeGreaterThanOrEqual(14);
    for (const c of v.decisions) expect(decideEscalation(v.config, c.calibration, c.risk)).toEqual(c.expect);
    for (const c of v.config_cases) expect(pricingConfigError(c.config)).toBe(c.expect);
    for (const c of v.calibration) expect(updateCalibration(c.config, c.start, c.answers, new Map(Object.entries(c.risks)))).toEqual(c.expect);
  });
});

// ---- exact-outcome boundary tests (mutation kill set, T-700..704) ----
describe('config and input boundaries (C-284)', () => {
  const sign = (over: Record<string, unknown>) => signPricingConfig({ v: 1, principal, currency: 'USD', interruptionCost: 100, maxInterruptionCost: 500, hardCeilingLoss: 100_000, tightenStepPpm: 500_000, epoch: 1, ...over } as never, p.secretKey);
  it('config amounts and step at and beyond their limits', () => {
    expect(pricingConfigError(sign({ interruptionCost: 500 }))).toBeNull();
    expect(pricingConfigError(sign({ interruptionCost: 501 }))).toBe('config_cost_above_max');
    expect(pricingConfigError(sign({ tightenStepPpm: 0 }))).toBeNull();
    expect(pricingConfigError(sign({ tightenStepPpm: 100 * PPM }))).toBeNull();
    expect(pricingConfigError(sign({ tightenStepPpm: 100 * PPM + 1 }))).toBe('config_step_invalid');
    expect(pricingConfigError(sign({ tightenStepPpm: -1 }))).toBe('config_step_invalid');
    expect(pricingConfigError(sign({ epoch: -1 }))).toBe('config_amounts_invalid');
    expect(pricingConfigError(sign({ hardCeilingLoss: 1.5 }))).toBe('config_amounts_invalid');
    expect(pricingConfigError(sign({ epoch: 0 }))).toBeNull();
    expect(pricingConfigError({ ...cfg, v: 2 })).toBe('config_malformed');
    expect(pricingConfigError(null)).toBe('config_malformed');
  });
  it('multiplier and probability bounds are inclusive', () => {
    const d = (mult: number, pb: number, loss = 1) => decideEscalation(cfg, { multiplierPpm: mult, seen: [] }, risk(loss, pb));
    expect(d(PPM, 0).reason).toBe('expected_loss_within_interruption_cost');
    expect(d(PPM - 1, 0).reason).toBe('calibration_invalid');
    expect(d(100 * PPM, 0).reason).toBe('expected_loss_within_interruption_cost');
    expect(d(100 * PPM + 1, 0).reason).toBe('calibration_invalid');
    expect(d(PPM, PPM).reason).toBe('expected_loss_within_interruption_cost');
    expect(d(PPM, PPM + 1).reason).toBe('risk_input_invalid');
    expect(d(PPM, -1).reason).toBe('risk_input_invalid');
    expect(decideEscalation(cfg, undefined as never, risk(1, 0)).reason).toBe('calibration_invalid');
  });
  it('the ceiling is inclusive and the effective probability is capped at one', () => {
    expect(decideEscalation(cfg, freshCalibration(), risk(100_000, 0)).ask).toBe(false);
    expect(decideEscalation(cfg, freshCalibration(), risk(100_001, 0)).reason).toBe('above_hard_ceiling');
    // p = 1, loss 100 = cost: equal is no ask; the multiplier cannot push the probability above one
    expect(decideEscalation(cfg, { multiplierPpm: 100 * PPM, seen: [] }, risk(100, PPM)).ask).toBe(false);
    expect(decideEscalation(cfg, { multiplierPpm: 100 * PPM, seen: [] }, risk(101, PPM)).ask).toBe(true);
    expect(decideEscalation(cfg, freshCalibration(), null as never).reason).toBe('currency_mismatch');
  });
});

describe('answers and calibration boundaries (C-285, C-286)', () => {
  it('a nonce shorter than 8 characters is ignored, 8 counts', () => {
    const r = risk(1000, 100_000);
    const risks = new Map([['d', r]]);
    const mk = (nonce: string) => signAnswer({ v: 1, principal, nonce, action_digest: 'd', answer: 'deny' } as AnswerBody, p.secretKey);
    expect(updateCalibration(cfg, freshCalibration(), [mk('1234567')], risks)).toEqual({ multiplierPpm: PPM, seen: [] });
    expect(updateCalibration(cfg, freshCalibration(), [mk('12345678')], risks)).toEqual({ multiplierPpm: PPM + 500_000, seen: ['12345678'] });
  });
  it('the multiplier stops at the maximum; prior seen nonces are kept and block replays', () => {
    const r = risk(1000, 0);
    const risks = new Map([['d', r]]);
    const big = signPricingConfig({ v: 1, principal, currency: 'USD', interruptionCost: 100, maxInterruptionCost: 500, hardCeilingLoss: 100_000, tightenStepPpm: 100 * PPM, epoch: 1 }, p.secretKey);
    const a1 = signAnswer({ v: 1, principal, nonce: 'nonce-cap-1', action_digest: 'd', answer: 'deny' } as AnswerBody, p.secretKey);
    const out = updateCalibration(big, { multiplierPpm: 99 * PPM, seen: ['old-nonce-1'] }, [a1], risks);
    expect(out).toEqual({ multiplierPpm: 100 * PPM, seen: ['old-nonce-1', 'nonce-cap-1'] });
    expect(updateCalibration(big, out, [a1], risks)).toEqual(out);
  });
  it('an answer for another principal is ignored; an answer with a wrong version is ignored', () => {
    const r = risk(1000, 100_000);
    const risks = new Map([['d', r]]);
    const o = encodeKey(other.publicKey);
    const foreign = signAnswer({ v: 1, principal: o, nonce: 'nonce-foreign', action_digest: 'd', answer: 'deny' } as AnswerBody, other.secretKey);
    const v2 = signAnswer({ v: 2, principal, nonce: 'nonce-v2-xx', action_digest: 'd', answer: 'deny' } as never, p.secretKey);
    expect(updateCalibration(cfg, freshCalibration(), [foreign, v2], risks)).toEqual({ multiplierPpm: PPM, seen: [] });
  });
});

describe('autonomy raise boundaries (C-287)', () => {
  it('the maximum itself is allowed; epoch must strictly advance; the principal must match', () => {
    const at = applyAutonomyRaise(cfg, signAutonomyRaise({ v: 1, principal, epoch: 2, newInterruptionCost: 500 }, p.secretKey), p.secretKey);
    expect(at.interruptionCost).toBe(500);
    expect(at.epoch).toBe(2);
    expect(pricingConfigError(at)).toBeNull();
    expect(() => applyAutonomyRaise(cfg, signAutonomyRaise({ v: 1, principal, epoch: 1, newInterruptionCost: 200 }, p.secretKey), p.secretKey)).toThrow(/epoch/);
    expect(() => applyAutonomyRaise(cfg, signAutonomyRaise({ v: 1, principal: encodeKey(other.publicKey), epoch: 3, newInterruptionCost: 200 }, other.secretKey), p.secretKey)).toThrow(/signature/);
    expect(() => applyAutonomyRaise(cfg, signAutonomyRaise({ v: 1, principal, epoch: 3, newInterruptionCost: -1 }, p.secretKey), p.secretKey)).toThrow(/maximum/);
  });
});
