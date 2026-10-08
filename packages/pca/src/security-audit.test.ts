/**
 * Adversarial security audit for the PCA product + integration modules (facade / catalog / adapters /
 * nl / approvals / policy-sim / immune / policy-templates / console / passport / dlp / reputation /
 * compliance / receipt / budget-forecast / session / kem).
 *
 * One describe per threat class. Each test feeds a concrete hostile input and asserts the module stays
 * SAFE: no prototype is polluted, no attacker-controlled key indexes/assigns through the prototype
 * chain, no `new RegExp` is reachable from input, malformed numbers (NaN/±Infinity/negative) can neither
 * fail OPEN nor propagate, and no secret is compared in variable time.
 *
 * These lock the fixes made to dlp.ts (non-finite taint failed open), immune.ts (a non-finite timestamp
 * poisoned the threat counters into a permanent calm), facade.ts compilePolicy (limit lookup read
 * inherited Object.prototype members), compliance.ts (framework key resolved `constructor` to the Object
 * ctor), policy-templates.ts (connector read inherited members) and reputation.ts (NaN exposure).
 */

import { describe, expect, it } from 'vitest';

import { type Limits, type PermissionMap, compilePolicy, parseLimit } from './facade';
import { parseNLPolicy } from './nl';
import { type ActivityEvent, buildConsole } from './console';
import { INITIAL_IMMUNE_STATE, assess, observe } from './immune';
import { type DlpPolicy, evaluateDlp } from './dlp';
import { simulate } from './policy-sim';
import { type ComplianceInput, type Framework, complianceReport } from './compliance';
import { priceCoverage, reputation } from './reputation';
import { policy } from './policy-templates';
import { appendReceipt, verifyReceiptChain } from './receipt';
import { agent } from './facade';
import { generateKeyPair } from './keys';

/** A fresh, provably-untouched probe for proto-pollution assertions. */
const probe = () => ({}) as Record<string, unknown>;
const protoProbe = () => Object.prototype as unknown as Record<string, unknown>;

// =====================================================================================================
describe('Threat class 1: prototype pollution / prototype-chain key confusion', () => {
  it('parseNLPolicy: a __proto__/constructor payload neither pollutes nor throws', () => {
    expect(probe().polluted).toBeUndefined();
    // Raw JSON with literal dangerous keys (an object literal would set the prototype instead).
    const raw =
      '{"permissions":{"__proto__":{"polluted":1},"constructor":["refund"]},' +
      '"limits":{"__proto__":"$5/day","constructor":"bad"}}';
    const out = parseNLPolicy(raw);
    // Nothing granted (the keys are not catalog verbs) and nothing poisoned.
    expect(Object.keys(out.permissions)).toHaveLength(0);
    expect(probe().polluted).toBeUndefined();
    expect(protoProbe().polluted).toBeUndefined();
  });

  it('parseNLPolicy: a __proto__-named permission that WOULD assign is dropped as an unknown verb', () => {
    const raw = '{"permissions":{"__proto__":["send"]},"limits":{"__proto__":"$5/day"}}';
    const out = parseNLPolicy(raw);
    expect(Object.prototype.hasOwnProperty.call(out.permissions, '__proto__')).toBe(false);
    expect(out.unknownVerbs).toContain('__proto__.send');
    expect(probe().send).toBeUndefined();
  });

  it('compilePolicy: an action named like a prototype member does not read the inherited value and throw', () => {
    // Before the fix, the limit lookup read rawLimits['toString'] -> Object.prototype.toString (a
    // function) -> parseLimit(function) -> threw, even though no limit was configured.
    expect(() => compilePolicy({ permissions: { foo: ['toString'] } })).not.toThrow();
    expect(() => compilePolicy({ permissions: { foo: ['constructor', 'valueOf', 'hasOwnProperty'] } })).not.toThrow();
    const compiled = compilePolicy({ permissions: { foo: ['toString'] } });
    expect(compiled.actions).toHaveLength(1);
    expect(Object.keys(compiled.limits)).not.toContain('toString');
  });

  it('compilePolicy: own __proto__/constructor connectors neither pollute nor throw', () => {
    // Computed keys create OWN properties named __proto__/constructor (prototype stays intact).
    const permissions: PermissionMap = { ['__proto__']: ['x'], ['constructor']: ['y'], stripe: ['refund'] };
    const limits: Limits = { ['__proto__']: '$5/day', ['constructor']: '9/day', refund: '$100/day' };
    const compiled = compilePolicy({ permissions, limits });
    expect(compiled.actions.map((a) => a.verb)).toEqual(
      expect.arrayContaining(['__proto__.x', 'constructor.y', 'stripe.refund']),
    );
    // Only the real, dotted own-key limit landed; the dangerous bare keys were never looked up.
    expect(Object.keys(compiled.limits)).toEqual(['stripe.refund']);
    expect(probe().polluted).toBeUndefined();
    expect(protoProbe().x).toBeUndefined();
  });

  it('buildConsole: a __proto__ agent id is grouped via a Map and never pollutes', () => {
    const events: ActivityEvent[] = [
      { at: 1, agent: '__proto__', verb: '__proto__', resource: 'r', outcome: 'auto', r: 0.1 },
      { at: 2, agent: 'constructor', verb: 'x', resource: 'r', outcome: 'deny', r: 0.2 },
      { at: 3, agent: '__proto__', verb: 'y', resource: 'r', outcome: 'step_up', r: 0.3 },
    ];
    const view = buildConsole(events);
    const ids = view.agents.map((a) => a.agent);
    expect(ids).toContain('__proto__');
    expect(ids).toContain('constructor');
    expect(view.totals.actions).toBe(3);
    expect(probe().polluted).toBeUndefined();
    expect(protoProbe().verb).toBeUndefined();
  });

  it('PolicyBuilder.allow: a connector named like a prototype member does not read the inherited value', () => {
    // Before the fix allow('toString', …) read Object.prototype.toString and crashed on the spread.
    expect(() => policy().allow('toString', ['read']).allow('stripe', ['refund']).build()).not.toThrow();
    const built = policy().allow('constructor', ['read']).allow('stripe', ['refund']).build();
    expect(built.permissions.stripe).toEqual(['refund']);
  });

  it('complianceReport: a constructor/__proto__ framework is rejected, not resolved up the prototype chain', () => {
    const input: ComplianceInput = { policy: compilePolicy({ permissions: { stripe: ['refund'] } }), events: [] };
    // 'constructor' would resolve to the Object ctor (callable) -> type confusion if indexed naively.
    expect(() => complianceReport('constructor' as Framework, input)).toThrow(/unknown framework/);
    expect(() => complianceReport('__proto__' as Framework, input)).toThrow(/unknown framework/);
    expect(() => complianceReport('toString' as Framework, input)).toThrow(/unknown framework/);
    // A legitimate framework still works.
    expect(complianceReport('soc2', input).framework).toBe('soc2');
  });
});

// =====================================================================================================
describe('Threat class 2: ReDoS / regex built from input', () => {
  it('parseLimit uses a fixed linear regex — a pathological long input returns fast, never hangs', () => {
    const t0 = Date.now();
    // A 100k-char input that does not match: a catastrophic-backtracking regex would stall here.
    expect(() => parseLimit('$' + '1'.repeat(100_000) + 'x')).toThrow();
    // A 100k-digit amount overflows to Infinity and is rejected (not hung, not accepted).
    expect(() => parseLimit('$' + '9'.repeat(100_000))).toThrow(/bad amount|cannot parse/);
    expect(Date.now() - t0).toBeLessThan(1000);
  });

  it('parseLimit accepts well-formed limits with finite amounts', () => {
    expect(parseLimit('$500/day').amount).toBe(500);
    expect(parseLimit('10/hour').unit).toBe('count');
    expect(Number.isFinite(parseLimit('999999999999').amount)).toBe(true);
  });
});

// =====================================================================================================
describe('Threat class 3: unbounded / malformed numeric input', () => {
  it('parseLimit rejects $Infinity / $-5 / $NaN / empty', () => {
    expect(() => parseLimit('$Infinity')).toThrow();
    expect(() => parseLimit('$-5')).toThrow();
    expect(() => parseLimit('$NaN')).toThrow();
    expect(() => parseLimit('$1e308')).toThrow();
    expect(() => parseLimit('')).toThrow();
    expect(() => parseLimit('   ')).toThrow();
  });

  it('dlp: a non-finite taint FAILS CLOSED (never silently auto-allows a sensitive sink)', () => {
    const p: DlpPolicy = {
      classes: [
        { name: 'pii', resource: 'customer:*', maxTaintForAuto: 0, hardDenyAbove: 2 },
        { name: 'public', resource: 'public:*', maxTaintForAuto: 5 },
      ],
      defaultMaxTaintForAuto: 1,
    };
    // NaN / Infinity would make every `>` comparison false -> 'allow' before the fix.
    expect(evaluateDlp(p, { verb: 'gmail.send', resource: 'customer:42', taint: Number.NaN }).outcome).toBe('deny');
    expect(evaluateDlp(p, { verb: 'gmail.send', resource: 'customer:42', taint: Number.POSITIVE_INFINITY }).outcome).toBe('deny');
    // No hard ceiling on this class -> escalate rather than allow.
    expect(evaluateDlp(p, { verb: 'http.post', resource: 'public:blog', taint: Number.NaN }).outcome).toBe('step_up');
    // Default class (no hard ceiling) -> escalate.
    expect(evaluateDlp(p, { verb: 'files.write', resource: 'tmp:x', taint: Number.NaN }).outcome).toBe('step_up');
    // A finite negative taint is cleaner-than-clean and still allowed (behaviour preserved).
    expect(evaluateDlp(p, { verb: 'gmail.send', resource: 'customer:42', taint: -5 }).outcome).toBe('allow');
  });

  it('immune.observe: a NaN risk stays finite and bounded in [0,1]', () => {
    const s = observe(INITIAL_IMMUNE_STATE, { r: Number.NaN, at: 1000 });
    expect(Number.isFinite(s.ewma)).toBe(true);
    expect(Number.isFinite(s.baseline.mean)).toBe(true);
    expect(Number.isFinite(s.baseline.m2)).toBe(true);
    const a = assess(s);
    expect(Number.isFinite(a.score)).toBe(true);
    expect(a.score).toBeGreaterThanOrEqual(0);
    expect(a.score).toBeLessThanOrEqual(1);
  });

  it('immune.observe: a non-finite timestamp cannot poison the decayed counters into a permanent calm', () => {
    let s = observe(INITIAL_IMMUNE_STATE, { r: 0.2, at: 1000, stepUp: true });
    // A PCActn with a missing/NaN iat used to turn stepUps/denies into NaN -> score NaN -> always calm.
    s = observe(s, { r: 0.3, at: Number.NaN, stepUp: true, denied: true });
    s = observe(s, { r: 0.4, at: Number.POSITIVE_INFINITY, denied: true });
    expect(Number.isFinite(s.stepUps)).toBe(true);
    expect(Number.isFinite(s.denies)).toBe(true);
    expect(Number.isFinite(s.lastAt)).toBe(true);
    expect(s.denies).toBeGreaterThan(0); // the violations actually registered
    const a = assess(s);
    expect(Number.isFinite(a.score)).toBe(true);
    expect(a.components.violation).toBeGreaterThan(0);
  });

  it('simulate: a 10k-action replay stays bounded and finite, even with NaN/Infinity amounts', () => {
    const compiled = compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$100/day' } });
    const actions = Array.from({ length: 10_000 }, (_, i) => ({
      verb: 'stripe.refund',
      resource: `charge:${i}`,
      params: { amount: i % 97 === 0 ? Number.NaN : i % 89 === 0 ? Number.POSITIVE_INFINITY : 50 },
      at: i,
    }));
    const t0 = Date.now();
    const report = simulate(compiled, actions);
    expect(Date.now() - t0).toBeLessThan(5000);
    expect(report.results).toHaveLength(10_000);
    expect(report.auto + report.stepUp + report.deny).toBe(10_000);
    expect(Number.isFinite(report.endBudget)).toBe(true);
    expect(Number.isFinite(report.peakRisk)).toBe(true);
    expect(report.peakRisk).toBeLessThanOrEqual(1);
    expect(report.results.every((r) => Number.isFinite(r.budgetAfter) && r.r >= 0 && r.r <= 1)).toBe(true);
  });

  it('reputation: adversarial event streams keep the score finite in [0,1]', () => {
    const events: ActivityEvent[] = Array.from({ length: 500 }, (_, i) => ({
      at: i,
      agent: 'a',
      verb: 'x',
      resource: 'r',
      outcome: i % 2 ? 'deny' : 'step_up',
    }));
    const rep = reputation({ subject: 'a', events, disputes: [{ subject: 'a', slashed: true, at: 0 }] });
    expect(Number.isFinite(rep.score)).toBe(true);
    expect(rep.score).toBeGreaterThanOrEqual(0);
    expect(rep.score).toBeLessThanOrEqual(1);
  });

  it('priceCoverage: a NaN / Infinity exposure cannot quote a NaN premium', () => {
    const rep = reputation({ subject: 'a', events: [{ at: 1, agent: 'a', verb: 'x', resource: 'r', outcome: 'auto' }] });
    for (const exposure of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      const q = priceCoverage(rep, exposure);
      expect(Number.isFinite(q.premium)).toBe(true);
      expect(Number.isFinite(q.coverage)).toBe(true);
      expect(q.premium).toBe(0);
    }
  });
});

// =====================================================================================================
describe('Threat class 4: timing — no secret-dependent comparison in the audited surface', () => {
  // The only equality checks in scope are over PUBLIC content hashes (receipt chain) and public
  // allowlists (passport binding); none compares a secret, so no constant-time path is required. This
  // guards the receipt integrity check, which must reject a tampered body via hash inequality.
  const a = agent({
    principal: generateKeyPair(),
    goal: 'audit',
    permissions: { stripe: ['refund'] },
    limits: { refund: '$500/day' },
    aud: 'rs',
  });
  const pcactnFor = (resource: string) => a.act('stripe.refund', resource, { amount: 10 }, { counter: 1 }).pcactn;

  it('receipt chain detects a tampered body (public-hash equality, fail-closed)', () => {
    let log = appendReceipt([], pcactnFor('charge:a'), { allow: true, checks: {} });
    log = appendReceipt(log, pcactnFor('charge:b'), { allow: true, checks: {} });
    expect(verifyReceiptChain(log).ok).toBe(true);
    const tampered = log.map((r, i) => (i === 0 ? { ...r, verb: 'evil' } : r));
    const check = verifyReceiptChain(tampered);
    expect(check.ok).toBe(false);
    expect(check.brokenAt).toBe(0);
  });
});
