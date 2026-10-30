// Business rules per action: authoring validation, compilation into tighten rules + count accumulators, evaluation (fail closed),
// rules only ever tighten, lint for contradictions, the semantic diff, and the reviewer's signature over a rules block.
import { b64u, generateKeyPair } from '@atlasauth/pca';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  DECISION_RANK, action, businessRulesDigest, businessRulesError, compileBusinessRules, defDigest, diffBusinessRules, evaluateBusinessRules,
  explainBusinessRules, lintBusinessRules, p, rulesReviewError, runRuleExamples, signRulesReview, withBusinessRules,
  type ActionDef, type BusinessRules, type Decision,
} from '../src';

const pay = (x: Partial<Parameters<typeof action>[1]> = {}): ActionDef =>
  action('acme.payment.send', {
    title: 'Send a payment', description: 'Pays a customer.', effects: ['pay'], resource: 'acme.payment:pm_*',
    params: { amount: p.money({ from: 'currency' }, { max: 100_000_000 }), currency: p.ccy(), customer: p.id('acme.customer'), to: p.email(), reason: p.optional(p.text(200)), cc: p.optional(p.array('string', 4)) },
    since: '0.1.0', ...x,
  });
const D = pay();
const WED_10_NY = Date.parse('2026-01-07T15:00:00Z');
const base = { amount: 1000, currency: 'USD', customer: 'cus_1', to: 'a@example.com', reason: 'refund' };
const run = (rules: BusinessRules, params: Record<string, unknown> = base, o: { subject?: Record<string, unknown>; now?: number; counts?: Record<string, number> } = {}) =>
  evaluateBusinessRules(compileBusinessRules(D, rules), { params, ...(o.subject ? { subject: o.subject } : {}), now: o.now ?? WED_10_NY, ...(o.counts ? { counts: o.counts } : {}) });

describe('business rules: validation (fail closed at authoring)', () => {
  it('accepts every rule kind; refuses unknown members, unknown params, wrong kinds, over-precise money, unbounded lists', () => {
    expect(businessRulesError(D, { amount: { max: { USD: '500.00', EUR: 45000 } }, approval: { above: { USD: '100.00' }, approvers: 2, group: 'finance' }, scope: [{ param: 'customer', caller: 'customer_id' }], rate: [{ max: 10, per: 'hour' }, { max: 50, per: 'day', by: 'org' }], hours: { days: ['mon', 'tue'], from: '09:00', to: '17:00', tz: 'America/New_York' }, recipients: { param: 'to', domains: ['example.com'] }, required: ['reason'] })).toBeNull();
    expect(businessRulesError(D, { nope: 1 })).toMatch(/nope/);
    expect(businessRulesError(D, { amount: { max: { USD: '1.234' } } })).toMatch(/decimals/);
    expect(businessRulesError(D, { amount: { max: { USD: -1 } } })).not.toBeNull();
    expect(businessRulesError(D, { amount: { max: { usd: 1 } } })).not.toBeNull();
    expect(businessRulesError(D, { approval: { always: true, approvers: 17 } })).not.toBeNull();
    expect(businessRulesError(D, { scope: [{ param: 'missing', caller: 'customer_id' }] })).toMatch(/missing/);
    expect(businessRulesError(D, { rate: [{ max: 0, per: 'hour' }] })).not.toBeNull();
    expect(businessRulesError(D, { rate: [{ max: 1, per: 'week' }] })).not.toBeNull();
    expect(businessRulesError(D, { hours: { days: ['mon'], from: '25:00', to: '17:00', tz: 'UTC' } })).not.toBeNull();
    expect(businessRulesError(D, { hours: { days: ['mon'], from: '09:00', to: '17:00', tz: 'Mars/Olympus' } })).not.toBeNull();
    expect(businessRulesError(D, { recipients: { param: 'amount', domains: ['example.com'] } })).not.toBeNull();
    expect(businessRulesError(D, { required: ['nope'] })).not.toBeNull();
    // an amount rule needs exactly one money.amount parameter with a currency
    const noMoney = action('acme.note.add', { title: 'Add a note', description: 'Adds a note.', effects: ['create'], resource: 'acme.note:nt_*', params: { body: p.text(100) }, since: '0.1.0' });
    expect(businessRulesError(noMoney, { amount: { max: { USD: 1 } } })).toMatch(/money\.amount/);
  });
});

describe('business rules: evaluation', () => {
  it('amount ceilings per currency; an unlisted currency is refused', () => {
    const r: BusinessRules = { amount: { max: { USD: '500.00', EUR: 45000 } } };
    expect(run(r, { ...base, amount: 50000 }).decision).toBe('allow');
    expect(run(r, { ...base, amount: 50001 }).decision).toBe('deny');
    expect(run(r, { ...base, currency: 'EUR', amount: 45001 }).decision).toBe('deny');
    expect(run(r, { ...base, currency: 'GBP', amount: 1 }).decision).toBe('deny');
    // an absent or non-numeric amount is undecided: the ceiling fires
    expect(run(r, { ...base, amount: undefined }).decision).toBe('deny');
    expect(run(r, { ...base, amount: '1' }).decision).toBe('deny');
  });
  it('approval above a threshold names the approvers and the group', () => {
    const r: BusinessRules = { approval: { above: { USD: '100.00' }, approvers: 2, group: 'finance' } };
    expect(run(r, { ...base, amount: 10000 })).toMatchObject({ decision: 'allow' });
    expect(run(r, { ...base, amount: 10001 })).toMatchObject({ decision: 'escalate', approval: { approvers: 2, group: 'finance' } });
    expect(run(r, { ...base, currency: 'JPY', amount: 1 }).decision).toBe('escalate');
    expect(run({ approval: { always: true } }).decision).toBe('escalate');
  });
  it("scope: only the caller's own records; an unattested caller is refused", () => {
    const r: BusinessRules = { scope: [{ param: 'customer', caller: 'customer_id' }] };
    expect(run(r, base, { subject: { customer_id: 'cus_1' } }).decision).toBe('allow');
    expect(run(r, base, { subject: { customer_id: 'cus_2' } }).decision).toBe('deny');
    expect(run(r, base).decision).toBe('deny');
  });
  it('rate limits count the window; a missing count fires the rule', () => {
    const r: BusinessRules = { rate: [{ max: 10, per: 'hour' }] };
    expect(run(r, base, { counts: { rate_0: 9 } }).decision).toBe('allow');
    expect(run(r, base, { counts: { rate_0: 10 } }).decision).toBe('deny');
    expect(run(r, base).decision).toBe('deny');
    expect(run(r, base, { counts: { rate_0: -1 } }).decision).toBe('deny');
  });
  it('business hours in a time zone, including an overnight window', () => {
    const r: BusinessRules = { hours: { days: ['mon', 'tue', 'wed', 'thu', 'fri'], from: '09:00', to: '17:00', tz: 'America/New_York' } };
    expect(run(r).decision).toBe('allow'); // Wednesday 10:00 in New York
    expect(run(r, base, { now: Date.parse('2026-01-07T23:00:00Z') }).decision).toBe('escalate'); // 18:00
    expect(run(r, base, { now: Date.parse('2026-01-10T15:00:00Z') }).decision).toBe('escalate'); // Saturday
    expect(run({ hours: { ...r.hours!, outside: 'deny' } }, base, { now: Date.parse('2026-01-10T15:00:00Z') }).decision).toBe('deny');
    const night: BusinessRules = { hours: { days: ['mon'], from: '22:00', to: '06:00', tz: 'America/New_York' } };
    expect(run(night, base, { now: Date.parse('2026-01-06T04:00:00Z') }).decision).toBe('allow'); // Mon 23:00
    expect(run(night, base, { now: Date.parse('2026-01-06T10:00:00Z') }).decision).toBe('allow'); // Tue 05:00 (Monday's window)
    expect(run(night, base, { now: Date.parse('2026-01-07T04:00:00Z') }).decision).toBe('escalate'); // Tue 23:00
    expect(run(r, base, { now: Number.NaN }).decision).not.toBe('allow'); // no clock: fires
  });
  it('allowed recipients by domain or address, every element of a list', () => {
    const r: BusinessRules = { recipients: { param: 'to', domains: ['example.com'], addresses: ['ops@example.net'] } };
    expect(run(r).decision).toBe('allow');
    expect(run(r, { ...base, to: 'ops@example.net' }).decision).toBe('allow');
    expect(run(r, { ...base, to: 'a@example.net' }).decision).toBe('deny');
    expect(run(r, { ...base, to: 'a@example.com.example.net' }).decision).toBe('deny');
    expect(run(r, { ...base, to: 'a@sub.example.org' }).decision).toBe('deny');
    const list: BusinessRules = { recipients: { param: 'cc', domains: ['example.com'] } };
    expect(run(list, { ...base, cc: ['a@example.com', 'b@example.com'] }).decision).toBe('allow');
    expect(run(list, { ...base, cc: ['a@example.com', 'b@example.net'] }).decision).toBe('deny');
  });
  it('required fields: absent or empty is refused', () => {
    const r: BusinessRules = { required: ['reason'] };
    expect(run(r).decision).toBe('allow');
    expect(run(r, { ...base, reason: '' }).decision).toBe('deny');
    const { reason: _r, ...rest } = base;
    void _r;
    expect(run(r, rest).decision).toBe('deny');
  });
});

describe('business rules only tighten', () => {
  const RULES: BusinessRules[] = [
    { amount: { max: { USD: '500.00' } } }, { approval: { always: true } }, { approval: { above: { USD: 1 } } }, { scope: [{ param: 'customer', caller: 'customer_id' }] },
    { rate: [{ max: 3, per: 'day', by: 'org' }] }, { hours: { days: ['sat'], from: '01:00', to: '02:00', tz: 'UTC', outside: 'deny' } }, { recipients: { param: 'to', domains: ['x.io'] } }, { required: ['reason'] },
  ];
  it('every compiled rule escalates or denies; nothing grants', () => {
    for (const r of RULES) for (const t of compileBusinessRules(D, r).tighten) expect(['escalate', 'deny']).toContain(t.signal);
  });
  it('folding the rules into any base decision never ranks above it (property)', () => {
    const DEC: Decision[] = ['allow', 'escalate', 'deny'];
    fc.assert(fc.property(
      fc.constantFrom(...DEC), fc.subarray(RULES, { minLength: 1 }), fc.record({ amount: fc.oneof(fc.integer({ min: -5, max: 10 ** 9 }), fc.constant(undefined), fc.string()), currency: fc.constantFrom('USD', 'EUR', 'X'), to: fc.oneof(fc.emailAddress(), fc.string()), reason: fc.oneof(fc.string(), fc.constant(undefined)) }),
      fc.integer({ min: 0, max: 2 ** 41 }), fc.option(fc.integer({ min: -2, max: 20 })),
      (b, picked, params, now, n) => {
        const merged = Object.assign({}, ...picked) as BusinessRules;
        const v = evaluateBusinessRules(compileBusinessRules(D, merged), { params: { ...base, ...params }, now, ...(n === null ? {} : { counts: { rate_0: n } }) });
        expect(DECISION_RANK[withBusinessRules(b, v)]).toBeLessThanOrEqual(DECISION_RANK[b]);
      },
    ), { numRuns: 300 });
  });
  it('a compile or evaluation fault denies, never allows', () => {
    const c = compileBusinessRules(D, { amount: { max: { USD: 1 } } });
    expect(evaluateBusinessRules({ ...c, tighten: [{ id: 'x', when: { bogus: true } as never, signal: 'escalate', reason: 'r' }] }, { params: base, now: WED_10_NY }).decision).not.toBe('allow');
  });
});

describe('business rules: lint, examples, explain', () => {
  it('contradictions are errors; dead rules are warnings; a failing example is an error', () => {
    const ids = (r: unknown) => lintBusinessRules(D, r).map((f) => `${f.rule}:${f.severity}`);
    expect(ids({ amount: { max: { USD: 0 } } })).toContain('LR-002:error'); // below the parameter's minimum (1)
    expect(ids({ hours: { days: ['mon'], from: '09:00', to: '09:00', tz: 'UTC' } })).toContain('LR-002:error');
    expect(ids({ rate: [{ max: 5, per: 'hour' }, { max: 3, per: 'hour' }] })).toContain('LR-003:warning');
    expect(ids({ amount: { max: { USD: '500.00' } }, approval: { above: { USD: '600.00' } } })).toContain('LR-003:warning');
    expect(ids({ required: ['reason'], examples: [{ params: base, expect: 'deny' }] })).toContain('LR-004:error');
    expect(ids({ nope: true })).toEqual(['LR-001:error']);
    expect(lintBusinessRules(D, { amount: { max: { USD: '500.00' } }, required: ['reason'], examples: [{ params: base, expect: 'allow' }, { params: { ...base, amount: 50001 }, expect: 'deny' }] })).toEqual([]);
  });
  it('examples run with their caller, time and recent counts', () => {
    const r: BusinessRules = { scope: [{ param: 'customer', caller: 'customer_id' }], rate: [{ max: 2, per: 'hour' }], examples: [
      { params: base, caller: { customer_id: 'cus_1' }, expect: 'allow' },
      { params: base, caller: { customer_id: 'cus_1' }, recent: { '0': 2 }, expect: 'deny' },
      { params: base, expect: 'deny' },
    ] };
    expect(runRuleExamples(D, r).map((x) => x.ok)).toEqual([true, true, true]);
  });
  it('explains each rule in plain words, with money in major units', () => {
    const text = explainBusinessRules(D, { amount: { max: { USD: 50000 } }, approval: { above: { USD: '100.00' }, approvers: 2, group: 'finance' }, rate: [{ max: 10, per: 'hour' }] }).join(' ');
    expect(text).toMatch(/500\.00/);
    expect(text).toMatch(/finance/);
    expect(text).toMatch(/At most 10 per hour per principal/);
  });
});

describe('business rules: semantic diff', () => {
  const cls = (a: BusinessRules | undefined, b: BusinessRules | undefined) => diffBusinessRules(D, a, b).class;
  it('lowering a ceiling or adding a rule narrows; raising, removing or loosening widens', () => {
    const r = { amount: { max: { USD: '500.00' } } };
    expect(cls(r, r)).toBe('equal');
    expect(cls(r, { amount: { max: { USD: '400.00' } } })).toBe('narrow');
    expect(cls(r, { amount: { max: { USD: '900.00' } } })).toBe('widen');
    expect(cls(r, { amount: { max: { USD: '500.00', EUR: 1 } } })).toBe('widen'); // a currency that was refused is now allowed
    expect(cls(undefined, r)).toBe('narrow');
    expect(cls(r, undefined)).toBe('widen');
    expect(cls({ rate: [{ max: 5, per: 'hour' }] }, { rate: [{ max: 9, per: 'hour' }] })).toBe('widen');
    expect(cls({ approval: { always: true, approvers: 3 } }, { approval: { always: true, approvers: 2 } })).toBe('widen');
    expect(cls({ recipients: { param: 'to', domains: ['example.org'] } }, { recipients: { param: 'to', domains: ['example.org', 'example.net'] } })).toBe('widen');
    // examples are tests, not rules
    expect(cls(r, { ...r, examples: [{ params: base, expect: 'allow' }] })).toBe('equal');
  });
});

describe('rules review: a reviewer signature over exactly this def and these rules', () => {
  const reviewer = generateKeyPair();
  const other = generateKeyPair();
  const pins = { keys: [{ kid: 'rev-1', pk: b64u(reviewer.publicKey), roles: ['reviewer' as const] }, { kid: 'imp-1', pk: b64u(other.publicKey), roles: ['importer' as const] }] };
  const rules: BusinessRules = { amount: { max: { USD: '900.00' } } };
  const sign = (kid: string, secret: Uint8Array, d = D, r = rules) => signRulesReview({ verb: d.verb, def_digest: defDigest(d), rules_digest: businessRulesDigest(d.verb, r), reviewer_kid: kid, ts: 1_700_000_000 }, secret);
  it('verifies under a pinned reviewer key', () => {
    expect(rulesReviewError(sign('rev-1', reviewer.secretKey), D, rules, pins)).toBeNull();
  });
  it('a key in another role, an unpinned key, no pins, or a forged signature never counts', () => {
    expect(rulesReviewError(sign('imp-1', other.secretKey), D, rules, pins)).not.toBeNull();
    expect(rulesReviewError(sign('rev-2', other.secretKey), D, rules, pins)).not.toBeNull();
    expect(rulesReviewError(sign('rev-1', other.secretKey), D, rules, pins)).not.toBeNull();
    expect(rulesReviewError(sign('rev-1', reviewer.secretKey), D, rules, undefined)).not.toBeNull();
    expect(rulesReviewError(undefined, D, rules, pins)).not.toBeNull();
  });
  it('a tampered def or tampered rules invalidate it', () => {
    const r = sign('rev-1', reviewer.secretKey);
    expect(rulesReviewError(r, pay({ description: 'Pays anyone.' }), rules, pins)).not.toBeNull();
    expect(rulesReviewError(r, D, { amount: { max: { USD: '901.00' } } }, pins)).not.toBeNull();
    expect(rulesReviewError({ ...r, ts: r.ts + 1 }, D, rules, pins)).not.toBeNull();
  });
});
