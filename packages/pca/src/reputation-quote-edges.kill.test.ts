/** Edge inputs for reputation, pricing and coverage quotes: each guard on its own, boundaries, and signed-but-malformed quotes. */
import { describe, expect, it } from 'vitest';
import { b64u, canonicalBytesLenient, utf8 } from './hash';
import { encodeKey, generateKeyPair, sign } from './keys';
import {
  type CoverageQuote,
  issueCoverageQuote,
  MAX_REPUTATION_RECORDS,
  priceCoverage,
  reputation,
  validateReputationInput,
  verifyCoverageQuote,
} from './reputation';

const ev = (outcome: string) => ({ outcome }) as never;
const d = (id: unknown, over: object = {}) => ({ id, subject: 's', slashed: true, at: 1, ...over }) as never;
const SUBJ = 'subject must be a non-empty string';

describe('validateReputationInput / reputation: each guard on its own', () => {
  it('a missing input or subject is invalid, and the invalid result carries an empty subject', () => {
    expect(validateReputationInput(undefined as never)).toBe(SUBJ);
    expect(validateReputationInput({} as never)).toBe(SUBJ);
    expect(validateReputationInput({ subject: 5 } as never)).toBe(SUBJ);
    const empty = { subject: '', actions: 0, autos: 0, stepUps: 0, denies: 0, slashes: 0, disputes: 0, score: 0, factors: [`invalid input: ${SUBJ}`] };
    expect(reputation(undefined as never)).toEqual(empty);
    expect(reputation({} as never)).toEqual(empty);
    expect(reputation({} as never).subject).toBe('');
  });
  it('exactly MAX_REPUTATION_RECORDS events or disputes is allowed; one more disputes is too many', () => {
    expect(MAX_REPUTATION_RECORDS).toBe(100_000);
    expect(validateReputationInput({ subject: 's', events: new Array(MAX_REPUTATION_RECORDS).fill(ev('auto')) })).toBeNull();
    const one = d('x');
    expect(validateReputationInput({ subject: 's', disputes: new Array(MAX_REPUTATION_RECORDS).fill(one) })).toBeNull();
    expect(validateReputationInput({ subject: 's', disputes: new Array(MAX_REPUTATION_RECORDS + 1).fill(one) })).toBe('too many records');
  });
  it('a null event, a null dispute and a non-string dispute id are refused (no throw)', () => {
    expect(validateReputationInput({ subject: 's', events: [null as never] })).toBe('event with an unknown outcome');
    expect(validateReputationInput({ subject: 's', disputes: [null as never] })).toBe('dispute without an id');
    expect(validateReputationInput({ subject: 's', disputes: [d(5)] })).toBe('dispute without an id');
  });
  it('dispute time 0 and amount 0 are allowed; a negative time is not', () => {
    expect(validateReputationInput({ subject: 's', disputes: [d('x', { at: 0 })] })).toBeNull();
    expect(validateReputationInput({ subject: 's', disputes: [d('x', { amount: 0 })] })).toBeNull();
    expect(validateReputationInput({ subject: 's', disputes: [d('x', { at: -1 })] })).toBe('dispute.at must be finite and >= 0');
  });
});

describe('priceCoverage: score 0 is a valid (declined) score, not an invalid one', () => {
  it('declines below the floor with the floor rationale', () => {
    expect(priceCoverage({ score: 0 }, 100)).toEqual({ declined: true, premium: 0, coverage: 0, rationale: 'reputation 0.00 below underwriting floor 0.25' });
  });
});

describe('issueCoverageQuote / verifyCoverageQuote edges', () => {
  const U = generateKeyPair();
  const UK = encodeKey(U.publicKey);
  const rep = () => reputation({ subject: 's', events: [ev('auto'), ev('step_up')] });
  const q = () => issueCoverageQuote({ rep: rep(), exposure: 1000, underwriterSecret: U.secretKey, now: 100, ttlMs: 50 });
  const resign = (c: Record<string, unknown>): CoverageQuote => {
    const pre = utf8('atlas-pca/coverage-quote/v1\0');
    const body = canonicalBytesLenient(c);
    const m = new Uint8Array(pre.length + body.length);
    m.set(pre);
    m.set(body, pre.length);
    return { ...c, sig: b64u(sign(U.secretKey, m)) } as CoverageQuote;
  };
  const claim = (): Record<string, unknown> => {
    const { sig: _s, ...c } = q();
    void _s;
    return c;
  };
  const at120 = { underwriter: UK, now: 120 };

  it('exposure 0 and scores 0 and 1 are issued; NaN, -0.1 and 1.1 throw', () => {
    const z = issueCoverageQuote({ rep: rep(), exposure: 0, underwriterSecret: U.secretKey, now: 1, ttlMs: 1 });
    expect([z.exposure, z.premium, z.coverage, z.declined]).toEqual([0, 0, 0, false]);
    const s0 = issueCoverageQuote({ rep: { ...rep(), score: 0 }, exposure: 10, underwriterSecret: U.secretKey, now: 1, ttlMs: 1 });
    expect([s0.declined, s0.premium, s0.coverage]).toEqual([true, 0, 0]);
    const s1 = issueCoverageQuote({ rep: { ...rep(), score: 1 }, exposure: 10, underwriterSecret: U.secretKey, now: 1, ttlMs: 1 });
    expect([s1.declined, s1.premium, s1.coverage]).toEqual([false, 0.01 * 10, 10]);
    for (const score of [NaN, -0.1, 1.1]) {
      expect(() => issueCoverageQuote({ rep: { ...rep(), score }, exposure: 10, underwriterSecret: U.secretKey, now: 1, ttlMs: 1 })).toThrow('issueCoverageQuote: invalid reputation score');
    }
  });

  it('non-default pricing options are priced with, signed, and re-derived on verify', () => {
    const opts = { baseRate: 0.02, riskLoad: 2, minScore: 0.1 };
    const r = rep();
    const c = issueCoverageQuote({ rep: r, exposure: 1000, underwriterSecret: U.secretKey, now: 100, ttlMs: 50, opts });
    expect(c.premium).toBe(0.02 * 1000 * (1 + 2 * (1 - r.score)));
    expect(c.premium).toBe(priceCoverage(r, 1000, opts).premium);
    expect(c.premium).not.toBe(priceCoverage(r, 1000).premium);
    expect([c.baseRate, c.riskLoad, c.minScore]).toEqual([0.02, 2, 0.1]);
    expect(verifyCoverageQuote(c, at120)).toEqual({ ok: true });
  });

  it('valid from exactly issued_at', () => {
    expect(verifyCoverageQuote(q(), { underwriter: UK, now: 100 })).toEqual({ ok: true });
  });

  it('a quote that is a function (not a plain object) is malformed even with every field and a valid signature', () => {
    const f = Object.assign(function quote() {}, q());
    expect(verifyCoverageQuote(f as never, at120)).toEqual({ ok: false, reason: 'malformed' });
  });

  it('a correctly signed quote with v 2 is malformed', () => {
    expect(verifyCoverageQuote(resign({ ...claim(), v: 2 }), at120)).toEqual({ ok: false, reason: 'malformed' });
  });

  it('a non-string signature is malformed before the underwriter is compared', () => {
    expect(verifyCoverageQuote({ ...q(), sig: 5 } as never, { underwriter: 'someone-else', now: 120 })).toEqual({ ok: false, reason: 'malformed' });
  });

  it('a correctly signed quote with a numeric field given as a string is malformed', () => {
    // priced as the declined "invalid score" quote, so only the type check refuses it
    const c = resign({ ...claim(), score: '0.925', declined: true, premium: 0, coverage: 0 });
    expect(verifyCoverageQuote(c, at120)).toEqual({ ok: false, reason: 'malformed' });
  });

  it('a non-finite number is malformed before the underwriter is compared', () => {
    expect(verifyCoverageQuote({ ...q(), score: NaN }, { underwriter: 'someone-else', now: 120 })).toEqual({ ok: false, reason: 'malformed' });
    expect(verifyCoverageQuote({ ...q(), expires_at: Infinity }, { underwriter: 'someone-else', now: 120 })).toEqual({ ok: false, reason: 'malformed' });
  });

  it('a correctly signed quote with a non-boolean declined, or a non-string subject, is malformed', () => {
    expect(verifyCoverageQuote(resign({ ...claim(), declined: 'no' }), at120)).toEqual({ ok: false, reason: 'malformed' });
    expect(verifyCoverageQuote(resign({ ...claim(), subject: 5 }), at120)).toEqual({ ok: false, reason: 'malformed' });
  });

  it('a non-string underwriter pin is refused as "underwriter" even when it equals the quote field', () => {
    expect(verifyCoverageQuote({ ...q(), underwriter: 42 } as never, { underwriter: 42 as never, now: 120 })).toEqual({ ok: false, reason: 'underwriter' });
  });

  it('a signed quote whose coverage alone was changed is a price mismatch', () => {
    const c = claim();
    expect(verifyCoverageQuote(resign({ ...c, coverage: (c.coverage as number) - 1 }), at120)).toEqual({ ok: false, reason: 'price-mismatch' });
  });

  it('a field getter that throws is reported as malformed (never throws)', () => {
    const bad = { ...q() };
    Object.defineProperty(bad, 'score', {
      enumerable: true,
      get() {
        throw new Error('boom');
      },
    });
    expect(verifyCoverageQuote(bad, at120)).toEqual({ ok: false, reason: 'malformed' });
  });
});
