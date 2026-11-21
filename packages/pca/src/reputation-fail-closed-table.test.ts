/** Exact-outcome table for reputation, coverage quotes and settlement-derived disputes: missing or malformed X gives Y. */
import { describe, expect, it } from 'vitest';
import { type SettlementRecord, settlementRecordDigest } from './bond-settlement';
import { BondLedger, InMemoryBondAccount } from './bond-ledger-testing';
import { b64u, canonicalBytesLenient, utf8 } from './hash';
import { encodeKey, generateKeyPair, sign } from './keys';
import {
  type CoverageQuote, issueCoverageQuote, priceCoverage, reputation, validateReputationInput, verifyCoverageQuote,
} from './reputation';
import { disputesFromSettlements } from './reputation-evidence';

const ev = (outcome: string) => ({ outcome }) as never;
const d = (id: string, over: object = {}) => ({ id, subject: 's', slashed: true, at: 1, ...over });
const INVALID = (why: string) => ({ subject: 's', actions: 0, autos: 0, stepUps: 0, denies: 0, slashes: 0, disputes: 0, score: 0, factors: [`invalid input: ${why}`] });

describe('reputation input table', () => {
  const rows: Array<[string, Parameters<typeof reputation>[0], string]> = [
    ['empty subject', { subject: '' }, 'subject must be a non-empty string'],
    ['unknown outcome', { subject: 's', events: [ev('nope')] }, 'event with an unknown outcome'],
    ['dispute without id', { subject: 's', disputes: [d('')] }, 'dispute without an id'],
    ['dispute for another subject', { subject: 's', disputes: [d('x', { subject: 'other' })] }, 'dispute for another subject'],
    ['NaN time', { subject: 's', disputes: [d('x', { at: NaN })] }, 'dispute.at must be finite and >= 0'],
    ['negative amount', { subject: 's', disputes: [d('x', { amount: -1 })] }, 'dispute.amount must be finite and >= 0'],
    ['slashed not boolean', { subject: 's', disputes: [d('x', { slashed: 1 })] }, 'dispute.slashed must be a boolean'],
    ['events not array', { subject: 's', events: 'x' as never }, 'events and disputes must be arrays'],
  ];
  it.each(rows)('%s -> score 0 with the reason', (_n, input, why) => {
    expect(validateReputationInput(input)).toBe(why);
    expect(reputation(input)).toEqual({ ...INVALID(why), subject: input.subject });
  });
  it('too many records -> invalid', () => {
    const big = Array.from({ length: 100_001 }, () => ev('auto'));
    expect(reputation({ subject: 's', events: big }).factors).toEqual(['invalid input: too many records']);
  });
  it('a repeated dispute id counts once', () => {
    const r = reputation({ subject: 's', disputes: [d('same'), d('same'), d('same')] });
    expect(r.slashes).toBe(1);
    expect(r.disputes).toBe(1);
    expect(r.score).toBeCloseTo(0.7, 12);
  });
});

describe('priceCoverage guards', () => {
  it.each([NaN, -0.1, 1.1])('score %s is declined', (score) => {
    expect(priceCoverage({ score }, 100)).toEqual({ declined: true, premium: 0, coverage: 0, rationale: 'invalid reputation score' });
  });
});

describe('coverage quotes', () => {
  const U = generateKeyPair();
  const UK = encodeKey(U.publicKey);
  const rep = reputation({ subject: 's', events: [ev('auto'), ev('step_up')] });
  const q = () => issueCoverageQuote({ rep, exposure: 1000, underwriterSecret: U.secretKey, now: 100, ttlMs: 50 });
  const resign = (c: Omit<CoverageQuote, 'sig'>): CoverageQuote => {
    const pre = utf8('atlas-pca/coverage-quote/v1\0');
    const body = canonicalBytesLenient(c);
    const m = new Uint8Array(pre.length + body.length);
    m.set(pre);
    m.set(body, pre.length);
    return { ...c, sig: b64u(sign(U.secretKey, m)) };
  };
  it('valid inside the window', () => expect(verifyCoverageQuote(q(), { underwriter: UK, now: 120 })).toEqual({ ok: true }));
  it.each([
    ['wrong underwriter', () => q(), { underwriter: encodeKey(generateKeyPair().publicKey), now: 120 }, 'underwriter'],
    ['tampered premium', () => ({ ...q(), premium: 0.01 }), { underwriter: UK, now: 120 }, 'signature'],
    ['expired at the boundary', () => q(), { underwriter: UK, now: 150 }, 'expired'],
    ['before issue', () => q(), { underwriter: UK, now: 99 }, 'not-yet-valid'],
    ['NaN now', () => q(), { underwriter: UK, now: NaN }, 'not-yet-valid'],
    ['null', () => null, { underwriter: UK, now: 120 }, 'malformed'],
    ['NaN field', () => ({ ...q(), exposure: NaN }), { underwriter: UK, now: 120 }, 'malformed'],
  ])('%s -> %s', (_n, mk, o, reason) => {
    expect(verifyCoverageQuote(mk() as never, o)).toEqual({ ok: false, reason });
  });
  it('a correctly signed but mispriced quote is refused (recomputation)', () => {
    const { sig: _s, ...c } = q();
    expect(verifyCoverageQuote(resign({ ...c, premium: c.premium / 2 }), { underwriter: UK, now: 120 })).toEqual({ ok: false, reason: 'price-mismatch' });
    expect(verifyCoverageQuote(resign({ ...c, declined: true }), { underwriter: UK, now: 120 })).toEqual({ ok: false, reason: 'price-mismatch' });
  });
  it('issue refuses nonsense and records declines honestly', () => {
    expect(() => issueCoverageQuote({ rep, exposure: -1, underwriterSecret: U.secretKey, now: 1, ttlMs: 1 })).toThrow('exposure');
    expect(() => issueCoverageQuote({ rep, exposure: 1, underwriterSecret: U.secretKey, now: 1, ttlMs: 0 })).toThrow('ttlMs');
    expect(() => issueCoverageQuote({ rep: { ...rep, score: 2 }, exposure: 1, underwriterSecret: U.secretKey, now: 1, ttlMs: 1 })).toThrow('score');
    const low = issueCoverageQuote({ rep: { ...rep, score: 0.1 }, exposure: 100, underwriterSecret: U.secretKey, now: 1, ttlMs: 10 });
    expect(low).toMatchObject({ declined: true, premium: 0, coverage: 0 });
    expect(verifyCoverageQuote(low, { underwriter: UK, now: 2 })).toEqual({ ok: true });
  });
});

describe('disputesFromSettlements', () => {
  const G = generateKeyPair();
  const GK = encodeKey(G.publicKey);
  const L = new BondLedger({ guardianSecret: G.secretKey, accounts: new InMemoryBondAccount({ alice: 1000 }) });
  const open = L.openBond({ claimId: 'c1', amount: 10, depositor: 'alice', at: 5 });
  const release = L.releaseBond({ claimId: 'c1', at: 9 });
  const signed = (body: Omit<SettlementRecord, 'sig'>): SettlementRecord => {
    const pre = utf8('atlas-pca/bond-settlement/v1\0');
    const b = canonicalBytesLenient(body);
    const m = new Uint8Array(pre.length + b.length);
    m.set(pre);
    m.set(b, pre.length);
    return { ...body, sig: b64u(sign(G.secretKey, m)) };
  };
  const subj = (id: string) => (id === 'c1' ? 'alice' : undefined);
  it('open is skipped; release is a clean dispute; slash is slashed; ids are record digests', () => {
    const { sig: _s, ...body } = release;
    const slash = signed({ ...body, action: 'slash', to: 'tr', at: 11, evidenceDigest: 'e' });
    const out = disputesFromSettlements([open, release, slash], GK, subj);
    expect(out.rejected).toBe(0);
    expect(out.disputes).toEqual([
      { id: settlementRecordDigest(release), subject: 'alice', slashed: false, at: 9, amount: 10 },
      { id: settlementRecordDigest(slash), subject: 'alice', slashed: true, at: 11, amount: 10 },
    ]);
    expect(reputation({ subject: 'alice', disputes: out.disputes }).slashes).toBe(1);
  });
  it('forged, wrong-key, and unknown-subject records are rejected, not counted', () => {
    const forged = { ...release, action: 'slash' as const };
    expect(disputesFromSettlements([forged], GK, subj)).toEqual({ disputes: [], rejected: 1 });
    expect(disputesFromSettlements([release], encodeKey(generateKeyPair().publicKey), subj)).toEqual({ disputes: [], rejected: 1 });
    expect(disputesFromSettlements([release], GK, () => undefined)).toEqual({ disputes: [], rejected: 1 });
    expect(disputesFromSettlements([null as never], GK, subj)).toEqual({ disputes: [], rejected: 1 });
  });
});
