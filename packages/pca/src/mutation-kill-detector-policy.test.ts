/**
 * Mutation-kill tests for the detector policy validator and the tighten-only fold: every bound at its edge, a list with one
 * good and one bad member, values that only match an id pattern after coercion, and the exact refusal result of a bad policy.
 */
import { describe, expect, it } from 'vitest';
import { detectorInputDigest, detectorPolicyError, detectorSignal, signDetectorReceipt, type DetectorInput, type DetectorPolicy } from './detector-receipt';
import { encodeKey, generateKeyPair } from './keys';

const gw = generateKeyPair();
const PK = encodeKey(gw.publicKey);
const entry = (o: Record<string, unknown> = {}) => ({ id: 'a', keys: [{ pk: PK }], on_suspicious: 'escalate', max_age_ms: 1000, ...o });
const one = (o: Record<string, unknown> = {}) => detectorPolicyError({ detectors: [entry(o)] });
const IDS = 'detector ids must be distinct ids other than "invalid"';
const KEYS = "detector 'a': keys must hold 1..8 pins";
const CATS = "detector 'a': categories must be 1+ ids";
const AGE = "detector 'a': max_age_ms must be 1..86400000";

describe('detectorPolicyError: bounds and member checks', () => {
  it('at most 16 detectors', () => {
    const n = (k: number) => ({ detectors: Array.from({ length: k }, (_, i) => entry({ id: `d${i}` })) });
    expect(detectorPolicyError(n(16))).toBeNull();
    expect(detectorPolicyError(n(17))).toBe('detectors must hold at most 16 entries');
  });
  it('an entry with an unknown or a missing member is malformed', () => {
    expect(one({ extra: 1 })).toBe('detector entry is malformed');
    expect(detectorPolicyError({ detectors: [{ id: 'a', keys: [{ pk: PK }], on_suspicious: 'escalate' }] })).toBe('detector entry is malformed');
  });
  it('ids: a string that is not an id, a non-string that coerces to one, and a duplicate are refused', () => {
    expect(one({ id: 'Bad' })).toBe(IDS);
    expect(one({ id: ['abc'] })).toBe(IDS);
    expect(detectorPolicyError({ detectors: [entry(), entry()] })).toBe(IDS);
    expect(detectorPolicyError({ detectors: [entry(), entry({ id: 'b' })] })).toBeNull();
  });
  it('keys: 8 pins pass, 9 are refused; every pin needs a string pk', () => {
    expect(one({ keys: Array.from({ length: 8 }, () => ({ pk: PK })) })).toBeNull();
    expect(one({ keys: Array.from({ length: 9 }, () => ({ pk: PK })) })).toBe(KEYS);
    expect(one({ keys: [{ pk: PK }, { pk: 5 }] })).toBe(KEYS);
    expect(one({ keys: [{ pk: 5 }] })).toBe(KEYS);
    expect(one({ keys: [PK] })).toBe(KEYS);
  });
  it('categories: every member must be a string id', () => {
    expect(one({ categories: ['prompt_injection'] })).toBeNull();
    expect(one({ categories: ['prompt_injection', 'Bad'] })).toBe(CATS);
    expect(one({ categories: ['Bad'] })).toBe(CATS);
    expect(one({ categories: [['abc']] })).toBe(CATS);
  });
  it('max_age_ms: 1 and 86400000 pass, 0 and 86400001 are refused', () => {
    expect(one({ max_age_ms: 1 })).toBeNull();
    expect(one({ max_age_ms: 86_400_000 })).toBeNull();
    expect(one({ max_age_ms: 0 })).toBe(AGE);
    expect(one({ max_age_ms: 86_400_001 })).toBe(AGE);
  });
});

describe('detectorSignal: a bad policy and the tighten-only fold', () => {
  it('a missing input or a malformed policy is the exact policy refusal', () => {
    const refusal = (why: string) => ({ signal: 'deny', env: { detect: { invalid: 0 } }, flagged: [], rejected: [{ index: -1, reason: `policy: ${why}` }] });
    expect(detectorSignal(undefined as unknown as DetectorInput)).toEqual(refusal('policy must be {detectors}'));
    expect(detectorSignal({ policy: { detectors: [entry({ max_age_ms: 0 })] } as unknown as DetectorPolicy, input_digests: [], now: 0 })).toEqual(refusal(AGE));
  });
  it('a later, weaker signal never raises an earlier deny', () => {
    const NOW = 1_800_000_000_000;
    const DIG = detectorInputDigest('content');
    const policy: DetectorPolicy = { detectors: [{ id: 'guard', keys: [{ pk: PK }], on_suspicious: 'deny', max_age_ms: 60_000 }] };
    const deny = signDetectorReceipt({ v: 1, kind: 'pca-detector-receipt', detector: 'guard', version: 'v1', input_digest: DIG, verdict: 'suspicious', categories: ['prompt_injection'], iat: NOW - 1000 }, gw.secretKey);
    const out = detectorSignal({ receipts: [deny, { v: 1 }], policy, input_digests: [DIG], now: NOW });
    expect(out.signal).toBe('deny');
    expect(out.flagged).toEqual(['guard']);
    expect(out.env.detect).toEqual({ guard: true, invalid: 1 });
    expect(out.rejected.map((r) => r.index)).toEqual([1]);
  });
});
