import { describe, expect, it } from 'vitest';
import { b64u, canonicalBytesStrict } from './hash';
import { decodePcaNeed, encodePcaNeed, pcaNeedFromChallenge, PCA_NEED_MAX_ENCODED, validatePcaNeed, type PcaNeed } from './pca-need';

const base: PcaNeed = { v: 1, kind: 'scope', verb: 'stripe.refund', resource: 'charge/ch_1' };
const BF = { ok: false, code: 'bad_field' };
const lim = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`k${i}`, i]));

describe('validatePcaNeed shape and string bounds', () => {
  it('refuses non-objects with bad_shape', () => {
    for (const x of ['str', 5, true, null, undefined, [], [1]]) expect(validatePcaNeed(x)).toEqual({ ok: false, code: 'bad_shape' });
  });
  it('bounds verb (128) and resource (512) exactly and rejects non-strings', () => {
    expect(validatePcaNeed({ ...base, verb: 'v'.repeat(128) })).toMatchObject({ ok: true });
    expect(validatePcaNeed({ ...base, verb: 'v'.repeat(129) })).toEqual(BF);
    expect(validatePcaNeed({ ...base, resource: 'r'.repeat(512) })).toMatchObject({ ok: true });
    expect(validatePcaNeed({ ...base, resource: 'r'.repeat(513) })).toEqual(BF);
    expect(validatePcaNeed({ ...base, verb: ['abcd'] })).toEqual(BF);
    expect(validatePcaNeed({ ...base, resource: ['abcd'] })).toEqual(BF);
  });
  it('checks scopes: at most 16, each a short string without whitespace', () => {
    const n = (k: number) => Array.from({ length: k }, (_, i) => `s${i}`);
    expect(validatePcaNeed({ ...base, scopes: n(16) })).toMatchObject({ ok: true });
    expect(validatePcaNeed({ ...base, scopes: n(17) })).toEqual(BF);
    expect(validatePcaNeed({ ...base, scopes: ['ok', 'a b'] })).toEqual(BF);
    expect(validatePcaNeed({ ...base, scopes: ['a b', 'ok'] })).toEqual(BF);
    expect(validatePcaNeed({ ...base, scopes: 'ok' })).toEqual(BF);
  });
  it('checks grant_ref and policy_digest', () => {
    const ok = { ...base, grant_ref: 'g'.repeat(128), policy_digest: 'p'.repeat(128) };
    expect(validatePcaNeed(ok)).toEqual({ ok: true, need: ok });
    expect(validatePcaNeed({ ...base, grant_ref: '' })).toEqual(BF);
    expect(validatePcaNeed({ ...base, grant_ref: 'g'.repeat(129) })).toEqual(BF);
    expect(validatePcaNeed({ ...base, policy_digest: '' })).toEqual(BF);
    expect(validatePcaNeed({ ...base, policy_digest: 'p'.repeat(129) })).toEqual(BF);
  });
  it('accepts only tier 2 or 3, and only on an escalation', () => {
    const esc = (tier: unknown) => ({ v: 1, kind: 'escalate', verb: 'v', resource: 'r', tier });
    expect(validatePcaNeed(esc(2))).toEqual({ ok: true, need: esc(2) });
    expect(validatePcaNeed(esc(3))).toEqual({ ok: true, need: esc(3) });
    for (const t of [1, 4, '2', null, 0]) expect(validatePcaNeed(esc(t))).toEqual(BF);
  });
  it('checks limits: a plain object, at most 16 keys, named keys, finite non-negative numbers', () => {
    expect(validatePcaNeed({ ...base, limits: lim(16) })).toMatchObject({ ok: true });
    expect(validatePcaNeed({ ...base, limits: lim(17) })).toEqual(BF);
    expect(validatePcaNeed({ ...base, limits: [] })).toEqual(BF);
    expect(validatePcaNeed({ ...base, limits: null })).toEqual(BF);
    expect(validatePcaNeed({ ...base, limits: 'str' })).toEqual(BF);
    expect(validatePcaNeed({ ...base, limits: { '': 1 } })).toEqual(BF);
    expect(validatePcaNeed({ ...base, limits: { ['k'.repeat(64)]: 1 } })).toMatchObject({ ok: true });
    expect(validatePcaNeed({ ...base, limits: { ['k'.repeat(65)]: 1 } })).toEqual(BF);
    expect(validatePcaNeed({ ...base, limits: { a: 0 } })).toMatchObject({ ok: true });
    expect(validatePcaNeed({ ...base, limits: { a: -1 } })).toEqual(BF);
    expect(validatePcaNeed({ ...base, limits: { a: Infinity } })).toEqual(BF);
    expect(validatePcaNeed({ ...base, limits: { a: NaN } })).toEqual(BF);
    expect(validatePcaNeed({ ...base, limits: { a: '1' } })).toEqual(BF);
  });
  it('checks discharges: an array of at most 16 closed entries', () => {
    const d = { issuer: 'https://i.example', claim: 'c' };
    const list = (n: number) => Array.from({ length: n }, () => d);
    expect(validatePcaNeed({ ...base, discharges: list(16) })).toMatchObject({ ok: true });
    expect(validatePcaNeed({ ...base, discharges: list(17) })).toEqual(BF);
    expect(validatePcaNeed({ ...base, discharges: {} })).toEqual(BF);
    expect(validatePcaNeed({ ...base, discharges: 'str' })).toEqual(BF);
    expect(validatePcaNeed({ ...base, discharges: [null] })).toEqual(BF);
    expect(validatePcaNeed({ ...base, discharges: [d, 'x'] })).toEqual(BF);
    expect(validatePcaNeed({ ...base, discharges: [{ issuer: 'i'.repeat(512), claim: 'c'.repeat(256) }] })).toMatchObject({ ok: true });
    expect(validatePcaNeed({ ...base, discharges: [{ issuer: 'i'.repeat(513), claim: 'c' }] })).toEqual(BF);
    expect(validatePcaNeed({ ...base, discharges: [{ issuer: 'i', claim: 'c'.repeat(257) }] })).toEqual(BF);
    expect(validatePcaNeed({ ...base, discharges: [{ issuer: 'i' }] })).toEqual(BF);
  });
});

describe('encode and decode edges', () => {
  it('names the failure code in the encode error', () => {
    expect(() => encodePcaNeed({ ...base, verb: '' })).toThrow('encodePcaNeed: malformed need (bad_field)');
    expect(() => encodePcaNeed({ ...base, v: 2 } as unknown as PcaNeed)).toThrow('encodePcaNeed: malformed need (bad_version)');
  });
  it('accepts an encoded value of exactly the maximum length and refuses one byte group more', () => {
    const mk = (n: number): PcaNeed => ({
      v: 1, kind: 'discharge', verb: 'v'.repeat(128), resource: 'r',
      discharges: [{ issuer: 'a'.repeat(512), claim: 'c'.repeat(256) }, { issuer: 'i'.repeat(n), claim: 'c'.repeat(256) }],
    });
    const want = (PCA_NEED_MAX_ENCODED / 4) * 3;
    const n = 1 + (want - canonicalBytesStrict(mk(1)).length);
    const exact = mk(n);
    expect(canonicalBytesStrict(exact).length).toBe(want);
    const e = encodePcaNeed(exact);
    expect(e.length).toBe(PCA_NEED_MAX_ENCODED);
    expect(decodePcaNeed(e)).toEqual({ ok: true, need: exact });
    expect(() => encodePcaNeed(mk(n + 1))).toThrow(/too large/);
    expect(decodePcaNeed(b64u(canonicalBytesStrict(mk(n + 1))))).toEqual({ ok: false, code: 'too_long' });
  });
  it('treats a non-string value as bad_base64 whatever its length property says', () => {
    expect(decodePcaNeed({ length: 5000 })).toEqual({ ok: false, code: 'bad_base64' });
    expect(decodePcaNeed(['abc'])).toEqual({ ok: false, code: 'bad_base64' });
  });
  it('reads the parameter at the start of the header and only from a string', () => {
    const e = encodePcaNeed(base);
    expect(pcaNeedFromChallenge(`pca_need="${e}"`)).toEqual({ ok: true, need: base });
    expect(pcaNeedFromChallenge(`Bearer a="b",pca_need="${e}"`)).toEqual({ ok: true, need: base });
    expect(pcaNeedFromChallenge([`pca_need="${e}"`])).toBeNull();
    expect(pcaNeedFromChallenge({ toString: () => `pca_need="${e}"` })).toBeNull();
  });
});
