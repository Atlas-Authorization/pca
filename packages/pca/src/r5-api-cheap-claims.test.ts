/**
 * R5-API-03: a server must be able to refuse a PCActn for another audience, or outside its iat/exp window, BEFORE it meters
 * anything or verifies any signature. `pcactnCheapClaims` is that check: the same decision the full verifier makes for its
 * `audience` and `validity` checks (it calls the same verified-core `validityDecision`), on unauthenticated fields, at O(1).
 */
import { describe, expect, it } from 'vitest';
import { PCACTN_MAX_LIFETIME_MS, PCACTN_MAX_SKEW_MS, pcactnCheapClaims } from './index';

const NOW = 1_800_000_000_000;
const ok = { aud: 'ins_a', iat: NOW - 1_000, exp: NOW + 60_000 };

describe('R5-API-03: pcactnCheapClaims', () => {
  it('passes a well-formed, in-window PCActn for this audience', () => {
    expect(pcactnCheapClaims(ok, { audience: 'ins_a', now: NOW })).toBeNull();
    expect(pcactnCheapClaims({ ...ok, exp: NOW }, { audience: 'ins_a', now: NOW })).toBeNull(); // valid THROUGH exp
    expect(pcactnCheapClaims({ ...ok, iat: NOW + PCACTN_MAX_SKEW_MS, exp: NOW + PCACTN_MAX_SKEW_MS + 1 }, { audience: 'ins_a', now: NOW })).toBeNull();
  });

  it('refuses another audience, a missing or non-string aud', () => {
    for (const aud of ['ins_b', '', undefined, 7, null]) {
      expect(pcactnCheapClaims({ ...ok, aud }, { audience: 'ins_a', now: NOW })?.check).toBe('audience');
    }
  });

  it('refuses expired, future, non-increasing, over-long and non-integer windows', () => {
    const v = (o: Record<string, unknown>) => pcactnCheapClaims({ ...ok, ...o }, { audience: 'ins_a', now: NOW })?.check;
    expect(v({ exp: NOW - 1 })).toBe('validity');
    expect(v({ iat: NOW + PCACTN_MAX_SKEW_MS + 1, exp: NOW + PCACTN_MAX_SKEW_MS + 2 })).toBe('validity');
    expect(v({ exp: ok.iat })).toBe('validity');
    expect(v({ iat: NOW - 10, exp: NOW - 10 + PCACTN_MAX_LIFETIME_MS + 1 })).toBe('validity');
    for (const bad of [1.5, '1', undefined, Number.NaN, Number.MAX_SAFE_INTEGER + 2]) {
      expect(v({ iat: bad })).toBe('validity');
      expect(v({ exp: bad })).toBe('validity');
    }
  });

  it('a non-safe-integer server clock fails closed', () => {
    expect(pcactnCheapClaims(ok, { audience: 'ins_a', now: Number.NaN })?.check).toBe('validity');
  });
});
