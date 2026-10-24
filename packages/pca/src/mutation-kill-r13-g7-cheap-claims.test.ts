/**
 * r13 mutation kills for pcactn-cheap-claims.ts: the exact refusal for every audience / validity outcome, and the
 * fail-closed catch around the verified-core validityDecision (fault-injected through a module mock in a fresh module).
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { pcactnCheapClaims } from './pcactn-cheap-claims';

const NOW = 1_800_000_000_000;
const ok = { aud: 'rs', iat: NOW - 1000, exp: NOW + 1000 };
const run = (over: Record<string, unknown> = {}, opts: { audience?: string; now?: number } = {}) => pcactnCheapClaims({ ...ok, ...over }, { audience: 'rs', now: NOW, ...opts });
const V = (reason: string) => ({ check: 'validity', reason });

afterEach(() => {
  vi.doUnmock('@atlasauth/pca-verified-core');
  vi.resetModules();
});

describe('pcactnCheapClaims', () => {
  it('passes a well-formed window', () => {
    expect(run()).toBeNull();
  });
  it('audience', () => {
    const A = { check: 'audience', reason: 'aud does not match this resource server / instance' };
    expect(run({ aud: 'other' })).toEqual(A);
    expect(run({ aud: 5 })).toEqual(A);
    expect(run({ aud: '' }, { audience: '' })).toEqual(A);
    // a missing or null aud is refused as a value, never by a TypeError
    for (const aud of [undefined, null]) {
      let got: unknown;
      try {
        got = pcactnCheapClaims({ aud, iat: ok.iat, exp: ok.exp }, { audience: 'rs', now: NOW });
      } catch (e) {
        got = { threw: String(e) };
      }
      expect(got).toEqual(A);
    }
  });
  it('non-integer iat or exp', () => {
    const I = V('iat and exp must be safe-integer epoch ms');
    expect(run({ iat: 1.5 })).toEqual(I);
    expect(run({ exp: 1.5 })).toEqual(I);
    expect(run({ iat: '1' })).toEqual(I);
  });
  it('every validity decision has its own reason', () => {
    expect(run({}, { now: NaN })).toEqual(V('the verifier clock is not a safe integer epoch-ms'));
    expect(run({ exp: ok.iat })).toEqual(V('exp must be greater than iat'));
    expect(run({ iat: NOW - 4_000_000, exp: NOW + 1 })).toEqual(V('lifetime exceeds 3600000 ms'));
    expect(run({ iat: NOW + 120_000, exp: NOW + 130_000 })).toEqual(V('iat is in the future (clock skew)'));
    expect(run({ iat: NOW - 3000, exp: NOW - 2000 })).toEqual(V('the PCActn has expired'));
  });
  it('fails closed when the validity decision throws', async () => {
    vi.resetModules();
    vi.doMock('@atlasauth/pca-verified-core', async (orig) => ({
      ...(await orig<typeof import('@atlasauth/pca-verified-core')>()),
      validityDecision: () => {
        throw new Error('boom');
      },
    }));
    const m = await import('./pcactn-cheap-claims');
    expect(m.pcactnCheapClaims(ok, { audience: 'rs', now: NOW })).toEqual(V('unverifiable validity window'));
  });
});
