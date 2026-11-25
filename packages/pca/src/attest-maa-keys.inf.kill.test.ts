import { describe, expect, it } from 'vitest';
import { createMaaKeyTrust, createMemoryMaaKeyStateStore, evaluateMaaJwks } from './attest-maa-keys';
import type { MaaJwks } from './attest-azure-maa';

const ISSUER = 'https://sharedwus.wus.attest.azure.net';
const mk = (policy: Record<string, unknown>) => () =>
  createMaaKeyTrust({ policy: { trustedIssuers: [ISSUER], ...policy }, store: createMemoryMaaKeyStateStore(), fetch: (async () => new Response('{}')) as typeof fetch });

describe('a non-finite window never admits (MAA key trust)', () => {
  // old code used the values as-is: an infinite skew kept every expired key live, a NaN max-stale never aged a cache out
  it('an infinite or NaN ttl or skew is refused at construction', () => {
    for (const v of [Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, Number.NaN]) {
      expect(mk({ ttlMs: v })).toThrow(TypeError);
      expect(mk({ clockSkewMs: v })).toThrow(TypeError);
    }
  });
  it('a NaN max-stale or key-count limit is refused at construction', () => {
    expect(mk({ maxStaleMs: Number.NaN })).toThrow(TypeError);
    expect(mk({ maxNewKeysPerFetch: Number.NaN })).toThrow(TypeError);
    expect(mk({ maxInitialKeys: Number.NaN })).toThrow(TypeError);
  });
  it('a finite default policy still constructs', () => {
    expect(mk({})).not.toThrow();
  });
  // old evaluation compared with the skew directly, so a NaN or infinite skew skipped the validity window; the key never even reached it here
  it('evaluating a key set with a non-finite skew or clock rejects every key', () => {
    const jwks = { keys: [{ kid: 'k', x5c: ['AAAA'] }] } as unknown as MaaJwks;
    for (const v of [Number.POSITIVE_INFINITY, Number.NaN]) {
      const ev = evaluateMaaJwks(jwks, ISSUER, { trustedIssuers: [ISSUER], clockSkewMs: v }, 1_000);
      expect(ev.rejected).toEqual([{ kid: 'k', reason: 'clock and skew must be finite' }]);
    }
    expect(evaluateMaaJwks(jwks, ISSUER, { trustedIssuers: [ISSUER] }, Number.NEGATIVE_INFINITY).rejected[0]?.reason).toBe('clock and skew must be finite');
  });
});
