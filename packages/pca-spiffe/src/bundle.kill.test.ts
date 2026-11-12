import { describe, expect, it } from 'vitest';
import { exportJWK, generateKeyPair } from 'jose';
import { SpiffeError, createTrustBundleSource, type TrustBundle } from './index';

async function rejection(p: Promise<unknown>): Promise<{ code: string; message: string; spiffe: boolean }> {
  try {
    await p;
  } catch (e) {
    const x = e as { code?: string; message?: string };
    return { code: String(x.code), message: String(x.message), spiffe: e instanceof SpiffeError };
  }
  throw new Error('expected a rejection');
}
const jwk = async () => ({ ...(await exportJWK((await generateKeyPair('ES256')).publicKey)), kid: 'k', alg: 'ES256' });

describe('createTrustBundleSource construction', () => {
  it('a missing options object or fetch is a SpiffeError, not a TypeError', () => {
    for (const bad of [undefined, null, {}]) {
      let err: unknown;
      try {
        createTrustBundleSource(bad as never);
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(SpiffeError);
      expect((err as SpiffeError).code).toBe('trust_bundle_unavailable');
      expect((err as SpiffeError).message).toBe('createTrustBundleSource requires `fetch`');
    }
  });
  it('rejects bad timing with the exact code and accepts maxStaleMs equal to refreshMs', () => {
    const fetch = async (): Promise<TrustBundle> => ({});
    let err: unknown;
    try {
      createTrustBundleSource({ fetch, refreshMs: 10, maxStaleMs: 9 });
    } catch (e) {
      err = e;
    }
    expect((err as SpiffeError).code).toBe('trust_bundle_unavailable');
    expect((err as SpiffeError).message).toBe('refreshMs must be > 0 and maxStaleMs >= refreshMs (both finite)');
    expect(() => createTrustBundleSource({ fetch, refreshMs: 10, maxStaleMs: 10 })).not.toThrow();
  });
});

describe('createTrustBundleSource fetch outcomes', () => {
  it('a null, function-shaped or empty fetched bundle is trust_bundle_invalid with the exact message', async () => {
    const fn = Object.assign(() => 1, { x509Authorities: ['pem'] });
    for (const b of [null, fn, {}, { jwks: { keys: [] }, x509Authorities: [] }]) {
      const src = createTrustBundleSource({ fetch: async () => b as never, refreshMs: 10, maxStaleMs: 30, now: () => 0 });
      expect(await rejection(src.x509Roots())).toEqual({ code: 'trust_bundle_invalid', message: 'fetched trust bundle has no authorities', spiffe: true });
    }
  });
  it('a failing fetch is trust_bundle_unavailable carrying the cause', async () => {
    const a = createTrustBundleSource({ fetch: async () => { throw new Error('boom'); }, refreshMs: 10, maxStaleMs: 30, now: () => 0 });
    expect(await rejection(a.x509Roots())).toEqual({ code: 'trust_bundle_unavailable', message: 'trust bundle fetch failed: boom', spiffe: true });
    const b = createTrustBundleSource({ fetch: () => Promise.reject('plain'), refreshMs: 10, maxStaleMs: 30, now: () => 0 });
    expect(await rejection(b.x509Roots())).toEqual({ code: 'trust_bundle_unavailable', message: 'trust bundle fetch failed: plain', spiffe: true });
  });
  it('keeps the last good bundle within maxStaleMs and refuses beyond it', async () => {
    let t = 1_000_000;
    let down = false;
    const src = createTrustBundleSource({
      fetch: async () => { if (down) throw new Error('down'); return { x509Authorities: ['root'] }; },
      refreshMs: 10, maxStaleMs: 30, now: () => t,
    });
    expect(await src.x509Roots()).toEqual(['root']);
    down = true;
    t += 30;
    expect(await src.x509Roots()).toEqual(['root']);
    t += 1;
    expect((await rejection(src.x509Roots())).code).toBe('trust_bundle_unavailable');
  });
  it('a clock that outruns maxStaleMs during the fetch leaves no usable bundle', async () => {
    let t = 0;
    const src = createTrustBundleSource({ fetch: async () => ({ x509Authorities: ['root'] }), refreshMs: 10, maxStaleMs: 10, now: () => (t += 100) });
    expect(await rejection(src.x509Roots())).toEqual({ code: 'trust_bundle_unavailable', message: 'no trust bundle available', spiffe: true });
  });
});

describe('createTrustBundleSource authorities', () => {
  it('jwtKey refuses a bundle with no JWT authorities, x509Roots one with no X.509 authorities', async () => {
    const x509Only = createTrustBundleSource({ fetch: async () => ({ jwks: { keys: [] }, x509Authorities: ['root'] }), refreshMs: 10, maxStaleMs: 30, now: () => 0 });
    expect(await rejection(Promise.resolve(x509Only.jwtKey({ alg: 'ES256' }, {} as never)))).toEqual({ code: 'trust_bundle_invalid', message: 'trust bundle has no JWT authorities', spiffe: true });
    const noJwks = createTrustBundleSource({ fetch: async () => ({ x509Authorities: ['root'] }), refreshMs: 10, maxStaleMs: 30, now: () => 0 });
    expect((await rejection(Promise.resolve(noJwks.jwtKey({ alg: 'ES256' }, {} as never)))).message).toBe('trust bundle has no JWT authorities');
    const jwtOnly = createTrustBundleSource({ fetch: async () => ({ jwks: { keys: [await jwk()] }, x509Authorities: [] }), refreshMs: 10, maxStaleMs: 30, now: () => 0 });
    expect(await rejection(jwtOnly.x509Roots())).toEqual({ code: 'trust_bundle_invalid', message: 'trust bundle has no X.509 authorities', spiffe: true });
  });
});
