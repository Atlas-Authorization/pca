import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { createTrustBundleSource, verifyJwtSvid, verifyX509Svid, type TrustBundle } from './index';

const pem = (n: string): string => readFileSync(resolve(__dirname, '..', 'fixtures', 'generated', `${n}.pem`), 'utf8');
const settle = async <T>(p: Promise<T>): Promise<{ ok: true; v: T } | { ok: false; code: string }> =>
  p.then((v) => ({ ok: true as const, v }), (e: { code?: string }) => ({ ok: false as const, code: String(e.code) }));

async function jwtBundle(): Promise<{ bundle: TrustBundle; token: string }> {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'ES256' };
  const token = await new SignJWT({}).setProtectedHeader({ alg: 'ES256', kid: 'k1' }).setSubject('spiffe://example.org/a').setAudience('rs').setExpirationTime('1h').sign(privateKey);
  return { bundle: { jwks: { keys: [jwk] } }, token };
}
const verify = (src: ReturnType<typeof createTrustBundleSource>, token: string) => settle(verifyJwtSvid(token, { audience: 'rs', trustDomain: 'example.org', key: src.jwtKey }).then((s) => s.spiffeId.id));

describe('createTrustBundleSource fails closed', () => {
  it('refuses to start without valid timing', () => {
    const f = async (): Promise<TrustBundle> => ({});
    for (const [r, m] of [[0, 1], [10, 5], [Number.NaN, 5], [5, Infinity]] as const) {
      expect(() => createTrustBundleSource({ fetch: f, refreshMs: r, maxStaleMs: m })).toThrowError(/refreshMs must be > 0/);
    }
    expect(() => createTrustBundleSource({} as never)).toThrowError(/requires `fetch`/);
  });

  it('first fetch failing or empty denies; success then verifies', async () => {
    const { bundle, token } = await jwtBundle();
    let t = 0;
    let mode: 'down' | 'empty' | 'ok' = 'down';
    const src = createTrustBundleSource({
      fetch: async () => { if (mode === 'down') throw new Error('boom'); return mode === 'empty' ? { jwks: { keys: [] }, x509Authorities: [] } : bundle; },
      refreshMs: 10, maxStaleMs: 30, now: () => t,
    });
    expect(await verify(src, token)).toEqual({ ok: false, code: 'trust_bundle_unavailable' });
    mode = 'empty';
    expect(await verify(src, token)).toEqual({ ok: false, code: 'trust_bundle_invalid' });
    mode = 'ok';
    expect(await verify(src, token)).toEqual({ ok: true, v: 'spiffe://example.org/a' });
  });

  it('serves stale only until maxStaleMs after the last good fetch, then denies; recovers on success', async () => {
    const { bundle, token } = await jwtBundle();
    let t = 0;
    let up = true;
    let calls = 0;
    const src = createTrustBundleSource({ fetch: async () => { calls++; if (!up) throw new Error('down'); return bundle; }, refreshMs: 10, maxStaleMs: 30, now: () => t });
    expect(await verify(src, token)).toEqual({ ok: true, v: 'spiffe://example.org/a' });
    t = 9; await verify(src, token);
    expect(calls).toBe(1); // within refreshMs: cached
    up = false;
    t = 10; // refresh due, fetch fails, stale (age 10) still allowed
    expect(await verify(src, token)).toEqual({ ok: true, v: 'spiffe://example.org/a' });
    expect(calls).toBe(2);
    t = 30; // exactly maxStaleMs: still allowed
    expect(await verify(src, token)).toEqual({ ok: true, v: 'spiffe://example.org/a' });
    t = 31; // past it: denied with the fetch failure
    expect(await verify(src, token)).toEqual({ ok: false, code: 'trust_bundle_unavailable' });
    up = true;
    expect(await verify(src, token)).toEqual({ ok: true, v: 'spiffe://example.org/a' });
  });

  it('a malformed refresh does not replace the good bundle, and a good refresh replaces (removed authority stops being trusted)', async () => {
    const a = await jwtBundle();
    const b = await jwtBundle(); // different key, same kid
    let t = 0;
    let next: unknown = a.bundle;
    const src = createTrustBundleSource({ fetch: async () => next as TrustBundle, refreshMs: 10, maxStaleMs: 100, now: () => t });
    expect(await verify(src, a.token)).toEqual({ ok: true, v: 'spiffe://example.org/a' });
    t = 10; next = { jwks: { keys: 'nope' } };
    expect(await verify(src, a.token)).toEqual({ ok: true, v: 'spiffe://example.org/a' }); // stale, still within window
    t = 20; next = b.bundle;
    expect((await verify(src, a.token)).ok).toBe(false); // old key no longer trusted
    expect(await verify(src, b.token)).toEqual({ ok: true, v: 'spiffe://example.org/a' });
  });

  it('concurrent callers share one fetch', async () => {
    const { bundle, token } = await jwtBundle();
    let calls = 0;
    const src = createTrustBundleSource({ fetch: async () => { calls++; await Promise.resolve(); return bundle; }, refreshMs: 10, maxStaleMs: 30, now: () => 0 });
    await Promise.all([verify(src, token), verify(src, token), verify(src, token)]);
    expect(calls).toBe(1);
  });

  it('an X.509-only bundle gives roots but no JWT key, and a JWT-only bundle gives no roots', async () => {
    const x = createTrustBundleSource({ fetch: async () => ({ x509Authorities: [pem('root')] }), refreshMs: 10, maxStaleMs: 30, now: () => 0 });
    const { token } = await jwtBundle();
    expect(await verify(x, token)).toEqual({ ok: false, code: 'trust_bundle_invalid' });
    const roots = await x.x509Roots();
    expect(verifyX509Svid([pem('leaf'), pem('inter0')], { trustDomain: 'example.org', roots, now: new Date('2027-06-01T00:00:00Z') }).spiffeId.id).toBe('spiffe://example.org/workload/db');
    const j = createTrustBundleSource({ fetch: async () => (await jwtBundle()).bundle, refreshMs: 10, maxStaleMs: 30, now: () => 0 });
    expect(await settle(j.x509Roots())).toEqual({ ok: false, code: 'trust_bundle_invalid' });
  });
});
