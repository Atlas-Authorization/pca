import { describe, expect, it } from 'vitest';
import { generateKeyPair } from '@atlasauth/pca';
import { DIRECTORY_CONTENT_TYPE, buildKeyDirectory, fetchKeyDirectory, signRequest, verifySignedRequest } from './index';

const kp = generateKeyPair();
const dir = buildKeyDirectory([{ publicKey: kp.publicKey, keyid: 'k1' }]);
const resp = (status: number, body: string, ct: string | null = DIRECTORY_CONTENT_TYPE) => async () => ({
  status,
  headers: { get: (n: string) => (n === 'content-type' ? ct : null) },
  text: async () => body,
});
const err = (p: Promise<unknown>) => p.then(() => 'ok', (e: Error) => e.message);
const URL_ = 'https://bots.example/.well-known/http-message-signatures-directory';

describe('fetchKeyDirectory (fail closed)', () => {
  it('returns a well-formed directory', async () => {
    expect(await fetchKeyDirectory(URL_, { fetch: resp(200, JSON.stringify(dir)) })).toEqual(dir);
  });
  it('refuses http, non-200, wrong content type, oversize, bad JSON, empty and malformed keys', async () => {
    const f = (r: ReturnType<typeof resp>, o = {}) => err(fetchKeyDirectory(URL_, { fetch: r, ...o }));
    expect(await err(fetchKeyDirectory('http://bots.example/d', { fetch: resp(200, JSON.stringify(dir)) }))).toBe('directory URL must be https');
    expect(await f(resp(404, JSON.stringify(dir)))).toBe('directory fetch returned status 404');
    expect(await f(resp(200, JSON.stringify(dir), 'application/json'))).toBe('directory has the wrong content type');
    expect(await f(resp(200, JSON.stringify(dir), null))).toBe('directory has the wrong content type');
    expect(await f(resp(200, JSON.stringify(dir)), { maxBytes: 10 })).toBe('directory response is too large');
    expect(await f(resp(200, '{'))).toMatch(/JSON/);
    expect(await f(resp(200, '{"keys":[]}'))).toBe('directory has no keys');
    const k = dir.keys[0]!;
    for (const bad of [{ ...k, crv: 'X25519' }, { ...k, kty: 'EC' }, { ...k, kid: '' }, { ...k, x: 'AAAA' }, { ...k, nbf: 'x' }]) {
      expect(await f(resp(200, JSON.stringify({ keys: [k, bad] })))).toBe('directory contains a malformed key');
    }
  });
  it('passes redirect:error so a redirect cannot move the trust anchor', async () => {
    let seen: unknown;
    await fetchKeyDirectory(URL_, { fetch: async (_u, i) => { seen = i.redirect; return resp(200, JSON.stringify(dir))(); } });
    expect(seen).toBe('error');
  });
});

describe('directory key validity window is enforced when verifying via jwks', () => {
  const NOW = 1_700_000_000;
  const mk = (extra: { nbf?: number; exp?: number }) => {
    const d = buildKeyDirectory([{ publicKey: kp.publicKey, keyid: 'k1', ...extra }]);
    const s = signRequest({ method: 'GET', url: 'https://a.example/x', headers: {}, key: kp, keyid: 'k1', created: NOW, expiresInSec: 60 });
    return { d, req: { method: 'GET', url: 'https://a.example/x', headers: s.headers } };
  };
  it('valid inside the window; expired or not-yet-valid keys are refused', async () => {
    const ok = mk({ nbf: NOW - 10, exp: NOW + 100 });
    expect((await verifySignedRequest(ok.req, { jwks: ok.d, now: NOW })).valid).toBe(true);
    const old = mk({ exp: NOW - 1 });
    expect(await verifySignedRequest(old.req, { jwks: old.d, now: NOW })).toEqual({ valid: false, reason: 'could not resolve key "k1"' });
    const early = mk({ nbf: NOW + 1 });
    expect(await verifySignedRequest(early.req, { jwks: early.d, now: NOW })).toEqual({ valid: false, reason: 'could not resolve key "k1"' });
    expect((await verifySignedRequest(early.req, { jwks: early.d, now: NOW, clockSkewSec: 1 })).valid).toBe(true);
  });
});
