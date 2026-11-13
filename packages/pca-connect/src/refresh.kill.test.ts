import { describe, expect, it } from 'vitest';
import { refreshConnection, type ProviderConfig, type VaultFetch, type VaultHttpResponse } from './refresh';
import type { StoredConnection } from './store';

const NOW = 1_000_000;
const LIFETIME = 300_000;
const conn: StoredConnection = {
  agentId: 'ag', provider: 'google', connectionId: 'default', accessToken: 'OLD-AT', refreshToken: 'RT', expiresAt: 1, scopes: ['s1', 's2'],
  authority: { provider: 'google', principal: 'P', scopes: ['s1', 's2'] }, createdAt: 1, useCount: 0,
};
const cfg: ProviderConfig = { tokenEndpoint: 'https://idp.example/token', clientId: 'cid' };
const ok = (body: unknown): VaultHttpResponse => ({ ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) });

function run(body: unknown, over: { config?: ProviderConfig; requested?: string[] } = {}) {
  const calls: Array<{ url: string; init: Parameters<VaultFetch>[1] }> = [];
  const fetch: VaultFetch = async (url, init) => { calls.push({ url, init }); return ok(body); };
  const p = refreshConnection({ connection: conn, config: over.config ?? cfg, refreshToken: 'RT', requested: over.requested ?? [], fetch, now: NOW, defaultTokenLifetimeMs: LIFETIME });
  return { p, calls };
}
const fails = async (p: Promise<unknown>): Promise<string> => { try { await p; return 'no error'; } catch (e) { return `${(e as { code?: string }).code}: ${(e as Error).message}`; } };
const b64u = (s: string): string => Buffer.from(s).toString('base64url');
const jwt = (payloadJson: string): string => `${b64u('{"alg":"none"}')}.${b64u(payloadJson)}.sig`;

describe('refresh request', () => {
  it('posts a form with every configured parameter, joined with &', async () => {
    const { p, calls } = run({ access_token: 'AT' }, { config: { ...cfg, clientSecret: 'sec', extraParams: { audience: 'api' }, supportsScopeNarrowing: true }, requested: ['a', 'b'] });
    await p;
    expect(calls).toEqual([{
      url: 'https://idp.example/token',
      init: {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
        body: 'grant_type=refresh_token&refresh_token=RT&client_id=cid&client_secret=sec&audience=api&scope=a%20b',
      },
    }]);
  });

  it('sends only the basics for a public client without extras', async () => {
    const { p, calls } = run({ access_token: 'AT' }, { requested: ['a'] });
    await p;
    expect(calls[0]?.init.body).toBe('grant_type=refresh_token&refresh_token=RT&client_id=cid');
  });

  it('sends no scope when narrowing is on but nothing is requested', async () => {
    const { p, calls } = run({ access_token: 'AT' }, { config: { ...cfg, supportsScopeNarrowing: true }, requested: [] });
    await p;
    expect(calls[0]?.init.body).toBe('grant_type=refresh_token&refresh_token=RT&client_id=cid');
  });

  it('sends no scope when narrowing is explicitly off', async () => {
    const { p, calls } = run({ access_token: 'AT' }, { config: { ...cfg, supportsScopeNarrowing: false }, requested: ['a'] });
    await p;
    expect(calls[0]?.init.body).toBe('grant_type=refresh_token&refresh_token=RT&client_id=cid');
  });
});

describe('refresh result: scopes', () => {
  it('narrowing with a request and no echo yields the request', async () => {
    const r = await run({ access_token: 'AT' }, { config: { ...cfg, supportsScopeNarrowing: true }, requested: ['s1'] }).p;
    expect(r.scopes).toEqual(['s1']);
  });

  it('narrowing with nothing requested keeps a copy of the stored scopes', async () => {
    const r = await run({ access_token: 'AT' }, { config: { ...cfg, supportsScopeNarrowing: true }, requested: [] }).p;
    expect(r.scopes).toEqual(['s1', 's2']);
    expect(r.scopes).not.toBe(conn.scopes);
  });

  it('without narrowing the stored scopes are kept even when scopes were requested', async () => {
    const r = await run({ access_token: 'AT' }, { requested: ['s1'] }).p;
    expect(r.scopes).toEqual(['s1', 's2']);
  });

  it('the provider echo wins, split on runs of whitespace and trimmed', async () => {
    const r = await run({ access_token: 'AT', scope: '  a  b\tc\n d ' }, { config: { ...cfg, supportsScopeNarrowing: true }, requested: ['s1'] }).p;
    expect(r.scopes).toEqual(['a', 'b', 'c', 'd']);
    expect((await run({ access_token: 'AT', scope: 'solo' }).p).scopes).toEqual(['solo']);
  });

  it('a blank or non-string echo is ignored', async () => {
    for (const scope of ['', '   ', 5, null]) expect((await run({ access_token: 'AT', scope }).p).scopes, String(scope)).toEqual(['s1', 's2']);
  });
});

describe('refresh result: expiry', () => {
  it('expires_in is seconds from now', async () => {
    expect((await run({ access_token: 'AT', expires_in: 60 }).p).expiresAt).toBe(NOW + 60_000);
  });

  it('ignores an expires_in that is not a positive finite number', async () => {
    for (const v of [0, -5, Infinity, NaN, '60', null]) expect((await run({ access_token: 'AT', expires_in: v }).p).expiresAt, String(v)).toBe(NOW + LIFETIME);
  });

  it('falls back to the JWT exp claim, in seconds, when there is no expires_in', async () => {
    expect((await run({ access_token: jwt('{"exp":2000000}') }).p).expiresAt).toBe(2_000_000_000);
  });

  it('expires_in outranks the JWT exp', async () => {
    expect((await run({ access_token: jwt('{"exp":2000000}'), expires_in: 10 }).p).expiresAt).toBe(NOW + 10_000);
  });

  it('uses the default lifetime for an opaque token, a JWT without exp, and an exp that is not a finite number', async () => {
    for (const t of ['opaque-token', jwt('{"sub":"x"}'), jwt('{"exp":"123"}'), jwt('{"exp":1e999}')]) expect((await run({ access_token: t }).p).expiresAt, t).toBe(NOW + LIFETIME);
  });
});

describe('refresh result: tokens', () => {
  it('rotates the refresh token only for a non-empty string', async () => {
    expect((await run({ access_token: 'AT', refresh_token: 'NEW' }).p).refreshToken).toBe('NEW');
    for (const v of ['', 123, null, undefined]) expect((await run({ access_token: 'AT', refresh_token: v }).p).refreshToken, String(v)).toBe('RT');
  });
});

describe('refresh failures', () => {
  it('refuses a body that is not an object or has no access_token', async () => {
    expect(await fails(run('abc').p)).toBe("refresh_failed: refresh for 'google' failed: token endpoint returned a non-object body");
    expect(await fails(run(null).p)).toBe("refresh_failed: refresh for 'google' failed: token endpoint returned a non-object body");
    expect(await fails(run([]).p)).toBe("refresh_failed: refresh for 'google' failed: token endpoint returned a non-object body");
    expect(await fails(run({}).p)).toBe("refresh_failed: refresh for 'google' failed: token endpoint response has no access_token");
    expect(await fails(run({ access_token: '' }).p)).toBe("refresh_failed: refresh for 'google' failed: token endpoint response has no access_token");
  });

  it('truncates a failing endpoint body to 256 characters', async () => {
    const fetch: VaultFetch = async () => ({ ok: false, status: 500, json: async () => ({}), text: async () => 'x'.repeat(300) });
    const p = refreshConnection({ connection: conn, config: cfg, refreshToken: 'RT', requested: [], fetch, now: NOW, defaultTokenLifetimeMs: LIFETIME });
    expect(await fails(p)).toBe(`refresh_failed: refresh for 'google' failed: token endpoint 500: ${'x'.repeat(256)}`);
  });

  it('redaction copes with an absent client secret and leaves text alone for an empty secret value', async () => {
    const fetch: VaultFetch = async () => { throw new Error('boom'); };
    const p = refreshConnection({ connection: conn, config: { ...cfg, extraParams: { empty: '' } }, refreshToken: 'RT', requested: [], fetch, now: NOW, defaultTokenLifetimeMs: LIFETIME });
    expect(await fails(p)).toBe("refresh_failed: refresh for 'google' failed: transport error: boom");
  });

  it('redacts a secret from an error body', async () => {
    const fetch: VaultFetch = async () => ({ ok: false, status: 400, json: async () => ({}), text: async () => 'bad RT and OLD-AT here' });
    const p = refreshConnection({ connection: conn, config: cfg, refreshToken: 'RT', requested: [], fetch, now: NOW, defaultTokenLifetimeMs: LIFETIME });
    expect(await fails(p)).toBe("refresh_failed: refresh for 'google' failed: token endpoint 400: bad [redacted] and [redacted] here");
  });
});
