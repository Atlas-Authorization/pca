import { type KeyPair, type PCActn, InMemoryReplayStore, buildPCActn, encodeKey, generateKeyPair, mintRoot } from '@atlasauth/pca';
import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  EncryptedConnectionStore,
  LocalKeyWrapper,
  NotAuthorizedError,
  RefreshFailedError,
  StoreError,
  TokenVault,
  type ConnectionStore,
  type StoredConnection,
  type VaultFetch,
  type VaultHttpResponse,
  oauthScopeCaveat,
} from './index';
import { InMemoryConnectionStore } from './testing';
const mkVault = (o: ConstructorParameters<typeof TokenVault>[0] = {}) => new TokenVault({ strict: false, insecureSkipPlanRootCheck: true, insecureBearerRelease: true, store: new InMemoryConnectionStore(), ...o });

const NOW = 1_800_000_000_000;
const P: KeyPair = generateKeyPair();
const A: KeyPair = generateKeyPair();
const principal = encodeKey(P.publicKey);
const agentId = encodeKey(A.publicKey);
const grant = mintRoot({ principalSecret: P.secretKey, principalPublic: principal, holder: agentId, caveats: [oauthScopeCaveat('google', ['read'])] });
let counter = 0;
const actn = (nonce?: string): PCActn =>
  buildPCActn({
    grant,
    chain: [grant],
    plan: [{ id: 'use', verb: 'use_connection', resource: 'oauth:google' }],
    nodeId: 'use',
    counter: ++counter,
    signerSecret: A.secretKey,
    aud: 'rs',
    now: NOW,
    ...(nonce === undefined ? {} : { nonce }),
  });
const put = (v: TokenVault, extra: Record<string, unknown> = {}) =>
  v.putConnection({ agentId, provider: 'google', accessToken: 'AT-secret-1', refreshToken: 'RT-secret-1', expiresAt: NOW + 3_600_000, scopes: ['read'], authority: { principal, scopes: ['read'] }, ...extra });
const key32 = () => new Uint8Array(randomBytes(32));
const res = (ok: boolean, status: number, body: unknown, text?: string): VaultHttpResponse => ({
  ok,
  status,
  json: async () => body,
  text: async () => text ?? JSON.stringify(body),
});

describe('encrypted store', () => {
  const mk = (keys = { k1: key32() }, active = 'k1') => {
    const inner = new InMemoryConnectionStore();
    const w = new LocalKeyWrapper(keys, active);
    return { inner, w, store: new EncryptedConnectionStore(inner, w) };
  };
  const conn = (over: Partial<StoredConnection> = {}): StoredConnection => ({
    agentId, provider: 'google', connectionId: 'default', accessToken: 'AT-secret-1', refreshToken: 'RT-secret-1', expiresAt: NOW, scopes: ['read'],
    authority: { provider: 'google', principal, scopes: ['read'] }, createdAt: 1, useCount: 0, ...over,
  });
  const k = { agentId, provider: 'google', connectionId: 'default' };

  it('round-trips and stores neither token in the clear', async () => {
    const { inner, store } = mk();
    await store.set(conn());
    expect(await store.get(k)).toEqual(conn());
    const raw = await inner.get(k);
    expect(JSON.stringify(raw)).not.toContain('AT-secret-1');
    expect(JSON.stringify(raw)).not.toContain('RT-secret-1');
    expect(raw?.accessToken.startsWith('pca1.')).toBe(true);
  });
  it('encrypts the same token differently each time', async () => {
    const { inner, store } = mk();
    await store.set(conn());
    const a = (await inner.get(k))?.accessToken;
    await store.set(conn());
    expect((await inner.get(k))?.accessToken).not.toBe(a);
  });
  it('refuses a plaintext record (downgrade)', async () => {
    const { inner, store } = mk();
    await inner.set(conn());
    await expect(store.get(k)).rejects.toThrow(StoreError);
    await expect(store.get(k)).rejects.toMatchObject({ code: 'store_error', message: 'a stored token could not be decrypted' });
  });
  it('refuses a ciphertext moved to another connection or field', async () => {
    const { inner, store } = mk();
    await store.set(conn());
    const sealed = (await inner.get(k)) as StoredConnection;
    await inner.set({ ...sealed, connectionId: 'other' });
    await expect(store.get({ ...k, connectionId: 'other' })).rejects.toThrow(StoreError);
    await inner.set({ ...sealed, accessToken: sealed.refreshToken as string });
    await expect(store.get(k)).rejects.toThrow(StoreError);
  });
  it('refuses a flipped ciphertext bit and a truncated envelope', async () => {
    const { inner, store } = mk();
    await store.set(conn());
    const sealed = (await inner.get(k)) as StoredConnection;
    const parts = sealed.accessToken.split('.');
    const ct = Buffer.from(parts[3] as string, 'base64url');
    ct[ct.length - 1] = (ct[ct.length - 1] as number) ^ 1;
    await inner.set({ ...sealed, accessToken: [...parts.slice(0, 3), ct.toString('base64url')].join('.') });
    await expect(store.get(k)).rejects.toThrow(StoreError);
    await inner.set({ ...sealed, accessToken: parts.slice(0, 3).join('.') });
    await expect(store.get(k)).rejects.toThrow(StoreError);
  });
  it('key rotation: old records open until the old key goes, reencrypt moves them, then the old key can be removed', async () => {
    const k1 = key32();
    const { inner, w, store } = mk({ k1 }, 'k1');
    await store.set(conn());
    w.addKey('k2', key32());
    w.setActive('k2');
    expect(await store.get(k)).toEqual(conn());
    expect((await inner.get(k))?.accessToken.split('.')[1]).toBe(Buffer.from('k1').toString('base64url'));
    expect(await store.reencrypt(k)).toBe(true);
    expect((await inner.get(k))?.accessToken.split('.')[1]).toBe(Buffer.from('k2').toString('base64url'));
    w.removeKey('k1');
    expect(await store.get(k)).toEqual(conn());
  });
  it('removing a key revokes access to what it sealed', async () => {
    const { w, store } = mk({ k1: key32() }, 'k1');
    await store.set(conn());
    w.addKey('k2', key32());
    w.setActive('k2');
    w.removeKey('k1');
    await expect(store.get(k)).rejects.toThrow(StoreError);
  });
  it('the active key cannot be removed; keys must be 32 bytes; the ring needs the active id', () => {
    const { w } = mk();
    expect(() => w.removeKey('k1')).toThrow('LocalKeyWrapper: cannot remove the active key');
    expect(() => w.addKey('x', new Uint8Array(16))).toThrow('LocalKeyWrapper: keys must be 32 bytes');
    expect(() => w.addKey('', key32())).toThrow('LocalKeyWrapper: key id must not be empty');
    expect(() => new LocalKeyWrapper({ a: key32() }, 'b')).toThrow('LocalKeyWrapper: the active key id is not in the key ring');
  });
  it('the wrapper copies its keys, and destroy() makes everything unreadable', async () => {
    const key = key32();
    const w = new LocalKeyWrapper({ k1: key }, 'k1');
    const store = new EncryptedConnectionStore(new InMemoryConnectionStore(), w);
    key.fill(0);
    await store.set(conn());
    expect(await store.get(k)).toEqual(conn());
    w.destroy();
    await expect(store.get(k)).rejects.toThrow(StoreError);
    await expect(store.set(conn())).rejects.toMatchObject({ message: 'a token could not be encrypted; nothing was stored' });
  });
  it('a failing wrapper stores nothing', async () => {
    const inner = new InMemoryConnectionStore();
    const store = new EncryptedConnectionStore(inner, { wrap: async () => { throw new Error('kms down: arn:aws:secret'); }, unwrap: async () => new Uint8Array() });
    await expect(store.set(conn())).rejects.toMatchObject({ code: 'store_error' });
    expect(await inner.get(k)).toBeUndefined();
  });
  it('reencrypt of a missing record is false', async () => {
    expect(await mk().store.reencrypt(k)).toBe(false);
  });
  it('works behind the vault end to end', async () => {
    const { inner, store } = mk();
    const v = mkVault({ store, now: () => NOW });
    await put(v);
    expect((await v.getConnectionToken(actn(), { provider: 'google' })).accessToken).toBe('AT-secret-1');
    expect(JSON.stringify(await inner.get(k))).not.toContain('AT-secret-1');
  });
});

describe('strict mode', () => {
  const enc = () => new EncryptedConnectionStore(new InMemoryConnectionStore(), new LocalKeyWrapper({ k: key32() }, 'k'));
  const full = () => ({ strict: true, store: enc(), replay: new InMemoryReplayStore(), isRevoked: () => false, audience: 'rs' });
  it('accepts a complete production configuration', () => {
    expect(() => new TokenVault(full())).not.toThrow();
  });
  it.each([
    ['store', { store: new InMemoryConnectionStore() }, 'an encrypting store'],
    ['no store', { store: undefined }, 'an encrypting store'],
    ['replay', { replay: undefined }, 'replay'],
    ['isRevoked', { isRevoked: undefined }, 'isRevoked'],
    ['audience', { audience: undefined }, 'audience'],
    ['null audience', { audience: null }, 'audience'],
  ])('refuses to start without %s', (_n, patch, what) => {
    expect(() => new TokenVault({ ...full(), ...patch } as never)).toThrow(`TokenVault strict mode requires ${what}`);
  });
  it('strict is the default: a vault with no options is refused', () => {
    expect(() => new TokenVault()).toThrow('TokenVault strict mode requires an encrypting store, replay, isRevoked, audience');
    expect(() => new TokenVault({ store: new InMemoryConnectionStore() })).toThrow('TokenVault strict mode requires an encrypting store, replay, isRevoked, audience');
  });
  it('strict: false still needs an explicit store', () => {
    expect(() => new TokenVault({ strict: false })).toThrow('TokenVault requires a store');
  });
  it('lists everything that is missing', () => {
    expect(() => new TokenVault({ strict: true })).toThrow('TokenVault strict mode requires an encrypting store, replay, isRevoked, audience');
  });
  it('a store that merely claims nothing is not accepted', () => {
    expect(() => new TokenVault({ ...full(), store: { get: async () => undefined, set: async () => {}, delete: async () => {} } })).toThrow('an encrypting store');
  });
});

describe('replay and revocation', () => {
  it('a captured action releases a token once, then is refused', async () => {
    const v = mkVault({ now: () => NOW, replay: new InMemoryReplayStore() });
    await put(v);
    const a = actn('nonce-1');
    expect((await v.getConnectionToken(a, { provider: 'google' })).accessToken).toBe('AT-secret-1');
    await expect(v.getConnectionToken(a, { provider: 'google' })).rejects.toMatchObject({
      code: 'not_authorized',
      message: 'replay guard refused the action: nonce already consumed',
    });
  });
  it('a refused request does not burn the action', async () => {
    const replay = new InMemoryReplayStore();
    const v = mkVault({ now: () => NOW, replay });
    await put(v);
    const a = actn('nonce-2');
    await expect(v.getConnectionToken(a, { provider: 'google', scopes: ['write'] })).rejects.toMatchObject({ code: 'scope_exceeded' });
    expect((await v.getConnectionToken(a, { provider: 'google' })).provider).toBe('google');
  });
  it('an action with no nonce is refused when a replay store is set', async () => {
    const v = mkVault({ now: () => NOW, replay: new InMemoryReplayStore() });
    await put(v);
    await expect(v.getConnectionToken(actn(), { provider: 'google' })).rejects.toMatchObject({ code: 'not_authorized' });
  });
  it('a replay store that throws refuses', async () => {
    const v = mkVault({ now: () => NOW, replay: { consumeOnce: async () => { throw new Error('boom'); } } });
    await put(v);
    await expect(v.getConnectionToken(actn('n3'), { provider: 'google' })).rejects.toMatchObject({
      code: 'not_authorized',
      message: 'replay guard refused the action: replay store failed closed: boom',
    });
  });
  it('a revoked chain is refused, with the exact reason', async () => {
    const v = mkVault({ now: () => NOW, isRevoked: () => true });
    await put(v);
    await expect(v.getConnectionToken(actn(), { provider: 'google' })).rejects.toMatchObject({ code: 'not_authorized', message: 'the capability chain is revoked' });
  });
  it('a revocation source that throws or rejects refuses', async () => {
    for (const hook of [() => { throw new Error('x'); }, async () => { throw new Error('x'); }]) {
      const v = mkVault({ now: () => NOW, isRevoked: hook });
      await put(v);
      await expect(v.getConnectionToken(actn(), { provider: 'google' })).rejects.toMatchObject({ message: 'revocation source unavailable' });
    }
  });
  it('a revocation source that returns anything but false refuses', async () => {
    const v = mkVault({ now: () => NOW, isRevoked: () => undefined as never });
    await put(v);
    await expect(v.getConnectionToken(actn(), { provider: 'google' })).rejects.toBeInstanceOf(NotAuthorizedError);
  });
  it('a clean chain passes the revocation hook, which is handed the action', async () => {
    const seen: PCActn[] = [];
    const v = mkVault({ now: () => NOW, isRevoked: (p) => { seen.push(p); return false; } });
    await put(v);
    const a = actn();
    await v.getConnectionToken(a, { provider: 'google' });
    expect(seen).toEqual([a]);
  });
});

describe('input and clock validation', () => {
  it('putConnection rejects a non-finite expiresAt (it would never look stale)', async () => {
    const v = mkVault({ now: () => NOW });
    await expect(put(v, { expiresAt: Number.NaN })).rejects.toThrow('putConnection: expiresAt must be a finite number');
    await expect(put(v, { expiresAt: '9' })).rejects.toThrow('putConnection: expiresAt must be a finite number');
  });
  it.each([
    ['accessToken', { accessToken: '' }],
    ['agentId', { agentId: '' }],
    ['provider', { provider: '' }],
    ['principal', { authority: { principal: '' } }],
  ])('putConnection rejects an empty %s', async (name, patch) => {
    await expect(put(mkVault(), patch)).rejects.toThrow(`putConnection: ${name} must be a non-empty string`);
  });
  it('putConnection rejects an empty refresh token and non-string scopes', async () => {
    await expect(put(mkVault(), { refreshToken: '' })).rejects.toThrow('putConnection: refreshToken must be a non-empty string when given');
    await expect(put(mkVault(), { scopes: [1] })).rejects.toThrow('putConnection: scopes must be a list of strings');
  });
  it('a NaN expiry already in the store is treated as stale, not fresh', async () => {
    const store = new InMemoryConnectionStore();
    const v = mkVault({ store, now: () => NOW });
    await put(v);
    const c = (await store.get({ agentId, provider: 'google', connectionId: 'default' })) as StoredConnection;
    await store.set({ ...c, expiresAt: Number.NaN, refreshToken: undefined as never });
    delete (c as { refreshToken?: string }).refreshToken;
    const s2 = (await store.get({ agentId, provider: 'google', connectionId: 'default' })) as StoredConnection;
    delete (s2 as { refreshToken?: string }).refreshToken;
    await store.set(s2);
    await expect(v.getConnectionToken(actn(), { provider: 'google' })).rejects.toMatchObject({ code: 'expired_no_refresh' });
  });
  it('a NaN clock never releases a token as fresh', async () => {
    const v = mkVault({ now: () => Number.NaN });
    await put(v, { refreshToken: undefined });
    await expect(v.getConnectionToken(actn(), { provider: 'google' })).rejects.toBeDefined();
  });
});

describe('store failures', () => {
  const failing = (over: Partial<ConnectionStore>): ConnectionStore => ({
    get: async () => undefined,
    set: async () => {},
    delete: async () => {},
    ...over,
  });
  it('a store that throws surfaces a typed error with none of its text', async () => {
    const boom = async () => { throw new Error('postgres://user:pw@db/vault'); };
    for (const over of [{ get: boom }, { set: boom }]) {
      const v = mkVault({ store: failing(over), now: () => NOW });
      const act = over.get ? v.getConnectionToken(actn(), { provider: 'google' }) : put(v);
      const err = await act.catch((e) => e);
      expect(err).toBeInstanceOf(StoreError);
      expect(err.code).toBe('store_error');
      expect(err.message).toBe('the connection store failed');
    }
    await expect(mkVault({ store: failing({ delete: async () => { throw new Error('pw'); } }) }).deleteConnection('a', 'b')).rejects.toBeInstanceOf(StoreError);
  });
});

describe('refresh', () => {
  const stale = async (fetch: VaultFetch, extra: Record<string, unknown> = {}) => {
    const v = mkVault({ now: () => NOW, fetch, providers: { google: { tokenEndpoint: 'https://idp/token', clientId: 'cid', clientSecret: 'CS-secret' } }, ...extra });
    await put(v, { expiresAt: NOW - 1 });
    return v;
  };
  it('single-flights concurrent refreshes so a rotating refresh token is spent once', async () => {
    let calls = 0;
    const fetch: VaultFetch = async () => {
      calls++;
      await new Promise((r) => setTimeout(r, 5));
      return res(true, 200, { access_token: 'AT-2', expires_in: 3600, refresh_token: 'RT-2' });
    };
    const v = await stale(fetch);
    const out = await Promise.all([1, 2, 3].map(() => v.getConnectionToken(actn(), { provider: 'google' })));
    expect(calls).toBe(1);
    expect(out.map((o) => [o.accessToken, o.refreshed])).toEqual([['AT-2', true], ['AT-2', true], ['AT-2', true]]);
  });
  it('a failed refresh does not stay cached: the next call tries again', async () => {
    let calls = 0;
    const fetch: VaultFetch = async () => (++calls === 1 ? res(false, 500, {}, 'oops') : res(true, 200, { access_token: 'AT-2', expires_in: 60 }));
    const v = await stale(fetch);
    await expect(v.getConnectionToken(actn(), { provider: 'google' })).rejects.toBeInstanceOf(RefreshFailedError);
    expect((await v.getConnectionToken(actn(), { provider: 'google' })).accessToken).toBe('AT-2');
  });
  const leak = ['RT-secret-1', 'AT-secret-1', 'CS-secret'];
  const msgOf = async (fetch: VaultFetch) => {
    const v = await stale(fetch);
    return (await v.getConnectionToken(actn(), { provider: 'google' }).catch((e) => e)) as Error;
  };
  it('an error body that echoes the refresh token, client secret or access token is redacted', async () => {
    const e = await msgOf(async () => res(false, 400, {}, '{"error":"invalid_grant","echo":"refresh_token=RT-secret-1&client_secret=CS-secret AT-secret-1"}'));
    expect(e.message).toBe(`refresh for 'google' failed: token endpoint 400: {"error":"invalid_grant","echo":"refresh_token=[redacted]&client_secret=[redacted] [redacted]"}`);
    for (const s of leak) expect(e.message).not.toContain(s);
  });
  it('a transport error that quotes the request is redacted', async () => {
    const e = await msgOf(async () => { throw new Error('ECONNRESET sending refresh_token=RT-secret-1'); });
    expect(e.message).toBe("refresh for 'google' failed: transport error: ECONNRESET sending refresh_token=[redacted]");
  });
  it('a JSON parse error does not quote the body', async () => {
    const e = await msgOf(async () => ({ ok: true, status: 200, text: async () => '', json: async () => JSON.parse('{"access_token":"AT-new-secret" oops') }));
    expect(e.message).toBe("refresh for 'google' failed: unparseable JSON body");
  });
  it('an unreadable error body still fails closed', async () => {
    const e = await msgOf(async () => ({ ok: false, status: 502, json: async () => ({}), text: async () => { throw new Error('x'); } }));
    expect(e.message).toBe("refresh for 'google' failed: token endpoint 502: <unreadable body>");
  });
  it.each([
    ['array body', []],
    ['empty access_token', { access_token: '' }],
    ['numeric access_token', { access_token: 7 }],
    ['null body', null],
  ])('a token response with %s is refused', async (_n, body) => {
    const e = await msgOf(async () => res(true, 200, body));
    expect(e).toBeInstanceOf(RefreshFailedError);
  });
  it('a missing provider config or transport is refused', async () => {
    const v = mkVault({ now: () => NOW });
    await put(v, { expiresAt: NOW - 1 });
    await expect(v.getConnectionToken(actn(), { provider: 'google' })).rejects.toMatchObject({ message: "refresh for 'google' failed: no provider token-endpoint config" });
    const v2 = mkVault({ now: () => NOW, providers: { google: { tokenEndpoint: 'x', clientId: 'c' } } });
    await put(v2, { expiresAt: NOW - 1 });
    await expect(v2.getConnectionToken(actn(), { provider: 'google' })).rejects.toMatchObject({ message: "refresh for 'google' failed: no fetch transport configured" });
  });
  it('the refreshed token is persisted and the old refresh token kept when none is issued', async () => {
    const store = new InMemoryConnectionStore();
    const v = await stale(async () => res(true, 200, { access_token: 'AT-2', expires_in: 100 }), { store });
    await put(v, { expiresAt: NOW - 1 });
    await v.getConnectionToken(actn(), { provider: 'google' });
    const c = await store.get({ agentId, provider: 'google', connectionId: 'default' });
    expect([c?.accessToken, c?.refreshToken, c?.expiresAt]).toEqual(['AT-2', 'RT-secret-1', NOW + 100_000]);
  });
});
