import {
  type CapabilityChain,
  type PCActn,
  type PlanNode,
  InMemoryReplayStore,
  buildPCActn,
  encodeKey,
  generateKeyPair,
  mintRoot,
  paramsDigest,
  verifyPCActnCore,
} from '@atlasauth/pca';
import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  EncryptedConnectionStore,
  LocalKeyWrapper,
  NotAuthorizedError,
  ProxyFailedError,
  ScopeExceededError,
  TokenVault,
  httpExtractor,
  oauthScopeCaveat,
  outboundRequestDigest,
  type ProxyFetch,
  type ProxyRequest,
  type ProxyResponse,
  type ReleaseReceipt,
  type TokenVaultOptions,
  type VaultAction,
  type VaultFetch,
} from './index';
import { InMemoryConnectionStore } from './testing';

const NOW = 1_800_000_000_000;

type Failure = Error & { code?: string };
const err = async (p: Promise<unknown>): Promise<Failure | undefined> => {
  try {
    await p;
    return undefined;
  } catch (e) {
    return e as Failure;
  }
};
const failure = async (p: Promise<unknown>): Promise<string> => {
  const e = await err(p);
  return e === undefined ? 'no error' : `${e.code ?? e.name}: ${e.message}`;
};

const mkVault = (o: TokenVaultOptions = {}) =>
  new TokenVault({ strict: false, insecureSkipPlanRootCheck: true, insecureBearerRelease: true, store: new InMemoryConnectionStore(), now: () => NOW, ...o });

function world(o: { grant?: string[] | null; provider?: string } = {}) {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const principal = encodeKey(P.publicKey);
  const agentId = encodeKey(A.publicKey);
  const grant = mintRoot({
    principalSecret: P.secretKey,
    principalPublic: principal,
    holder: agentId,
    caveats: o.grant === null ? [] : [oauthScopeCaveat(o.provider ?? 'bank', o.grant ?? ['transfers:write'])],
  });
  let counter = 0;
  const actn = (a: { verb?: string; resource?: string; params?: Record<string, unknown>; now?: number } = {}): PCActn => {
    const node: PlanNode = {
      id: 'n',
      verb: a.verb ?? 'use_connection',
      resource: a.resource ?? 'oauth:bank',
      ...(a.params ? { params_digest: paramsDigest(a.params), reversibility_class: 'irreversible' as const } : {}),
    };
    return buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n', ...(a.params ? { params: a.params } : {}), counter: ++counter, signerSecret: A.secretKey, aud: 'rs', now: a.now ?? NOW });
  };
  return { P, A, principal, agentId, grant, actn };
}
type World = ReturnType<typeof world>;

const put = (v: TokenVault, w: World, over: Partial<Parameters<TokenVault['putConnection']>[0]> = {}) =>
  v.putConnection({ agentId: w.agentId, provider: 'bank', accessToken: 'AT', expiresAt: NOW + 3_600_000, scopes: ['transfers:write'], authority: { principal: w.principal }, ...over });

describe('construction', () => {
  it('strict mode refuses an empty audience', () => {
    const store = new EncryptedConnectionStore(new InMemoryConnectionStore(), new LocalKeyWrapper({ k: new Uint8Array(randomBytes(32)) }, 'k'));
    const base = { store, replay: new InMemoryReplayStore(), isRevoked: () => false };
    expect(() => new TokenVault({ ...base, audience: '' })).toThrow('TokenVault strict mode requires audience');
    expect(() => new TokenVault({ ...base, audience: 'rs' })).not.toThrow();
  });

  it('uses the real clock when none is injected', async () => {
    const w = world();
    const v = new TokenVault({ strict: false, insecureSkipPlanRootCheck: true, insecureBearerRelease: true, store: new InMemoryConnectionStore() });
    const before = Date.now();
    const stored = await put(v, w, { expiresAt: Date.now() + 3_600_000 });
    expect(stored.createdAt).toBeGreaterThanOrEqual(before);
    expect(stored.createdAt).toBeLessThanOrEqual(Date.now());
    const t = await v.getConnectionToken(w.actn({ now: Date.now() }), { provider: 'bank' });
    expect(t.refreshed).toBe(false);
    expect(t.accessToken).toBe('AT');
  });

  it('refuses every release unless a plan root is authorized or the check is explicitly skipped', async () => {
    const w = world();
    const a = w.actn();
    const strictish = mkVault({ insecureSkipPlanRootCheck: false });
    await put(strictish, w);
    const e = await err(strictish.getConnectionToken(a, { provider: 'bank' }));
    expect(e).toBeInstanceOf(NotAuthorizedError);
    const direct = await verifyPCActnCore(a, { grant: w.grant, grantFromArtifact: true, audience: null, nowEpoch: NOW });
    expect(direct.allow).toBe(false);
    expect(direct.reason).toBeTypeOf('string');
    expect(direct.reason).not.toBe('rejected');
    expect(e?.message).toBe(`PCActn verification failed: ${direct.reason}`);
  });

  it('forwards the authorized plan roots to the verifier', async () => {
    const w = world();
    const a = w.actn();
    const ok = mkVault({ insecureSkipPlanRootCheck: false, authorizedPlanRoots: [a.plan.root] });
    await put(ok, w);
    expect((await ok.getConnectionToken(a, { provider: 'bank' })).accessToken).toBe('AT');
    const other = mkVault({ insecureSkipPlanRootCheck: false, authorizedPlanRoots: ['someone-elses-root'] });
    await put(other, w);
    expect(await err(other.getConnectionToken(a, { provider: 'bank' }))).toBeInstanceOf(NotAuthorizedError);
  });
});

describe('putConnection validation and shape', () => {
  it('names the offending field', async () => {
    const w = world();
    const v = mkVault();
    expect(await failure(put(v, w, { accessToken: 5 as unknown as string }))).toBe('TypeError: putConnection: accessToken must be a non-empty string');
    expect(await failure(put(v, w, { accessToken: '' }))).toBe('TypeError: putConnection: accessToken must be a non-empty string');
    expect(await failure(put(v, w, { authority: {} as never }))).toBe('TypeError: putConnection: principal must be a non-empty string');
    expect(await failure(put(v, w, { refreshToken: 5 as unknown as string }))).toBe('TypeError: putConnection: refreshToken must be a non-empty string when given');
    expect(await failure(put(v, w, { refreshToken: '' }))).toBe('TypeError: putConnection: refreshToken must be a non-empty string when given');
    expect(await failure(put(v, w, { scopes: ['a', 5 as unknown as string] }))).toBe('TypeError: putConnection: scopes must be a list of strings');
    expect(await failure(put(v, w, { expiresAt: '5' as unknown as number }))).toBe('TypeError: putConnection: expiresAt must be a finite number');
  });

  it('authority scopes default to the connection scopes, and an explicit list wins', async () => {
    const w = world();
    const v = mkVault();
    expect((await put(v, w, { scopes: ['a', 'b'] })).authority.scopes).toEqual(['a', 'b']);
    expect((await put(v, w, { scopes: ['a', 'b'], authority: { principal: w.principal, scopes: ['b'] } })).authority.scopes).toEqual(['b']);
  });

  it('records the audience and refresh token only when given', async () => {
    const w = world();
    const v = mkVault();
    const bare = await put(v, w);
    expect(Object.keys(bare.authority).sort()).toEqual(['principal', 'provider', 'scopes']);
    expect(Object.keys(bare)).not.toContain('refreshToken');
    const full = await put(v, w, { refreshToken: 'RT', authority: { principal: w.principal, audience: 'rs-1' } });
    expect(full.authority.audience).toBe('rs-1');
    expect(full.refreshToken).toBe('RT');
  });
});

describe('capability chain and binding (bearer path)', () => {
  it('refuses a missing, empty or malformed capability chain', async () => {
    const w = world();
    const v = mkVault();
    const a = w.actn();
    const withChain = (c: unknown): PCActn => ({ ...a, cap_chain: c as CapabilityChain });
    const none = 'not_authorized: PCActn has no capability chain';
    expect(await failure(v.getConnectionToken(withChain([]), { provider: 'bank' }))).toBe(none);
    expect(await failure(v.getConnectionToken(withChain(undefined), { provider: 'bank' }))).toBe(none);
    const malformed = 'not_authorized: PCActn capability chain is malformed';
    expect(await failure(v.getConnectionToken(withChain([undefined]), { provider: 'bank' }))).toBe(malformed);
    expect(await failure(v.getConnectionToken(withChain([w.grant, undefined]), { provider: 'bank' }))).toBe(malformed);
    expect(await failure(v.getConnectionToken(withChain([undefined, w.grant]), { provider: 'bank' }))).toBe(malformed);
  });

  it('refuses a chain rooted at another principal, with the exact reason', async () => {
    const w = world();
    const v = mkVault();
    await put(v, w, { authority: { principal: encodeKey(generateKeyPair().publicKey) } });
    expect(await failure(v.getConnectionToken(w.actn(), { provider: 'bank' }))).toBe("not_authorized: capability chain is not rooted at the connection's bound principal");
  });

  it('binds the action to the connection resource and the use verb, with exact reasons', async () => {
    const w = world();
    const v = mkVault();
    await put(v, w);
    expect(await failure(v.getConnectionToken(w.actn({ resource: 'oauth:other' }), { provider: 'bank' }))).toBe("not_authorized: PCActn action resource 'oauth:other' is not for this connection (expected 'oauth:bank')");
    expect(await failure(v.getConnectionToken(w.actn({ verb: 'weird' }), { provider: 'bank' }))).toBe("not_authorized: PCActn action verb 'weird' is not a connection-use verb (expected 'use_connection')");
  });

  it('skips the binding only when requireActionBinding is false', async () => {
    const w = world();
    const v = mkVault({ requireActionBinding: false });
    await put(v, w);
    expect((await v.getConnectionToken(w.actn({ resource: 'oauth:other', verb: 'weird' }), { provider: 'bank' })).accessToken).toBe('AT');
  });

  it('honours a custom use verb, and null disables the verb check', async () => {
    const w = world();
    const custom = mkVault({ useVerb: 'custom.use' });
    await put(custom, w);
    expect((await custom.getConnectionToken(w.actn({ verb: 'custom.use' }), { provider: 'bank' })).accessToken).toBe('AT');
    expect(await failure(custom.getConnectionToken(w.actn({ verb: 'use_connection' }), { provider: 'bank' }))).toBe("not_authorized: PCActn action verb 'use_connection' is not a connection-use verb (expected 'custom.use')");
    const any = mkVault({ useVerb: null });
    await put(any, w);
    expect((await any.getConnectionToken(w.actn({ verb: 'whatever' }), { provider: 'bank' })).accessToken).toBe('AT');
  });

  it('says which provider the capability does not cover', async () => {
    const w = world({ grant: ['x'], provider: 'other' });
    const v = mkVault();
    await put(v, w);
    expect(await failure(v.getConnectionToken(w.actn(), { provider: 'bank' }))).toBe("not_authorized: capability grants no authority for provider 'bank'");
  });

  it('reports the granted scopes when the connection scopes exceed the grant', async () => {
    const w = world({ grant: ['a'] });
    const v = mkVault();
    await put(v, w, { scopes: ['a', 'b'] });
    const e = await err(v.getConnectionToken(w.actn(), { provider: 'bank' }));
    expect(e).toBeInstanceOf(ScopeExceededError);
    const s = e as ScopeExceededError;
    expect(s.requested).toEqual(['a', 'b']);
    expect(s.granted).toEqual(['a']);
    expect(s.missing).toEqual(['b']);
  });
});

describe('refresh timing', () => {
  const fresh = (token: string): VaultFetch => async () => ({ ok: true, status: 200, json: async () => ({ access_token: token }), text: async () => '' });
  const providers = { bank: { tokenEndpoint: 'https://idp.example/token', clientId: 'c' } };

  it('refreshes at exactly the leeway and not a millisecond before', async () => {
    const w = world();
    const v = mkVault({ providers, fetch: fresh('NEW'), expiryLeewayMs: 30_000 });
    await put(v, w, { refreshToken: 'RT', expiresAt: NOW + 30_000 });
    const at = await v.getConnectionToken(w.actn(), { provider: 'bank' });
    expect(at.refreshed).toBe(true);
    expect(at.accessToken).toBe('NEW');
    await put(v, w, { refreshToken: 'RT', expiresAt: NOW + 30_001 });
    const after = await v.getConnectionToken(w.actn(), { provider: 'bank' });
    expect(after.refreshed).toBe(false);
    expect(after.accessToken).toBe('AT');
  });

  it('applies the configured default lifetime to a token that states none', async () => {
    const w = world();
    const custom = mkVault({ providers, fetch: fresh('opaque'), defaultTokenLifetimeMs: 1_000 });
    await put(custom, w, { refreshToken: 'RT', expiresAt: NOW - 1 });
    expect((await custom.getConnectionToken(w.actn(), { provider: 'bank' })).expiresAt).toBe(NOW + 1_000);
    const dflt = mkVault({ providers, fetch: fresh('opaque') });
    await put(dflt, w, { refreshToken: 'RT', expiresAt: NOW - 1 });
    expect((await dflt.getConnectionToken(w.actn(), { provider: 'bank' })).expiresAt).toBe(NOW + 300_000);
  });

  it('single-flights per connection, never across connections', async () => {
    const w = world();
    const fetch: VaultFetch = async (_u, init) => {
      const rt = new URLSearchParams(init.body).get('refresh_token') ?? '';
      await new Promise((r) => setTimeout(r, 10));
      return { ok: true, status: 200, json: async () => ({ access_token: `AT-for-${rt}` }), text: async () => '' };
    };
    const v = mkVault({ providers, fetch });
    await put(v, w, { connectionId: 'c1', refreshToken: 'RT1', expiresAt: NOW - 1 });
    await put(v, w, { connectionId: 'c2', refreshToken: 'RT2', expiresAt: NOW - 1 });
    const [a, b] = await Promise.all([
      v.getConnectionToken(w.actn(), { provider: 'bank', connectionId: 'c1' }),
      v.getConnectionToken(w.actn(), { provider: 'bank', connectionId: 'c2' }),
    ]);
    expect(a.accessToken).toBe('AT-for-RT1');
    expect(b.accessToken).toBe('AT-for-RT2');
  });
});

describe('deleteConnection', () => {
  it('removes the named connection, defaulting to the default id', async () => {
    const w = world();
    const v = mkVault();
    await put(v, w, { connectionId: 'c1' });
    await put(v, w);
    await v.deleteConnection(w.agentId, 'bank', 'c1');
    expect(await failure(v.getConnectionToken(w.actn(), { provider: 'bank', connectionId: 'c1' }))).toMatch(/^unknown_connection:/);
    expect((await v.getConnectionToken(w.actn(), { provider: 'bank' })).accessToken).toBe('AT');
    await v.deleteConnection(w.agentId, 'bank');
    expect(await failure(v.getConnectionToken(w.actn(), { provider: 'bank' }))).toMatch(/^unknown_connection:/);
  });
});

// ---- derived (pinned action) mode and proxy mode ----------------------------------------------------------------------------

const BANK_URL = 'https://api.bank.example/v1/accounts/{account}/transfers';
const postExtract = httpExtractor({ method: 'POST', url: BANK_URL, body: 'json', fixed: { source: 'vault' } });
const getExtract = httpExtractor({ method: 'GET', url: 'https://api.bank.example/v1/accounts/{account}' });
const PARAMS = { account: 'acct_1', amount: 1 };
const POST: ProxyRequest = {
  method: 'POST',
  url: 'https://api.bank.example/v1/accounts/acct_1/transfers',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ source: 'vault', amount: 1 }),
};
const GET: ProxyRequest = { method: 'GET', url: 'https://api.bank.example/v1/accounts/acct_1' };
const VERB = 'bank.send';
const action = (over: Partial<VaultAction> = {}): VaultAction => ({ verb: VERB, def_digest: 'A'.repeat(43), confirmed: true, upstream: { provider: 'bank', scopes_min: ['transfers:write'] }, extract: postExtract, ...over });

function dw(o: { grant?: string[]; stored?: string[]; authority?: string[]; action?: VaultAction | undefined; fetch?: ProxyFetch; vault?: TokenVaultOptions; params?: Record<string, unknown> } = {}) {
  const w = world(o.grant ? { grant: o.grant } : {});
  const act = 'action' in o ? o.action : action();
  const sent: Parameters<ProxyFetch>[0][] = [];
  const receipts: ReleaseReceipt[] = [];
  const proxyFetch: ProxyFetch = async (r) => {
    sent.push(r);
    return o.fetch ? o.fetch(r) : { status: 201, headers: {}, body: '{"id":1}' };
  };
  const vault = mkVault({
    actions: (v) => (act !== undefined && v === act.verb ? act : undefined),
    proxyFetch,
    receipts: { secretKey: generateKeyPair().secretKey, sink: (r) => { receipts.push(r); } },
    ...o.vault,
  });
  const stored = o.stored ?? ['transfers:write'];
  const putIt = () => put(vault, w, { scopes: stored, authority: { principal: w.principal, scopes: o.authority ?? stored } });
  const actn = () => w.actn({ verb: VERB, resource: 'bank:acct_1', params: o.params ?? PARAMS });
  return { w, vault, putIt, actn, sent, receipts };
}

describe('proxyCall prerequisites', () => {
  it('needs actions and a transport, each with its own message', async () => {
    const w = world();
    const a = w.actn();
    expect(await failure(mkVault({ proxyFetch: async () => ({ status: 200, headers: {}, body: '' }) }).proxyCall(a, GET, { provider: 'bank' }))).toBe('TypeError: proxyCall requires the vault to be constructed with `actions`');
    expect(await failure(mkVault({ actions: () => action() }).proxyCall(a, GET, { provider: 'bank' }))).toBe('TypeError: proxyCall requires the vault to be constructed with `proxyFetch`');
  });
});

describe('proxyCall transport', () => {
  it('sends a body only when the request has one', async () => {
    const withBody = dw();
    await withBody.putIt();
    await withBody.vault.proxyCall(withBody.actn(), POST, { provider: 'bank' });
    expect(withBody.sent[0]).toEqual({ method: 'POST', url: POST.url, headers: { 'content-type': 'application/json', authorization: 'Bearer AT' }, body: POST.body, redirect: 'manual' });

    const noBody = dw({ action: action({ extract: getExtract }), params: { account: 'acct_1' } });
    await noBody.putIt();
    await noBody.vault.proxyCall(noBody.actn(), GET, { provider: 'bank' });
    expect(noBody.sent[0]).toEqual({ method: 'GET', url: GET.url, headers: { authorization: 'Bearer AT' }, redirect: 'manual' });
    expect(Object.keys(noBody.sent[0]!)).not.toContain('body');
  });

  it('a transport failure is a typed refusal with a failed receipt that commits to the request', async () => {
    const d = dw({ fetch: async () => { throw new Error('net'); } });
    await d.putIt();
    const e = await err(d.vault.proxyCall(d.actn(), POST, { provider: 'bank' }));
    expect(e).toBeInstanceOf(ProxyFailedError);
    expect(e?.code).toBe('proxy_failed');
    expect(e?.message).toBe('the outbound call failed before a response');
    expect(d.receipts).toHaveLength(1);
    expect(d.receipts[0]).toMatchObject({
      kind: 'pca-release-receipt',
      mode: 'proxy',
      outcome: 'failed',
      http_status: null,
      provider: 'bank',
      connection_id: 'default',
      scopes_released: ['transfers:write'],
      request_digest: outboundRequestDigest('POST', POST.url, { 'content-type': 'application/json' }, POST.body),
    });
  });

  it('no response at all, or a response without a text body, is refused as oversize and still receipted as executed', async () => {
    const msg = 'the response is larger than maxProxyResponseBytes (the call was made and the action is spent)';
    const none = dw({ fetch: async () => undefined as unknown as ProxyResponse });
    await none.putIt();
    expect(await failure(none.vault.proxyCall(none.actn(), POST, { provider: 'bank' }))).toBe(`proxy_failed: ${msg}`);
    expect(none.receipts[0]).toMatchObject({ mode: 'proxy', outcome: 'executed', http_status: null });

    const noBody = dw({ fetch: async () => ({ status: 200, headers: {}, body: undefined as unknown as string }) });
    await noBody.putIt();
    expect(await failure(noBody.vault.proxyCall(noBody.actn(), POST, { provider: 'bank' }))).toBe(`proxy_failed: ${msg}`);
    expect(noBody.receipts[0]).toMatchObject({ outcome: 'executed', http_status: 200 });
  });

  it('enforces maxProxyResponseBytes in bytes, inclusive of the limit', async () => {
    let body = '0123456789';
    const d = dw({ vault: { maxProxyResponseBytes: 10 }, fetch: async () => ({ status: 200, headers: {}, body }) });
    await d.putIt();
    expect((await d.vault.proxyCall(d.actn(), POST, { provider: 'bank' })).response.body).toBe('0123456789');
    body = '01234567890';
    expect(await failure(d.vault.proxyCall(d.actn(), POST, { provider: 'bank' }))).toBe('proxy_failed: the response is larger than maxProxyResponseBytes (the call was made and the action is spent)');
    body = '€€€€';
    expect((await err(d.vault.proxyCall(d.actn(), POST, { provider: 'bank' })))?.code).toBe('proxy_failed');
  });

  it('defaults the response limit to 4 MiB', async () => {
    let size = 4 * 1024 * 1024;
    const d = dw({ fetch: async () => ({ status: 200, headers: {}, body: 'a'.repeat(size) }) });
    await d.putIt();
    expect((await d.vault.proxyCall(d.actn(), POST, { provider: 'bank' })).response.body.length).toBe(4 * 1024 * 1024);
    size += 1;
    expect((await err(d.vault.proxyCall(d.actn(), POST, { provider: 'bank' })))?.code).toBe('proxy_failed');
  });
});

describe('pinned action resolution', () => {
  it('refuses an action whose verb is not the one asked for', async () => {
    const w = world();
    const v = mkVault({ actions: () => action({ verb: 'other.verb' }), proxyFetch: async () => ({ status: 200, headers: {}, body: '' }) });
    await put(v, w);
    expect(await failure(v.getConnectionToken(w.actn({ verb: VERB, resource: 'x' }), { provider: 'bank' }))).toBe(`unknown_action: no pinned action definition for verb '${VERB}': refusing to release a credential`);
  });

  it('says why an action for another provider or without scopes releases nothing', async () => {
    const other = dw({ action: action({ upstream: { provider: 'other', scopes_min: ['transfers:write'] } }) });
    await other.putIt();
    expect(await failure(other.vault.proxyCall(other.actn(), POST, { provider: 'bank' }))).toBe(`not_authorized: the action '${VERB}' is not for provider 'bank'`);
    const none = dw({ action: action({ upstream: { provider: 'bank', scopes_min: [] } }) });
    await none.putIt();
    expect(await failure(none.vault.proxyCall(none.actn(), POST, { provider: 'bank' }))).toBe(`not_authorized: the action '${VERB}' declares no upstream scopes (nothing to release)`);
  });
});

describe('derived scopes', () => {
  it('refuses a request beyond the action scopes', async () => {
    const d = dw({ grant: ['transfers:write', 'accounts:read'], stored: ['transfers:write', 'accounts:read'] });
    await d.putIt();
    const e = await err(d.vault.getConnectionToken(d.actn(), { provider: 'bank', scopes: ['transfers:write', 'accounts:read'] }));
    expect(e).toBeInstanceOf(ScopeExceededError);
    const s = e as ScopeExceededError;
    expect(s.requested).toEqual(['transfers:write', 'accounts:read']);
    expect(s.granted).toEqual(['transfers:write']);
    expect(s.missing).toEqual(['accounts:read']);
  });

  it('needs the action scopes in the stored connection AND in its bound authority', async () => {
    const notHeld = dw({ stored: [], authority: ['transfers:write'] });
    await notHeld.putIt();
    expect(await failure(notHeld.vault.proxyCall(notHeld.actn(), POST, { provider: 'bank' }))).toMatch(/^scope_exceeded:/);
    const notBound = dw({ stored: ['transfers:write'], authority: [] });
    await notBound.putIt();
    expect(await failure(notBound.vault.proxyCall(notBound.actn(), POST, { provider: 'bank' }))).toMatch(/^scope_exceeded:/);
  });

  it('needs every action scope in the grant even when the caller asks for fewer', async () => {
    const action2 = action({ upstream: { provider: 'bank', scopes_min: ['a', 'b'] } });
    const d = dw({ grant: ['a'], stored: ['a', 'b'], action: action2 });
    await d.putIt();
    const e = await err(d.vault.getConnectionToken(d.actn(), { provider: 'bank', scopes: ['a'] }));
    expect(e).toBeInstanceOf(ScopeExceededError);
    const s = e as ScopeExceededError;
    expect(s.requested).toEqual(['a', 'b']);
    expect(s.granted).toEqual(['a']);
    expect(s.missing).toEqual(['b']);
  });

  it('a bearer release refuses a connection that holds more than the action needs', async () => {
    const d = dw({ grant: ['transfers:write', 'accounts:read'], stored: ['transfers:write', 'accounts:read'] });
    await d.putIt();
    const e = await err(d.vault.getConnectionToken(d.actn(), { provider: 'bank' }));
    expect(e).toBeInstanceOf(ScopeExceededError);
    expect((e as ScopeExceededError).missing).toEqual(['accounts:read']);
  });
});

describe('proxy request binding', () => {
  const run = async (over: Partial<VaultAction>, req: ProxyRequest = POST) => {
    const d = dw({ action: action(over) });
    await d.putIt();
    return failure(d.vault.proxyCall(d.actn(), req, { provider: 'bank' }));
  };

  it('needs an extractor on the action', async () => {
    expect(await run({ extract: undefined })).toBe('request_mismatch: the action has no request extractor: proxy mode cannot bind the outbound request');
  });

  it('an extractor that fails for any other reason is a mismatch without its text', async () => {
    expect(await run({ extract: () => { throw new Error('secret internal detail'); } })).toBe('request_mismatch: the outbound request could not be mapped to the action parameters');
  });

  it('parameters with no canonical form are refused', async () => {
    expect(await run({ extract: () => ({ a: 10n }) })).toBe('request_mismatch: the outbound request parameters are not canonical');
  });

  it('parameters that hash differently are refused', async () => {
    expect(await run({ extract: () => ({ account: 'acct_1', amount: 2 }) })).toBe('request_mismatch: the outbound request does not carry the parameters the PCActn signed');
  });
});
