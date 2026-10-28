import { type KeyPair, type PCActn, type PlanNode, buildPCActn, encodeKey, generateKeyPair, mintRoot, paramsDigest, publicKeyOf, b64u } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import {
  BearerReleaseDisabledError, RequestMismatchError, ScopeExceededError, TokenVault, UnconfirmedActionError, UnknownActionError, httpExtractor, oauthScopeCaveat, verifyReleaseReceipt,
  type ProxyFetch, type ProxyRequest, type VaultAction,
} from './index';
import { InMemoryConnectionStore } from './testing';

const NOW = 1_800_000_000_000;
const VERB = 'bank.transfer.send';
const URL_ = 'https://api.bank.example/v1/accounts/{account}/transfers';
const extract = httpExtractor({ method: 'POST', url: URL_, body: 'json', query: ['dry_run'], fixed: { source: 'vault' } });
const PARAMS = { account: 'acct_1', amount: 12_500, currency: 'EUR', payee: 'Acme GmbH' };
const REQ: ProxyRequest = {
  method: 'POST', url: 'https://api.bank.example/v1/accounts/acct_1/transfers', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ source: 'vault', amount: 12_500, currency: 'EUR', payee: 'Acme GmbH' }),
};
const action = (over: Partial<VaultAction> = {}): VaultAction => ({ verb: VERB, def_digest: 'A'.repeat(43), confirmed: true, upstream: { provider: 'bank', scopes_min: ['transfers:write'] }, extract, ...over });

function setup(opts: { grantScopes?: string[]; stored?: string[]; action?: VaultAction | undefined; insecure?: boolean } = {}) {
  const P: KeyPair = generateKeyPair();
  const A: KeyPair = generateKeyPair();
  const principal = encodeKey(P.publicKey);
  const agentId = encodeKey(A.publicKey);
  const vk = generateKeyPair();
  const sent: Parameters<ProxyFetch>[0][] = [];
  const respond: { value: Awaited<ReturnType<ProxyFetch>> } = { value: { status: 201, headers: { 'content-type': 'application/json' }, body: '{"id":"tr_1"}' } };
  const proxyFetch: ProxyFetch = async (r) => { sent.push(r); return respond.value; };
  const receipts: unknown[] = [];
  const act = 'action' in opts ? opts.action : action();
  const vault = new TokenVault({
    strict: false, store: new InMemoryConnectionStore(), now: () => NOW, actions: (v) => (act !== undefined && v === act.verb ? act : undefined), proxyFetch,
    receipts: { secretKey: vk.secretKey, sink: (r) => { receipts.push(r); } }, ...(opts.insecure ? { insecureBearerRelease: true } : {}),
  });
  const grant = mintRoot({ principalSecret: P.secretKey, principalPublic: principal, holder: agentId, caveats: [oauthScopeCaveat('bank', opts.grantScopes ?? ['transfers:write'])] });
  const put = () => vault.putConnection({ agentId, provider: 'bank', accessToken: 'AT-SECRET', expiresAt: NOW + 3_600_000, scopes: opts.stored ?? ['transfers:write', 'accounts:read'], authority: { principal, scopes: opts.stored ?? ['transfers:write', 'accounts:read'] } });
  let counter = 0;
  const actn = (params: Record<string, unknown> = PARAMS, verb = VERB): PCActn => {
    const node: PlanNode = { id: 'n', verb, resource: 'bank:acct_1', params_digest: paramsDigest(params), reversibility_class: 'irreversible' };
    return buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n', params, counter: ++counter, signerSecret: A.secretKey, aud: 'rs', now: NOW });
  };
  return { vault, put, actn, sent, respond, receipts, vkPub: b64u(publicKeyOf(vk.secretKey)) };
}
const code = async (p: Promise<unknown>): Promise<string> => { try { await p; return 'no error'; } catch (e) { return (e as { code?: string }).code ?? String(e); } };

describe('proxy mode: the agent never holds the credential', () => {
  it('makes the call itself with the token attached, no redirect following, and signs a receipt', async () => {
    const s = setup();
    await s.put();
    const p = s.actn();
    const r = await s.vault.proxyCall(p, REQ, { provider: 'bank' });
    expect(r.response.status).toBe(201);
    expect(s.sent).toHaveLength(1);
    expect(s.sent[0]).toMatchObject({ method: 'POST', url: REQ.url, redirect: 'manual', headers: { authorization: 'Bearer AT-SECRET', 'content-type': 'application/json' } });
    expect(JSON.stringify(r)).not.toContain('AT-SECRET');
    // the receipt states what the token really carried, not what the action asked for
    expect(r.receipt).toMatchObject({ kind: 'pca-release-receipt', mode: 'proxy', provider: 'bank', outcome: 'executed', http_status: 201, scopes_released: ['accounts:read', 'transfers:write'] });
    expect(verifyReleaseReceipt(r.receipt!, s.vkPub)).toBe(true);
    expect(verifyReleaseReceipt({ ...r.receipt!, http_status: 200 }, s.vkPub)).toBe(false);
    expect(s.receipts).toHaveLength(1);
  });
  it('refuses any request that does not re-derive the signed params digest', async () => {
    const s = setup();
    await s.put();
    const body = (o: object) => JSON.stringify({ source: 'vault', amount: 12_500, currency: 'EUR', payee: 'Acme GmbH', ...o });
    const bad: ProxyRequest[] = [
      { ...REQ, body: body({ amount: 12_501 }) },
      { ...REQ, body: body({ payee: 'Mallory' }) },
      { ...REQ, body: body({ extra: 1 }) },
      { ...REQ, body: body({ source: 'other' }) },
      { ...REQ, url: 'https://api.bank.example/v1/accounts/acct_2/transfers' },
      { ...REQ, url: 'https://evil.example/v1/accounts/acct_1/transfers' },
      { ...REQ, url: `${REQ.url}?dry_run=1&x=2` },
      { ...REQ, url: `${REQ.url}?dry_run=1` },
      { ...REQ, method: 'PUT' },
      { ...REQ, body: '{"amount":1,"amount":12500,"currency":"EUR","payee":"Acme GmbH","source":"vault"}' },
      { ...REQ, headers: { 'content-type': 'text/plain' } },
    ];
    for (const r of bad) {
      expect(await code(s.vault.proxyCall(s.actn(), r, { provider: 'bank' })), `${r.method} ${r.url} ${r.body}`).toBe('request_mismatch');
    }
    expect(s.sent).toHaveLength(0);
  });
  it('a refused request does not spend the action; the same action then succeeds once and only once', async () => {
    const s = setup();
    await s.put();
    const p = s.actn();
    expect(await code(s.vault.proxyCall(p, { ...REQ, body: REQ.body!.replace('12500', '1') }, { provider: 'bank' }))).toBe('request_mismatch');
    expect((await s.vault.proxyCall(p, REQ, { provider: 'bank' })).response.status).toBe(201);
    expect(s.sent).toHaveLength(1);
  });
  it('refuses headers the agent must not set (authorization, cookie, host, method override) before anything is spent', async () => {
    const s = setup();
    await s.put();
    for (const h of ['Authorization', 'cookie', 'Host', 'X-HTTP-Method-Override']) {
      expect(await code(s.vault.proxyCall(s.actn(), { ...REQ, headers: { ...REQ.headers, [h]: 'x' } }, { provider: 'bank' })), h).toBe('request_mismatch');
    }
    expect(s.sent).toHaveLength(0);
  });
  it('an upstream that echoes the token does not hand it back; transport failure is a typed refusal with a failed receipt', async () => {
    const s = setup();
    await s.put();
    s.respond.value = { status: 200, headers: { 'x-echo': 'AT-SECRET', 'set-cookie': 'a=b' }, body: 'token AT-SECRET' };
    const r = await s.vault.proxyCall(s.actn(), REQ, { provider: 'bank' });
    expect(r.response.body).toBe('token [redacted]');
    expect(r.response.headers).toEqual({ 'x-echo': '[redacted]' });
    const failing = setup();
    await failing.put();
    (failing.vault as unknown as { proxyFetch: ProxyFetch }).proxyFetch = async () => { throw new Error('boom AT-SECRET'); };
    const err = (await failing.vault.proxyCall(failing.actn(), REQ, { provider: 'bank' }).catch((e: Error) => e)) as unknown as Error & { code: string };
    expect(err.code).toBe('proxy_failed');
    expect(String(err.message)).not.toContain('AT-SECRET');
    expect(failing.receipts[0]).toMatchObject({ outcome: 'failed', http_status: null });
  });
});

describe('scopes derive from the pinned, confirmed action', () => {
  it('an unknown verb and an unconfirmed definition release nothing', async () => {
    const s = setup();
    await s.put();
    expect(await code(s.vault.proxyCall(s.actn(PARAMS, 'bank.other.verb'), REQ, { provider: 'bank' }))).toBe('unknown_action');
    const u = setup({ action: action({ confirmed: false }) });
    await u.put();
    expect(await code(u.vault.proxyCall(u.actn(), REQ, { provider: 'bank' }))).toBe('unconfirmed_action');
    expect(u.sent).toHaveLength(0);
    expect(new UnknownActionError('x')).toBeInstanceOf(Error);
    expect(new UnconfirmedActionError('x').code).toBe('unconfirmed_action');
  });
  it('scopes_min must be inside the grant and inside the stored connection', async () => {
    const g = setup({ grantScopes: ['accounts:read'] });
    await g.put();
    expect(await code(g.vault.proxyCall(g.actn(), REQ, { provider: 'bank' }))).toBe('scope_exceeded');
    const c = setup({ stored: ['accounts:read'] });
    await c.put();
    expect(await code(c.vault.proxyCall(c.actn(), REQ, { provider: 'bank' }))).toBe('scope_exceeded');
    expect(new ScopeExceededError('p', [], [], []).code).toBe('scope_exceeded');
  });
  it('an action for another provider, or with no scopes, releases nothing', async () => {
    const a = setup({ action: action({ upstream: { provider: 'other', scopes_min: ['x'] } }) });
    await a.put();
    expect(await code(a.vault.proxyCall(a.actn(), REQ, { provider: 'bank' }))).toBe('not_authorized');
    const b = setup({ action: action({ upstream: { provider: 'bank', scopes_min: [] } }) });
    await b.put();
    expect(await code(b.vault.proxyCall(b.actn(), REQ, { provider: 'bank' }))).toBe('not_authorized');
  });
  it('proxy mode needs an extractor on the action', async () => {
    const s = setup({ action: action({ extract: undefined }) });
    await s.put();
    expect(await code(s.vault.proxyCall(s.actn(), REQ, { provider: 'bank' }))).toBe('request_mismatch');
  });
});

describe('plain bearer release is an explicit insecure opt-in', () => {
  it('is disabled by default', async () => {
    const s = setup();
    await s.put();
    expect(await code(s.vault.getConnectionToken(s.actn(), { provider: 'bank' }))).toBe('bearer_release_disabled');
    expect(new BearerReleaseDisabledError().message).toContain('insecureBearerRelease');
  });
  it('when enabled with actions, scopes derive from the action, the release never outlives the PCActn, and it is receipted', async () => {
    const s = setup({ insecure: true, stored: ['transfers:write'] });
    await s.put();
    const p = s.actn();
    const t = await s.vault.getConnectionToken(p, { provider: 'bank' });
    expect(t.scopes).toEqual(['transfers:write']);
    expect(t.expiresAt).toBe(Math.min(NOW + 3_600_000, p.exp));
    expect(s.receipts[0]).toMatchObject({ mode: 'bearer', outcome: 'released', request_digest: null });
    const u = setup({ insecure: true, action: action({ confirmed: false }) });
    await u.put();
    expect(await code(u.vault.getConnectionToken(u.actn(), { provider: 'bank' }))).toBe('unconfirmed_action');
    const wide = setup({ insecure: true, stored: ['transfers:write'] });
    await wide.put();
    expect(await code(wide.vault.getConnectionToken(wide.actn(), { provider: 'bank', scopes: ['accounts:read'] }))).toBe('scope_exceeded');
    // a token that carries more than the action needs cannot be narrowed after issue: not releasable as a bearer
    const broad = setup({ insecure: true });
    await broad.put();
    expect(await code(broad.vault.getConnectionToken(broad.actn(), { provider: 'bank' }))).toBe('scope_exceeded');
  });
});

describe('httpExtractor', () => {
  it('rejects a malformed spec at configuration time', () => {
    expect(() => httpExtractor({ method: 'post', url: 'https://a.example/x' })).toThrow(TypeError);
    expect(() => httpExtractor({ method: 'GET', url: 'http://a.example/x' })).toThrow(TypeError);
    expect(() => httpExtractor({ method: 'GET', url: 'https://a.example/x?y=1' })).toThrow(TypeError);
  });
  it('maps path placeholders, allowed query keys and body members to parameters, and nothing else', () => {
    const e = httpExtractor({ method: 'GET', url: 'https://a.example/v1/{kind}/{id}', query: ['expand'] });
    expect(e({ method: 'GET', url: 'https://a.example/v1/charges/ch%5F1?expand=customer' })).toEqual({ kind: 'charges', id: 'ch_1', expand: 'customer' });
    expect(() => e({ method: 'GET', url: 'https://a.example/v1/charges/ch_1/extra' })).toThrow(RequestMismatchError);
    expect(() => e({ method: 'GET', url: 'https://a.example/v1/charges/ch_1', body: 'x' })).toThrow(RequestMismatchError);
    expect(() => e({ method: 'GET', url: 'https://user:pw@a.example/v1/charges/ch_1' })).toThrow(RequestMismatchError);
    expect(() => e({ method: 'GET', url: 'https://a.example/v1/charges/ch_1#f' })).toThrow(RequestMismatchError);
  });
  it('a parameter carried in two places is refused', () => {
    const e = httpExtractor({ method: 'POST', url: 'https://a.example/v1/{id}', body: 'json' });
    expect(() => e({ method: 'POST', url: 'https://a.example/v1/x', headers: { 'content-type': 'application/json' }, body: '{"id":"y"}' })).toThrow(/twice/);
  });
  it('form bodies: string parameters, repeated keys refused', () => {
    const e = httpExtractor({ method: 'POST', url: 'https://a.example/v1/refunds', body: 'form' });
    const h = { 'content-type': 'application/x-www-form-urlencoded' };
    expect(e({ method: 'POST', url: 'https://a.example/v1/refunds', headers: h, body: 'charge=ch_1&amount=100' })).toEqual({ charge: 'ch_1', amount: '100' });
    expect(() => e({ method: 'POST', url: 'https://a.example/v1/refunds', headers: h, body: 'charge=a&charge=b' })).toThrow(/repeated/);
  });
});
