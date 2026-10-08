import {
  type Capability,
  type CapabilityChain,
  type KeyPair,
  type PCActn,
  type PlanNode,
  buildPCActn,
  encodeKey,
  generateKeyPair,
  mintRoot,
} from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import {
  type ProviderManifest,
  type VaultFetch,
  type VaultHttpRequest,
  type VaultHttpResponse,
  InMemoryConnectionStore,
  ManifestValidationError,
  ScopeExceededError,
  TokenVault,
  applyAccessToken,
  assertManifest,
  buildAuthorizeUrl,
  buildVaultProviders,
  createDefaultRegistry,
  exchangeCode,
  getProvider,
  listProviders,
  manifestToProviderConfig,
  oauthScopeCaveat,
  pkceChallenge,
  providers,
  refresh,
  registerProvider,
  validateManifest,
} from './index';

const NOW = 1_800_000_000_000;

/** A principal P who mints grants to agent A, over some provider, and signs real PCActns against them. */
function world(provider: string) {
  const P: KeyPair = generateKeyPair();
  const A: KeyPair = generateKeyPair();
  const principal = encodeKey(P.publicKey);
  const agentId = encodeKey(A.publicKey);

  function grantFor(scopes: string[] | null): Capability {
    const caveats = scopes === null ? [] : [oauthScopeCaveat(provider, scopes)];
    return mintRoot({ principalSecret: P.secretKey, principalPublic: principal, holder: agentId, caveats });
  }

  function actn(opts: { chain: CapabilityChain; signer?: Uint8Array; aud?: string }): PCActn {
    const node: PlanNode = { id: 'use', verb: 'use_connection', resource: `oauth:${provider}` };
    const root = opts.chain[0];
    if (root === undefined) throw new Error('empty chain');
    return buildPCActn({
      grant: root,
      chain: opts.chain,
      plan: [node],
      nodeId: 'use',
      counter: 1,
      signerSecret: opts.signer ?? A.secretKey,
      aud: opts.aud ?? 'rs',
      now: NOW,
    });
  }

  return { P, A, principal, agentId, grantFor, actn };
}

/** A recording mock transport returning one scripted token-endpoint response. */
function mockFetch(response: VaultHttpResponse): {
  fetch: VaultFetch;
  calls: Array<{ url: string; init: VaultHttpRequest }>;
} {
  const calls: Array<{ url: string; init: VaultHttpRequest }> = [];
  const fetch: VaultFetch = async (url, init) => {
    calls.push({ url, init });
    return response;
  };
  return { fetch, calls };
}

function jsonResponse(body: unknown): VaultHttpResponse {
  return { ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) };
}

/** A seeded manifest, asserted present (the catalog is static). */
function manifest(id: string): ProviderManifest {
  const m = getProvider(id);
  if (m === undefined) throw new Error(`missing seeded provider ${id}`);
  return m;
}

describe('registry (catalog loads)', () => {
  it('seeds the 15 top providers, each a valid manifest with least-privilege defaults', () => {
    const list = listProviders();
    expect(list.length).toBe(15);
    const ids = list.map((m) => m.id);
    expect(ids).toEqual([...ids].sort()); // list() is id-sorted
    expect(new Set(ids)).toEqual(
      new Set([
        'airtable',
        'atlassian',
        'dropbox',
        'github',
        'google',
        'hubspot',
        'linear',
        'microsoft',
        'notion',
        'salesforce',
        'shopify',
        'slack',
        'snowflake',
        'stripe',
        'zoom',
      ]),
    );
    for (const m of list) {
      // Every seeded manifest passes the validator, and defaults are a subset of what is available.
      expect(validateManifest(m).ok).toBe(true);
      if (m.scopesAvailable.length > 0) {
        const available = new Set(m.scopesAvailable);
        expect(m.defaultScopes.every((s) => available.has(s))).toBe(true);
      }
    }
    expect(getProvider('google')?.displayName).toBe('Google Workspace');
    expect(getProvider('does-not-exist')).toBeUndefined();
    expect(providers.BUILTIN_MANIFESTS.length).toBe(15);
  });

  it('registers a validated custom manifest onto a fresh registry', () => {
    const registry = createDefaultRegistry();
    const custom: ProviderManifest = {
      id: 'acme',
      displayName: 'Acme',
      authorizeUrl: 'https://acme.example/oauth/authorize',
      tokenUrl: 'https://acme.example/oauth/token',
      scopesAvailable: ['read', 'write'],
      defaultScopes: ['read'],
      refresh: { mode: 'refresh_token' },
      tokenPlacement: 'bearer',
    };
    registry.register(custom);
    expect(registry.get('acme')?.displayName).toBe('Acme');
    expect(registry.list().length).toBe(16);
    // The shared defaultRegistry (what registerProvider targets) is unaffected.
    expect(getProvider('acme')).toBeUndefined();
  });
});

describe('buildAuthorizeUrl (+ PKCE)', () => {
  it('builds a correct PKCE authorize URL for google', () => {
    const verifier = 'test-verifier-0123456789-abcdefghijklmnopqrstuvwxyz';
    const { url, state, pkce } = buildAuthorizeUrl('google', {
      clientId: 'cid-google',
      redirectUri: 'https://app.example/cb',
      scopes: ['openid', 'email'],
      state: 'xyz',
      pkce: { verifier },
    });
    expect(url.startsWith('https://accounts.google.com/o/oauth2/v2/auth?')).toBe(true);
    expect(url).toContain('response_type=code');
    expect(url).toContain('client_id=cid-google');
    expect(url).toContain('redirect_uri=https%3A%2F%2Fapp.example%2Fcb');
    expect(url).toContain('scope=openid%20email'); // space-delimited
    expect(url).toContain('state=xyz');
    expect(url).toContain('code_challenge_method=S256');
    expect(url).toContain(`code_challenge=${pkceChallenge(verifier)}`);
    // Google-specific authParams flow through.
    expect(url).toContain('access_type=offline');
    expect(url).toContain('prompt=consent');
    expect(state).toBe('xyz');
    expect(pkce).toEqual({ verifier, challenge: pkceChallenge(verifier), method: 'S256' });
  });

  it('builds a correct PKCE authorize URL for microsoft (follows the manifest pkce flag)', () => {
    const { url, pkce } = buildAuthorizeUrl('microsoft', {
      clientId: 'cid-ms',
      redirectUri: 'https://app.example/cb',
    });
    expect(url.startsWith('https://login.microsoftonline.com/common/oauth2/v2.0/authorize?')).toBe(true);
    // scopes default to the manifest's least-privilege set
    expect(url).toContain('scope=openid%20profile%20offline_access%20User.Read');
    // manifest.pkce === true => PKCE auto-generated (no verifier supplied)
    expect(pkce?.method).toBe('S256');
    expect(pkce?.verifier.length).toBeGreaterThanOrEqual(43);
    expect(url).toContain(`code_challenge=${pkce?.challenge ?? ''}`);
  });

  it('joins comma-delimited scopes and substitutes {var} hosts', () => {
    // slack uses a comma scope separator
    const slackUrl = buildAuthorizeUrl('slack', {
      clientId: 'c',
      redirectUri: 'https://app.example/cb',
      scopes: ['chat:write', 'channels:read'],
      state: 's',
    }).url;
    expect(slackUrl).toContain('scope=chat%3Awrite%2Cchannels%3Aread'); // comma-joined

    // shopify needs a {shop} host var
    const shopUrl = buildAuthorizeUrl('shopify', {
      clientId: 'c',
      redirectUri: 'https://app.example/cb',
      state: 's',
      vars: { shop: 'acme' },
    }).url;
    expect(shopUrl.startsWith('https://acme.myshopify.com/admin/oauth/authorize?')).toBe(true);

    // a missing required var is a hard error (never ship a URL with a live placeholder)
    expect(() => buildAuthorizeUrl('shopify', { clientId: 'c', redirectUri: 'https://app.example/cb' })).toThrow(
      /missing URL variable/,
    );
  });
});

describe('exchangeCode / refresh feed the capability-bound vault', () => {
  it('exchangeCode populates the vault with a connection usable only via a verified PCActn', async () => {
    const { principal, agentId, grantFor, actn } = world('google');
    const store = new InMemoryConnectionStore();
    const vault = new TokenVault({ store, now: () => NOW });
    const { fetch, calls } = mockFetch(
      jsonResponse({ access_token: 'AT-1', refresh_token: 'RT-1', expires_in: 3600, scope: 'openid email' }),
    );

    const stored = await exchangeCode({
      providerId: 'google',
      clientId: 'cid',
      clientSecret: 'sec',
      code: 'auth-code',
      redirectUri: 'https://app.example/cb',
      codeVerifier: 'the-verifier-used-at-authorize-time-0123456789abcd',
      scopes: ['openid', 'email'],
      fetch,
      now: NOW,
      bind: { vault, agentId, authority: { principal } },
    });

    // The connection is stored, capability-bound to the requested (least-privilege) scopes.
    expect(stored.provider).toBe('google');
    expect(stored.authority.scopes.sort()).toEqual(['email', 'openid']);
    expect(stored.refreshToken).toBe('RT-1');
    expect(stored.expiresAt).toBe(NOW + 3_600_000);

    // The token request went to the right endpoint, as an authorization_code grant with the PKCE verifier.
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe('https://oauth2.googleapis.com/token');
    expect(calls[0]?.init.body).toContain('grant_type=authorization_code');
    expect(calls[0]?.init.body).toContain('code=auth-code');
    expect(calls[0]?.init.body).toContain('code_verifier=');

    // A verified PCActn whose capability grants the scopes releases a fresh token.
    const token = await vault.getConnectionToken(actn({ chain: [grantFor(['openid', 'email'])] }), {
      provider: 'google',
    });
    expect(token.accessToken).toBe('AT-1');
    expect(token.refreshed).toBe(false);
  });

  it('refuses a release whose requested scope is not granted by the capability (scope_exceeded, via pca-connect)', async () => {
    const { principal, agentId, grantFor, actn } = world('google');
    const store = new InMemoryConnectionStore();
    const vault = new TokenVault({ store, now: () => NOW });
    const { fetch } = mockFetch(jsonResponse({ access_token: 'AT-1', expires_in: 3600, scope: 'openid email' }));

    // Connection bound to require BOTH openid and email.
    await exchangeCode({
      providerId: 'google',
      clientId: 'cid',
      code: 'c',
      redirectUri: 'https://app.example/cb',
      codeVerifier: 'verifier-verifier-verifier-verifier-012345',
      scopes: ['openid', 'email'],
      fetch,
      now: NOW,
      bind: { vault, agentId, authority: { principal } },
    });

    // The capability chain grants ONLY 'openid'. Requesting the connection's bound scopes (openid+email)
    // is a least-privilege violation the vault refuses — the proof-carrying guarantee a plain vault lacks.
    await expect(
      vault.getConnectionToken(actn({ chain: [grantFor(['openid'])] }), { provider: 'google' }),
    ).rejects.toBeInstanceOf(ScopeExceededError);
    await expect(
      vault.getConnectionToken(actn({ chain: [grantFor(['openid'])] }), {
        provider: 'google',
        scopes: ['openid', 'email'],
      }),
    ).rejects.toMatchObject({ code: 'scope_exceeded', missing: ['email'] });

    // Attenuation still works: requesting only the granted scope succeeds.
    const ok = await vault.getConnectionToken(actn({ chain: [grantFor(['openid'])] }), {
      provider: 'google',
      scopes: ['openid'],
    });
    expect(ok.accessToken).toBe('AT-1');
  });

  it('refresh() re-stores a rotated token, and the vault auto-refreshes from a manifest ProviderConfig', async () => {
    const { principal, agentId, grantFor, actn } = world('microsoft');

    // 1. Standalone refresh(): rotate the token and re-bind.
    const store = new InMemoryConnectionStore();
    const vault = new TokenVault({ store, now: () => NOW });
    const refreshMock = mockFetch(
      jsonResponse({ access_token: 'AT-2', refresh_token: 'RT-2', expires_in: 3600, scope: 'User.Read' }),
    );
    const restored = await refresh({
      providerId: 'microsoft',
      clientId: 'cid',
      clientSecret: 'sec',
      refreshToken: 'RT-1',
      scopes: ['User.Read'],
      fetch: refreshMock.fetch,
      now: NOW,
      bind: { vault, agentId, authority: { principal } },
    });
    expect(restored.accessToken).toBe('AT-2');
    expect(restored.refreshToken).toBe('RT-2');
    expect(refreshMock.calls[0]?.init.body).toContain('grant_type=refresh_token');
    expect(refreshMock.calls[0]?.init.body).toContain('refresh_token=RT-1');
    const t1 = await vault.getConnectionToken(actn({ chain: [grantFor(['User.Read'])] }), { provider: 'microsoft' });
    expect(t1.accessToken).toBe('AT-2');

    // 2. The vault's OWN auto-refresh is wired from the same manifest via manifestToProviderConfig.
    const store2 = new InMemoryConnectionStore();
    const autoMock = mockFetch(jsonResponse({ access_token: 'AT-3', expires_in: 3600 }));
    const vault2 = new TokenVault({
      store: store2,
      now: () => NOW,
      fetch: autoMock.fetch,
      providers: buildVaultProviders({ microsoft: { clientId: 'cid', clientSecret: 'sec' } }),
    });
    const cfg = manifestToProviderConfig(manifest('microsoft'), { clientId: 'cid' });
    expect(cfg.tokenEndpoint).toBe('https://login.microsoftonline.com/common/oauth2/v2.0/token');
    await vault2.putConnection({
      agentId,
      provider: 'microsoft',
      accessToken: 'AT-OLD',
      refreshToken: 'RT-9',
      expiresAt: NOW - 1000, // already expired => forces the vault to refresh via the manifest config
      scopes: ['User.Read'],
      authority: { principal, scopes: ['User.Read'] },
    });
    const t2 = await vault2.getConnectionToken(actn({ chain: [grantFor(['User.Read'])] }), { provider: 'microsoft' });
    expect(t2).toMatchObject({ accessToken: 'AT-3', refreshed: true });
    expect(autoMock.calls[0]?.url).toBe('https://login.microsoftonline.com/common/oauth2/v2.0/token');
  });

  it('refuses refresh() for a provider whose manifest cannot refresh', async () => {
    const { principal, agentId } = world('github');
    const vault = new TokenVault({ now: () => NOW });
    const { fetch } = mockFetch(jsonResponse({ access_token: 'x' }));
    await expect(
      refresh({
        providerId: 'github',
        clientId: 'c',
        refreshToken: 'rt',
        fetch,
        bind: { vault, agentId, authority: { principal } },
      }),
    ).rejects.toThrow(/does not support token refresh/);
  });
});

describe('manifest validation', () => {
  it('rejects malformed manifests with specific issues', () => {
    // not an object
    expect(validateManifest(null).ok).toBe(false);
    expect(validateManifest(42).ok).toBe(false);

    // missing id / non-https url / bad placement / defaults not a subset / unknown refresh mode
    const bad = validateManifest({
      id: 'Bad Id!',
      displayName: '',
      authorizeUrl: 'http://insecure.example/auth',
      tokenUrl: 'https://ok.example/token',
      scopesAvailable: ['read'],
      defaultScopes: ['read', 'write'],
      refresh: { mode: 'magic' },
      tokenPlacement: 'cookie',
    });
    expect(bad.ok).toBe(false);
    if (bad.ok) throw new Error('expected failure');
    const joined = bad.issues.join(' | ');
    expect(joined).toMatch(/id/);
    expect(joined).toMatch(/displayName/);
    expect(joined).toMatch(/authorizeUrl must be an https/);
    expect(joined).toMatch(/defaultScopes must be a subset/);
    expect(joined).toMatch(/refresh.mode/);
    expect(joined).toMatch(/tokenPlacement/);

    // assertManifest / registerProvider throw on a malformed manifest
    expect(() => assertManifest({ id: 'x' })).toThrow(ManifestValidationError);
    expect(() => registerProvider({ id: 'x' })).toThrow(ManifestValidationError);
  });

  it('rejects a header placement with no headerName, and an undeclared URL {var}', () => {
    const noHeader = validateManifest({
      id: 'h',
      displayName: 'H',
      authorizeUrl: 'https://h.example/a',
      tokenUrl: 'https://h.example/t',
      scopesAvailable: [],
      defaultScopes: [],
      refresh: { mode: 'none' },
      tokenPlacement: 'header',
    });
    expect(noHeader.ok).toBe(false);
    if (!noHeader.ok) expect(noHeader.issues.join(' ')).toMatch(/headerName/);

    const undeclaredVar = validateManifest({
      id: 'v',
      displayName: 'V',
      authorizeUrl: 'https://{tenant}.example/a',
      tokenUrl: 'https://{tenant}.example/t',
      scopesAvailable: [],
      defaultScopes: [],
      refresh: { mode: 'none' },
      tokenPlacement: 'bearer',
    });
    expect(undeclaredVar.ok).toBe(false);
    if (!undeclaredVar.ok) expect(undeclaredVar.issues.join(' ')).toMatch(/\{tenant\}/);
  });
});

describe('applyAccessToken (token placement)', () => {
  it('places the token per the manifest', () => {
    expect(applyAccessToken(manifest('google'), 'AT')).toEqual({
      kind: 'header',
      name: 'Authorization',
      value: 'Bearer AT',
    });
    // shopify is header-placed with a custom header
    expect(applyAccessToken(manifest('shopify'), 'AT')).toEqual({
      kind: 'header',
      name: 'X-Shopify-Access-Token',
      value: 'AT',
    });
  });
});
