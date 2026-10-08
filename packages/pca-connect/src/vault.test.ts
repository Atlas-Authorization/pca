import {
  type Capability,
  type CapabilityChain,
  type KeyPair,
  type PCActn,
  type PlanNode,
  buildPCActn,
  delegate,
  encodeKey,
  generateKeyPair,
  mintRoot,
} from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import {
  ExpiredNoRefreshError,
  InMemoryConnectionStore,
  NotAuthorizedError,
  RefreshFailedError,
  ScopeExceededError,
  TokenVault,
  UnknownConnectionError,
  type VaultFetch,
  type VaultHttpRequest,
  type VaultHttpResponse,
  grantedOAuthScopes,
  oauthScopeCaveat,
} from './index';

const NOW = 1_800_000_000_000;

/** A principal P who mints grants to agent A; helpers to build real, signed PCActns against it. */
function world() {
  const P: KeyPair = generateKeyPair();
  const A: KeyPair = generateKeyPair();
  const principal = encodeKey(P.publicKey);
  const agentId = encodeKey(A.publicKey);

  /** A grant rooted at P, held by A, carrying the given google scopes (`null` => no oauth authority at all). */
  function grantFor(googleScopes: string[] | null): Capability {
    const caveats = googleScopes === null ? [] : [oauthScopeCaveat('google', googleScopes)];
    return mintRoot({ principalSecret: P.secretKey, principalPublic: principal, holder: agentId, caveats });
  }

  /** Build a signed PCActn for a token-use action over `chain`, signed by `signer` (defaults to A). */
  function actn(opts: {
    chain: CapabilityChain;
    signer?: Uint8Array;
    verb?: string;
    resource?: string;
    aud?: string;
  }): PCActn {
    const node: PlanNode = { id: 'use', verb: opts.verb ?? 'use_connection', resource: opts.resource ?? 'oauth:google' };
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

/** A recording mock transport returning a scripted token-endpoint response. */
function mockFetch(
  response: VaultHttpResponse,
): { fetch: VaultFetch; calls: Array<{ url: string; init: VaultHttpRequest }> } {
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

describe('grantedOAuthScopes (authority reader)', () => {
  it('returns null for an uncovered provider and intersects attenuated grants down the chain', () => {
    const { A, grantFor } = world();
    const grant = grantFor(['read', 'write']);
    expect(grantedOAuthScopes([grant], 'slack')).toBeNull();
    expect([...(grantedOAuthScopes([grant], 'google') ?? new Set<string>())].sort()).toEqual(['read', 'write']);

    const S = generateKeyPair();
    const sub = delegate(grant, encodeKey(S.publicKey), [oauthScopeCaveat('google', ['read'])], A.secretKey);
    expect([...(grantedOAuthScopes([grant, sub], 'google') ?? new Set<string>())]).toEqual(['read']);
  });
});

describe('TokenVault.getConnectionToken', () => {
  it('releases a fresh token when an authorizing PCActn verifies (and records usage)', async () => {
    const { principal, agentId, grantFor, actn } = world();
    const store = new InMemoryConnectionStore();
    const vault = new TokenVault({ store, now: () => NOW });
    await vault.putConnection({
      agentId,
      provider: 'google',
      accessToken: 'AT-1',
      refreshToken: 'RT-1',
      expiresAt: NOW + 3_600_000,
      scopes: ['read', 'write'],
      authority: { principal, scopes: ['read'] },
    });

    const token = await vault.getConnectionToken(actn({ chain: [grantFor(['read', 'write'])] }), { provider: 'google' });
    expect(token).toMatchObject({ provider: 'google', connectionId: 'default', accessToken: 'AT-1', refreshed: false });
    expect(token.scopes.sort()).toEqual(['read', 'write']);

    const stored = await store.get({ agentId, provider: 'google', connectionId: 'default' });
    expect(stored?.useCount).toBe(1);
    expect(stored?.lastUsedAt).toBe(NOW);
  });

  it('denies a PCActn whose capability covers no authority for the provider (not_authorized)', async () => {
    const { principal, agentId, grantFor, actn } = world();
    const store = new InMemoryConnectionStore();
    const v = new TokenVault({ store, now: () => NOW });
    await v.putConnection({
      agentId,
      provider: 'google',
      accessToken: 'AT-1',
      expiresAt: NOW + 3_600_000,
      scopes: ['read'],
      authority: { principal, scopes: ['read'] },
    });
    // Grant carries NO oauth_scope caveat => the capability authorizes nothing for google.
    await expect(v.getConnectionToken(actn({ chain: [grantFor(null)] }), { provider: 'google' })).rejects.toBeInstanceOf(
      NotAuthorizedError,
    );
    await expect(
      v.getConnectionToken(actn({ chain: [grantFor(null)] }), { provider: 'google' }),
    ).rejects.toMatchObject({ code: 'not_authorized' });
  });

  it('denies a chain not rooted at the connection\'s bound principal (not_authorized)', async () => {
    const { agentId, grantFor, actn } = world();
    const store = new InMemoryConnectionStore();
    const vault = new TokenVault({ store, now: () => NOW });
    await vault.putConnection({
      agentId,
      provider: 'google',
      accessToken: 'AT-1',
      expiresAt: NOW + 3_600_000,
      scopes: ['read'],
      authority: { principal: encodeKey(generateKeyPair().publicKey), scopes: ['read'] }, // a DIFFERENT principal
    });
    await expect(
      vault.getConnectionToken(actn({ chain: [grantFor(['read'])] }), { provider: 'google' }),
    ).rejects.toMatchObject({ code: 'not_authorized' });
  });

  it('denies a forged leaf signature (real PCActn verification, not a stub)', async () => {
    const { principal, agentId, grantFor, actn } = world();
    const store = new InMemoryConnectionStore();
    const vault = new TokenVault({ store, now: () => NOW });
    await vault.putConnection({
      agentId,
      provider: 'google',
      accessToken: 'AT-1',
      expiresAt: NOW + 3_600_000,
      scopes: ['read'],
      authority: { principal, scopes: ['read'] },
    });
    // Signed by a key that is NOT the chain's leaf holder => leaf_signature fails inside verifyPCActnCore.
    const forged = actn({ chain: [grantFor(['read'])], signer: generateKeyPair().secretKey });
    try {
      await vault.getConnectionToken(forged, { provider: 'google' });
      throw new Error('expected a refusal');
    } catch (e) {
      expect(e).toBeInstanceOf(NotAuthorizedError);
      if (!(e instanceof NotAuthorizedError)) throw e;
      expect(e.code).toBe('not_authorized');
      expect(e.checks?.['leaf_signature']).toBe('fail');
    }
  });

  it('rejects requested scopes that exceed the grant (scope_exceeded)', async () => {
    const { principal, agentId, grantFor, actn } = world();
    const store = new InMemoryConnectionStore();
    const vault = new TokenVault({ store, now: () => NOW });
    await vault.putConnection({
      agentId,
      provider: 'google',
      accessToken: 'AT-1',
      expiresAt: NOW + 3_600_000,
      scopes: ['read'],
      authority: { principal, scopes: ['read'] },
    });
    // Capability grants only ['read']; the call asks for ['read','write'].
    try {
      await vault.getConnectionToken(actn({ chain: [grantFor(['read'])] }), {
        provider: 'google',
        scopes: ['read', 'write'],
      });
      throw new Error('expected a refusal');
    } catch (e) {
      expect(e).toBeInstanceOf(ScopeExceededError);
      if (!(e instanceof ScopeExceededError)) throw e;
      expect(e.code).toBe('scope_exceeded');
      expect(e.missing).toEqual(['write']);
    }
  });

  it('enforces attenuation: a delegated, narrowed chain rejects the dropped scope but passes the kept one', async () => {
    const { A, principal, grantFor, actn } = world();
    const S = generateKeyPair();
    const subAgentId = encodeKey(S.publicKey);
    const grant = grantFor(['read', 'write']);
    // A delegates to sub-agent S, narrowing google authority to ['read'] (signed by A, the parent holder).
    const sub = delegate(grant, subAgentId, [oauthScopeCaveat('google', ['read'])], A.secretKey);

    const store = new InMemoryConnectionStore();
    const vault = new TokenVault({ store, now: () => NOW });
    await vault.putConnection({
      agentId: subAgentId, // the connection belongs to the sub-agent (the chain's leaf holder)
      provider: 'google',
      accessToken: 'AT-sub',
      expiresAt: NOW + 3_600_000,
      scopes: ['read', 'write'],
      authority: { principal, scopes: ['read'] },
    });

    // 'write' was dropped by the delegation => scope_exceeded even though the connection token carries it.
    await expect(
      vault.getConnectionToken(actn({ chain: [grant, sub], signer: S.secretKey }), {
        provider: 'google',
        scopes: ['write'],
      }),
    ).rejects.toMatchObject({ code: 'scope_exceeded' });

    // 'read' survived the delegation => allowed.
    const token = await vault.getConnectionToken(actn({ chain: [grant, sub], signer: S.secretKey }), {
      provider: 'google',
      scopes: ['read'],
    });
    expect(token.accessToken).toBe('AT-sub');
  });

  it('refreshes a stale token via the provider endpoint and returns the new token', async () => {
    const { principal, agentId, grantFor, actn } = world();
    const store = new InMemoryConnectionStore();
    const { fetch, calls } = mockFetch(jsonResponse({ access_token: 'AT-2', expires_in: 3600, refresh_token: 'RT-2' }));
    const vault = new TokenVault({
      store,
      now: () => NOW,
      fetch,
      providers: { google: { tokenEndpoint: 'https://oauth2.example/token', clientId: 'cid', clientSecret: 'sec' } },
    });
    await vault.putConnection({
      agentId,
      provider: 'google',
      accessToken: 'AT-1',
      refreshToken: 'RT-1',
      expiresAt: NOW - 1000, // already expired
      scopes: ['read'],
      authority: { principal, scopes: ['read'] },
    });

    const token = await vault.getConnectionToken(actn({ chain: [grantFor(['read'])] }), { provider: 'google' });
    expect(token).toMatchObject({ accessToken: 'AT-2', refreshed: true });
    expect(token.expiresAt).toBe(NOW + 3_600_000);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe('https://oauth2.example/token');
    expect(calls[0]?.init.body).toContain('grant_type=refresh_token');
    expect(calls[0]?.init.body).toContain('refresh_token=RT-1');

    // Persisted: the rotated refresh token and new access token are stored, so a second call is fresh.
    const token2 = await vault.getConnectionToken(actn({ chain: [grantFor(['read'])] }), { provider: 'google' });
    expect(token2).toMatchObject({ accessToken: 'AT-2', refreshed: false });
    const stored = await store.get({ agentId, provider: 'google', connectionId: 'default' });
    expect(stored?.refreshToken).toBe('RT-2');
  });

  it('refuses when the token is stale and there is no refresh token (expired_no_refresh)', async () => {
    const { principal, agentId, grantFor, actn } = world();
    const store = new InMemoryConnectionStore();
    const vault = new TokenVault({ store, now: () => NOW });
    await vault.putConnection({
      agentId,
      provider: 'google',
      accessToken: 'AT-1',
      expiresAt: NOW - 1000, // expired, no refresh token
      scopes: ['read'],
      authority: { principal, scopes: ['read'] },
    });
    await expect(
      vault.getConnectionToken(actn({ chain: [grantFor(['read'])] }), { provider: 'google' }),
    ).rejects.toBeInstanceOf(ExpiredNoRefreshError);
  });

  it('surfaces a provider token-endpoint failure as refresh_failed', async () => {
    const { principal, agentId, grantFor, actn } = world();
    const store = new InMemoryConnectionStore();
    const { fetch } = mockFetch({ ok: false, status: 400, json: async () => ({}), text: async () => 'invalid_grant' });
    const vault = new TokenVault({
      store,
      now: () => NOW,
      fetch,
      providers: { google: { tokenEndpoint: 'https://oauth2.example/token', clientId: 'cid' } },
    });
    await vault.putConnection({
      agentId,
      provider: 'google',
      accessToken: 'AT-1',
      refreshToken: 'RT-1',
      expiresAt: NOW - 1000,
      scopes: ['read'],
      authority: { principal, scopes: ['read'] },
    });
    try {
      await vault.getConnectionToken(actn({ chain: [grantFor(['read'])] }), { provider: 'google' });
      throw new Error('expected a refusal');
    } catch (e) {
      expect(e).toBeInstanceOf(RefreshFailedError);
      if (!(e instanceof RefreshFailedError)) throw e;
      expect(e.status).toBe(400);
    }
  });

  it('reports unknown_connection for an agent/provider/connectionId with no stored connection', async () => {
    const { grantFor, actn } = world();
    const vault = new TokenVault({ now: () => NOW });
    await expect(
      vault.getConnectionToken(actn({ chain: [grantFor(['read'])] }), { provider: 'google', connectionId: 'missing' }),
    ).rejects.toBeInstanceOf(UnknownConnectionError);
  });
});
