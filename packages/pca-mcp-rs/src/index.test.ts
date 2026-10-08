import { describe, expect, it } from 'vitest';
import {
  agent,
  b64u,
  generateKeyPair,
  signShare,
  thresholdMessage,
  utf8,
  type Agent,
  type Capability,
  type PCActn,
} from '@atlasauth/pca';
import {
  WELL_KNOWN_OAUTH_PRM,
  accumulateScopes,
  authorizeRequest,
  clientIdMetadataDocument,
  extractPCActn,
  prmHandler,
  protectedResourceMetadata,
  requiredRolesForTier,
  verifyCimd,
  wwwAuthenticateChallenge,
  type ClientIdMetadataDocument,
} from './index';

const AUD = 'https://api.acme.com';
const PRM_URL = `${AUD}${WELL_KNOWN_OAUTH_PRM}`;

function mkAgent(): Agent {
  return agent({
    principal: generateKeyPair(),
    goal: 'reconcile tickets',
    permissions: { tickets: ['write', 'read', 'delete'] },
    aud: AUD,
  });
}

/** A request whose body carries the PCActn object (the `{ pcactn }` body form). */
const bodyReq = (p: PCActn) => ({ headers: {} as Record<string, string>, body: { pcactn: p } });

// =====================================================================================================
// 1. RFC 9728 Protected Resource Metadata
// =====================================================================================================

describe('protectedResourceMetadata (RFC 9728)', () => {
  it('serves resource, authorization_servers, scopes_supported, bearer_methods_supported', () => {
    const prm = protectedResourceMetadata({
      resource: AUD,
      authorizationServers: ['https://as.acme.com'],
      scopesSupported: ['tickets:read', 'tickets:write'],
    });
    expect(prm.resource).toBe(AUD);
    expect(prm.authorization_servers).toEqual(['https://as.acme.com']);
    expect(prm.scopes_supported).toEqual(['tickets:read', 'tickets:write']);
    expect(prm.bearer_methods_supported).toEqual(['header']);
    // CIMD advertised; DCR is gone in 2026-07-28.
    expect(prm.client_id_metadata_document_supported).toBe(true);
    // one source of truth: the embedded PCA discovery audience IS the OAuth resource
    expect(prm.pca.audience).toBe(AUD);
    expect(prm.pca_action_header).toBe('PCA-Action');
    expect(prm.pca_configuration_endpoint).toBe(`${AUD}/.well-known/pca-configuration`);
  });

  it('throws when resource / authorizationServers are missing', () => {
    expect(() => protectedResourceMetadata({ resource: '', authorizationServers: ['x'], scopesSupported: [] })).toThrow(/resource/);
    expect(() => protectedResourceMetadata({ resource: AUD, authorizationServers: [], scopesSupported: [] })).toThrow(/authorizationServers/);
  });

  it('prmHandler returns the well-known path + body', () => {
    const { path, body } = prmHandler({ resource: AUD, authorizationServers: ['https://as.acme.com'], scopesSupported: ['tickets:read'] });
    expect(path).toBe('/.well-known/oauth-protected-resource');
    expect(body.resource).toBe(AUD);
  });
});

// =====================================================================================================
// 2. WWW-Authenticate challenge
// =====================================================================================================

describe('wwwAuthenticateChallenge (MCP 2026-07-28 + RFC 6750/9470)', () => {
  it('carries the Bearer resource_metadata pointer', () => {
    const h = wwwAuthenticateChallenge({ resourceMetadataUrl: PRM_URL });
    expect(h).toContain(`Bearer resource_metadata="${PRM_URL}"`);
  });

  it('includes error / scope / RFC 9470 step-up params', () => {
    const h = wwwAuthenticateChallenge({
      resourceMetadataUrl: PRM_URL,
      error: 'insufficient_scope',
      scope: 'tickets:write',
      acrValues: 'pca:tier2',
      maxAge: 0,
    });
    expect(h).toContain('error="insufficient_scope"');
    expect(h).toContain('scope="tickets:write"');
    expect(h).toContain('acr_values="pca:tier2"');
    expect(h).toContain('max_age=0');
  });

  it('appends a PCA-StepUp challenge when a step-up is given', () => {
    const h = wwwAuthenticateChallenge({
      resourceMetadataUrl: PRM_URL,
      error: 'insufficient_user_authentication',
      pcaStepUp: { tier: 2, requiredRoles: ['guardian', 'principal'], acr: 'pca:tier2', reason: 'x', stepUpEndpoint: `${AUD}/v1/pca/stepup` },
    });
    expect(h).toContain('PCA-StepUp realm="pca"');
    expect(h).toContain('tier="2"');
    expect(h).toContain('roles="guardian principal"');
    expect(h).toContain(`stepup_uri="${AUD}/v1/pca/stepup"`);
  });

  it('rejects an empty url and header-injecting values', () => {
    expect(() => wwwAuthenticateChallenge({ resourceMetadataUrl: '' })).toThrow();
    expect(() => wwwAuthenticateChallenge({ resourceMetadataUrl: 'https://x/"evil' })).toThrow();
  });
});

// =====================================================================================================
// 3. CIMD — Client-ID Metadata Documents (DCR replacement)
// =====================================================================================================

describe('clientIdMetadataDocument / verifyCimd (CIMD)', () => {
  it('builds a well-formed https CIMD', () => {
    const doc = clientIdMetadataDocument({
      clientId: 'https://app.example/.well-known/cimd.json',
      redirectUris: ['https://app.example/callback', 'http://127.0.0.1:8976/cb', 'myapp://auth'],
      clientName: 'Example Agent',
    });
    expect(doc.client_id).toBe('https://app.example/.well-known/cimd.json');
    expect(doc.redirect_uris).toHaveLength(3);
    expect(doc.client_name).toBe('Example Agent');
  });

  it('throws building a CIMD with an http client_id or no redirect URIs', () => {
    expect(() => clientIdMetadataDocument({ clientId: 'http://app.example/cimd', redirectUris: ['https://app.example/cb'] })).toThrow(/https/);
    expect(() => clientIdMetadataDocument({ clientId: 'https://app.example/cimd', redirectUris: [] })).toThrow(/redirect/);
  });

  it('verifyCimd accepts an https client_id URL and rejects http/malformed', () => {
    expect(verifyCimd('https://app.example/cimd.json')).toMatchObject({ ok: true, clientId: 'https://app.example/cimd.json' });
    expect(verifyCimd('http://app.example/cimd.json')).toMatchObject({ ok: false });
    expect(verifyCimd('not a url')).toMatchObject({ ok: false });
  });

  it('verifyCimd accepts a well-formed https document', () => {
    const doc: ClientIdMetadataDocument = { client_id: 'https://app.example/cimd', redirect_uris: ['https://app.example/cb'] };
    const r = verifyCimd(doc, { expectedClientId: 'https://app.example/cimd' });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.doc?.redirect_uris).toEqual(['https://app.example/cb']);
  });

  it('verifyCimd rejects http client_id, missing redirect_uris, unsafe redirect, and id mismatch', () => {
    expect(verifyCimd({ client_id: 'http://app.example/cimd', redirect_uris: ['https://app.example/cb'] })).toMatchObject({ ok: false });
    expect(verifyCimd({ client_id: 'https://app.example/cimd', redirect_uris: [] })).toMatchObject({ ok: false });
    expect(verifyCimd({ client_id: 'https://app.example/cimd' })).toMatchObject({ ok: false });
    expect(verifyCimd({ client_id: 'https://app.example/cimd', redirect_uris: ['http://evil.example/cb'] })).toMatchObject({ ok: false });
    expect(verifyCimd({ client_id: 'https://app.example/cimd', redirect_uris: ['https://app.example/cb'] }, { expectedClientId: 'https://other/cimd' })).toMatchObject({ ok: false });
  });
});

// =====================================================================================================
// 4. Scope accumulation
// =====================================================================================================

describe('accumulateScopes', () => {
  it('seeds from the first scope caveat and narrows (intersects) on each later one', () => {
    const caveats = [
      { type: 'reversibility_max', class: 'irreversible' },
      { type: 'scope', scopes: ['tickets:read', 'tickets:write'] },
      { type: 'scope', scopes: ['tickets:read'] },
    ];
    expect(accumulateScopes(caveats)).toEqual(['tickets:read']);
  });

  it('intersects a provided base and fails closed with neither base nor caveat', () => {
    expect(accumulateScopes([{ type: 'scope', scopes: ['a', 'b'] }], ['b', 'c'])).toEqual(['b']);
    expect(accumulateScopes([])).toEqual([]);
  });
});

// =====================================================================================================
// 5. authorizeRequest — the RS admission check
// =====================================================================================================

describe('authorizeRequest', () => {
  const resolveGrant = (grant: Capability) => (ref: string) => (ref === grant.id ? grant : null);

  it('admits a valid proof-carrying call (body + PCA-Action header forms)', async () => {
    const a = mkAgent();
    const sub = a.subAgent({ addedCaveats: [{ type: 'scope', scopes: ['tickets:read', 'tickets:write'] }] });
    const { pcactn, encoded } = sub.act('tickets.write', 'ticket:1', {}, { aud: AUD });

    const opts = {
      resource: AUD,
      authorizationServers: [a.principalPublic],
      resolveGrant: resolveGrant(a.grant),
      prmUrl: PRM_URL,
      tool: 'tickets.write',
      toolScopes: { 'tickets.write': 'tickets:write' },
      now: pcactn.iat,
    };

    const viaBody = await authorizeRequest(bodyReq(pcactn), opts);
    expect(viaBody.ok).toBe(true);
    if (viaBody.ok) {
      expect(viaBody.status).toBe(200);
      expect(viaBody.grantedScopes).toEqual(['tickets:read', 'tickets:write']);
      expect(viaBody.checks.leaf_signature).toBe('pass');
    }

    // header form: PCA-Action: base64url(PCActn JSON)
    const viaHeader = await authorizeRequest({ headers: { 'PCA-Action': b64u(utf8(encoded)) } }, opts);
    expect(viaHeader.ok).toBe(true);
  });

  it('RFC 8707: rejects a PCActn whose audience is a different resource server', async () => {
    const a = mkAgent();
    const { pcactn } = a.act('tickets.write', 'ticket:1', {}, { aud: AUD });
    const res = await authorizeRequest(bodyReq(pcactn), {
      resource: 'https://other.example',
      authorizationServers: [a.principalPublic],
      resolveGrant: resolveGrant(a.grant),
      prmUrl: PRM_URL,
      now: pcactn.iat,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.status).toBe(401);
      expect(res.error).toBe('invalid_token');
      expect(res.errorDescription).toMatch(/RFC 8707/);
    }
  });

  it('RFC 9207: rejects a credential from an unexpected authorization server (mix-up)', async () => {
    const a = mkAgent();
    const { pcactn } = a.act('tickets.write', 'ticket:1', {}, { aud: AUD });
    const res = await authorizeRequest(bodyReq(pcactn), {
      resource: AUD,
      authorizationServers: ['https://evil-as.example'], // does NOT include the grant's issuer
      resolveGrant: resolveGrant(a.grant),
      prmUrl: PRM_URL,
      now: pcactn.iat,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.status).toBe(401);
      expect(res.errorDescription).toMatch(/RFC 9207/);
    }
  });

  it('denies an unknown grant_ref and a missing PCActn', async () => {
    const a = mkAgent();
    const { pcactn } = a.act('tickets.write', 'ticket:1', {}, { aud: AUD });
    const unknown = await authorizeRequest(bodyReq(pcactn), {
      resource: AUD,
      authorizationServers: [a.principalPublic],
      resolveGrant: () => null,
      prmUrl: PRM_URL,
      now: pcactn.iat,
    });
    expect(unknown.ok).toBe(false);
    if (!unknown.ok) expect(unknown.errorDescription).toMatch(/unknown grant_ref/);

    const missing = await authorizeRequest({ headers: {}, body: {} }, {
      resource: AUD,
      authorizationServers: [a.principalPublic],
      resolveGrant: resolveGrant(a.grant),
      prmUrl: PRM_URL,
    });
    expect(missing.ok).toBe(false);
    if (!missing.ok) {
      expect(missing.status).toBe(401);
      expect(missing.wwwAuthenticate).toContain('resource_metadata=');
    }
  });

  it('denies insufficient scope (403) — and scopes NARROW across the delegation chain', async () => {
    const a = mkAgent();
    const sub1 = a.subAgent({ addedCaveats: [{ type: 'scope', scopes: ['tickets:read', 'tickets:write'] }] });
    const sub2 = sub1.subAgent({ addedCaveats: [{ type: 'scope', scopes: ['tickets:read'] }] }); // narrowed: no write

    const base = (which: Agent) => {
      const { pcactn } = which.act('tickets.write', 'ticket:1', {}, { aud: AUD });
      return {
        req: bodyReq(pcactn),
        opts: {
          resource: AUD,
          authorizationServers: [a.principalPublic],
          resolveGrant: resolveGrant(a.grant),
          prmUrl: PRM_URL,
          tool: 'tickets.write',
          toolScopes: { 'tickets.write': 'tickets:write' },
          now: pcactn.iat,
        },
      };
    };

    const ok = await authorizeRequest(base(sub1).req, base(sub1).opts);
    expect(ok.ok).toBe(true);

    const narrowed = base(sub2);
    const denied = await authorizeRequest(narrowed.req, narrowed.opts);
    expect(denied.ok).toBe(false);
    if (!denied.ok) {
      expect(denied.status).toBe(403);
      expect(denied.error).toBe('insufficient_scope');
      expect(denied.wwwAuthenticate).toContain('scope="tickets:write"');
    }
  });

  it('a tampered PCActn (bad signature) is a 401 invalid_token', async () => {
    const a = mkAgent();
    const { pcactn } = a.act('tickets.write', 'ticket:1', {}, { aud: AUD });
    const tampered: PCActn = { ...pcactn, counter: pcactn.counter + 1 }; // breaks the leaf signature
    const res = await authorizeRequest(bodyReq(tampered), {
      resource: AUD,
      authorizationServers: [a.principalPublic],
      resolveGrant: resolveGrant(a.grant),
      prmUrl: PRM_URL,
      now: pcactn.iat,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.status).toBe(401);
      expect(res.error).toBe('invalid_token');
    }
  });

  it('a step-up-required tool returns the RFC 9470 step-up challenge; a co-signed PCActn is admitted', async () => {
    const a = mkAgent();
    const { pcactn } = a.act('tickets.delete', 'ticket:1', {}, { aud: AUD });
    const opts = {
      resource: AUD,
      authorizationServers: [a.principalPublic],
      resolveGrant: resolveGrant(a.grant),
      prmUrl: PRM_URL,
      tool: 'tickets.delete',
      toolStepUp: { 'tickets.delete': 2 as const },
      stepUpEndpoint: `${AUD}/v1/pca/stepup`,
      now: pcactn.iat,
    };

    const challenge = await authorizeRequest(bodyReq(pcactn), opts);
    expect(challenge.ok).toBe(false);
    if (!challenge.ok) {
      expect(challenge.status).toBe(401);
      expect(challenge.error).toBe('insufficient_user_authentication');
      expect(challenge.stepUp?.tier).toBe(2);
      expect(challenge.stepUp?.requiredRoles).toEqual(requiredRolesForTier(2));
      expect(challenge.wwwAuthenticate).toContain('PCA-StepUp');
      expect(challenge.wwwAuthenticate).toContain(`stepup_uri="${AUD}/v1/pca/stepup"`);
    }

    // re-present the SAME action carrying a guardian co-sign (threshold share) → admitted.
    const guardian = generateKeyPair();
    const coSigned: PCActn = {
      ...pcactn,
      threshold: {
        shares: [signShare('guardian', guardian.secretKey, thresholdMessage(pcactn), { signerSet: [{ role: 'guardian', publicKey: b64u(guardian.publicKey) }], t: 2 })],
      },
    };
    const admitted = await authorizeRequest(bodyReq(coSigned), opts);
    expect(admitted.ok).toBe(true);
  });

  it('derives the step-up tier from the risk claim (RFC 9470 step-up by risk)', async () => {
    const a = mkAgent();
    const { pcactn } = a.act('tickets.delete', 'ticket:1', {}, { aud: AUD }); // uncatalogued → blastRadius 0.8
    const res = await authorizeRequest(bodyReq(pcactn), {
      resource: AUD,
      authorizationServers: [a.principalPublic],
      resolveGrant: resolveGrant(a.grant),
      prmUrl: PRM_URL,
      riskTiers: { theta1: 0.3, theta2: 0.6 }, // 0.8 > theta2 → tier 3
      now: pcactn.iat,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.stepUp?.tier).toBe(3);
  });
});

// =====================================================================================================
// 6. extractPCActn
// =====================================================================================================

describe('extractPCActn', () => {
  it('reads the header form, the body form, and returns null when absent', () => {
    const a = mkAgent();
    const { pcactn, encoded } = a.act('tickets.write', 'ticket:1', {}, { aud: AUD });
    expect(extractPCActn({ headers: { 'pca-action': b64u(utf8(encoded)) } })?.grant_ref).toBe(pcactn.grant_ref);
    expect(extractPCActn(bodyReq(pcactn))?.grant_ref).toBe(pcactn.grant_ref);
    expect(extractPCActn({ headers: {}, body: {} })).toBeNull();
  });
});
