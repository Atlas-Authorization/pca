/** Mutation-kill tests for pca-mcp-rs (real crypto): PRM, challenge strings, CIMD, scopes, header forms, admission. */
import { describe, expect, it } from 'vitest';
import {
  type Capability,
  type PCActn,
  type PlanNode,
  b64u,
  buildDiscoveryDocument,
  buildPCActn,
  encodeKey,
  generateKeyPair,
  mintRoot,
  signShare,
  thresholdMessage,
  utf8,
} from '@atlasauth/pca';
import {
  SCOPE_CAVEAT,
  WELL_KNOWN_OAUTH_PRM,
  accumulateScopes,
  authorizeRequest,
  clientIdMetadataDocument,
  extractPCActn,
  isScopeCaveat,
  prmHandler,
  protectedResourceMetadata,
  requiredRolesForTier,
  verifyCimd,
  verifyStepUp,
  wwwAuthenticateChallenge,
} from './index';

const NOW = 1_800_000_000_000;
const AUD = 'https://api.acme.com';
const PRM = `${AUD}${WELL_KNOWN_OAUTH_PRM}`;
const thrown = (f: () => unknown): Error => {
  try {
    f();
  } catch (e) {
    return e as Error;
  }
  throw new Error('no throw');
};

describe('protectedResourceMetadata', () => {
  const base = { resource: AUD, authorizationServers: ['https://as'], scopesSupported: ['a'] };
  it('defaults: exact document', () => {
    const d = buildDiscoveryDocument({ audience: AUD });
    expect(protectedResourceMetadata(base)).toStrictEqual({
      resource: AUD,
      authorization_servers: ['https://as'],
      bearer_methods_supported: ['header'],
      scopes_supported: ['a'],
      client_id_metadata_document_supported: true,
      pca_action_header: 'PCA-Action',
      pca_signature_suites: d.signature_suites,
      pca_versions: [2],
      pca_configuration_endpoint: `${AUD}/.well-known/pca-configuration`,
      pca: d,
    });
    expect(d.signature_suites.length).toBeGreaterThan(0);
  });
  it('every option is forwarded; arrays are copies', () => {
    const o = {
      ...base,
      bearerMethodsSupported: ['header', 'body'] as ('header' | 'body')[],
      resourceName: 'RN',
      resourceDocumentation: 'https://doc',
      resourceSigningAlgValuesSupported: ['EdDSA'],
      pcaConfigurationEndpoint: 'https://x/cfg',
      signatureSuites: ['ed25519'],
      pcaVersions: [2, 3],
      actionHeader: 'X-A',
      requiredChecks: ['counter'],
      endpoints: { stepup: 'https://s' },
      trustedRoots: ['root'],
      metadata: { m: 1 },
    };
    const prm = protectedResourceMetadata(o);
    expect(prm).toStrictEqual({
      resource: AUD,
      authorization_servers: ['https://as'],
      bearer_methods_supported: ['header', 'body'],
      scopes_supported: ['a'],
      client_id_metadata_document_supported: true,
      pca_action_header: 'X-A',
      pca_signature_suites: ['ed25519'],
      pca_versions: [2, 3],
      pca_configuration_endpoint: 'https://x/cfg',
      pca: buildDiscoveryDocument({
        audience: AUD,
        signatureSuites: ['ed25519'],
        pcaVersions: [2, 3],
        actionHeader: 'X-A',
        requiredChecks: ['counter'],
        endpoints: { stepup: 'https://s' },
        trustedRoots: ['root'],
        metadata: { m: 1 },
      }),
      resource_name: 'RN',
      resource_documentation: 'https://doc',
      resource_signing_alg_values_supported: ['EdDSA'],
    });
    expect(prm.authorization_servers).not.toBe(o.authorizationServers);
    expect(prm.scopes_supported).not.toBe(o.scopesSupported);
    expect(prm.bearer_methods_supported).not.toBe(o.bearerMethodsSupported);
    expect(prm.resource_signing_alg_values_supported).not.toBe(o.resourceSigningAlgValuesSupported);
  });
  it('the configuration endpoint strips every trailing slash of the resource', () => {
    expect(protectedResourceMetadata({ ...base, resource: 'https://x///' }).pca_configuration_endpoint).toBe('https://x/.well-known/pca-configuration');
    expect(protectedResourceMetadata({ ...base, resource: 'https://x/a' }).pca_configuration_endpoint).toBe('https://x/a/.well-known/pca-configuration');
  });
  it('argument validation messages', () => {
    for (const resource of ['', 5 as never]) {
      expect(thrown(() => protectedResourceMetadata({ ...base, resource })).message).toBe('protectedResourceMetadata: `resource` (the RS id = PCActn audience) is required');
    }
    for (const authorizationServers of [[], undefined as never, 'x' as never]) {
      expect(thrown(() => protectedResourceMetadata({ ...base, authorizationServers })).message).toBe('protectedResourceMetadata: `authorizationServers` is required (RFC 9207 mix-up defense anchor)');
    }
    expect(thrown(() => protectedResourceMetadata({ ...base, scopesSupported: undefined as never })).message).toBe('protectedResourceMetadata: `scopesSupported` must be an array');
    expect(thrown(() => protectedResourceMetadata({ ...base, scopesSupported: 'a' as never })).message).toBe('protectedResourceMetadata: `scopesSupported` must be an array');
    expect(protectedResourceMetadata({ ...base, scopesSupported: [] }).scopes_supported).toStrictEqual([]);
    expect(prmHandler(base)).toStrictEqual({ path: '/.well-known/oauth-protected-resource', body: protectedResourceMetadata(base) });
  });
});

describe('wwwAuthenticateChallenge', () => {
  it('exact full string, parameter order and separators', () => {
    expect(
      wwwAuthenticateChallenge({
        resourceMetadataUrl: PRM,
        realm: 'R',
        error: 'insufficient_scope',
        errorDescription: 'need more',
        scope: 'a b',
        acrValues: 'pca:tier2',
        maxAge: 0,
      }),
    ).toBe(`Bearer realm="R", resource_metadata="${PRM}", error="insufficient_scope", error_description="need more", scope="a b", acr_values="pca:tier2", max_age=0`);
    expect(wwwAuthenticateChallenge({ resourceMetadataUrl: PRM })).toBe(`Bearer resource_metadata="${PRM}"`);
    expect(wwwAuthenticateChallenge({ resourceMetadataUrl: PRM, error: '', errorDescription: '', scope: '', acrValues: '', realm: '' })).toBe(`Bearer resource_metadata="${PRM}"`);
  });
  it('max_age: truncated, floored at zero, non-finite / non-number omitted', () => {
    const f = (maxAge: unknown) => wwwAuthenticateChallenge({ resourceMetadataUrl: PRM, maxAge: maxAge as number });
    expect(f(300.9)).toBe(`Bearer resource_metadata="${PRM}", max_age=300`);
    expect(f(-5)).toBe(`Bearer resource_metadata="${PRM}", max_age=0`);
    expect(f(7)).toBe(`Bearer resource_metadata="${PRM}", max_age=7`);
    for (const bad of [NaN, Infinity, '5', null, undefined]) expect(f(bad)).toBe(`Bearer resource_metadata="${PRM}"`);
  });
  it('step-up challenge appended as a second challenge', () => {
    const su = { tier: 3 as const, requiredRoles: ['principal' as const], reason: 'r', acr: 'pca:tier3', stepUpEndpoint: 'https://s/step' };
    expect(wwwAuthenticateChallenge({ resourceMetadataUrl: PRM, pcaStepUp: su })).toBe(
      `Bearer resource_metadata="${PRM}", PCA-StepUp realm="pca", tier="3", roles="principal", stepup_uri="https://s/step", acr="pca:tier3"`,
    );
    expect(wwwAuthenticateChallenge({ resourceMetadataUrl: PRM, realm: 'X', pcaStepUp: { ...su, requiredRoles: ['guardian', 'principal'], stepUpEndpoint: undefined, acr: '' } })).toBe(
      `Bearer realm="X", resource_metadata="${PRM}", PCA-StepUp realm="X", tier="3", roles="guardian principal"`,
    );
  });
  it('rejects empty / non-string URL and header injection in every parameter', () => {
    expect(thrown(() => wwwAuthenticateChallenge({ resourceMetadataUrl: '' })).message).toBe('wwwAuthenticateChallenge: resourceMetadataUrl is required');
    expect(thrown(() => wwwAuthenticateChallenge({ resourceMetadataUrl: 5 as never })).message).toBe('wwwAuthenticateChallenge: resourceMetadataUrl is required');
    const inj = 'pca-mcp-rs: a WWW-Authenticate parameter value may not contain a quote or newline';
    for (const bad of ['a"b', 'a\nb', 'a\rb']) {
      for (const k of ['realm', 'error', 'errorDescription', 'scope', 'acrValues'] as const) {
        expect(thrown(() => wwwAuthenticateChallenge({ resourceMetadataUrl: PRM, [k]: bad })).message).toBe(inj);
      }
      expect(thrown(() => wwwAuthenticateChallenge({ resourceMetadataUrl: bad })).message).toBe(inj);
      const su = { tier: 2 as const, requiredRoles: ['guardian' as const], reason: 'r', acr: 'a', stepUpEndpoint: 'e' };
      expect(thrown(() => wwwAuthenticateChallenge({ resourceMetadataUrl: PRM, pcaStepUp: { ...su, acr: bad } })).message).toBe(inj);
      expect(thrown(() => wwwAuthenticateChallenge({ resourceMetadataUrl: PRM, pcaStepUp: { ...su, stepUpEndpoint: bad } })).message).toBe(inj);
    }
  });
});

describe('clientIdMetadataDocument', () => {
  it('every optional field is carried; minimal has none', () => {
    expect(clientIdMetadataDocument({ clientId: 'https://c/x', redirectUris: ['https://c/cb'] })).toStrictEqual({ client_id: 'https://c/x', redirect_uris: ['https://c/cb'] });
    const r = ['https://c/cb'];
    const doc = clientIdMetadataDocument({
      clientId: 'https://c/x',
      redirectUris: r,
      clientName: 'N',
      clientUri: 'https://c',
      logoUri: 'https://c/l',
      scope: 's',
      contacts: ['a@b'],
      tosUri: 'https://c/t',
      policyUri: 'https://c/p',
      grantTypes: ['authorization_code'],
      responseTypes: ['code'],
      tokenEndpointAuthMethod: 'none',
    });
    expect(doc).toStrictEqual({
      client_id: 'https://c/x',
      redirect_uris: ['https://c/cb'],
      client_name: 'N',
      client_uri: 'https://c',
      logo_uri: 'https://c/l',
      scope: 's',
      contacts: ['a@b'],
      tos_uri: 'https://c/t',
      policy_uri: 'https://c/p',
      grant_types: ['authorization_code'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    });
    expect(doc.redirect_uris).not.toBe(r);
    expect(clientIdMetadataDocument({ clientId: 'https://c/x', redirectUris: r, clientName: '' }).client_name).toBe('');
  });
  it('validation messages', () => {
    for (const clientId of ['http://c/x', 'nope', '', 5 as never, new URL('https://c/x') as never]) {
      expect(thrown(() => clientIdMetadataDocument({ clientId, redirectUris: ['https://c/cb'] })).message).toBe('clientIdMetadataDocument: `clientId` must be an https URL (CIMD requires https)');
    }
    for (const redirectUris of [[], undefined as never]) {
      expect(thrown(() => clientIdMetadataDocument({ clientId: 'https://c/x', redirectUris })).message).toBe('clientIdMetadataDocument: at least one redirect URI is required');
    }
    for (const bad of ['http://evil/cb', 'not a uri', '', 5, new URL('https://c/cb')]) {
      expect(thrown(() => clientIdMetadataDocument({ clientId: 'https://c/x', redirectUris: ['https://c/cb', bad as never] })).message).toBe(`clientIdMetadataDocument: unsafe redirect URI ${JSON.stringify(bad)}`);
    }
  });
  it('redirect URI policy: https, loopback http, custom schemes', () => {
    const ok = (u: string) => clientIdMetadataDocument({ clientId: 'https://c/x', redirectUris: [u] }).redirect_uris[0];
    for (const u of ['https://a/cb', 'http://localhost:1/cb', 'http://127.0.0.1:8/cb', 'http://[::1]:9/cb', 'myapp://cb', 'com.example.app:/cb']) expect(ok(u)).toBe(u);
    for (const u of ['http://example.com/cb', 'http://localhost.evil.com/cb', 'http://127.0.0.2/cb']) expect(() => ok(u)).toThrow(/unsafe redirect URI/);
  });
});

describe('verifyCimd', () => {
  const doc = { client_id: 'https://c/x', redirect_uris: ['https://c/cb'] };
  it('string form', () => {
    expect(verifyCimd('https://c/x')).toStrictEqual({ ok: true, clientId: 'https://c/x' });
    expect(verifyCimd('https://c/x', { expectedClientId: 'https://c/x' })).toStrictEqual({ ok: true, clientId: 'https://c/x' });
    expect(verifyCimd('https://c/x', { expectedClientId: 'https://c/y' })).toStrictEqual({ ok: false, reason: 'client_id URL does not match the expected client_id' });
    for (const bad of ['http://c/x', 'nope', '']) {
      expect(verifyCimd(bad)).toStrictEqual({ ok: false, reason: 'client_id must be an https URL (CIMD requires https; http/malformed rejected)' });
    }
  });
  it('object form: reasons', () => {
    for (const bad of [null, 5, true, undefined]) {
      expect(verifyCimd(bad as never)).toStrictEqual({ ok: false, reason: 'CIMD must be a string URL or a metadata object' });
    }
    const idMsg = 'client_id must be an https URL (CIMD requires https)';
    for (const client_id of ['http://c/x', undefined, 5, '', new URL('https://c/x')]) {
      expect(verifyCimd({ ...doc, client_id } as never)).toStrictEqual({ ok: false, reason: idMsg });
    }
    expect(verifyCimd(doc, { expectedClientId: 'https://c/y' })).toStrictEqual({ ok: false, reason: 'document client_id does not match the URL it was fetched from (CIMD integrity)' });
    const ruMsg = 'redirect_uris is required and must be a non-empty array';
    for (const redirect_uris of [undefined, [], 'https://c/cb', {}]) {
      expect(verifyCimd({ ...doc, redirect_uris } as never)).toStrictEqual({ ok: false, reason: ruMsg });
    }
    for (const bad of ['http://evil/cb', 'not a uri', '', 5, new URL('https://c/cb'), null]) {
      expect(verifyCimd({ ...doc, redirect_uris: ['https://c/cb', bad] } as never)).toStrictEqual({ ok: false, reason: `unsafe or malformed redirect URI ${JSON.stringify(bad)}` });
    }
  });
  it('object form: accepted without expectedClientId, and typed optional members are validated', () => {
    expect(verifyCimd(doc)).toStrictEqual({ ok: true, clientId: 'https://c/x', doc: { client_id: 'https://c/x', redirect_uris: ['https://c/cb'] } });
    const full = {
      ...doc,
      client_name: 'N',
      client_uri: 'u1',
      logo_uri: 'u2',
      scope: 's',
      contacts: ['a', 'b'],
      tos_uri: 'u3',
      policy_uri: 'u4',
      grant_types: ['g'],
      response_types: ['r'],
      token_endpoint_auth_method: 'none',
      extra: 'dropped',
    };
    expect(verifyCimd(full, { expectedClientId: 'https://c/x' })).toStrictEqual({
      ok: true,
      clientId: 'https://c/x',
      doc: {
        client_id: 'https://c/x',
        redirect_uris: ['https://c/cb'],
        client_name: 'N',
        client_uri: 'u1',
        logo_uri: 'u2',
        scope: 's',
        contacts: ['a', 'b'],
        tos_uri: 'u3',
        policy_uri: 'u4',
        grant_types: ['g'],
        response_types: ['r'],
        token_endpoint_auth_method: 'none',
      },
    });
    // wrongly-typed members are dropped, mixed arrays are dropped, non-arrays are dropped
    const junk = {
      ...doc,
      client_name: 5,
      client_uri: 5,
      logo_uri: 5,
      scope: 5,
      contacts: ['a', 5],
      tos_uri: 5,
      policy_uri: 5,
      grant_types: ['g', 5],
      response_types: ['r', 5],
      token_endpoint_auth_method: 5,
    };
    expect(verifyCimd(junk)).toStrictEqual({ ok: true, clientId: 'https://c/x', doc: { client_id: 'https://c/x', redirect_uris: ['https://c/cb'] } });
    const notArrays = { ...doc, contacts: 'a', grant_types: 'g', response_types: 'r' };
    expect(verifyCimd(notArrays)).toStrictEqual({ ok: true, clientId: 'https://c/x', doc: { client_id: 'https://c/x', redirect_uris: ['https://c/cb'] } });
    expect(verifyCimd({ ...doc, contacts: [], grant_types: [], response_types: [] })).toMatchObject({ doc: { contacts: [], grant_types: [], response_types: [] } });
  });
});

describe('scope accumulation', () => {
  it('isScopeCaveat', () => {
    expect(SCOPE_CAVEAT).toBe('scope');
    expect(isScopeCaveat({ type: 'scope', scopes: ['a'] })).toBe(true);
    expect(isScopeCaveat({ type: 'scope', scopes: [] })).toBe(true);
    for (const bad of [null, undefined, 'scope', 5, { type: 'other', scopes: ['a'] }, { scopes: ['a'] }, { type: 'scope' }, { type: 'scope', scopes: 'a' }, { type: 'scope', scopes: ['a', 5] }, { type: 'scope', scopes: [5, 'a'] }]) {
      expect(isScopeCaveat(bad)).toBe(false);
    }
  });
  it('ignores junk, seeds from the first scope caveat, narrows, sorts', () => {
    const junk = [null, 'x', { type: 'other', scopes: ['zzz'] }, { type: 'scope' }, { type: 'scope', scopes: ['zzz', 5] }] as never[];
    expect(accumulateScopes(junk)).toStrictEqual([]);
    expect(accumulateScopes([...junk, { type: 'scope', scopes: ['z', 'a', 'm'] }])).toStrictEqual(['a', 'm', 'z']);
    expect(accumulateScopes([{ type: 'scope', scopes: ['z', 'a', 'm'] }, { type: 'scope', scopes: ['m', 'z', 'q'] }])).toStrictEqual(['m', 'z']);
    expect(accumulateScopes([{ type: 'scope', scopes: ['a'] }, { type: 'scope', scopes: [] }])).toStrictEqual([]);
  });
  it('base scopes: intersected, deduplicated and sorted; non-array caveats tolerated', () => {
    expect(accumulateScopes([], ['b', 'a', 'b'])).toStrictEqual(['a', 'b']);
    expect(accumulateScopes(undefined as never, ['b', 'a'])).toStrictEqual(['a', 'b']);
    expect(accumulateScopes([{ type: 'scope', scopes: ['c', 'b'] }], ['b', 'c', 'd'])).toStrictEqual(['b', 'c']);
    expect(accumulateScopes([], [])).toStrictEqual([]);
    expect(accumulateScopes([{ type: 'scope', scopes: ['a'] }], [])).toStrictEqual([]);
  });
  it('requiredRolesForTier', () => {
    expect(requiredRolesForTier(2)).toStrictEqual(['guardian', 'principal']);
    expect(requiredRolesForTier(3)).toStrictEqual(['principal']);
  });
});

// ---------------------------------------------------------------------------------------------------
// extractPCActn
// ---------------------------------------------------------------------------------------------------

const P = generateKeyPair();
const A = generateKeyPair();
const mkGrant = (caveats: Record<string, unknown>[] = [{ type: 'ttl', secs: 3600 }]): Capability =>
  mintRoot({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), caveats: caveats as never });
const plan: PlanNode[] = [{ id: 'n1', verb: 'tickets.write', resource: 'ticket:1', reversibility_class: 'reversible' }];
const mkAct = (grant: Capability, counter = 1, aud = AUD): PCActn =>
  buildPCActn({ grant, chain: [grant], plan, nodeId: 'n1', counter, signerSecret: A.secretKey, aud, now: NOW });
const enc = (p: PCActn): string => b64u(utf8(JSON.stringify(p)));

describe('extractPCActn', () => {
  const grant = mkGrant();
  const p = mkAct(grant);
  const e = enc(p);
  it('header forms: record (any case, array value, trimmed) and Headers-like', () => {
    expect(extractPCActn({ headers: { 'PCA-Action': e } })).toStrictEqual(JSON.parse(JSON.stringify(p)));
    expect(extractPCActn({ headers: { 'pca-action': e } })).toBeTruthy();
    expect(extractPCActn({ headers: { 'Pca-Action': e } })).toBeTruthy();
    expect(extractPCActn({ headers: { 'PCA-ACTION': [e, 'junk'] } })).toBeTruthy();
    expect(extractPCActn({ headers: { 'PCA-Action': `  ${e}\n` } })).toBeTruthy();
    expect(extractPCActn({ headers: new Headers({ 'PCA-Action': e }) })).toBeTruthy();
    expect(extractPCActn({ headers: { get: (n: string) => (n === 'pca-action' ? e : null) } })).toBeTruthy();
    expect(extractPCActn({ headers: { get: (n: string) => (n === 'PCA-ACTION' ? e : null) } })).toBeNull();
  });
  it('record scan: only a matching key with a usable value counts, direct key wins', () => {
    expect(extractPCActn({ headers: { 'x-other': 'junk', 'PCA-ACTION': e } })).toBeTruthy();
    expect(extractPCActn({ headers: { 'PCA-ACTION': 5 as never, 'Pca-Action': e } })).toBeTruthy();
    expect(extractPCActn({ headers: { 'PCA-ACTION': 'junk-not-b64!!', 'pca-action': e } })).toBeTruthy();
    expect(extractPCActn({ headers: { 'x-other': e } })).toBeNull();
    expect(extractPCActn({ headers: { 'PCA-Action': undefined } })).toBeNull();
  });
  it('an empty header falls through to the body', () => {
    expect(extractPCActn({ headers: { 'PCA-Action': '' }, body: { pcactn: p } })).toBe(p);
    expect(extractPCActn({ headers: { 'PCA-Action': '' } })).toBeNull();
  });
  it('body forms', () => {
    expect(extractPCActn({ headers: {}, body: { pcactn: p } })).toBe(p);
    expect(extractPCActn({ headers: {}, body: JSON.stringify({ pcactn: p }) })).toStrictEqual(JSON.parse(JSON.stringify(p)));
    expect(extractPCActn({ headers: {}, body: { pcactn: JSON.stringify(p) } })).toStrictEqual(JSON.parse(JSON.stringify(p)));
    expect(extractPCActn({ headers: {}, body: { pcactn: null } })).toBeNull();
    expect(extractPCActn({ headers: {}, body: { pcactn: 5 } })).toBeNull();
    expect(extractPCActn({ headers: {} })).toBeNull();
    expect(extractPCActn({ headers: {}, body: null })).toBeNull();
    expect(extractPCActn({ headers: {}, body: '' })).toBeNull();
    expect(extractPCActn({ headers: {}, body: 5 })).toBeNull();
    expect(extractPCActn({ headers: {}, body: [JSON.stringify({ pcactn: p })] })).toBeNull();
    expect(() => extractPCActn({ headers: {}, body: 'not json' })).toThrow();
    expect(() => extractPCActn({ headers: { 'PCA-Action': '!!!' } })).toThrow();
  });
});

// ---------------------------------------------------------------------------------------------------
// authorizeRequest
// ---------------------------------------------------------------------------------------------------

describe('authorizeRequest', () => {
  const grant = mkGrant([{ type: 'ttl', secs: 3600 }, { type: 'scope', scopes: ['tickets:write', 'tickets:read'] }]);
  const p = mkAct(grant);
  const req = { headers: {}, body: { pcactn: p } };
  const base = {
    resource: AUD,
    authorizationServers: [grant.issuer],
    resolveGrant: (ref: string) => (ref === grant.id ? grant : null),
    prmUrl: PRM,
    now: NOW,
  };
  const deny = async (r: unknown, o: Record<string, unknown> = {}) => {
    const res = await authorizeRequest(r as never, { ...base, ...o } as never);
    if (res.ok) throw new Error('expected a deny');
    return res;
  };

  it('admits and returns the exact allow shape', async () => {
    const r = await authorizeRequest(req, { ...base, tool: 'tickets.write', toolScopes: { 'tickets.write': 'tickets:write' } });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.status).toBe(200);
      expect(r.pcactn).toBe(p);
      expect(r.grant).toBe(grant);
      expect(r.grantedScopes).toStrictEqual(['tickets:read', 'tickets:write']);
      expect(r.checks.leaf_signature).toBe('pass');
    }
  });
  it('the verifier clock is opts.now (not the wall clock)', async () => {
    expect((await authorizeRequest(req, base)).ok).toBe(true);
    const wall = await deny(req, { now: undefined });
    expect(wall.status).toBe(401);
  });
  it('config errors fail closed with the exact message', async () => {
    const pre = 'admission error (fail closed): ';
    for (const resource of ['', 5]) {
      const d = await deny(req, { resource });
      expect([d.status, d.error, d.errorDescription]).toStrictEqual([403, 'forbidden', `${pre}authorizeRequest: \`resource\` is required`]);
    }
    for (const authorizationServers of [[], undefined, 'x']) {
      const d = await deny(req, { authorizationServers });
      expect([d.status, d.error, d.errorDescription]).toStrictEqual([403, 'forbidden', `${pre}authorizeRequest: \`authorizationServers\` is required (RFC 9207)`]);
    }
    const d = await deny(req, { resolveGrant: () => { throw 'boom'; } });
    expect(d.errorDescription).toBe(`${pre}unknown`);
    const d2 = await deny(req, { resolveGrant: () => { throw new Error('kaboom'); } });
    expect(d2.errorDescription).toBe(`${pre}kaboom`);
  });
  it('extraction failures', async () => {
    const none = await deny({ headers: {}, body: {} });
    expect([none.status, none.error, none.errorDescription]).toStrictEqual([401, 'invalid_request', 'no PCActn presented (PCA-Action header or {pcactn} body)']);
    for (const r of [{ headers: {} }, { headers: {}, body: '' }, { headers: {}, body: null }]) {
      expect((await deny(r)).error).toBe('invalid_request');
    }
    const bad = await deny({ headers: { 'PCA-Action': '!!!' } });
    expect([bad.status, bad.error]).toStrictEqual([401, 'invalid_request']);
    expect(bad.errorDescription).toMatch(/^unreadable PCActn: .+/);
    const bad2 = await deny({ headers: {}, body: 'not json' });
    expect(bad2.errorDescription).toMatch(/^unreadable PCActn: .+/);
    expect(bad2.wwwAuthenticate).toContain('error="invalid_request"');
    // attacker-influenced decoder messages with quotes / newlines must not break the header or the status
    expect(bad2.errorDescription).toContain('"');
    expect(bad2.wwwAuthenticate).not.toMatch(/error_description="[^"]*"[^,]/);
    const q = await deny(req, { resolveGrant: () => { throw new Error('has "quote"\nand newline'); } });
    expect([q.status, q.error]).toStrictEqual([403, 'forbidden']);
    expect(q.errorDescription).toBe('admission error (fail closed): has "quote"\nand newline');
    expect(q.wwwAuthenticate).toContain('error_description="admission error (fail closed): has  quote  and newline"');
  });
  it('malformed PCActn / unknown grant / audience / issuer', async () => {
    for (const x of [{}, { grant_ref: 5 }]) {
      const d = await deny({ headers: {}, body: { pcactn: x } });
      expect([d.status, d.error, d.errorDescription]).toStrictEqual([401, 'invalid_token', 'malformed PCActn']);
    }
    for (const g of [null, undefined]) {
      const d = await deny(req, { resolveGrant: () => g });
      expect([d.status, d.error, d.errorDescription]).toStrictEqual([401, 'invalid_token', 'unknown grant_ref']);
    }
    const asyncGrant = await authorizeRequest(req, { ...base, resolveGrant: async () => grant });
    expect(asyncGrant.ok).toBe(true);
    const aud = await deny(req, { resource: 'https://other' });
    expect([aud.status, aud.error, aud.errorDescription]).toStrictEqual([401, 'invalid_token', `RFC 8707: PCActn audience (${AUD}) is not this resource server (https://other)`]);
    const iss = await deny(req, { authorizationServers: ['https://evil'] });
    expect([iss.status, iss.error, iss.errorDescription]).toStrictEqual([401, 'invalid_token', `RFC 9207: credential issuer (${grant.issuer}) is not an expected authorization server`]);
    const custom = await deny(req, { resolveIssuer: () => 'https://custom' });
    expect(custom.errorDescription).toBe('RFC 9207: credential issuer (https://custom) is not an expected authorization server');
    expect((await authorizeRequest(req, { ...base, authorizationServers: ['https://custom'], resolveIssuer: () => 'https://custom' })).ok).toBe(true);
  });
  it('core failures: a tampered proof is a 401 carrying the checks and the core reason', async () => {
    const tampered = { ...p, counter: p.counter + 1 };
    const d = await deny({ headers: {}, body: { pcactn: tampered } });
    expect([d.status, d.error]).toStrictEqual([401, 'invalid_token']);
    expect(d.checks?.leaf_signature).toBe('fail');
    expect(d.errorDescription).toMatch(/leaf_signature/);
    expect(d.errorDescription).not.toBe('PCActn verification failed');
    expect(d.wwwAuthenticate).toContain('error="invalid_token"');
    expect('stepUp' in d).toBe(false);
  });
  it('scope enforcement: exact message, header and checks', async () => {
    const d = await deny(req, { requiredScopes: ['tickets:write', 'admin', 'root'] });
    expect([d.status, d.error, d.errorDescription]).toStrictEqual([403, 'insufficient_scope', 'missing required scope(s): admin root']);
    expect(d.wwwAuthenticate).toContain('scope="tickets:write admin root"');
    expect(d.checks?.leaf_signature).toBe('pass');
    // requiredScopes overrides toolScopes (and an empty list needs nothing)
    expect((await authorizeRequest(req, { ...base, requiredScopes: [], tool: 't', toolScopes: { t: 'zzz' } })).ok).toBe(true);
    // an unmapped tool needs nothing; a tool without a map needs nothing
    expect((await authorizeRequest(req, { ...base, tool: 'unmapped', toolScopes: { other: 'zzz' } })).ok).toBe(true);
    expect((await authorizeRequest(req, { ...base, tool: 'tickets.write' })).ok).toBe(true);
    // no tool given: nothing is looked up even if a key spelled 'undefined' exists
    expect((await authorizeRequest(req, { ...base, toolScopes: { undefined: 'zzz' } })).ok).toBe(true);
    // string and array forms
    expect((await authorizeRequest(req, { ...base, tool: 't', toolScopes: { t: ['tickets:read', 'tickets:write'] } })).ok).toBe(true);
    expect((await deny(req, { tool: 't', toolScopes: { t: 'zzz' } })).errorDescription).toBe('missing required scope(s): zzz');
  });
  it('granted scopes: baseScopes intersect, resolveGrantedScopes overrides', async () => {
    const plain = mkGrant();
    const pp = mkAct(plain);
    const o = { ...base, authorizationServers: [plain.issuer], resolveGrant: () => plain };
    const r = await authorizeRequest({ headers: {}, body: { pcactn: pp } }, { ...o, baseScopes: ['b', 'a'], requiredScopes: ['a'] });
    expect(r.ok && r.grantedScopes).toStrictEqual(['a', 'b']);
    expect((await authorizeRequest({ headers: {}, body: { pcactn: pp } }, { ...o, requiredScopes: ['a'] })).ok).toBe(false);
    let seen: unknown[] = [];
    const rr = await authorizeRequest(req, { ...base, requiredScopes: ['x'], resolveGrantedScopes: (...a: unknown[]) => { seen = a; return ['x']; } });
    expect(rr.ok && rr.grantedScopes).toStrictEqual(['x']);
    expect(seen[0]).toBe(grant);
    expect(seen[1]).toStrictEqual(p.cap_chain);
    expect(seen[2]).toBe(p);
  });

  describe('step-up', () => {
    const guardian = generateKeyPair();
    const signerSet = [
      { role: 'agent' as const, publicKey: b64u(A.publicKey) },
      { role: 'guardian' as const, publicKey: b64u(guardian.publicKey) },
      { role: 'principal' as const, publicKey: b64u(P.publicKey) },
    ];
    const coSign = (t: 2 | 3, roles: ('guardian' | 'principal')[]): PCActn => ({
      ...p,
      threshold: { shares: roles.map((r) => signShare(r, (r === 'guardian' ? guardian : P).secretKey, thresholdMessage(p), { signerSet, t })) },
    });
    const su = { ...base, tool: 'tickets.write', toolStepUp: { 'tickets.write': 2 as const }, stepUpSignerSet: signerSet, stepUpEndpoint: 'https://s/step' };

    it('tier 2 challenge: exact shape', async () => {
      const d = await deny(req, su);
      expect([d.status, d.error]).toStrictEqual([401, 'insufficient_user_authentication']);
      expect(d.stepUp).toStrictEqual({
        tier: 2,
        requiredRoles: ['guardian', 'principal'],
        reason: 'this action requires a tier-2 guardian co-sign; drive the step-up and re-present a PCActn carrying the threshold',
        acr: 'pca:tier2',
        stepUpEndpoint: 'https://s/step',
      });
      expect(d.errorDescription).toBe(d.stepUp!.reason);
      expect(d.checks?.leaf_signature).toBe('pass');
      expect(d.wwwAuthenticate).toBe(
        `Bearer realm="pca", resource_metadata="${PRM}", error="insufficient_user_authentication", error_description="${d.stepUp!.reason}", acr_values="pca:tier2", max_age=0, PCA-StepUp realm="pca", tier="2", roles="guardian principal", stepup_uri="https://s/step", acr="pca:tier2"`,
      );
    });
    it('tier 3 reason, no endpoint key when none advertised, custom realm', async () => {
      const { stepUpEndpoint: _e, ...noEp } = su;
      const d = await deny(req, { ...noEp, toolStepUp: { 'tickets.write': 3 }, realm: 'RR' });
      expect(d.stepUp).toStrictEqual({
        tier: 3,
        requiredRoles: ['principal'],
        reason: 'this action requires a tier-3 principal (human) co-sign; drive the step-up and re-present a PCActn carrying the threshold',
        acr: 'pca:tier3',
      });
      expect(d.wwwAuthenticate).toContain('realm="RR"');
      expect(d.wwwAuthenticate).toContain('PCA-StepUp realm="RR"');
      expect(d.wwwAuthenticate).not.toContain('stepup_uri');
    });
    it('a verified co-sign admits; verifyStepUp is cryptographic', async () => {
      expect((await authorizeRequest({ headers: {}, body: { pcactn: coSign(2, ['guardian']) } }, su as never)).ok).toBe(true);
      expect(await verifyStepUp(coSign(2, ['guardian']), 2, grant, signerSet)).toBe(true);
      expect(await verifyStepUp(coSign(2, ['guardian']), 2, grant, signerSet, NOW)).toBe(true);
      expect(await verifyStepUp(p, 2, grant, signerSet)).toBe(false);
      expect(await verifyStepUp(coSign(3, ['guardian']), 3, grant, signerSet)).toBe(false);
      expect(await verifyStepUp(coSign(3, ['guardian', 'principal']), 3, grant, signerSet)).toBe(true);
    });
    it('stepUpSatisfied must return exactly true, and receives (pcactn, tier); the verifier is not consulted', async () => {
      const calls: unknown[][] = [];
      const mk = (v: unknown) => ({ ...su, stepUpSignerSet: undefined, stepUpSatisfied: (...a: unknown[]) => { calls.push(a); return v; } });
      expect((await authorizeRequest(req, mk(true) as never)).ok).toBe(true);
      expect(calls[0]![0]).toBe(p);
      expect(calls[0]![1]).toBe(2);
      expect((await authorizeRequest(req, mk(Promise.resolve(true)) as never)).ok).toBe(true);
      for (const v of [false, 'yes', 1, undefined]) expect((await authorizeRequest(req, mk(v) as never)).ok).toBe(false);
    });
    it('a tier with no verifier fails closed', async () => {
      const { stepUpSignerSet: _s, ...none } = su;
      const d = await deny(req, none);
      expect(d.errorDescription).toBe('admission error (fail closed): authorizeRequest: a step-up tier applies but neither `stepUpSignerSet` nor `stepUpSatisfied` is configured (no presence-check default)');
    });
    it('tier sources: toolStepUp needs a tool, own-property lookup, requiredTier, max rule', async () => {
      const { tool: _t, ...noTool } = su;
      expect((await deny(req, noTool)).errorDescription).toBe('admission error (fail closed): authorizeRequest: `toolStepUp` is configured but no `tool` was passed, so the per-tool step-up tier cannot be applied (fail closed)');
      // a prototype-chain name is not a configured tool
      expect((await authorizeRequest(req, { ...su, tool: 'constructor' } as never)).ok).toBe(true);
      expect((await authorizeRequest(req, { ...su, tool: 'unmapped' } as never)).ok).toBe(true);
      // requiredTier alone applies, and is not lowered by a missing per-tool entry
      expect((await deny(req, { ...su, toolStepUp: {}, requiredTier: 2 })).stepUp?.tier).toBe(2);
      expect((await deny(req, { ...su, toolStepUp: { other: 3 }, requiredTier: 3 })).stepUp?.tier).toBe(3);
      // max rule in both directions
      expect((await deny(req, { ...su, requiredTier: 3 })).stepUp?.tier).toBe(3);
      expect((await deny(req, { ...su, toolStepUp: { 'tickets.write': 3 }, requiredTier: 2 })).stepUp?.tier).toBe(3);
      expect((await deny(req, { ...su, toolStepUp: { 'tickets.write': 2 }, requiredTier: 2 })).stepUp?.tier).toBe(2);
    });
    it('risk tiers: server-computed r selects the tier; missing serverRisk is a config error', async () => {
      const calls: number[] = [];
      const o = (r: unknown) => ({ ...su, toolStepUp: undefined, riskTiers: { theta1: 0.3, theta2: 0.6 }, serverRisk: () => r, stepUpSatisfied: (_p: unknown, t: number) => { calls.push(t); return false; } });
      // low risk: no step-up at all
      expect((await authorizeRequest(req, o(0.1) as never)).ok).toBe(true);
      expect(calls).toStrictEqual([]);
      expect((await authorizeRequest(req, o(0.3) as never)).ok).toBe(true);
      expect((await deny(req, o(0.5))).stepUp?.tier).toBe(2);
      expect((await deny(req, o(0.9))).stepUp?.tier).toBe(3);
      // an unusable r fails closed to the highest tier
      for (const bad of [NaN, Infinity, '0.1', null, undefined]) expect((await deny(req, o(bad))).stepUp?.tier).toBe(3);
      const { serverRisk: _r, ...noRisk } = o(0.1);
      expect((await deny(req, noRisk)).errorDescription).toBe('admission error (fail closed): authorizeRequest: `riskTiers` needs a server-computed `serverRisk` (the agent-signed risk_claim.r is never used)');
      // async serverRisk
      expect((await deny(req, { ...o(0), serverRisk: async () => 0.9 })).stepUp?.tier).toBe(3);
    });
  });
});
