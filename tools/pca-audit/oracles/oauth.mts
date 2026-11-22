// Oracle: @atlasauth/pca-oauth (RFC 9728 metadata, MCP 401 challenges, RFC 8707 resource indicators, pca_grant details,
// scopes derived from the confirmed action). Deterministic. Writes out/ref-oauth.json.gz.
// Every fn takes JSON args; an options object uses the TS option names (camelCase). Compare by JSON value; a throw only
// requires the native to refuse (the message is not part of the contract).
import * as M0 from '@atlasauth/pca-oauth';
import { Oracle, refWrite } from './lib.mjs';

const M: any = (M0 as any).default ?? M0;
const o = new Oracle('oauth', 'tools/pca-audit/oracles/oauth.mts', 'TS-reference oracle for the OAuth / MCP-authorization bridge.');

const URLS = [
  'https://rs.example.com', 'https://rs.example.com/', 'https://rs.example.com/mcp', 'https://rs.example.com/mcp/', 'https://rs.example.com/a/b?x=1',
  'https://RS.Example.com:443/Mcp', 'https://rs.example.com:8443/mcp', 'https://rs.example.com/a/../b', 'https://rs.example.com/a%20b', 'https://rs.example.com/?',
  'https://rs.example.com/m#frag', 'http://rs.example.com/mcp', 'rs.example.com/mcp', '', 'https://', 'ftp://x.example/a', 'https://rs.example.com/a?q=1&r=2',
  'https://u:p@rs.example.com/x', 'https://rs.example.com//double', 'https://[::1]/x',
];
const BAD: any[] = [null, 1, true, [], {}];
for (const [i, u] of [...URLS, ...BAD].entries()) await o.run('resourceIdentifierProblem', `u${i}`, M.resourceIdentifierProblem, [u]);
for (const [i, u] of URLS.entries()) {
  await o.run('prmPathForResource', `u${i}`, M.prmPathForResource, [u]);
  if (M.resourceIdentifierProblem(u) === undefined) await o.run('prmUrlForResource', `u${i}`, M.prmUrlForResource, [u]);
}

const optsList: any[] = [
  { resource: 'https://rs.example.com/mcp' },
  { resource: 'https://rs.example.com' },
  { resource: 'https://rs.example.com/mcp/?a=1' },
  { resource: 'http://localhost:3000/mcp', strict: false },
  { resource: 'http://localhost:3000/mcp' },
  { resource: '' },
  { resource: 'https://rs.example.com/x#f' },
  {
    resource: 'https://rs.example.com/tools', authorizationServers: ['https://as.example.com'], bearerMethodsSupported: ['header', 'body'],
    resourceDocumentation: 'https://docs.example.com', scopesSupported: ['read', 'write'], resourceName: 'Tools',
    resourceSigningAlgValuesSupported: ['EdDSA'], authorizationDetailsTypesSupported: ['pca_grant'], pcaConfigurationEndpoint: 'https://rs.example.com/cfg',
    signatureSuites: ['ed25519'], pcaVersions: [1, 2], actionHeader: 'X-PCA', requiredChecks: ['replay'], endpoints: { stepup: 'https://rs.example.com/stepup' },
    trustedRoots: ['root1'], metadata: { a: 1, b: [true] },
  },
  { resource: 'https://rs.example.com/t', authorizationServers: [], scopesSupported: [], resourceDocumentation: '', resourceName: '' },
];
for (const [i, op] of optsList.entries()) {
  await o.run('protectedResourceMetadata', `o${i}`, M.protectedResourceMetadata, [op]);
  await o.run('oauthDiscoveryHandler', `o${i}`, M.oauthDiscoveryHandler, [op]);
}

const good = M.protectedResourceMetadata(optsList[7]);
const docs: any[] = [
  good, M.protectedResourceMetadata(optsList[0]), M.protectedResourceMetadata(optsList[3]), null, 'x', [], {},
  { ...good, resource: '' }, { ...good, bearer_methods_supported: 'header' }, { ...good, bearer_methods_supported: ['cookie'] },
  { ...good, bearer_methods_supported: [1] }, { ...good, pca_action_header: '' }, { ...good, pca_signature_suites: [1] },
  { ...good, pca_versions: ['2'] }, { ...good, pca: null }, { ...good, pca: { audience: '' } }, { ...good, pca: { ...good.pca, audience: 'https://other.example' } },
  { ...good, authorization_servers: [1] }, { ...good, scopes_supported: 'read' }, { ...good, resource_name: 5 }, { ...good, resource: 'http://rs.example.com/tools' },
  { ...good, resource_signing_alg_values_supported: [1] }, { ...good, pca_configuration_endpoint: 7 }, { ...good, extra: 1 },
];
const popts: any[] = [undefined, {}, { strict: false }, { expectedResource: 'https://rs.example.com/tools' }, { expectedResource: 'https://rs.example.com/mcp' },
  { expectedResource: 'https://rs.example.com/tools', strict: false }, { expectedResource: 'http://localhost:3000/mcp', strict: false }, { expectedResource: 'http://localhost:3000/mcp' }];
for (const [i, d] of docs.entries()) for (const [j, p] of popts.entries()) await o.run('parseProtectedResourceMetadata', `d${i}p${j}`, M.parseProtectedResourceMetadata, p === undefined ? [d] : [d, p]);

const NEED = { v: 1, kind: 'scope', verb: 'files.read', resource: 'files/a', scopes: ['files:read'] };
const wopts: any[] = [
  undefined, {}, { error: 'invalid_token' }, { error: 'insufficient_scope', errorDescription: 'need more', scope: 'a b' }, { includePca: false },
  { realm: 'r' }, { hint: '' }, { hint: 'h', realm: 'x' }, { pcaChallenge: 'PCA realm="custom"' }, { pcaChallenge: 'bad\nline' }, { pcaChallenge: 'tab\tok' },
  { error: 'a"b' }, { errorDescription: 'x\\y' }, { scope: '\u007f' }, { pcaNeed: NEED }, { pcaNeed: { ...NEED, v: 2 } }, { pcaNeed: { v: 1, kind: 'escalate', verb: 'v', resource: 'r', tier: 2 } },
  { realm: 'é' }, { error: '' }, { includePca: false, pcaChallenge: 'X' },
];
for (const [i, w] of wopts.entries()) {
  for (const [j, u] of ['https://rs.example.com/.well-known/oauth-protected-resource/mcp', '', 'https://x/"q'].entries()) {
    const a = w === undefined ? [u] : [u, w];
    await o.run('wwwAuthenticate', `w${i}u${j}`, M.wwwAuthenticate, a);
    await o.run('mcpUnauthorized', `w${i}u${j}`, M.mcpUnauthorized, a);
    for (const [k, r] of [{}, { wwwAuthenticate: 'PCA realm="pca", error="x"' }, { wwwAuthenticate: '' }, { status: 401, wwwAuthenticate: 'a\nb' }].entries()) {
      await o.run('upgradeUnauthorizedChallenge', `w${i}u${j}r${k}`, M.upgradeUnauthorizedChallenge, [r, u, ...(w === undefined ? [] : [w])]);
    }
  }
}

const AUD = 'https://rs.example.com/mcp';
const RES: any[] = [undefined, null, AUD, 'https://other', '', [], [AUD], ['', AUD], [1, AUD], ['https://a', 'https://b'], 5, [null]];
for (const [i, r] of RES.entries()) for (const [j, a] of [AUD, ''].entries()) {
  await o.run('checkResourceIndicator', `r${i}a${j}`, M.checkResourceIndicator, [r ?? null, a]);
  await o.run('checkTokenAudience', `r${i}a${j}`, M.checkTokenAudience, [r ?? null, a]);
}
await o.run('checkTokenAudience', 'obj', M.checkTokenAudience, [{ a: 1 }, AUD]);

const gopts: any[] = [
  { chainIds: ['c1', 'c2'] }, { chainIds: [] }, { chainIds: ['c1'], chainRef: 'https://rs.example.com/chain/1', bundleRevision: 3, locations: ['https://rs.example.com/mcp'] },
  { chainIds: ['c1'], locations: [] }, { chainIds: ['c1'], bundleRevision: -1 }, { chainIds: ['c1'], bundleRevision: 1.5 }, { chainIds: ['c1'], chainRef: 'http://x' },
  { chainIds: ['c1'], locations: ['ftp://x'] }, { chainIds: [''] }, { chainIds: ['a'.repeat(300)] }, { chainIds: Array.from({ length: 40 }, (_, i) => `c${i}`) },
];
const details: any[] = [];
for (const [i, g] of gopts.entries()) {
  await o.run('buildPcaGrantDetail', `g${i}`, M.buildPcaGrantDetail, [g]);
  try { details.push(M.buildPcaGrantDetail(g)); } catch { /* refused */ }
}
for (const [i, d] of [[], details.slice(0, 1), details, [{ type: 'x' }]].entries()) await o.run('pcaGrantRequestParam', `p${i}`, M.pcaGrantRequestParam, [d]);

const authz: any[] = [];
for (const ad of [details.slice(0, 1), details.slice(1, 2), details, [], null, 'x', [{ type: 'pca_grant' }], [{ type: 'other' }, ...details.slice(0, 1)]]) {
  for (const chainIds of [['c1', 'c2'], ['c1'], []]) for (const resource of ['https://rs.example.com/mcp', 'https://evil.example']) for (const proofVerified of [true, false]) {
    authz.push({ authorizationDetails: ad, resource, chainIds, proofVerified });
  }
}
for (const [i, a] of authz.entries()) await o.run('authorizePcaGrantToken', `a${i}`, M.authorizePcaGrantToken, [a]);

const ACT = { verb: 'repo.read', def_digest: 'd1', confirmed: true, upstream: { provider: 'github', scopes_min: ['repo', 'read:org', 'repo'] } };
const acts: any[] = [ACT, undefined, null, { ...ACT, confirmed: false }, { ...ACT, upstream: { provider: 'gitlab', scopes_min: ['x'] } }, { ...ACT, upstream: { provider: 'github', scopes_min: [] } },
  { ...ACT, upstream: { provider: 'github', scopes_min: ['a b'] } }, { ...ACT, upstream: { provider: 'github', scopes_min: ['a"'] } }, { ...ACT, upstream: { provider: 'github', scopes_min: [1] } },
  { ...ACT, upstream: { provider: 'github', scopes_min: ['x'.repeat(257)] } }, { ...ACT, upstream: null }, { ...ACT, upstream: { provider: 'github', scopes_min: ['b', 'a', 'B'] } }];
const sopts: any[] = [{ provider: 'github' }, { provider: 'github', granted: ['repo', 'read:org'] }, { provider: 'github', granted: ['repo'] }, { provider: 'github', resource: AUD }, { provider: 'github', granted: [] }];
for (const [i, a] of acts.entries()) for (const [j, s] of sopts.entries()) await o.run('oauthScopeForAction', `a${i}s${j}`, M.oauthScopeForAction, [a ?? null, s]);

refWrite(o, 'oauth');
