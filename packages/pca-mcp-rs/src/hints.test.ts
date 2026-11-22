import { describe, expect, it } from 'vitest';
import { agent, generateKeyPair, pcaHeaders, type Capability } from '@atlasauth/pca';
import { WELL_KNOWN_OAUTH_PRM, admitRequest, type AdmissionOptions } from './index';

/**
 * `AuthorizeDeny.hint`: a developer suggestion for the common configuration mistake behind a denial. Additive: the status,
 * error, errorDescription and WWW-Authenticate challenge are unchanged, and an allow carries no hint.
 */
const AUD = 'https://mcp.example.com';

function setup() {
  const a = agent({ principal: generateKeyPair(), goal: 'process refunds', permissions: { stripe: ['refund'] }, aud: AUD });
  const grants = new Map<string, Capability>([[a.grant.id, a.grant]]);
  const opts: AdmissionOptions = {
    resource: AUD,
    authorizationServers: [a.grant.issuer],
    resolveGrant: (ref) => grants.get(ref) ?? null,
    prmUrl: `${AUD}${WELL_KNOWN_OAUTH_PRM}`, insecureSkipPlanRootCheck: true,
  };
  return { a, opts };
}

describe('admitRequest denial hints', () => {
  it('no hint on an allow', async () => {
    const { a, opts } = setup();
    const r = await admitRequest({ headers: pcaHeaders(a.act('stripe.refund', 'charge:ch_1', { amount: 1 }).encoded) }, opts);
    expect(r.ok).toBe(true);
    expect('hint' in r).toBe(false);
  });

  it('missing and unreadable header point at pcaHeaders()', async () => {
    const { a, opts } = setup();
    const none = await admitRequest({ headers: {} }, opts);
    expect(!none.ok && none.hint).toMatch(/pcaHeaders\(encoded\)/);
    expect(!none.ok && none.errorDescription).toBe('no PCActn presented (PCA-Action header or {pcactn} body)');
    const raw = await admitRequest({ headers: { 'PCA-Action': a.act('stripe.refund', 'charge:ch_1', {}).encoded } }, opts);
    expect(!raw.ok && raw.hint).toMatch(/not the raw encoded JSON/);
  });

  it('unknown grant, wrong audience, URL-only issuer allowlist and missing scope each name the fix', async () => {
    const { a, opts } = setup();
    const h = () => ({ headers: pcaHeaders(a.act('stripe.refund', 'charge:ch_1', {}).encoded) });
    const unknown = await admitRequest(h(), { ...opts, resolveGrant: () => null });
    expect(!unknown.ok && unknown.hint).toMatch(/register the agent's grant/);
    const aud = await admitRequest({ headers: pcaHeaders(a.act('stripe.refund', 'charge:ch_1', {}, { aud: 'ins_acme' }).encoded) }, opts);
    expect(!aud.ok && aud.hint).toMatch(/aud must equal the `resource` option/);
    const iss = await admitRequest(h(), { ...opts, authorizationServers: ['https://as.example.com'] });
    expect(!iss.ok && iss.hint).toMatch(/principal's public key \(grant\.issuer\)/);
    expect(!iss.ok && iss.wwwAuthenticate).not.toMatch(/principal/);
    const scope = await admitRequest(h(), { ...opts, tool: 'refund', toolScopes: { refund: 'refund:write' } });
    expect(!scope.ok && scope.error).toBe('insufficient_scope');
    expect(!scope.ok && scope.hint).toMatch(/scope` caveats/);
  });
});
