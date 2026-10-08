import { describe, it, expect } from 'vitest';
import {
  WELL_KNOWN_OAUTH_PRM,
  protectedResourceMetadata,
  parseProtectedResourceMetadata,
  wwwAuthenticate,
  checkResourceIndicator,
  oauthDiscoveryHandler,
  mcpUnauthorized,
  upgradeUnauthorizedChallenge,
} from './index';

const AUDIENCE = 'https://api.acme.com';
const PRM_URL = `${AUDIENCE}${WELL_KNOWN_OAUTH_PRM}`;

describe('WELL_KNOWN_OAUTH_PRM', () => {
  it('is the RFC 9728 well-known path', () => {
    expect(WELL_KNOWN_OAUTH_PRM).toBe('/.well-known/oauth-protected-resource');
  });
});

describe('protectedResourceMetadata (RFC 9728)', () => {
  it('contains the resource = audience and the PCA extension fields', () => {
    const prm = protectedResourceMetadata({ resource: AUDIENCE });
    expect(prm.resource).toBe(AUDIENCE);
    // one source of truth: the embedded discovery audience equals the OAuth resource
    expect(prm.pca.audience).toBe(AUDIENCE);
    expect(prm.bearer_methods_supported).toEqual(['header']);
    // PCA extension advertising that this RS verifies a PCActn
    expect(prm.pca_action_header).toBe('PCA-Action');
    expect(Array.isArray(prm.pca_signature_suites)).toBe(true);
    expect(prm.pca_signature_suites.length).toBeGreaterThan(0);
    expect(prm.pca_versions).toContain(2);
    expect(prm.pca_configuration_endpoint).toBe(`${AUDIENCE}/.well-known/pca-configuration`);
    expect(prm.pca.action_header).toBe('PCA-Action');
  });

  it('forwards optional OAuth + PCA fields', () => {
    const prm = protectedResourceMetadata({
      resource: AUDIENCE,
      authorizationServers: ['https://as.acme.com'],
      resourceDocumentation: 'https://docs.acme.com/pca',
      scopesSupported: ['tickets:write'],
      resourceName: 'Acme API',
      signatureSuites: ['ed25519'],
      endpoints: { revocation_epoch: `${AUDIENCE}/v1/pca/revocations/epoch` },
    });
    expect(prm.authorization_servers).toEqual(['https://as.acme.com']);
    expect(prm.resource_documentation).toBe('https://docs.acme.com/pca');
    expect(prm.scopes_supported).toEqual(['tickets:write']);
    expect(prm.resource_name).toBe('Acme API');
    expect(prm.pca_signature_suites).toEqual(['ed25519']);
    expect(prm.pca.endpoints?.revocation_epoch).toBe(`${AUDIENCE}/v1/pca/revocations/epoch`);
  });

  it('throws on an empty resource', () => {
    expect(() => protectedResourceMetadata({ resource: '' })).toThrow(/resource/);
  });

  it('round-trips through JSON + the validating parser', () => {
    const prm = protectedResourceMetadata({
      resource: AUDIENCE,
      authorizationServers: ['https://as.acme.com'],
      resourceName: 'Acme API',
    });
    const roundTripped = parseProtectedResourceMetadata(JSON.parse(JSON.stringify(prm)));
    expect(roundTripped).toEqual(prm);
    expect(roundTripped.resource).toBe(AUDIENCE);
    expect(roundTripped.pca.audience).toBe(AUDIENCE);
  });

  it('parser rejects a malformed document', () => {
    expect(() => parseProtectedResourceMetadata(null)).toThrow();
    expect(() => parseProtectedResourceMetadata({ resource: '' })).toThrow(/resource/);
    expect(() => parseProtectedResourceMetadata({ resource: AUDIENCE })).toThrow();
  });
});

describe('wwwAuthenticate (MCP 2025-11-25 + RFC 6750/7235)', () => {
  it('carries both the Bearer resource_metadata and the PCA realm challenge', () => {
    const h = wwwAuthenticate(PRM_URL);
    expect(h).toContain(`Bearer resource_metadata="${PRM_URL}"`);
    expect(h).toContain('PCA realm="pca"');
  });

  it('includes optional error / error_description on the Bearer challenge', () => {
    const h = wwwAuthenticate(PRM_URL, { error: 'invalid_token', errorDescription: 'expired' });
    expect(h).toContain('error="invalid_token"');
    expect(h).toContain('error_description="expired"');
  });

  it('can emit a pure OAuth/MCP challenge with includePca=false', () => {
    const h = wwwAuthenticate(PRM_URL, { includePca: false });
    expect(h).toContain('resource_metadata=');
    expect(h).not.toContain('PCA realm');
  });

  it('reuses an existing PCA challenge verbatim', () => {
    const existing = 'PCA realm="pca", error="invalid_pcactn", hint="send PCA-Action"';
    const h = wwwAuthenticate(PRM_URL, { pcaChallenge: existing });
    expect(h).toContain(existing);
    expect(h.startsWith('Bearer resource_metadata=')).toBe(true);
  });

  it('rejects an empty prmUrl and header-injecting values', () => {
    expect(() => wwwAuthenticate('')).toThrow();
    expect(() => wwwAuthenticate('https://x/"evil')).toThrow();
  });
});

describe('checkResourceIndicator (RFC 8707)', () => {
  it('accepts a matching audience', () => {
    const r = checkResourceIndicator(AUDIENCE, AUDIENCE);
    expect(r.ok).toBe(true);
    expect(r.matched).toBe(AUDIENCE);
  });

  it('accepts the array form when any value matches', () => {
    const r = checkResourceIndicator(['https://other', AUDIENCE], AUDIENCE);
    expect(r.ok).toBe(true);
    expect(r.matched).toBe(AUDIENCE);
  });

  it('rejects a mismatch', () => {
    const r = checkResourceIndicator('https://evil.example', AUDIENCE);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/does not match/);
  });

  it('rejects a missing indicator', () => {
    expect(checkResourceIndicator(undefined, AUDIENCE).ok).toBe(false);
    expect(checkResourceIndicator(null, AUDIENCE).ok).toBe(false);
    expect(checkResourceIndicator([], AUDIENCE).ok).toBe(false);
  });

  it('throws without an expected audience', () => {
    expect(() => checkResourceIndicator(AUDIENCE, '')).toThrow();
  });
});

describe('oauthDiscoveryHandler (glue)', () => {
  it('returns the well-known path and PRM body', () => {
    const { path, body } = oauthDiscoveryHandler({ resource: AUDIENCE });
    expect(path).toBe(WELL_KNOWN_OAUTH_PRM);
    expect(body.resource).toBe(AUDIENCE);
    expect(body.pca.audience).toBe(AUDIENCE);
  });
});

describe('mcpUnauthorized (glue)', () => {
  it('returns a 401 with the WWW-Authenticate header and a resource_metadata body', () => {
    const r = mcpUnauthorized(PRM_URL, { error: 'invalid_request' });
    expect(r.status).toBe(401);
    expect(r.headers['WWW-Authenticate']).toContain(`resource_metadata="${PRM_URL}"`);
    expect(r.headers['WWW-Authenticate']).toContain('PCA realm="pca"');
    expect(r.body.error).toBe('invalid_request');
    expect(r.body.resource_metadata).toBe(PRM_URL);
  });
});

describe('upgradeUnauthorizedChallenge (glue)', () => {
  it('prepends the resource_metadata pointer while preserving the existing PCA challenge + fields', () => {
    const deny = {
      ok: false as const,
      status: 401 as const,
      wwwAuthenticate: 'PCA realm="pca", error="invalid_pcactn", hint="send PCA-Action"',
      verdict: { allow: false },
    };
    const upgraded = upgradeUnauthorizedChallenge(deny, PRM_URL);
    expect(upgraded.wwwAuthenticate).toContain(`Bearer resource_metadata="${PRM_URL}"`);
    expect(upgraded.wwwAuthenticate).toContain('PCA realm="pca"');
    expect(upgraded.wwwAuthenticate).toContain('invalid_pcactn');
    // other fields preserved
    expect(upgraded.status).toBe(401);
    expect(upgraded.verdict).toEqual({ allow: false });
  });

  it('builds a fresh PCA challenge when the deny result had none', () => {
    const deny: { status: 401; wwwAuthenticate?: string } = { status: 401 };
    const upgraded = upgradeUnauthorizedChallenge(deny, PRM_URL);
    expect(upgraded.wwwAuthenticate).toContain('resource_metadata=');
    expect(upgraded.wwwAuthenticate).toContain('PCA realm="pca"');
  });
});
