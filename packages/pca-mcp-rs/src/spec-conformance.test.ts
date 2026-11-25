import { describe, expect, it } from 'vitest';
import { agent, generateKeyPair, type Agent, type PCActn } from '@atlasauth/pca';
import { pcaNeedFromChallenge } from '@atlasauth/pca';
import { WELL_KNOWN_OAUTH_PRM, admitRequest, protectedResourceMetadata, type AdmissionOptions } from './index';
import { MCP_AUTH_REVISIONS, MCP_AUTH_RS_ROWS } from './spec-conformance';

const AUD = 'https://api.acme.com';
const PRM = `${AUD}${WELL_KNOWN_OAUTH_PRM}`;

function mk(): Agent {
  return agent({ principal: generateKeyPair(), goal: 'tickets', permissions: { tickets: ['write', 'read'] }, aud: AUD });
}
const a = mk();
const proof = (): PCActn => a.act('write', 'tickets/1', { aud: AUD }).pcactn;
const grant = a.grant;
const base = (over: Partial<AdmissionOptions> = {}): AdmissionOptions => ({
  resource: AUD,
  authorizationServers: [grant.issuer],
  resolveGrant: (ref) => (ref === grant.id ? grant : null),
  prmUrl: PRM, insecureSkipPlanRootCheck: true,
  baseScopes: ['tickets:write'],
  ...over,
});
const req = (p: PCActn) => ({ headers: {} as Record<string, string>, body: { pcactn: p } });

/** A stock client reads only these; everything else in the header is ignored. */
function stockClientView(h: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of ['error', 'scope', 'resource_metadata']) {
    const m = new RegExp(`${k}="([^"]*)"`).exec(h);
    if (m) out[k] = m[1] as string;
  }
  return out;
}

const CHECKS: Record<string, () => Promise<void> | void> = {
  'prm-served': () => {
    const prm = protectedResourceMetadata({ resource: AUD, authorizationServers: ['https://as.acme.com'], scopesSupported: ['tickets:read'] });
    expect(prm.resource).toBe(AUD);
    expect(prm.authorization_servers).toEqual(['https://as.acme.com']);
  },
  'challenge-resource-metadata': async () => {
    const r = await admitRequest({ headers: {}, body: {} }, base());
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.status).toBe(401);
      expect(r.wwwAuthenticate).toContain(`resource_metadata="${PRM}"`);
      expect(r.wwwAuthenticate.startsWith('Bearer ')).toBe(true);
    }
  },
  'unauthorized-401': async () => {
    const none = await admitRequest({ headers: {}, body: {} }, base());
    const expired = await admitRequest(req(proof()), base({ now: Date.now() + 3_600_000 }));
    for (const r of [none, expired]) {
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.status).toBe(401);
    }
  },
  'forbidden-403': async () => {
    const r = await admitRequest(req(proof()), base({ requiredScopes: ['tickets:admin'] }));
    expect(!r.ok && r.status).toBe(403);
  },
  'audience-validation': async () => {
    const r = await admitRequest(req(proof()), base({ resource: 'https://other.example.com' }));
    expect(!r.ok && r.status).toBe(401);
    expect(!r.ok && r.error).toBe('invalid_token');
  },
  'no-token-passthrough': async () => {
    const r = await admitRequest({ headers: { authorization: 'Bearer some.foreign.token' }, body: {} }, base());
    expect(r.ok).toBe(false);
    if (!r.ok) expect([r.status, r.error]).toEqual([401, 'invalid_request']);
  },
  'insufficient-scope-challenge': async () => {
    const r = await admitRequest(req(proof()), base({ requiredScopes: ['tickets:admin'] }));
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.status).toBe(403);
      expect(r.wwwAuthenticate).toContain('error="insufficient_scope"');
      expect(r.wwwAuthenticate).toContain('scope="tickets:admin"');
      expect(r.wwwAuthenticate).toContain(`resource_metadata="${PRM}"`);
    }
  },
  'scope-in-first-401': async () => {
    const r = await admitRequest({ headers: {}, body: {} }, base({ requiredScopes: ['tickets:write', 'tickets:read'] }));
    expect(!r.ok && r.wwwAuthenticate).toContain('scope="tickets:write tickets:read"');
  },
  'scopes-one-challenge': async () => {
    const r = await admitRequest(req(proof()), base({ requiredScopes: ['x:one', 'x:two', 'tickets:write'] }));
    expect(!r.ok && r.error).toBe('insufficient_scope');
    // the one challenge names every scope the operation needs, not just the first missing one
    expect(!r.ok && r.wwwAuthenticate).toContain('scope="x:one x:two tickets:write"');
    expect(!r.ok && (r.wwwAuthenticate.match(/scope=/g) ?? []).length).toBe(1);
  },
  'scope-hierarchy': async () => {
    const hier = { 'tickets:*': ['tickets:write', 'tickets:read'], 'tickets:write': ['tickets:comment'] };
    const ok = await admitRequest(req(proof()), base({ baseScopes: ['tickets:*'], requiredScopes: ['tickets:read', 'tickets:comment'], scopeHierarchy: hier }));
    expect(ok.ok).toBe(true);
    // implication is one-way: a narrow scope does not grant the broad one
    const no = await admitRequest(req(proof()), base({ baseScopes: ['tickets:write'], requiredScopes: ['tickets:*'], scopeHierarchy: hier }));
    expect(!no.ok && no.error).toBe('insufficient_scope');
    // a cycle terminates
    const cyc = await admitRequest(req(proof()), base({ baseScopes: ['a'], requiredScopes: ['b'], scopeHierarchy: { a: ['b'], b: ['a'] } }));
    expect(cyc.ok).toBe(true);
  },
  'pca-need-additive': async () => {
    const on = await admitRequest(req(proof()), base({ requiredScopes: ['tickets:admin'] }));
    const off = await admitRequest(req(proof()), base({ requiredScopes: ['tickets:admin'], pcaNeed: false }));
    expect(on.ok || off.ok).toBe(false);
    if (!on.ok && !off.ok) {
      expect(on.status).toBe(off.status);
      expect(on.error).toBe(off.error);
      expect(stockClientView(on.wwwAuthenticate)).toEqual(stockClientView(off.wwwAuthenticate));
      expect(off.wwwAuthenticate).not.toContain('pca_need');
      const n = pcaNeedFromChallenge(on.wwwAuthenticate);
      expect(n).not.toBeNull();
      expect(n !== null && n.ok && n.need).toMatchObject({ kind: 'scope', verb: 'write', resource: 'tickets/1', scopes: ['tickets:admin'] });
    }
  },
};

describe('MCP authorization conformance matrix (resource-server rows) - T-584', () => {
  it('every row has a check and every check has a row', () => {
    expect(Object.keys(CHECKS).sort()).toEqual(MCP_AUTH_RS_ROWS.map((r) => r.id).sort());
  });
  it('every revision is covered by at least one applicable row', () => {
    for (const rev of MCP_AUTH_REVISIONS) expect(MCP_AUTH_RS_ROWS.some((r) => r.levels[rev] !== 'n/a')).toBe(true);
  });
  for (const rev of MCP_AUTH_REVISIONS) {
    for (const row of MCP_AUTH_RS_ROWS) {
      const level = row.levels[rev];
      if (level === 'n/a') continue;
      it(`${rev}: ${row.id} (${level})`, async () => {
        await CHECKS[row.id]?.();
      });
    }
  }
});

describe('MCP scopes derived from the confirmed action - T-592', () => {
  const action = (confirmed: boolean) => ({ verb: 'write', def_digest: 'd'.repeat(43), confirmed, upstream: { provider: 'tickets', scopes_min: ['tickets:write'] } });
  it('a confirmed action supplies the required scope, over toolScopes', async () => {
    const ok = await admitRequest(req(proof()), base({ tool: 't', toolActions: { t: action(true) }, toolScopes: { t: 'zzz' } }));
    expect(ok.ok).toBe(true);
    const no = await admitRequest(req(proof()), base({ tool: 't', toolActions: { t: { ...action(true), upstream: { provider: 'tickets', scopes_min: ['tickets:admin'] } } } }));
    expect(!no.ok && no.error).toBe('insufficient_scope');
    expect(!no.ok && no.wwwAuthenticate).toContain('scope="tickets:admin"');
  });
  it('an unconfirmed or malformed action releases no scope: the call is refused, not admitted on a guess or an empty requirement', async () => {
    for (const a of [action(false), { ...action(true), upstream: { provider: 'tickets', scopes_min: [] } }]) {
      const r = await admitRequest(req(proof()), base({ tool: 't', toolActions: { t: a }, toolScopes: { t: 'tickets:write' } }));
      expect([r.ok, !r.ok && r.status, !r.ok && r.error]).toEqual([false, 403, 'forbidden']);
    }
    // the first 401 does not leak a fallback scope either
    const first = await admitRequest({ headers: {}, body: {} }, base({ tool: 't', toolActions: { t: action(false) }, toolScopes: { t: 'tickets:write' } }));
    expect(!first.ok && first.wwwAuthenticate).not.toContain('scope=');
  });
  it('tools not listed keep the old behaviour', async () => {
    expect((await admitRequest(req(proof()), base({ tool: 'other', toolActions: { t: action(false) } }))).ok).toBe(true);
  });
});
