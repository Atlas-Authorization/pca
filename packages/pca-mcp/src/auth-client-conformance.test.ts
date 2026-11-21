import { describe, expect, it } from 'vitest';
import { encodePcaNeed, type PcaNeed } from '@atlasauth/pca';
import { MCP_AUTH_CLIENT_ROWS, MCP_CLIENT_REVISIONS } from './auth-client-conformance';
import { checkAuthorizationResponseIss, parseChallenges, planStepUp } from './auth-client';

const need: PcaNeed = { v: 1, kind: 'scope', verb: 'v', resource: 'r', scopes: ['a:b'] };
const H = 'Bearer error="insufficient_scope", scope="a:b", resource_metadata="https://rs.example/.well-known/oauth-protected-resource"';

const CHECKS: Record<string, () => void> = {
  'parse-www-authenticate': () => {
    const c = parseChallenges('Bearer resource_metadata="https://rs.example/x", scope="a b", PCA realm="pca"');
    expect(c.map((x) => x.scheme)).toEqual(['bearer', 'pca']);
    expect(c[0]?.params).toEqual({ resource_metadata: 'https://rs.example/x', scope: 'a b' });
  },
  'step-up-on-insufficient-scope': () => {
    expect(planStepUp(403, H, { requested: [], attempts: 0 })).toEqual({ action: 'scope', scopes: ['a:b'], attempts: 1 });
  },
  'scope-union': () => {
    const p = planStepUp(403, H, { requested: ['x:y', 'a:b'.replace('b', 'c')], attempts: 0 });
    expect(p).toEqual({ action: 'scope', scopes: ['a:b', 'a:c', 'x:y'], attempts: 1 });
  },
  'retry-limit': () => {
    let attempts = 0;
    let requested: string[] = [];
    const trace: string[] = [];
    for (let i = 0; i < 10; i++) {
      // a server that keeps asking for a new scope each time must still be stopped by the limit
      const hdr = `Bearer error="insufficient_scope", scope="s${i}"`;
      const p = planStepUp(403, hdr, { requested, attempts });
      trace.push(p.action);
      if (p.action !== 'scope') break;
      attempts = p.attempts;
      requested = p.scopes;
    }
    expect(trace).toEqual(['scope', 'scope', 'scope', 'give_up']);
  },
  'iss-validation-table': () => {
    const r = 'https://as.example';
    expect(checkAuthorizationResponseIss({ recordedIssuer: r, issParameterSupported: true, iss: undefined })).toMatchObject({ proceed: false });
    expect(checkAuthorizationResponseIss({ recordedIssuer: r, issParameterSupported: false, iss: undefined })).toEqual({ proceed: true });
    expect(checkAuthorizationResponseIss({ recordedIssuer: r, issParameterSupported: undefined, iss: 'https://as.example/' })).toMatchObject({ proceed: false });
    expect(checkAuthorizationResponseIss({ recordedIssuer: r, issParameterSupported: true, iss: r })).toEqual({ proceed: true });
  },
  'pca-need-ignored-by-stock-client': () => {
    const withNeed = `${H}, pca_need="${encodePcaNeed(need)}"`;
    expect(planStepUp(403, withNeed, { requested: [], attempts: 0 })).toEqual(planStepUp(403, H, { requested: [], attempts: 0 }));
  },
};

describe('MCP authorization conformance matrix (client rows) - T-585', () => {
  it('every row has a check and every check has a row', () => {
    expect(Object.keys(CHECKS).sort()).toEqual(MCP_AUTH_CLIENT_ROWS.map((r) => r.id).sort());
  });
  for (const rev of MCP_CLIENT_REVISIONS) {
    for (const row of MCP_AUTH_CLIENT_ROWS) {
      const level = row.levels[rev];
      if (level === 'n/a') continue;
      it(`${rev}: ${row.id} (${level})`, () => {
        CHECKS[row.id]?.();
      });
    }
  }
});
