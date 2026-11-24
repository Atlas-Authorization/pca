import { describe, expect, it } from 'vitest';
import { encodePcaNeed, type PcaNeed } from '@atlasauth/pca';
import { checkAuthorizationResponseIss, parseChallenges, planStepUp } from './auth-client';

const need: PcaNeed = { v: 1, kind: 'scope', verb: 'stripe.refund', resource: 'charge/ch_1', scopes: ['refunds:write'] };
const hdr = (extra = '') => `Bearer error="insufficient_scope", scope="refunds:write", resource_metadata="https://rs.example/.well-known/oauth-protected-resource"${extra}`;

describe('parseChallenges - T-582', () => {
  it('reads quoted strings with commas and several challenges', () => {
    const c = parseChallenges('Bearer realm="a, b", error="insufficient_scope", PCA-StepUp tier="2", roles="guardian principal"');
    expect(c).toEqual([
      { scheme: 'bearer', params: { realm: 'a, b', error: 'insufficient_scope' } },
      { scheme: 'pca-stepup', params: { tier: '2', roles: 'guardian principal' } },
    ]);
  });
  it('unescapes quoted pairs, keeps the first of a repeated name and never throws on garbage', () => {
    expect(parseChallenges('Bearer a="x\\"y", a="z"')[0]?.params.a).toBe('x"y');
    expect(parseChallenges(undefined)).toEqual([]);
    expect(() => parseChallenges('=="" ,,, "')).not.toThrow();
    expect(parseChallenges('Bearer error="unterminated')[0]?.params.error).toBe('unterminated');
  });
});

describe('planStepUp: a stock client falls back cleanly, a PCA client completes an argument-aware step-up - T-582', () => {
  const withNeed = hdr(`, pca_need="${encodePcaNeed(need)}"`);
  it('a stock client ignores pca_need and steps up by the scope union', () => {
    const p = planStepUp(403, withNeed, { requested: ['tickets:read'], attempts: 0 });
    expect(p).toEqual({ action: 'scope', scopes: ['refunds:write', 'tickets:read'], attempts: 1 });
    // identical plan with and without the parameter
    expect(planStepUp(403, hdr(), { requested: ['tickets:read'], attempts: 0 })).toEqual(p);
  });
  it('a PCA-aware client gets the typed need and the same scope fallback', () => {
    const p = planStepUp(403, withNeed, { requested: ['tickets:read'], attempts: 0, pcaAware: true });
    expect(p).toEqual({ action: 'pca', need, fallbackScopes: ['refunds:write', 'tickets:read'], attempts: 1 });
  });
  it('a malformed pca_need degrades to the stock path', () => {
    const bad = hdr(', pca_need="!!!"');
    expect(planStepUp(403, bad, { requested: [], attempts: 0, pcaAware: true })).toEqual({ action: 'scope', scopes: ['refunds:write'], attempts: 1 });
  });
  it('only a 403 insufficient_scope on a Bearer challenge is a step-up', () => {
    expect(planStepUp(401, hdr(), { requested: [], attempts: 0 })).toEqual({ action: 'give_up', reason: 'not_insufficient_scope' });
    expect(planStepUp(403, 'Bearer error="invalid_token"', { requested: [], attempts: 0 })).toEqual({ action: 'give_up', reason: 'not_insufficient_scope' });
    expect(planStepUp(403, 'Basic error="insufficient_scope"', { requested: [], attempts: 0 })).toEqual({ action: 'give_up', reason: 'not_insufficient_scope' });
  });
  it('bounds the retries and refuses to loop when the union adds nothing', () => {
    expect(planStepUp(403, hdr(), { requested: [], attempts: 3 })).toEqual({ action: 'give_up', reason: 'retry_limit' });
    expect(planStepUp(403, hdr(), { requested: [], attempts: 1, maxAttempts: 1 })).toEqual({ action: 'give_up', reason: 'retry_limit' });
    expect(planStepUp(403, hdr(), { requested: ['refunds:write'], attempts: 1 })).toEqual({ action: 'give_up', reason: 'no_new_scope' });
  });
  it('a pca_need alone, without new scopes, still lets a PCA client act (the need is the new information)', () => {
    const p = planStepUp(403, withNeed, { requested: ['refunds:write'], attempts: 1, pcaAware: true });
    expect(p.action).toBe('pca');
  });
});

describe('checkAuthorizationResponseIss: the RFC 9207 table of the MCP specification - T-583', () => {
  const rec = 'https://as.example/tenant1';
  const c = (issParameterSupported: boolean | undefined, iss: string | undefined, recorded: string | null = rec) =>
    checkAuthorizationResponseIss({ recordedIssuer: recorded ?? undefined, issParameterSupported, iss });
  it('supported=true, iss present: compare', () => {
    expect(c(true, rec)).toEqual({ proceed: true });
    expect(c(true, 'https://evil.example')).toEqual({ proceed: false, reason: 'iss_mismatch' });
  });
  it('supported=true, iss absent: reject', () => expect(c(true, undefined)).toEqual({ proceed: false, reason: 'iss_missing' }));
  it('supported=false or absent, iss present: still compare', () => {
    for (const s of [false, undefined]) {
      expect(c(s, rec)).toEqual({ proceed: true });
      expect(c(s, 'https://evil.example')).toEqual({ proceed: false, reason: 'iss_mismatch' });
    }
  });
  it('supported=false or absent, iss absent: proceed', () => {
    expect(c(false, undefined)).toEqual({ proceed: true });
    expect(c(undefined, undefined)).toEqual({ proceed: true });
  });
  it('no normalization: case, default port, trailing slash and percent-encoding all differ', () => {
    for (const iss of ['HTTPS://as.example/tenant1', 'https://AS.example/tenant1', 'https://as.example:443/tenant1', `${rec}/`, 'https://as.example/tenant%31']) {
      expect(c(true, iss)).toEqual({ proceed: false, reason: 'iss_mismatch' });
    }
  });
  it('without a recorded issuer nothing can be checked: refuse, even when iss is absent and not required', () => {
    expect(c(false, undefined, null)).toEqual({ proceed: false, reason: 'no_recorded_issuer' });
    expect(c(true, rec, '')).toEqual({ proceed: false, reason: 'no_recorded_issuer' });
  });
});
