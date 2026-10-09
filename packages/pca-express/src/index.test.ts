import { describe, expect, it } from 'vitest';
import { pcaExpress } from './index';
import { agent, generateKeyPair, pcaHeaders, type Capability } from '@atlasauth/pca';

const AUD = 'ins_acme';

/** Node/Express deliver incoming header keys lowercased; mirror that for the fixture. */
function lowerHeaders(h: Record<string, string>): Record<string, string | string[] | undefined> {
  const out: Record<string, string | string[] | undefined> = {};
  for (const [k, v] of Object.entries(h)) out[k.toLowerCase()] = v;
  return out;
}

function mkAgentAndGrant() {
  const a = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD });
  return { a, grant: a.grant as Capability };
}

function fakeRes() {
  const r: { code?: number; headers: Record<string, string>; body?: unknown; status: (c: number) => typeof r; set: (k: string, v: string) => typeof r; json: (b: unknown) => unknown } = {
    headers: {},
    status(c) { this.code = c; return this; },
    set(k, v) { this.headers[k] = v; return this; },
    json(b) { this.body = b; return b; },
  };
  return r;
}

describe('pcaExpress', () => {
  it('verifies a valid PCActn, attaches req.pca and calls next()', async () => {
    const { a, grant } = mkAgentAndGrant();
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 20, currency: 'usd' }, { counter: 1 });
    const mw = pcaExpress({
      audience: AUD,
      resolveGrant: async () => grant,
      // The RS supplies the real action params + budget (the PCActn carries only a params digest).
      context: async () => ({
        params: { amount: 20, currency: 'usd' },
        budget: { B: 500, tau: 0 },
        risk: { semanticDistance: 0, reversibility: 0, blastRadius: 0.04, taint: 0, confidence: 1, age: 0 },
        planAuthorized: true,
      }),
      insecureAllowUnenforced: true, // exercise the glue; full default-deny enforcement is tested in @atlasauth/pca
    });
    const req = { headers: lowerHeaders(pcaHeaders(encoded)), body: undefined } as Record<string, unknown> & { headers: Record<string, string | string[] | undefined> };
    const res = fakeRes();
    let nexted = false;
    await mw(req as never, res as never, () => { nexted = true; });
    expect(nexted).toBe(true);
    expect(res.code).toBeUndefined();
    const attached = (req as { pca?: { pcactn: { action: { verb: string } } } }).pca;
    expect(attached?.pcactn.action.verb).toBe('stripe.refund');
  });

  it('answers 401 with a WWW-Authenticate challenge when no PCActn is presented', async () => {
    const mw = pcaExpress({ audience: AUD, resolveGrant: async () => null, insecureAllowUnenforced: true });
    const res = fakeRes();
    let nexted = false;
    await mw({ headers: {}, body: undefined } as never, res as never, () => { nexted = true; });
    expect(nexted).toBe(false);
    expect(res.code).toBe(401);
    expect(res.headers['WWW-Authenticate']).toMatch(/PCA realm/);
    expect((res.body as { error: string }).error).toBeTruthy();
  });

  it('401s an unknown grant_ref', async () => {
    const { a } = mkAgentAndGrant();
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 20, currency: 'usd' }, { counter: 1 });
    const mw = pcaExpress({ audience: AUD, resolveGrant: async () => null, insecureAllowUnenforced: true });
    const res = fakeRes();
    await mw({ headers: lowerHeaders(pcaHeaders(encoded)), body: undefined } as never, res as never, () => {});
    expect(res.code).toBe(401);
  });

  it('routes a denial through a custom onDeny', async () => {
    let seen: number | null = null;
    const mw = pcaExpress({ audience: AUD, resolveGrant: async () => null, insecureAllowUnenforced: true, onDeny: (result) => { seen = result.status; } });
    await mw({ headers: {}, body: undefined } as never, fakeRes() as never, () => {});
    expect(seen).toBe(401);
  });
});
