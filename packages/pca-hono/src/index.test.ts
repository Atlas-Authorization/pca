import { describe, expect, it } from 'vitest';
import { pcaHono } from './index';
import { agent, generateKeyPair, pcaHeaders, type Capability } from '@atlasauth/pca';

const AUD = 'ins_acme';

function mkAgentAndGrant() {
  const a = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD });
  return { a, grant: a.grant as Capability };
}

/** Minimal fake Hono context: lowercased header lookup + a `set` bag + a `json` responder. */
function fakeCtx(headers: Record<string, string | undefined>) {
  const vars: Record<string, unknown> = {};
  const lower: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
  const last: { status?: number; headers?: Record<string, string>; body?: unknown } = {};
  const c = {
    vars,
    last,
    req: {
      header: (name: string) => lower[name.toLowerCase()],
      json: async () => undefined as unknown,
    },
    set: (key: string, value: unknown) => { vars[key] = value; },
    json: (body: unknown, status?: number, hdrs?: Record<string, string>): Response => {
      last.body = body; last.status = status; last.headers = hdrs;
      return new Response(JSON.stringify(body), { status: status ?? 200, headers: hdrs });
    },
  };
  return c;
}

describe('pcaHono', () => {
  it('verifies a valid PCActn, sets c.get("pca") and calls next()', async () => {
    const { a, grant } = mkAgentAndGrant();
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 20, currency: 'usd' }, { counter: 1 });
    const mw = pcaHono({
      audience: AUD,
      resolveGrant: async () => grant,
      // The RS supplies the real action params + budget (the PCActn carries only a params digest).
      context: async () => ({
        params: { amount: 20, currency: 'usd' },
        budget: { B: 500, tau: 0 },
        risk: { semanticDistance: 0, reversibility: 0, blastRadius: 0.04, taint: 0, confidence: 1, age: 0 },
        planAuthorized: true,
      }),
      insecureAllowUnenforced: true, // exercise the glue; full default-deny enforcement is tested in @atlasauth/backend
    });
    const c = fakeCtx({ 'PCA-Action': pcaHeaders(encoded)['PCA-Action'] });
    let nexted = false;
    await mw(c as never, async () => { nexted = true; });
    expect(nexted).toBe(true);
    expect(c.last.status).toBeUndefined();
    const attached = c.vars.pca as { pcactn: { action: { verb: string } } } | undefined;
    expect(attached?.pcactn.action.verb).toBe('stripe.refund');
  });

  it('answers 401 with a WWW-Authenticate challenge when no PCActn is presented', async () => {
    const mw = pcaHono({ audience: AUD, resolveGrant: async () => null, insecureAllowUnenforced: true });
    const c = fakeCtx({});
    let nexted = false;
    await mw(c as never, async () => { nexted = true; });
    expect(nexted).toBe(false);
    expect(c.last.status).toBe(401);
    expect(c.last.headers?.['WWW-Authenticate']).toMatch(/PCA realm/);
    expect((c.last.body as { error: string }).error).toBeTruthy();
  });

  it('401s an unknown grant_ref', async () => {
    const { a } = mkAgentAndGrant();
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 20, currency: 'usd' }, { counter: 1 });
    const mw = pcaHono({ audience: AUD, resolveGrant: async () => null, insecureAllowUnenforced: true });
    const c = fakeCtx({ 'PCA-Action': pcaHeaders(encoded)['PCA-Action'] });
    await mw(c as never, async () => {});
    expect(c.last.status).toBe(401);
  });
});
