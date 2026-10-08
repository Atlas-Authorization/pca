import { describe, expect, it } from 'vitest';
import { pcaFastify } from './index';
import { agent, generateKeyPair, pcaHeaders, type Capability } from '@atlasauth/pca';

const AUD = 'ins_acme';

function mkAgentAndGrant() {
  const a = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD });
  return { a, grant: a.grant as Capability };
}

function fakeReply() {
  const r: { statusCode?: number; headers: Record<string, string>; body?: unknown; code: (c: number) => typeof r; header: (k: string, v: string) => typeof r; send: (b: unknown) => unknown } = {
    headers: {},
    code(c) { this.statusCode = c; return this; },
    header(k, v) { this.headers[k] = v; return this; },
    send(b) { this.body = b; return b; },
  };
  return r;
}

describe('pcaFastify', () => {
  it('verifies a valid PCActn, attaches req.pca and lets the handler run', async () => {
    const { a, grant } = mkAgentAndGrant();
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 20, currency: 'usd' }, { counter: 1 });
    const mw = pcaFastify({
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
    // Fastify delivers header keys lowercased; send it that way.
    const req = { headers: { 'pca-action': pcaHeaders(encoded)['PCA-Action'] }, body: undefined } as Record<string, unknown> & { headers: Record<string, string | string[] | undefined> };
    const reply = fakeReply();
    await mw(req as never, reply as never);
    expect(reply.statusCode).toBeUndefined();
    const attached = (req as { pca?: { pcactn: { action: { verb: string } } } }).pca;
    expect(attached?.pcactn.action.verb).toBe('stripe.refund');
  });

  it('answers 401 with a WWW-Authenticate challenge when no PCActn is presented', async () => {
    const mw = pcaFastify({ audience: AUD, resolveGrant: async () => null, insecureAllowUnenforced: true });
    const reply = fakeReply();
    await mw({ headers: {}, body: undefined } as never, reply as never);
    expect(reply.statusCode).toBe(401);
    expect(reply.headers['WWW-Authenticate']).toMatch(/PCA realm/);
    expect((reply.body as { error: string }).error).toBeTruthy();
  });

  it('401s an unknown grant_ref', async () => {
    const { a } = mkAgentAndGrant();
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 20, currency: 'usd' }, { counter: 1 });
    const mw = pcaFastify({ audience: AUD, resolveGrant: async () => null, insecureAllowUnenforced: true });
    const reply = fakeReply();
    await mw({ headers: { 'pca-action': pcaHeaders(encoded)['PCA-Action'] }, body: undefined } as never, reply as never);
    expect(reply.statusCode).toBe(401);
  });

  it('routes a denial through a custom onDeny', async () => {
    let seen: number | null = null;
    const mw = pcaFastify({ audience: AUD, resolveGrant: async () => null, insecureAllowUnenforced: true, onDeny: (result) => { seen = result.status; } });
    await mw({ headers: {}, body: undefined } as never, fakeReply() as never);
    expect(seen).toBe(401);
  });
});
