import { describe, expect, it } from 'vitest';
import { withPCA } from './index';
import { agent, generateKeyPair, pcaHeaders, type Capability } from '@atlasauth/pca';

const AUD = 'ins_acme';

function mkAgentAndGrant() {
  const a = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD });
  return { a, grant: a.grant as Capability };
}

/** Minimal fake App-Router Request: the web `Request` with the given headers and no body. */
function mkRequest(headers: Record<string, string | undefined>): Request {
  const h = new Headers();
  for (const [k, v] of Object.entries(headers)) if (v !== undefined) h.set(k, v);
  return new Request('https://rs.example/refunds', { method: 'POST', headers: h });
}

describe('withPCA', () => {
  it('verifies a valid PCActn and runs the handler with ctx.pca', async () => {
    const { a, grant } = mkAgentAndGrant();
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 20, currency: 'usd' }, { counter: 1 });
    let seenVerb: string | undefined;
    const route = withPCA(
      {
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
      },
      (_req, { pca }) => {
        seenVerb = pca.pcactn.action.verb;
        return new Response('ok');
      },
    );
    const res = await route(mkRequest({ 'PCA-Action': pcaHeaders(encoded)['PCA-Action'] }));
    expect(res.status).toBe(200);
    expect(seenVerb).toBe('stripe.refund');
  });

  it('answers 401 with a WWW-Authenticate challenge when no PCActn is presented', async () => {
    let ran = false;
    const route = withPCA(
      { audience: AUD, resolveGrant: async () => null, insecureAllowUnenforced: true },
      () => { ran = true; return new Response('ok'); },
    );
    const res = await route(mkRequest({}));
    expect(ran).toBe(false);
    expect(res.status).toBe(401);
    expect(res.headers.get('WWW-Authenticate')).toMatch(/PCA realm/);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBeTruthy();
  });

  it('401s an unknown grant_ref', async () => {
    const { a } = mkAgentAndGrant();
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 20, currency: 'usd' }, { counter: 1 });
    const route = withPCA(
      { audience: AUD, resolveGrant: async () => null, insecureAllowUnenforced: true },
      () => new Response('ok'),
    );
    const res = await route(mkRequest({ 'PCA-Action': pcaHeaders(encoded)['PCA-Action'] }));
    expect(res.status).toBe(401);
  });
});
