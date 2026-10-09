import { describe, expect, it } from 'vitest';
import { createPcaFetchGuard, withPCA } from './index';
import { agent, generateKeyPair, pcaHeaders, type Capability } from '@atlasauth/pca';

const AUD = 'ins_acme';

function mk() {
  const a = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD });
  return { a, grant: a.grant as Capability };
}

const okOpts = (grant: Capability) => ({
  audience: AUD,
  resolveGrant: async () => grant,
  context: async () => ({ params: { amount: 20, currency: 'usd' }, budget: { B: 500, tau: 0 }, planAuthorized: true }),
  insecureAllowUnenforced: true,
});

function reqWith(encoded?: string): Request {
  const headers = new Headers();
  if (encoded) headers.set('PCA-Action', pcaHeaders(encoded)['PCA-Action']!);
  return new Request('https://rs.example/refunds', { method: 'POST', headers });
}

describe('pca-fetch (Web Fetch guard)', () => {
  it('verifies and runs the handler with the verdict', async () => {
    const { a, grant } = mk();
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 20, currency: 'usd' }, { counter: 1 });
    let seen = '';
    const fetch = withPCA(okOpts(grant), async (_req, { pca }) => {
      seen = pca.pcactn.action.verb;
      return Response.json({ ok: true });
    });
    const res = await fetch(reqWith(encoded));
    expect(res.status).toBe(200);
    expect(seen).toBe('stripe.refund');
    expect(await res.json()).toEqual({ ok: true });
  });

  it('returns 401 + WWW-Authenticate when no PCActn is presented', async () => {
    const { grant } = mk();
    const fetch = withPCA(okOpts(grant), async () => Response.json({ ok: true }));
    const res = await fetch(reqWith());
    expect(res.status).toBe(401);
    expect(res.headers.get('WWW-Authenticate')).toMatch(/PCA realm/);
    expect((await res.json() as { error?: unknown }).error).toBeTruthy();
  });

  it('401s an unknown grant', async () => {
    const { a } = mk();
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 20, currency: 'usd' }, { counter: 1 });
    const fetch = withPCA({ audience: AUD, resolveGrant: async () => null, insecureAllowUnenforced: true }, async () => Response.json({ ok: true }));
    expect((await fetch(reqWith(encoded))).status).toBe(401);
  });

  it('createPcaFetchGuard returns the raw guard result for custom composition', async () => {
    const { a, grant } = mk();
    const { encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 20, currency: 'usd' }, { counter: 1 });
    const guard = createPcaFetchGuard(okOpts(grant));
    const result = await guard(reqWith(encoded));
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.pcactn.action.verb).toBe('stripe.refund');
  });
});
