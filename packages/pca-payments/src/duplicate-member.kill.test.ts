import { describe, expect, it } from 'vitest';
import { createStripeIssuingWebhook, signStripePayload } from './rails-stripe';

const secret = 'whsec_test';
const handler = createStripeIssuingWebhook({ secret, authorize: async () => ({ approved: true }) as never, nowSec: () => 1000 });
const send = (rawBody: string) => handler({ rawBody, signature: signStripePayload(rawBody, secret, 1000) });

describe('Stripe webhook body duplicate members', () => {
  it('a duplicate member is refused as bad_json', async () => {
    const r = await send('{"type":"x","type":"issuing_authorization.request"}');
    expect(r.status).toBe(400);
    expect(JSON.stringify(r)).toContain('bad_json');
  });
  it('non-canonical numbers (8.0, 1e3) are accepted', async () => {
    const r = await send('{"type":"other","amount":8.0,"n":1e3}');
    expect(r.status).toBe(200);
  });
});
