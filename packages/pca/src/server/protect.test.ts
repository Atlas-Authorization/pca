import { describe, expect, it } from 'vitest';
import { agent } from '../facade';
import { generateKeyPair } from '../keys';
import { requireAuthorized } from './authorize';
import { protect } from './protect';

const AUD = 'ins_protect';

function setup() {
  const a = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD });
  const p = protect({
    audience: AUD,
    grants: [a.grant],
    operation: (req) => {
      const b = req.body as { charge: string; params: Record<string, unknown> };
      return { verb: 'stripe.refund', resource: `charge:${b.charge}`, params: b.params };
    },
  });
  const guard = requireAuthorized(p.options);
  const call = (charge: string, amount: number) => {
    const params = { amount, currency: 'usd' };
    return guard({ headers: {}, body: { pcactn: a.act('stripe.refund', `charge:${charge}`, params).encoded, charge, params } });
  };
  return { a, p, call };
}

describe('protect', () => {
  it('allows an in-limit action and refuses an over-limit one with the defaults alone', async () => {
    const { call } = setup();
    expect((await call('ch_1', 42)).ok).toBe(true);
    expect((await call('ch_2', 5000)).ok).toBe(false);
  });
  it('refuses everything under a revoked grant', async () => {
    const { a, p, call } = setup();
    p.revoke(a.grant.id);
    expect((await call('ch_3', 10)).ok).toBe(false);
  });
});
