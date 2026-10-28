import { describe, expect, it } from 'vitest';
import { agent, generateKeyPair, protect } from '@atlasauth/pca';
import { pcaExpress } from './index';

const AUD = 'ins_protect_express';

/** `protect()` options plug straight into pcaExpress: the whole server side of the quickstart. */
describe('pcaExpress(protect(...).options)', () => {
  const setup = () => {
    const a = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD });
    const p = protect({
      audience: AUD,
      grants: [a.grant],
      operation: (req) => {
        const b = req.body as { charge: string; params: Record<string, unknown> };
        return { verb: 'stripe.refund', resource: `charge:${b.charge}`, params: b.params };
      },
    });
    const mw = pcaExpress(p.options);
    const call = async (charge: string, amount: number) => {
      const params = { amount, currency: 'usd' };
      const res: { code?: number; status(c: number): typeof res; set(k: string, v: string): typeof res; json(b: unknown): unknown } = {
        status(c) { this.code = c; return this; },
        set() { return this; },
        json(b) { return b; },
      };
      let nexted = false;
      await mw({ headers: {}, body: { pcactn: a.act('stripe.refund', `charge:${charge}`, params).encoded, charge, params } } as never, res as never, () => { nexted = true; });
      return nexted;
    };
    return { call };
  };

  it('calls next() for an in-limit action and answers 4xx for an over-limit one', async () => {
    const { call } = setup();
    expect(await call('ch_1', 42)).toBe(true);
    expect(await call('ch_2', 5000)).toBe(false);
  });
});
