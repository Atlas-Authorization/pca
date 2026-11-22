import { describe, expect, it } from 'vitest';
import { type AiSdkTool, withPCA } from './index';
import { agent, generateKeyPair, type PcaCall } from '@atlasauth/pca';

const mkAgent = () =>
  agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: 'ins_default' });
const args = { amount: 20, currency: 'usd', charge: 'ch_1' };
const okTool = (): AiSdkTool<typeof args, { ok: true }> => ({ execute: async () => ({ ok: true }) });

describe('withPCA option forwarding', () => {
  it('uses the spec audience when given and the agent default otherwise', async () => {
    let proof: PcaCall | undefined;
    await withPCA(mkAgent(), { verb: 'stripe.refund', resource: 'charge:ch_1', aud: 'ins_override', onProof: (p) => (proof = p) }, okTool()).execute!(args);
    expect(proof!.pcactn.aud).toBe('ins_override');
    await withPCA(mkAgent(), { verb: 'stripe.refund', resource: 'charge:ch_1', onProof: (p) => (proof = p) }, okTool()).execute!(args);
    expect(proof!.pcactn.aud).toBe('ins_default');
  });

  it('failFast false lets an over-cap call through; the default and true refuse it', async () => {
    const over = { amount: 9999, currency: 'usd', charge: 'ch_1' };
    let ran = 0;
    const tool: AiSdkTool<typeof over, number> = { execute: async () => ++ran };
    expect(await withPCA(mkAgent(), { verb: 'stripe.refund', resource: 'charge:ch_1', failFast: false }, tool).execute!(over)).toBe(1);
    await expect(withPCA(mkAgent(), { verb: 'stripe.refund', resource: 'charge:ch_1', failFast: true }, tool).execute!(over)).rejects.toThrow();
    await expect(withPCA(mkAgent(), { verb: 'stripe.refund', resource: 'charge:ch_1' }, tool).execute!(over)).rejects.toThrow();
    expect(ran).toBe(1);
  });

  it('runs without an onProof callback', async () => {
    expect(await withPCA(mkAgent(), { verb: 'stripe.refund', resource: 'charge:ch_1' }, okTool()).execute!(args)).toEqual({ ok: true });
  });

  it('refuses a wrapped tool that has no execute()', async () => {
    const tool: AiSdkTool<typeof args> = { description: 'x' };
    await expect(withPCA(mkAgent(), { verb: 'stripe.refund', resource: 'charge:ch_1' }, tool).execute!(args)).rejects.toThrow('withPCA: the wrapped tool has no execute()');
  });
});
