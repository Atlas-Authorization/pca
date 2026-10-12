import { describe, expect, it } from 'vitest';
import { type LlamaIndexTool, withPCA } from './index';
import { agent, decodePcaHeader, generateKeyPair, verifyPCActnCore, type PcaCall } from '@atlasauth/pca';

const AUD = 'ins_test';
const mkAgent = () =>
  agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD });

// a fake LlamaIndex FunctionTool
const refundTool = (sink: { ran?: unknown }): LlamaIndexTool<{ amount: number; currency: string; charge: string }, { ok: true }> => ({
  metadata: { name: 'refund', description: 'Refund a charge', parameters: { type: 'object' } },
  call: async (args) => {
    sink.ran = args;
    return { ok: true };
  },
});

describe('withPCA (LlamaIndex.TS)', () => {
  it('emits a verifiable PCActn, forwards the proof, then runs the original call', async () => {
    const a = mkAgent();
    const sink: { ran?: unknown } = {};
    let proof: PcaCall | undefined;
    const tool = withPCA(
      a,
      { verb: 'stripe.refund', resource: (args) => `charge:${args.charge}`, onProof: (p) => (proof = p) },
      refundTool(sink),
    );
    const out = await tool.call({ amount: 20, currency: 'usd', charge: 'ch_1' });
    expect(out).toEqual({ ok: true });
    expect(sink.ran).toEqual({ amount: 20, currency: 'usd', charge: 'ch_1' });
    expect(proof).toBeDefined();
    const res = await verifyPCActnCore(proof!.pcactn, { grant: a.grant, audience: AUD, nowEpoch: proof!.pcactn.iat });
    expect(res.allow).toBe(true);
    expect(res.checks.leaf_signature).toBe('pass');
    expect(decodePcaHeader(proof!.headers['PCA-Action']!)).toBe(proof!.encoded);
  });

  it('fast-fails an over-cap call without running the original call', async () => {
    const a = mkAgent();
    const sink: { ran?: unknown } = {};
    const tool = withPCA(a, { verb: 'stripe.refund', resource: 'charge:ch_1' }, refundTool(sink));
    await expect(tool.call({ amount: 9999, currency: 'usd', charge: 'ch_1' })).rejects.toThrow();
    expect(sink.ran).toBeUndefined();
  });

  it('preserves metadata on the wrapped tool', () => {
    const a = mkAgent();
    const tool = withPCA(a, { verb: 'stripe.refund', resource: 'charge:ch_1' }, refundTool({}));
    expect(tool.metadata.name).toBe('refund');
    expect(tool.metadata.description).toBe('Refund a charge');
    expect(tool.metadata.parameters).toEqual({ type: 'object' });
  });
});
