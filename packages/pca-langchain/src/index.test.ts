import { describe, expect, it } from 'vitest';
import { type LangChainTool, withPCA } from './index';
import { agent, decodePcaHeader, generateKeyPair, verifyPCActnCore, type PcaCall } from '@atlasauth/pca';

const AUD = 'ins_test';
const mkAgent = () =>
  agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD });

// a fake LangChain structured tool backed by `func`
const refundTool = (sink: { ran?: unknown }): LangChainTool<{ amount: number; currency: string; charge: string }, { ok: true }> => ({
  name: 'refund',
  description: 'Refund a charge',
  schema: { type: 'object' },
  func: async (args) => {
    sink.ran = args;
    return { ok: true };
  },
});

describe('withPCA (LangChain)', () => {
  it('emits a verifiable PCActn, forwards the proof, then runs the original func', async () => {
    const a = mkAgent();
    const sink: { ran?: unknown } = {};
    let proof: PcaCall | undefined;
    const tool = withPCA(
      a,
      { verb: 'stripe.refund', resource: (args) => `charge:${args.charge}`, onProof: (p) => (proof = p) },
      refundTool(sink),
    );
    const out = await tool.func!({ amount: 20, currency: 'usd', charge: 'ch_1' });
    expect(out).toEqual({ ok: true });
    expect(sink.ran).toEqual({ amount: 20, currency: 'usd', charge: 'ch_1' });
    expect(proof).toBeDefined();
    const res = await verifyPCActnCore(proof!.pcactn, { grant: a.grant, audience: AUD, nowEpoch: proof!.pcactn.iat });
    expect(res.allow).toBe(true);
    expect(res.checks.leaf_signature).toBe('pass');
    expect(decodePcaHeader(proof!.headers['PCA-Action']!)).toBe(proof!.encoded);
  });

  it('fast-fails an over-cap call without running the original func', async () => {
    const a = mkAgent();
    const sink: { ran?: unknown } = {};
    const tool = withPCA(a, { verb: 'stripe.refund', resource: 'charge:ch_1' }, refundTool(sink));
    await expect(tool.func!({ amount: 9999, currency: 'usd', charge: 'ch_1' })).rejects.toThrow();
    expect(sink.ran).toBeUndefined();
  });

  it('preserves non-func fields on the wrapped tool', () => {
    const a = mkAgent();
    const tool = withPCA(a, { verb: 'stripe.refund', resource: 'charge:ch_1' }, refundTool({}));
    expect(tool.name).toBe('refund');
    expect(tool.description).toBe('Refund a charge');
    expect(tool.schema).toEqual({ type: 'object' });
  });

  it('guards a tool exposing only invoke()', async () => {
    const a = mkAgent();
    const sink: { ran?: unknown } = {};
    let proof: PcaCall | undefined;
    const invokeOnly: LangChainTool<{ amount: number; currency: string; charge: string }, { ok: true }> = {
      name: 'refund',
      description: 'Refund a charge',
      invoke: async (args) => {
        sink.ran = args;
        return { ok: true };
      },
    };
    const tool = withPCA(
      a,
      { verb: 'stripe.refund', resource: (args) => `charge:${args.charge}`, onProof: (p) => (proof = p) },
      invokeOnly,
    );
    const out = await tool.invoke!({ amount: 20, currency: 'usd', charge: 'ch_1' });
    expect(out).toEqual({ ok: true });
    expect(sink.ran).toEqual({ amount: 20, currency: 'usd', charge: 'ch_1' });
    expect(proof).toBeDefined();
    const res = await verifyPCActnCore(proof!.pcactn, { grant: a.grant, audience: AUD, nowEpoch: proof!.pcactn.iat });
    expect(res.allow).toBe(true);
    expect(res.checks.leaf_signature).toBe('pass');
  });
});
