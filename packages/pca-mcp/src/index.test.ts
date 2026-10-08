import { describe, expect, it } from 'vitest';
import { type McpToolHandler, type McpToolResult, guardToolResult, withPCA } from './index';
import { agent, generateKeyPair, verifyPCActnCore, type PcaCall } from '@atlasauth/pca';

const AUD = 'ins_test';
const mkAgent = () =>
  agent({
    principal: generateKeyPair(),
    goal: 'refunds',
    permissions: { stripe: ['refund'] },
    limits: { refund: '$500/day' },
    aud: AUD,
  });

// a fake MCP tool handler that records its args
const refundHandler = (sink: { ran?: unknown }): McpToolHandler<{ amount: number; charge: string }> => (args) => {
  sink.ran = args;
  return { content: [{ type: 'text', text: 'refunded' }] };
};

describe('withPCA (MCP)', () => {
  it('emits a verifiable PCActn, forwards the proof, then runs the original handler', async () => {
    const a = mkAgent();
    const sink: { ran?: unknown } = {};
    let proof: PcaCall | undefined;
    const wrapped = withPCA(
      a,
      { verb: 'stripe.refund', resource: (args) => `charge:${args.charge}`, onProof: (p) => (proof = p) },
      refundHandler(sink),
    );

    const out = await wrapped({ amount: 20, charge: 'ch_1' });

    // original handler ran and its result flowed through unchanged
    expect(out).toEqual({ content: [{ type: 'text', text: 'refunded' }] });
    expect(sink.ran).toEqual({ amount: 20, charge: 'ch_1' });

    // the captured proof verifies through the core
    expect(proof).toBeDefined();
    const res = await verifyPCActnCore(proof!.pcactn, { grant: a.grant, audience: AUD, nowEpoch: proof!.pcactn.iat });
    expect(res.allow).toBe(true);
    expect(res.checks.leaf_signature).toBe('pass');
  });

  it('returns an MCP error result (not a throw) on an over-cap call and does NOT run the handler', async () => {
    const a = mkAgent();
    const sink: { ran?: unknown } = {};
    const wrapped = withPCA(a, { verb: 'stripe.refund', resource: 'charge:ch_1' }, refundHandler(sink));

    const out = await wrapped({ amount: 9999, charge: 'ch_1' });

    expect(out.isError).toBe(true);
    expect(out.content[0]).toMatchObject({ type: 'text' });
    expect(sink.ran).toBeUndefined();
  });

  it('guardToolResult attaches the proof into _meta without dropping existing content', () => {
    const a = mkAgent();
    const { pcactn, encoded } = a.act('stripe.refund', 'charge:ch_1', { amount: 20 }, { aud: AUD });
    const pca: PcaCall = { pcactn, encoded, headers: {} };
    const result: McpToolResult = { content: [{ type: 'text', text: 'refunded' }], _meta: { trace: 'abc' } };

    const out = guardToolResult(pca, result);

    expect(out.content).toEqual([{ type: 'text', text: 'refunded' }]);
    expect((out._meta as Record<string, unknown>)['x-pca-action']).toBe(encoded);
    expect((out._meta as Record<string, unknown>).trace).toBe('abc'); // existing _meta preserved
  });
});
