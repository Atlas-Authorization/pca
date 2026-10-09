import { describe, expect, it } from 'vitest';
import { type PcaCall, type ToolMapping, type ToolUseBlock, extractToolUses, handleToolUse } from './index';
import { agent, generateKeyPair, verifyPCActnCore } from '@atlasauth/pca';

const AUD = 'ins_test';
const mkAgent = () =>
  agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD });

const refundBlock: ToolUseBlock = {
  type: 'tool_use',
  id: 'tu_1',
  name: 'issue_refund',
  input: { amount: 20, currency: 'usd', charge: 'ch_1' },
};

const map: ToolMapping = (b) =>
  b.name === 'issue_refund' ? { verb: 'stripe.refund', resource: `charge:${b.input.charge}` } : null;

describe('handleToolUse (Anthropic / Claude)', () => {
  it('runs the mapped handler and returns a tool_result carrying a verifiable PCActn', async () => {
    const a = mkAgent();
    const sink: { ran?: unknown } = {};
    let proof: PcaCall | undefined;
    const handlers = {
      issue_refund: (input: Record<string, unknown>, pca: PcaCall) => {
        sink.ran = input;
        proof = pca;
        return { ok: true };
      },
    };

    const result = await handleToolUse(a, refundBlock, map, handlers);
    expect(result.type).toBe('tool_result');
    expect(result.tool_use_id).toBe('tu_1');
    expect(result.is_error).toBeFalsy();
    expect(result.content).toBe(JSON.stringify({ ok: true }));
    expect(sink.ran).toEqual({ amount: 20, currency: 'usd', charge: 'ch_1' });

    expect(proof).toBeDefined();
    const res = await verifyPCActnCore(proof!.pcactn, { grant: a.grant, audience: AUD, nowEpoch: proof!.pcactn.iat });
    expect(res.allow).toBe(true);
    expect(res.checks.leaf_signature).toBe('pass');
  });

  it('returns an error tool_result for an unmapped tool, without running a handler', async () => {
    const a = mkAgent();
    let ran = false;
    const handlers = {
      delete_everything: () => {
        ran = true;
        return { ok: true };
      },
    };
    const block: ToolUseBlock = { type: 'tool_use', id: 'tu_2', name: 'delete_everything', input: {} };
    const result = await handleToolUse(a, block, map, handlers);
    expect(result.tool_use_id).toBe('tu_2');
    expect(result.is_error).toBe(true);
    expect(ran).toBe(false);
  });

  it('returns an error tool_result when the handler throws', async () => {
    const a = mkAgent();
    const handlers = {
      issue_refund: () => {
        throw new Error('stripe is down');
      },
    };
    const result = await handleToolUse(a, refundBlock, map, handlers);
    expect(result.tool_use_id).toBe('tu_1');
    expect(result.is_error).toBe(true);
    expect(result.content).toBe('stripe is down');
  });

  it('extractToolUses pulls only tool_use blocks from a mixed content array', () => {
    const content = [
      { type: 'text', text: 'Let me refund that.' },
      { type: 'tool_use', id: 'tu_1', name: 'issue_refund', input: { charge: 'ch_1' } },
      { type: 'text', text: 'and also' },
      { type: 'tool_use', id: 'tu_2', name: 'lookup', input: {} },
    ];
    const uses = extractToolUses(content);
    expect(uses).toHaveLength(2);
    expect(uses.map((u) => u.id)).toEqual(['tu_1', 'tu_2']);
    expect(uses.every((u) => u.type === 'tool_use')).toBe(true);
  });
});
