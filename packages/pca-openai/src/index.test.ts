import { describe, expect, it } from 'vitest';
import {
  type OpenAIToolCall,
  type PcaCall,
  dispatchToolCall,
  dispatchToolCalls,
} from './index';
import { agent, generateKeyPair, verifyPCActnCore } from '@atlasauth/pca';

const AUD = 'ins_test';
const mkAgent = () =>
  agent({
    principal: generateKeyPair(),
    goal: 'refunds',
    permissions: { stripe: ['refund'] },
    limits: { refund: '$500/day' },
    aud: AUD,
  });

const refundCall = (args: Record<string, unknown>): OpenAIToolCall => ({
  id: 'call_1',
  type: 'function',
  function: { name: 'issue_refund', arguments: JSON.stringify(args) },
});

const refundMap = (call: { name: string }) =>
  call.name === 'issue_refund'
    ? { verb: 'stripe.refund', resource: 'charge:ch_1' }
    : null;

describe('dispatchToolCall (OpenAI)', () => {
  it('builds a verifiable PCActn, runs the handler with the proof, returns a tool message', async () => {
    const a = mkAgent();
    const sink: { ran?: unknown } = {};
    let proof: PcaCall | undefined;
    const handlers = {
      issue_refund: (args: Record<string, unknown>, pca: PcaCall) => {
        sink.ran = args;
        proof = pca;
        return { ok: true };
      },
    };

    const msg = await dispatchToolCall(a, refundCall({ amount: 20, currency: 'usd', charge: 'ch_1' }), refundMap, handlers);

    expect(msg.role).toBe('tool');
    expect(msg.tool_call_id).toBe('call_1');
    expect(JSON.parse(msg.content)).toEqual({ ok: true });
    expect(sink.ran).toEqual({ amount: 20, currency: 'usd', charge: 'ch_1' });

    expect(proof).toBeDefined();
    const res = await verifyPCActnCore(proof!.pcactn, { grant: a.grant, audience: AUD, nowEpoch: proof!.pcactn.iat });
    expect(res.allow).toBe(true);
    expect(res.checks.leaf_signature).toBe('pass');
  });

  it('tolerates empty-string arguments (→ {})', async () => {
    const a = mkAgent();
    let seen: Record<string, unknown> | undefined;
    const call: OpenAIToolCall = { id: 'call_empty', type: 'function', function: { name: 'issue_refund', arguments: '' } };
    await dispatchToolCall(a, call, refundMap, {
      issue_refund: (args) => {
        seen = args;
        return { ok: true };
      },
    });
    expect(seen).toEqual({});
  });

  it('returns a proof-echoing message when no handler is registered', async () => {
    const a = mkAgent();
    const msg = await dispatchToolCall(a, refundCall({ amount: 5, currency: 'usd', charge: 'ch_1' }), refundMap, {});
    const parsed = JSON.parse(msg.content) as { pca?: string };
    expect(typeof parsed.pca).toBe('string');
    expect(parsed.pca!.length).toBeGreaterThan(0);
  });

  it('throws on an unmapped tool name (no PCActn without a mapping)', async () => {
    const a = mkAgent();
    const call: OpenAIToolCall = { id: 'call_x', type: 'function', function: { name: 'delete_everything', arguments: '{}' } };
    await expect(dispatchToolCall(a, call, refundMap, {})).rejects.toThrow(/unmapped tool/);
  });

  it('does NOT fast-fail an over-cap call — bridge builds a PCActn; enforcement is the RS', async () => {
    const a = mkAgent();
    let proof: PcaCall | undefined;
    const msg = await dispatchToolCall(
      a,
      refundCall({ amount: 9999, currency: 'usd', charge: 'ch_1' }),
      refundMap,
      {
        issue_refund: (_args, pca) => {
          proof = pca;
          return { ok: true };
        },
      },
    );
    // dispatch still produces a tool message + a signed PCActn for the (over-cap) action...
    expect(msg.tool_call_id).toBe('call_1');
    expect(proof).toBeDefined();
    expect(proof!.pcactn.action.verb).toBe('stripe.refund');
    expect(proof!.pcactn.action.resource).toBe('charge:ch_1');
    // ...and the agent's own offline dry-run is what would flag the over-cap (the RS is authoritative).
    expect(a.dryRun('stripe.refund', 'charge:ch_1', { amount: 9999, currency: 'usd', charge: 'ch_1' }).allowed).toBe(false);
  });
});

describe('dispatchToolCalls (OpenAI)', () => {
  it('dispatches an array of tool calls, incrementing the counter', async () => {
    const a = mkAgent();
    const proofs: PcaCall[] = [];
    const handlers = {
      issue_refund: (_args: Record<string, unknown>, pca: PcaCall) => {
        proofs.push(pca);
        return { ok: true };
      },
    };
    const calls: OpenAIToolCall[] = [
      { id: 'c0', type: 'function', function: { name: 'issue_refund', arguments: JSON.stringify({ amount: 1, currency: 'usd', charge: 'ch_1' }) } },
      { id: 'c1', type: 'function', function: { name: 'issue_refund', arguments: JSON.stringify({ amount: 2, currency: 'usd', charge: 'ch_1' }) } },
    ];

    const msgs = await dispatchToolCalls(a, calls, refundMap, handlers, { counter: 10 });

    expect(msgs.map((m) => m.tool_call_id)).toEqual(['c0', 'c1']);
    expect(msgs.every((m) => m.role === 'tool')).toBe(true);
    expect(proofs).toHaveLength(2);
    expect(proofs[0]!.pcactn.counter).toBe(10);
    expect(proofs[1]!.pcactn.counter).toBe(11);
  });
});
