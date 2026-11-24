import { describe, expect, it } from 'vitest';
import { agent, generateKeyPair } from '@atlasauth/pca';
import { handleToolUse, handleToolUses, withPCAMessages, type ToolUseBlock } from './index';

const mkAgent = () => agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: 'rs' });
const map = (b: { name: string }) => (b.name === 'unmapped' ? null : { verb: 'stripe.refund', resource: 'charge:ch_1' });
const use = (id: string, name: string): ToolUseBlock => ({ type: 'tool_use', id, name, input: {} });

describe('pca-anthropic tool_result shapes', () => {
  it('unmapped tool: exact error result', async () => {
    const r = await handleToolUse(mkAgent(), use('t1', 'unmapped'), map, {});
    expect(r).toEqual({ type: 'tool_result', tool_use_id: 't1', content: 'No proof-carrying authority is mapped for tool "unmapped".', is_error: true });
  });

  it('mapped tool without a handler: exact error result', async () => {
    const r = await handleToolUse(mkAgent(), use('t2', 'refund'), map, {});
    expect(r).toEqual({ type: 'tool_result', tool_use_id: 't2', content: 'No handler registered for tool "refund".', is_error: true });
  });

  it('handler returning nothing yields the encoded proof; success has no is_error', async () => {
    let encoded = '';
    const r = await handleToolUse(mkAgent(), use('t3', 'refund'), map, { refund: (_i, pca) => { encoded = pca.encoded; } });
    expect(encoded).not.toBe('');
    expect(r).toEqual({ type: 'tool_result', tool_use_id: 't3', content: JSON.stringify({ pca: encoded }) });
  });

  it('thrown handler: exact error result; non-Error is stringified', async () => {
    const r = await handleToolUse(mkAgent(), use('t4', 'refund'), map, { refund: () => { throw new Error('boom'); } });
    expect(r).toEqual({ type: 'tool_result', tool_use_id: 't4', content: 'boom', is_error: true });
    const s = await handleToolUse(mkAgent(), use('t5', 'refund'), map, { refund: () => { throw 'plain'; } });
    expect(s).toEqual({ type: 'tool_result', tool_use_id: 't5', content: 'plain', is_error: true });
  });

  it('handleToolUses keeps only tool_use blocks, in order, and runs each', async () => {
    const seen: string[] = [];
    const blocks = [use('a', 'refund'), { type: 'text', id: 'x', name: 'refund', input: {} } as unknown as ToolUseBlock, use('b', 'refund')];
    const rs = await handleToolUses(mkAgent(), blocks, map, { refund: () => { seen.push('x'); return 1; } });
    expect(rs.map((r) => r.tool_use_id)).toEqual(['a', 'b']);
    expect(rs.map((r) => r.content)).toEqual(['1', '1']);
    expect(seen).toHaveLength(2);
  });

  it('withPCAMessages tolerates missing params / messages and records nothing', () => {
    const a = mkAgent();
    const create = withPCAMessages(a, (p: { messages?: unknown[] } | undefined) => p?.messages?.length ?? 'none');
    expect(create(undefined as never)).toBe('none');
    expect(create({})).toBe('none');
    expect(a.provenance!.receipts()).toEqual([]);
  });
});
