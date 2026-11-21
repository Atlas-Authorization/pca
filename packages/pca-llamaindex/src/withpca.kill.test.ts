import { describe, expect, it } from 'vitest';
import { type LlamaIndexTool, withPCA, withPCAEngine, type LlamaIndexEngine } from './index';
import { agent, generateKeyPair, type PcaCall } from '@atlasauth/pca';

const mkAgent = () =>
  agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: 'ins_default' });
const args = { amount: 20, currency: 'usd', charge: 'ch_1' };
const okTool = (): LlamaIndexTool<typeof args, { ok: true }> => ({ metadata: { name: 'r' }, call: async () => ({ ok: true }) });

describe('withPCA option forwarding', () => {
  it('uses the spec audience when given and the agent default otherwise', async () => {
    let proof: PcaCall | undefined;
    await withPCA(mkAgent(), { verb: 'stripe.refund', resource: 'charge:ch_1', aud: 'ins_override', onProof: (p) => (proof = p) }, okTool()).call(args);
    expect(proof!.pcactn.aud).toBe('ins_override');
    await withPCA(mkAgent(), { verb: 'stripe.refund', resource: 'charge:ch_1', onProof: (p) => (proof = p) }, okTool()).call(args);
    expect(proof!.pcactn.aud).toBe('ins_default');
  });

  it('failFast false lets an over-cap call through; the default and true refuse it', async () => {
    const over = { amount: 9999, currency: 'usd', charge: 'ch_1' };
    let ran = 0;
    const tool: LlamaIndexTool<typeof over, number> = { metadata: { name: 'r' }, call: async () => ++ran };
    expect(await withPCA(mkAgent(), { verb: 'stripe.refund', resource: 'charge:ch_1', failFast: false }, tool).call(over)).toBe(1);
    await expect(withPCA(mkAgent(), { verb: 'stripe.refund', resource: 'charge:ch_1', failFast: true }, tool).call(over)).rejects.toThrow();
    await expect(withPCA(mkAgent(), { verb: 'stripe.refund', resource: 'charge:ch_1' }, tool).call(over)).rejects.toThrow();
    expect(ran).toBe(1);
  });

  it('runs without an onProof callback', async () => {
    expect(await withPCA(mkAgent(), { verb: 'stripe.refund', resource: 'charge:ch_1' }, okTool()).call(args)).toEqual({ ok: true });
  });
});

describe('withPCAEngine', () => {
  const run = (engine: LlamaIndexEngine, m: 'chat' | 'query', p: unknown) => (withPCAEngine(mkAgent(), engine)[m] as (x: unknown) => unknown)(p);

  it('skips a missing or non-function method and keeps the original', () => {
    const wrapped = withPCAEngine(mkAgent(), { chat: 'nope' as unknown as undefined, query: undefined });
    expect(wrapped.chat).toBe('nope');
    expect(wrapped.query).toBeUndefined();
  });

  it('calls the original with its own this and params and returns its result', () => {
    const engine: LlamaIndexEngine = { tag: 'e', chat(this: { tag: string }, p: unknown) { return [this.tag, p]; } };
    const p = { message: 'hi' };
    expect(run(engine, 'chat', p)).toEqual(['e', p]);
  });

  it('handles null, string, object without history and non-array history params', () => {
    const calls: unknown[] = [];
    const engine: LlamaIndexEngine = { chat: (p: unknown) => (calls.push(p), 1) };
    expect(run(engine, 'chat', null)).toBe(1);
    expect(run(engine, 'chat', undefined)).toBe(1);
    expect(run(engine, 'chat', 'hello')).toBe(1);
    expect(run(engine, 'chat', { message: 'x' })).toBe(1);
    expect(run(engine, 'chat', { chatHistory: 'not-an-array' })).toBe(1);
    expect(calls).toHaveLength(5);
  });
});
