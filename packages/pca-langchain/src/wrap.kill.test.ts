import { describe, expect, it } from 'vitest';
import { type LangChainTool, withPCA, withPCAAgent } from './index';
import { agent, generateKeyPair, type PcaCall } from '@atlasauth/pca';

const mkAgent = () =>
  agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: 'ins_default' });
type Args = { amount: number; currency: string };
const ok: Args = { amount: 20, currency: 'usd' };

describe('withPCA wrapping', () => {
  it('uses the spec audience over the agent default, and the default when absent', async () => {
    const proofs: PcaCall[] = [];
    const base: LangChainTool<Args, number> = { name: 't', func: async () => 1 };
    await withPCA(mkAgent(), { verb: 'stripe.refund', resource: 'c:1', aud: 'ins_other', onProof: (p) => proofs.push(p) }, base).func!(ok);
    await withPCA(mkAgent(), { verb: 'stripe.refund', resource: 'c:1', onProof: (p) => proofs.push(p) }, base).func!(ok);
    expect(proofs.map((p) => p.pcactn.aud)).toEqual(['ins_other', 'ins_default']);
  });

  it('failFast false lets an over-cap call through; unset/true refuses it', async () => {
    const big: Args = { amount: 9999, currency: 'usd' };
    let ran = 0;
    const tool: LangChainTool<Args, number> = { name: 't', func: async () => ++ran };
    const spec = { verb: 'stripe.refund', resource: 'c:1' };
    expect(await withPCA(mkAgent(), { ...spec, failFast: false }, tool).func!(big)).toBe(1);
    await expect(withPCA(mkAgent(), { ...spec, failFast: true }, tool).func!(big)).rejects.toThrow();
    await expect(withPCA(mkAgent(), spec, tool).func!(big)).rejects.toThrow();
    expect(ran).toBe(1);
  });

  it('wraps only the callables the tool has', () => {
    const spec = { verb: 'stripe.refund', resource: 'c:1' };
    const onlyFunc = withPCA(mkAgent(), spec, { name: 't', func: async () => 1 } as LangChainTool<Args, number>);
    expect(typeof onlyFunc.func).toBe('function');
    expect(onlyFunc.invoke).toBeUndefined();
    const onlyInvoke = withPCA(mkAgent(), spec, { name: 't', invoke: async () => 1 } as LangChainTool<Args, number>);
    expect(typeof onlyInvoke.invoke).toBe('function');
    expect(onlyInvoke.func).toBeUndefined();
  });

  it('wraps both func and invoke, each running its own callable, with onProof optional', async () => {
    const calls: string[] = [];
    const proofs: string[] = [];
    const tool: LangChainTool<Args, string> = { name: 't', func: async () => { calls.push('func'); return 'f'; }, invoke: async () => { calls.push('invoke'); return 'i'; } };
    const noProof = withPCA(mkAgent(), { verb: 'stripe.refund', resource: 'c:1' }, tool);
    expect(await noProof.func!(ok)).toBe('f');
    expect(await noProof.invoke!(ok)).toBe('i');
    const withProof = withPCA(mkAgent(), { verb: 'stripe.refund', resource: 'c:1', onProof: (_p, a) => proofs.push(String(a.amount)) }, tool);
    await withProof.func!(ok);
    await withProof.invoke!(ok);
    expect(calls).toEqual(['func', 'invoke', 'func', 'invoke']);
    expect(proofs).toEqual(['20', '20']);
  });

  it('a tool with neither callable throws a clear error from both', () => {
    const t = withPCA(mkAgent(), { verb: 'stripe.refund', resource: 'c:1' }, { name: 't' } as LangChainTool<Args, number>);
    expect(() => t.func!(ok)).toThrow('withPCA: the wrapped tool exposes neither func() nor invoke()');
    expect(() => t.invoke!(ok)).toThrow('withPCA: the wrapped tool exposes neither func() nor invoke()');
  });
});

describe('withPCAAgent', () => {
  it('does not invent a stream when the runnable has none, and wraps it when present', async () => {
    const a = mkAgent();
    const plain = withPCAAgent(a, { invoke: () => 1 });
    expect(plain.stream).toBeUndefined();
    const seen: unknown[] = [];
    const streaming = withPCAAgent(a, { invoke: () => 1, stream: (i: unknown) => { seen.push(i); return 'S'; } });
    expect(streaming.stream!('hi')).toBe('S');
    expect(seen).toEqual(['hi']);
  });
});
