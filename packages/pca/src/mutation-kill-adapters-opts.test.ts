/** 0.4.2 mutation kills: guard / bridgeToolCall forward exactly the options the caller set (no undefined keys), PcaDenied's shape, and the PCA-Action header rules. */
import { describe, expect, it } from 'vitest';
import { PcaDenied, bridgeToolCall, guard, pcaHeaders } from './adapters';

type Act = (verb: string, resource: string, params: unknown, opts: Record<string, unknown>) => unknown;
const spyAgent = (allowed = true, reason?: string) => {
  const calls: { verb: string; resource: string; params: unknown; opts: Record<string, unknown> }[] = [];
  const agent = {
    act: ((verb, resource, params, opts) => {
      calls.push({ verb, resource, params, opts });
      return { pcactn: { p: 1 }, encoded: 'ENC', dryRun: { allowed, ...(reason ? { reason } : {}) } };
    }) as Act,
  };
  return { agent: agent as never, calls };
};

describe('guard', () => {
  it('forwards aud / counter / now only when set (the key is absent otherwise)', async () => {
    const { agent, calls } = spyAgent();
    await guard(agent, { verb: 'v.x', resource: 'r' }, (_p, pca) => pca)({ a: 1 });
    expect(Object.keys(calls[0]!.opts)).toEqual([]);
    await guard(agent, { verb: 'v.x', resource: 'r', aud: 'A' }, () => 0)({ a: 1 }, { counter: 3, now: 9 });
    expect(calls[1]!.opts).toEqual({ aud: 'A', counter: 3, now: 9 });
    await guard(agent, { verb: 'v.x', resource: 'r' }, () => 0)({ a: 1 }, { counter: 0 });
    expect(calls[2]!.opts).toEqual({ counter: 0 });
    expect(Object.keys(calls[2]!.opts)).toEqual(['counter']);
    await guard(agent, { verb: 'v.x', resource: 'r' }, () => 0)({ a: 1 }, { now: 0 });
    expect(calls[3]!.opts).toEqual({ now: 0 });
  });
  it('the resource may derive from the params; the call gets the proof and its headers', async () => {
    const { agent, calls } = spyAgent();
    const out = await guard(agent, { verb: 'v.x', resource: (p: { id: string }) => `thing:${p.id}` }, (_p, pca) => pca)({ id: '7' });
    expect(calls[0]).toMatchObject({ verb: 'v.x', resource: 'thing:7' });
    expect(out).toEqual({ pcactn: { p: 1 }, encoded: 'ENC', headers: pcaHeaders('ENC') });
  });
  it('a failing dry run throws PcaDenied before dispatch (default and failFast:true); failFast:false dispatches anyway', async () => {
    const { agent } = spyAgent(false, 'over the limit');
    let ran = 0;
    for (const spec of [{ verb: 'v.x', resource: 'r' }, { verb: 'v.x', resource: 'r', failFast: true }]) {
      const e = await guard(agent, spec, () => { ran++; })({}).catch((x) => x);
      expect(e).toBeInstanceOf(PcaDenied);
      expect(e).toMatchObject({ reason: 'over the limit', verb: 'v.x', resource: 'r', name: 'PcaDenied', message: 'PCA denied v.x on r: over the limit' });
    }
    expect(ran).toBe(0);
    await guard(agent, { verb: 'v.x', resource: 'r', failFast: false }, () => { ran++; })({});
    expect(ran).toBe(1);
    const noReason = spyAgent(false).agent;
    const e2 = await guard(noReason, { verb: 'v.x', resource: 'r' }, () => 0)({}).catch((x) => x);
    expect(e2.reason).toBe('denied');
    expect(e2.message).toBe('PCA denied v.x on r: denied');
  });
});

describe('bridgeToolCall', () => {
  it('forwards aud / counter / now only when set; an unmapped tool is null', () => {
    const { agent, calls } = spyAgent();
    const map = (c: { name: string }) => (c.name === 't' ? { verb: 'v.t', resource: 'rt' } : null);
    expect(bridgeToolCall(agent, { name: 'zz', arguments: {} }, map)).toBeNull();
    expect(calls).toHaveLength(0);
    const r = bridgeToolCall(agent, { name: 't', arguments: { q: 1 } }, map);
    expect(r).toEqual({ pcactn: { p: 1 }, encoded: 'ENC', headers: pcaHeaders('ENC') });
    expect(calls[0]).toMatchObject({ verb: 'v.t', resource: 'rt', params: { q: 1 }, opts: {} });
    expect(Object.keys(calls[0]!.opts)).toEqual([]);
    bridgeToolCall(agent, { name: 't', arguments: {} }, map, { aud: 'A', counter: 0, now: 0 });
    expect(calls[1]!.opts).toEqual({ aud: 'A', counter: 0, now: 0 });
    bridgeToolCall(agent, { name: 't', arguments: {} }, map, { counter: 4 });
    expect(Object.keys(calls[2]!.opts)).toEqual(['counter']);
    bridgeToolCall(agent, { name: 't', arguments: {} }, map, { now: 4 });
    expect(Object.keys(calls[3]!.opts)).toEqual(['now']);
    bridgeToolCall(agent, { name: 't', arguments: {} }, map, { aud: 'B' });
    expect(Object.keys(calls[4]!.opts)).toEqual(['aud']);
  });
});
