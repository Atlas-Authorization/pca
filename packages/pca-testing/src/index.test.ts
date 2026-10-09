import { describe, expect, it } from 'vitest';

import {
  expectDenied,
  expectVerifies,
  fakeVerify,
  makePCActn,
  memoryStateStore,
  tamper,
  testAgent,
} from './index';

describe('testAgent', () => {
  it('mints a verifiable agent with test defaults', async () => {
    const a = testAgent();
    expect(a.policy.actions.some((s) => s.verb === 'stripe.refund')).toBe(true);
    const { pcactn } = makePCActn(a, 'stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd' });
    const res = await fakeVerify(pcactn);
    expect(res.allow).toBe(true);
    expect(res.checks.audience).toBe('pass');
  });

  it('honours overrides', () => {
    const a = testAgent({ goal: 'custom', aud: 'ins_custom', permissions: { gmail: ['send'] } });
    const { pcactn } = makePCActn(a, 'gmail.send', 'thread:t_1');
    expect(pcactn.aud).toBe('ins_custom');
  });
});

describe('makePCActn + expectVerifies', () => {
  it('passes for an in-policy action', async () => {
    const a = testAgent();
    const { pcactn } = makePCActn(a, 'stripe.refund', 'charge:ch_9', { amount: 100, currency: 'usd' });
    const res = await expectVerifies(pcactn);
    expect(res.allow).toBe(true);
    expect(res.checks.plan_inclusion).toBe('pass');
    expect(res.checks.leaf_signature).toBe('pass');
  });

  it('auto-increments the counter across calls', () => {
    const a = testAgent();
    const first = makePCActn(a, 'stripe.refund', 'charge:ch_1', { amount: 1, currency: 'usd' });
    const second = makePCActn(a, 'stripe.refund', 'charge:ch_2', { amount: 1, currency: 'usd' });
    expect(second.pcactn.counter).toBe(first.pcactn.counter + 1);
  });
});

describe('tamper', () => {
  it('changing the action verb makes expectVerifies throw and expectDenied pass', async () => {
    const a = testAgent();
    const { encoded } = makePCActn(a, 'stripe.refund', 'charge:ch_7', { amount: 10, currency: 'usd' });

    const mutated = tamper(encoded, (p) => {
      const action = p.action as Record<string, unknown>;
      action.verb = 'stripe.payout';
    });
    const { decodePCActn } = await import('@atlasauth/pca');
    const tampered = decodePCActn(mutated);

    await expect(expectVerifies(tampered)).rejects.toThrow(/denied/);

    const res = await expectDenied(tampered);
    expect(res.allow).toBe(false);
    expect(res.checks.leaf_signature === 'fail' || res.checks.plan_inclusion === 'fail').toBe(true);
  });
});

describe('fakeVerify audience handling', () => {
  it('defaults to the PCActn aud, fails on a mismatch, opts out on null', async () => {
    const a = testAgent({ aud: 'ins_abc' });
    const { pcactn } = makePCActn(a, 'stripe.refund', 'charge:ch_3', { amount: 5, currency: 'usd' });

    expect((await fakeVerify(pcactn)).allow).toBe(true);

    const mismatch = await fakeVerify(pcactn, { audience: 'ins_other' });
    expect(mismatch.allow).toBe(false);
    expect(mismatch.checks.audience).toBe('fail');

    const anyAud = await fakeVerify(pcactn, { audience: null });
    expect(anyAud.checks.audience).toBe('not-enforced');
  });
});

describe('memoryStateStore', () => {
  it('get/put round-trips', async () => {
    const store = memoryStateStore();
    expect(await store.get('holder:1')).toBeUndefined();
    await store.put('holder:1', { lastCounter: 7, lastEpoch: 3, lastBeaconSeq: 2, budget: { B: 500 } });
    const back = await store.get('holder:1');
    expect(back?.lastCounter).toBe(7);
    expect(back?.lastEpoch).toBe(3);
    expect(back?.lastBeaconSeq).toBe(2);
  });
});
