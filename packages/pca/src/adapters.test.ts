import { describe, expect, it } from 'vitest';
import { PcaDenied, PCA_HEADER, bridgeToolCall, decodePcaHeader, guard, pcaHeaders } from './adapters';
import { agent } from './facade';
import { generateKeyPair } from './keys';
import { decodePCActn, verifyPCActnCore } from './pcactn';

const AUD = 'ins_test';
const mkAgent = () =>
  agent({ principal: generateKeyPair(), goal: 'g', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD });

describe('pcaHeaders', () => {
  it('carries the encoded action under the canonical header', () => {
    const h = pcaHeaders('abc');
    expect(Object.keys(h)).toEqual([PCA_HEADER]);
    expect(decodePcaHeader(h[PCA_HEADER]!)).toBe('abc'); // base64url round-trips
  });
});

describe('guard', () => {
  it('dispatches with a verifiable PCActn attached and returns the run() result', async () => {
    const a = mkAgent();
    let seenHeader = '';
    const refund = guard<{ amount: number; currency: string; charge: string }, { ok: true }>(
      a,
      { verb: 'stripe.refund', resource: (p) => `charge:${p.charge}` },
      async (_params, pca) => {
        seenHeader = decodePcaHeader(pca.headers[PCA_HEADER]!);
        // the attached proof verifies offline against the agent's grant
        const res = await verifyPCActnCore(pca.pcactn, { grant: a.grant, audience: AUD, nowEpoch: pca.pcactn.iat });
        expect(res.allow).toBe(true);
        expect(res.checks.leaf_signature).toBe('pass');
        expect(res.checks.cap_chain).toBe('pass');
        return { ok: true };
      },
    );
    const out = await refund({ amount: 10, currency: 'usd', charge: 'ch_1' }, { counter: 1 });
    expect(out).toEqual({ ok: true });
    // header actually carried the encoded action
    expect(decodePCActn(seenHeader).action.verb).toBe('stripe.refund');
  });

  it('fast-fails locally (PcaDenied) on an over-cap call, without dispatching', async () => {
    const a = mkAgent();
    let dispatched = false;
    const refund = guard<{ amount: number; currency: string }, void>(
      a,
      { verb: 'stripe.refund', resource: 'charge:ch_1' },
      async () => {
        dispatched = true;
      },
    );
    await expect(refund({ amount: 9_999, currency: 'usd' }, { counter: 1 })).rejects.toBeInstanceOf(PcaDenied);
    expect(dispatched).toBe(false);
  });

  it('failFast:false dispatches even on a local deny (server is the only gate)', async () => {
    const a = mkAgent();
    let dispatched = false;
    const refund = guard<{ amount: number; currency: string }, void>(
      a,
      { verb: 'stripe.refund', resource: 'charge:ch_1', failFast: false },
      async () => {
        dispatched = true;
      },
    );
    await refund({ amount: 9_999, currency: 'usd' }, { counter: 1 });
    expect(dispatched).toBe(true);
  });
});

describe('bridgeToolCall', () => {
  it('maps a framework tool call into a verifiable PCActn, or null when unmapped', async () => {
    const a = mkAgent();
    const map = (c: { name: string }) => (c.name === 'issue_refund' ? { verb: 'stripe.refund', resource: 'charge:ch_1' } : null);
    const call = { name: 'issue_refund', arguments: { amount: 5, currency: 'usd' } };
    const bridged = bridgeToolCall(a, call, map, { counter: 1 })!;
    expect(bridged).not.toBeNull();
    const res = await verifyPCActnCore(bridged.pcactn, { grant: a.grant, audience: AUD, nowEpoch: bridged.pcactn.iat });
    expect(res.allow).toBe(true);
    expect(res.checks.leaf_signature).toBe('pass');
    expect(bridgeToolCall(a, { name: 'unknown_tool', arguments: {} }, map)).toBeNull();
  });
});
