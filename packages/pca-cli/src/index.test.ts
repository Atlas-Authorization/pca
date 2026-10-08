import { agent, encodePCActn, generateKeyPair, unb64u } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';

import { cmdDecode, cmdDiscovery, cmdExplain, cmdKeygen, cmdSimulate } from './index';

/** Mint a real, signed PCActn via the facade for use across the decode/explain tests. */
function mintRefund() {
  const principal = generateKeyPair();
  const a = agent({
    principal,
    goal: 'reconcile october refunds',
    permissions: { stripe: ['refund'] },
    limits: { refund: '$500/day' },
    aud: 'ins_test',
  });
  return a.act('stripe.refund', 'charge:ch_123', { amount: 42, currency: 'usd' }, { counter: 1 });
}

describe('cmdDecode', () => {
  it('summarizes a PCActn from JSON text', () => {
    const { pcactn } = mintRefund();
    const out = cmdDecode(JSON.stringify(pcactn));
    expect(out).toContain('stripe.refund');
    expect(out).toContain('charge:ch_123');
    expect(out).toContain('ins_test');
    expect(out).toContain('counter       1');
  });

  it('accepts the base64url / wire form too', () => {
    const { pcactn, encoded } = mintRefund();
    // `encoded` is canonical JSON text; also exercise an actual base64url input.
    const b64 = Buffer.from(encodePCActn(pcactn), 'utf8').toString('base64url');
    expect(cmdDecode(encoded)).toContain('stripe.refund');
    expect(cmdDecode(b64)).toContain('stripe.refund');
  });

  it('throws a clear error on malformed input', () => {
    expect(() => cmdDecode('')).toThrow(/empty input/);
    expect(() => cmdDecode('{not json')).toThrow(/not a valid PCActn/);
  });
});

describe('cmdExplain', () => {
  it('ALLOWs with the correct audience and shows leaf_signature PASS', async () => {
    const { pcactn } = mintRefund();
    const res = await cmdExplain(JSON.stringify(pcactn), { audience: 'ins_test' });
    expect(res.allow).toBe(true);
    expect(res.checks.leaf_signature).toBe('PASS');
    expect(res.checks.audience).toBe('PASS');
    expect(res.text).toContain('VERDICT: ALLOW');
  });

  it('fails the audience check with the wrong audience', async () => {
    const { pcactn } = mintRefund();
    const res = await cmdExplain(JSON.stringify(pcactn), { audience: 'ins_wrong' });
    expect(res.allow).toBe(false);
    expect(res.checks.audience).toBe('FAIL');
    expect(res.reasons.some((r) => r.includes('audience'))).toBe(true);
  });
});

describe('cmdKeygen', () => {
  it('returns a 32-byte base64url public key', () => {
    const { publicKey, secretKey, text } = cmdKeygen();
    expect(unb64u(publicKey)).toHaveLength(32);
    expect(unb64u(secretKey)).toHaveLength(32);
    expect(text).toContain('public');
    expect(text).toContain('secret');
  });
});

describe('cmdSimulate', () => {
  it('shows auto, auto, step_up for three $40 refunds under a $100/day cap', () => {
    const policy = JSON.stringify({ permissions: { stripe: ['refund'] }, limits: { refund: '$100/day' } });
    const actions = JSON.stringify([
      { verb: 'stripe.refund', resource: 'charge:ch_1', params: { amount: 40 } },
      { verb: 'stripe.refund', resource: 'charge:ch_2', params: { amount: 40 } },
      { verb: 'stripe.refund', resource: 'charge:ch_3', params: { amount: 40 } },
    ]);
    const out = cmdSimulate(policy, actions);
    const outcomes = out
      .split('\n')
      .filter((l) => /^\s+\d+\s+stripe\.refund/.test(l)) // table data rows only, not the lint lines
      .map((l) => (l.includes('step_up') ? 'step_up' : l.includes('auto') ? 'auto' : l.includes('deny') ? 'deny' : '?'));
    expect(outcomes).toEqual(['auto', 'auto', 'step_up']);
    expect(out).toContain('autonomy bound');
  });
});

describe('cmdDiscovery', () => {
  it('emits a valid .well-known/pca-configuration document', () => {
    const out = cmdDiscovery({ audience: 'ins_acme', suites: ['ed25519', 'hybrid-ed25519-ml-dsa-65'], endpoints: { stepup: 'https://api.acme.com/v1/pca/stepups' } });
    const doc = JSON.parse(out) as { audience: string; signature_suites: string[]; action_header: string; endpoints?: { stepup?: string } };
    expect(doc.audience).toBe('ins_acme');
    expect(doc.action_header).toBe('PCA-Action');
    expect(doc.signature_suites).toContain('hybrid-ed25519-ml-dsa-65');
    expect(doc.endpoints?.stepup).toMatch(/stepups/);
  });
});
