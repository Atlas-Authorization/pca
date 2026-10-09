import { describe, expect, it } from 'vitest';
import { agent, buildDiscoveryDocument, generateKeyPair } from '@atlasauth/pca';
import { ALL_SCHEMAS, CAPABILITY_SCHEMA, DISCOVERY_SCHEMA, PCACTN_SCHEMA, validate } from './index';

/** Mint a real, signed PCActn the way an integrator would — via the `agent(...).act(...)` facade. */
function mintPCActn() {
  const principal = generateKeyPair();
  const a = agent({
    principal,
    goal: 'reconcile refunds for October',
    permissions: { stripe: ['refund'] },
    limits: { refund: '$500/day' },
    aud: 'ins_test',
  });
  return a.act('stripe.refund', 'charge:ch_123', { amount: 42, currency: 'usd' }, { counter: 1 }).pcactn;
}

describe('PCA wire schemas', () => {
  it('validates a REAL minted PCActn against PCACTN_SCHEMA', () => {
    const pcactn = mintPCActn();
    const res = validate(PCACTN_SCHEMA, pcactn);
    expect(res.errors).toEqual([]);
    expect(res.valid).toBe(true);
  });

  it('rejects a PCActn with a required field removed, naming it', () => {
    const { sig: _sig, ...withoutSig } = mintPCActn();
    void _sig;
    const res = validate(PCACTN_SCHEMA, withoutSig);
    expect(res.valid).toBe(false);
    expect(res.errors.some((e) => e.includes('sig'))).toBe(true);
  });

  it('validates a cap_chain hop against CAPABILITY_SCHEMA', () => {
    const pcactn = mintPCActn();
    const hop = pcactn.cap_chain[0];
    expect(hop).toBeDefined();
    const res = validate(CAPABILITY_SCHEMA, hop);
    expect(res.errors).toEqual([]);
    expect(res.valid).toBe(true);
  });

  it('validates a discovery document against DISCOVERY_SCHEMA', () => {
    const doc = buildDiscoveryDocument({ audience: 'x' });
    const res = validate(DISCOVERY_SCHEMA, doc);
    expect(res.errors).toEqual([]);
    expect(res.valid).toBe(true);
  });

  it('catches a wrong JSON type on a nested field', () => {
    const pcactn = mintPCActn();
    const broken = { ...pcactn, counter: 'not-a-number' };
    const res = validate(PCACTN_SCHEMA, broken);
    expect(res.valid).toBe(false);
    expect(res.errors.some((e) => e.includes('counter'))).toBe(true);
  });

  it('rejects a non-object top-level value', () => {
    const res = validate(PCACTN_SCHEMA, 'not an object');
    expect(res.valid).toBe(false);
    expect(res.errors.some((e) => e.includes('(root)'))).toBe(true);
  });

  it('exposes all three schemas in ALL_SCHEMAS', () => {
    expect(Object.keys(ALL_SCHEMAS).sort()).toEqual(['Capability', 'PCActn', 'PcaDiscoveryDocument']);
  });
});
