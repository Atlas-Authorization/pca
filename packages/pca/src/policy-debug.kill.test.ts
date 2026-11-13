import { describe, expect, it } from 'vitest';
import { explainDecision } from './policy-debug';
import type { DecideInput } from './policy-vm';
import { mintGrant } from './envelope';
import { encodeKey, generateKeyPair } from './keys';
import { DEFAULT_RISK_POLICY, type RiskInputs } from './risk';

const P = generateKeyPair();
const A = generateKeyPair();
const NOW = 1_000_000;
const GRANT = mintGrant({
  principalSecret: P.secretKey,
  principalPublic: encodeKey(P.publicKey),
  holder: encodeKey(A.publicKey),
  goal: 'secure my account',
  envelope: {
    predicates: [{ verb: 'revoke_session', resource: '/acct/*' }],
    caveats: [{ type: 'expires', at: 9e12 }] as never,
    agent_binding: {},
    risk_policy: DEFAULT_RISK_POLICY,
  },
}).grant;
const lowRisk: RiskInputs = { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 };
const input = (rFloor: number): DecideInput => ({
  grant: GRANT,
  action: { action: { verb: 'revoke_session', resource: '/acct/1/s', params: {} } },
  risk: lowRisk,
  budget: { B: 1, tau: NOW, asOf: NOW },
  now: NOW,
  rFloor,
});

describe('caution floor edges', () => {
  it('treats an infinite floor as no floor, not as the maximum', () => {
    expect(explainDecision(input(Number.POSITIVE_INFINITY)).risk.rFloor).toBe(0);
    expect(explainDecision(input(Number.NEGATIVE_INFINITY)).risk.rFloor).toBe(0);
  });
});
