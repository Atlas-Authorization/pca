import { describe, expect, it } from 'vitest';
import { b64u } from './hash';
import { encodeKey, generateKeyPair } from './keys';
import { attenuate } from './capability';
import { mintGrant } from './envelope';
import { DEFAULT_RISK_POLICY, type TrustBudget } from './risk';
import { decide, type DecideInput } from './policy-vm';

const P = generateKeyPair();
const A = generateKeyPair();
const NOW = 1_000_000;
const fresh: TrustBudget = { B: 1, tau: NOW, asOf: NOW };

const G = mintGrant({
  principalSecret: P.secretKey,
  principalPublic: encodeKey(P.publicKey),
  holder: encodeKey(A.publicKey),
  goal: 'secure account',
  envelope: {
    predicates: [{ verb: 'revoke_session', resource: '/acct/*' }],
    caveats: [{ type: 'expires', at: 9e12 }],
    agent_binding: {},
    risk_policy: DEFAULT_RISK_POLICY,
  },
}).grant;

const lowRisk = { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 };
const action = { action: { verb: 'revoke_session', resource: '/acct/1', params: {} } };
const base: DecideInput = { grant: G, action, risk: lowRisk, budget: fresh, now: NOW };

// a well-formed-but-UNSIGNED grant: its signature is the right length but wrong bytes
const tamperedGrant = { ...G, sig: b64u(new Uint8Array(64)) };

describe('A2h: decide() fails closed on an unverified capability chain', () => {
  it('a valid signed grant releases (upstream path unchanged)', () => {
    const d = decide(base);
    expect(d.releaseGuardianShare).toBe(true);
    expect(d.reasons.join(' ')).not.toMatch(/unverified/);
  });

  it('a valid delegated chain still releases (upstream path unchanged)', () => {
    const leaf = attenuate(G, [], A.secretKey);
    const d = decide({ ...base, chain: [G, leaf] });
    expect(d.releaseGuardianShare).toBe(true);
  });

  it('an UNSIGNED / tampered grant is DENIED with an "unverified" reason and r = 1', () => {
    const d = decide({ ...base, grant: tamperedGrant });
    expect(d.releaseGuardianShare).toBe(false);
    expect(d.admit).toBe(false);
    expect(d.r).toBe(1);
    expect(d.reasons[0]).toMatch(/capability chain unverified/);
  });

  it('a FORGED hop in the chain is denied', () => {
    const leaf = attenuate(G, [], A.secretKey);
    const forged = { ...leaf, sig: b64u(new Uint8Array(64)) };
    const d = decide({ ...base, chain: [G, forged] });
    expect(d.releaseGuardianShare).toBe(false);
    expect(d.reasons[0]).toMatch(/capability chain unverified/);
  });

  it('the already-verified marker (chainVerified) bypasses the gate — honored only post-verification', () => {
    const denied = decide({ ...base, grant: tamperedGrant });
    expect(denied.releaseGuardianShare).toBe(false);
    // with the marker set, decide trusts that an upstream verifier already ran verifyChain
    const d = decide({ ...base, grant: tamperedGrant, chainVerified: true });
    expect(d.reasons.join(' ')).not.toMatch(/unverified/);
    expect(d.releaseGuardianShare).toBe(true);
  });

  it('an empty chain keeps its existing denial semantics (not the unverified-signature path)', () => {
    const d = decide({ ...base, chain: [] });
    expect(d.releaseGuardianShare).toBe(false);
    expect(d.reasons.some((r) => /empty or malformed/.test(r))).toBe(true);
  });

  it('a grant with no envelope is still denied (fail-closed, reason preserved)', () => {
    const d = decide({ ...base, grant: { id: 'x', issuer: 'i', holder: 'h', caveats: [] } as never });
    expect(d.releaseGuardianShare).toBe(false);
    expect(d.r).toBe(1);
  });
});
