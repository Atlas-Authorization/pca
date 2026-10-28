/**
 * Attested-VM compliance mode: "missing / invalid X => exact result". The statement is a signed assertion by a prover key the
 * verifier trusts; it is NOT a proof. Every row is a denial with the exact reason; the control row passes.
 */
import { describe, expect, it } from 'vitest';
import { type ComplianceStatement, createAttestedComplianceProver, createZkVerifier, policyCommitment } from './zk';
import { assuranceLabelOf } from './assurance';
import { mintGrant } from './envelope';
import { buildPCActn, type PCActn } from './pcactn';
import { type DecideInput } from './policy-vm';
import { encodeKey, generateKeyPair } from './keys';
import { DEFAULT_RISK_POLICY, type TrustBudget } from './risk';
import type { Capability } from './capability';
import type { PlanNode } from './merkle';

const P = generateKeyPair();
const A = generateKeyPair();
const NOW = 1_000_000;
const fresh: TrustBudget = { B: 1, tau: NOW, asOf: NOW };
const GRANT: Capability = mintGrant({
  principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), goal: 'secure my account',
  envelope: { predicates: [{ verb: 'revoke_session', resource: '/acct/*' }], caveats: [{ type: 'expires', at: 9e12 }], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
}).grant;
const NODES: PlanNode[] = [{ id: 'n1', verb: 'revoke_session', resource: '/acct/1/s', reversibility_class: 'reversible' }];
const actn = (): PCActn => buildPCActn({ aud: 'a', grant: GRANT, chain: [GRANT], plan: NODES, nodeId: 'n1', counter: 1, signerSecret: A.secretKey });
const input = (p: PCActn): DecideInput => ({
  grant: GRANT, chain: [GRANT], action: { action: { verb: p.action.verb, resource: p.action.resource, params: {}, reversibility_class: p.action.reversibility_class } },
  plan: NODES, risk: { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 }, budget: fresh, now: NOW, nodeId: p.plan.node_id,
});
const prover = createAttestedComplianceProver(generateKeyPair().secretKey);
const stranger = createAttestedComplianceProver(generateKeyPair().secretKey);
const signedBy = (pr: typeof prover, issued = NOW - 1000, expires = NOW + 60_000): PCActn => {
  const p = actn();
  p.zk_compliance = pr.prove({ pcactn: p, decideInput: input(p), issued_at: issued, expires_at: expires });
  return p;
};
const verifier = (over: Record<string, unknown> = {}) => createZkVerifier({ trustedProverKeys: [prover.publicKey], policyCommitments: [policyCommitment(GRANT)], now: () => NOW, ...over });
const run = (p: PCActn, over: Record<string, unknown> = {}) => verifier(over)({ pcactn: p, grant: GRANT });
const OK = { enforced: true, ok: true };
const deny = (reason: string) => ({ enforced: true, ok: false, reason });
const tampered = (patch: Partial<ComplianceStatement>) => {
  const p = signedBy(prover);
  p.zk_compliance = { ...(p.zk_compliance as ComplianceStatement), ...patch };
  return p;
};

describe('attested-VM mode: a trusted signer, not a proof', () => {
  it('is labelled attested_vm (never snark), and the control row passes', async () => {
    expect(assuranceLabelOf(verifier())).toEqual({ level: 'attested_vm' });
    expect(await run(signedBy(prover))).toEqual(OK);
  });

  it.each([
    ['no zk_compliance member', () => actn(), {}, 'no zk_compliance proof present'],
    ['a statement of another version', () => tampered({ v: 2 as never }), {}, 'unrecognized compliance statement'],
    ['a statement of another mode', () => tampered({ mode: 'snark' as never }), {}, 'unrecognized compliance statement'],
    ['a statement that does not assert release', () => tampered({ released: false as never }), {}, 'statement does not assert release'],
    ['a prover key that is not trusted', () => signedBy(stranger), {}, 'prover key is not trusted'],
    ['no trusted prover keys at all', () => signedBy(prover), { trustedProverKeys: [] }, 'prover key is not trusted'],
    ['trusted prover keys that are not an array', () => signedBy(prover), { trustedProverKeys: 'x' }, 'prover key is not trusted'],
    ['a revoked prover key (still listed as trusted)', () => signedBy(prover), { revokedProverKeys: [prover.publicKey] }, 'prover key is revoked'],
    ['a body edited after signing', () => tampered({ r: 0.9 }), {}, 'compliance statement signature does not verify'],
    ['a missing signature', () => tampered({ sig: undefined as never }), {}, 'compliance statement signature does not verify'],
    ['a validity window that ends before it starts (signed)', () => signedBy(prover, NOW + 10, NOW - 10), {}, 'malformed statement validity window'],
    ['an expired statement', () => signedBy(prover, NOW - 5000, NOW - 1), {}, 'compliance statement expired'],
    ['a statement not yet valid', () => signedBy(prover, NOW + 1, NOW + 5000), {}, 'compliance statement not yet valid'],
    ['a statement replayed on another action', () => { const p = signedBy(prover); return { ...p, action: { ...p.action, resource: '/acct/2/s' } } as PCActn; }, {}, 'statement does not bind to this action'],
    ['a statement replayed on another plan root', () => { const p = signedBy(prover); return { ...p, plan: { ...p.plan, root: 'other' } } as PCActn; }, {}, 'statement does not bind to this plan commitment'],
    ['an expected-policy list that does not include the policy', () => signedBy(prover), { policyCommitments: ['other-policy'] }, 'statement policy commitment is not an expected policy'],
    ['an empty expected-policy list', () => signedBy(prover), { policyCommitments: [] }, 'statement policy commitment is not an expected policy'],
  ])('denies %s', async (_n, mk, over, reason) => {
    expect(await run(mk(), over as Record<string, unknown>)).toEqual(deny(reason));
  });

  it('a clock skew widens the window by exactly the skew and no more', async () => {
    const p = signedBy(prover, NOW - 5000, NOW - 100);
    expect(await run(p)).toEqual(deny('compliance statement expired'));
    expect(await run(p, { clockSkewMs: 100 })).toEqual(OK);
    expect(await run(p, { clockSkewMs: 99 })).toEqual(deny('compliance statement expired'));
    expect(await run(p, { clockSkewMs: -1e9 })).toEqual(deny('compliance statement expired'));
  });

  it('the prover refuses to sign a statement for a non-compliant action: you cannot prove a false statement', () => {
    const p = actn();
    const bad = { ...input(p), action: { action: { verb: 'delete_everything', resource: '/x', params: {}, reversibility_class: 'irreversible' } } } as DecideInput;
    expect(() => prover.prove({ pcactn: p, decideInput: bad, issued_at: NOW - 1, expires_at: NOW + 1 })).toThrow('action is not compliant, nothing to prove');
  });
});
