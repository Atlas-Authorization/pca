import { describe, expect, it } from 'vitest';
import { attenuate, delegate, holderPqCommitment, verifyChain } from './capability';
import { mintGrant } from './envelope';
import { encodeKey, generateKeyPair } from './keys';
import { buildPCActn, signPCActnSuite } from './pcactn';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from './pq';
import { DEFAULT_RISK_POLICY } from './risk';
import { verifyPCActn } from './server/verify';

/**
 * F-2 / F-4 regressions (docs/pca/security/proofs/02-threshold-hybrid.md C.2): the PQ key of a hybrid or pure-PQ
 * suite is part of the holder identity the chain binds, and the verifier has a suite policy.
 */
const NOW = Date.now();
const safeRisk = { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 };
const seed = () => crypto.getRandomValues(new Uint8Array(32));

function setup(opts: { bindPq: boolean }) {
  const P = generateKeyPair();
  const A = generateKeyPair(); // legitimate agent; the "Ed25519 forger" is modelled by using A.secretKey
  const agentPq = mlDsa65Keygen(seed());
  const { grant } = mintGrant({
    principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), goal: 'g',
    ...(opts.bindPq ? { holderPq: encodeMlDsaPublicKey(agentPq.publicKey) } : {}),
    envelope: { predicates: [{ verb: '*' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
  });
  const nodes = [{ id: 'n1', verb: 'wire', resource: 'bank', reversibility_class: 'reversible' }];
  const body = (): never => {
    const legit = buildPCActn({ aud: 'x', now: NOW, grant, chain: [grant], plan: nodes, nodeId: 'n1', counter: 1, signerSecret: A.secretKey, riskClaim: { r: 0, inputs: {} } });
    const { sig: _s, ...b } = legit as never as Record<string, unknown>;
    return b as never;
  };
  const verify = (p: unknown, extra: Record<string, unknown> = {}) =>
    verifyPCActn(p as never, { grant, audience: 'x', now: NOW, context: { risk: safeRisk, budget: { B: 1, tau: NOW } }, ...extra });
  return { P, A, agentPq, grant, body, verify };
}

describe('F-2: the PQ key of a hybrid leaf is bound to the holder', () => {
  it('Ed25519 forger substituting its own ML-DSA key is rejected (holder committed to the real PQ key)', async () => {
    const s = setup({ bindPq: true });
    const atk = mlDsa65Keygen(seed());
    const forged = signPCActnSuite(s.body(), { alg: 'hybrid-ed25519-ml-dsa-65', edLeafSecret: s.A.secretKey, mlDsa: atk });
    const v = await s.verify(forged);
    expect(v.checks.leaf_signature).toBe('fail');
    expect(v.allow).toBe(false);
  });

  it('the genuine holder PQ key is accepted', async () => {
    const s = setup({ bindPq: true });
    const ok = signPCActnSuite(s.body(), { alg: 'hybrid-ed25519-ml-dsa-65', edLeafSecret: s.A.secretKey, mlDsa: s.agentPq });
    const v = await s.verify(ok);
    expect(v.checks.leaf_signature, v.reasons.join('|')).toBe('pass');
    expect(v.allow).toBe(true);
  });

  it('a holder with NO committed PQ key cannot present a hybrid leaf (default); allowUnboundPq is the loud legacy opt-out', async () => {
    const s = setup({ bindPq: false });
    const atk = mlDsa65Keygen(seed());
    const forged = signPCActnSuite(s.body(), { alg: 'hybrid-ed25519-ml-dsa-65', edLeafSecret: s.A.secretKey, mlDsa: atk });
    expect((await s.verify(forged)).allow).toBe(false);
    expect((await s.verify(forged, { allowUnboundPq: true })).checks.leaf_signature).toBe('pass');
  });

  it('a delegated hop of a hybrid suite must be signed with the PQ key the parent committed to', () => {
    const s = setup({ bindPq: true });
    const sub = generateKeyPair();
    const atk = mlDsa65Keygen(seed());
    const bad = delegate(s.grant, encodeKey(sub.publicKey), [{ type: 'task' }], s.A.secretKey, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: atk });
    expect(verifyChain([s.grant, bad], s.grant.issuer).ok).toBe(false);
    const good = delegate(s.grant, encodeKey(sub.publicKey), [{ type: 'task' }], s.A.secretKey, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: s.agentPq });
    expect(verifyChain([s.grant, good], s.grant.issuer)).toEqual({ ok: true });
    expect(verifyChain([s.grant, bad], s.grant.issuer, { allowUnboundPq: true }).ok).toBe(true);
  });

  it('attenuate keeps the holder PQ commitment', () => {
    const s = setup({ bindPq: true });
    const c1 = attenuate(s.grant, [{ type: 'task' }], s.A.secretKey);
    expect(c1.holder_pq).toBe(holderPqCommitment(encodeMlDsaPublicKey(s.agentPq.publicKey)));
  });
});

describe('F-4: suite policy; pure-PQ leaf must be bound to the holder', () => {
  it('a pure ml-dsa-65 leaf signed by a key unrelated to the holder is rejected (PoC)', async () => {
    const s = setup({ bindPq: false });
    const atk = mlDsa65Keygen(seed());
    const forged = signPCActnSuite(s.body(), { alg: 'ml-dsa-65', mlDsa: atk });
    const v = await s.verify(forged);
    expect(v.checks.leaf_signature).toBe('fail');
    expect(v.allow).toBe(false);
  });

  it('a pure ml-dsa-65 leaf under the holder\'s committed PQ key is accepted, unless the suite is not allowed', async () => {
    const s = setup({ bindPq: true });
    const ok = signPCActnSuite(s.body(), { alg: 'ml-dsa-65', mlDsa: s.agentPq });
    expect((await s.verify(ok)).allow).toBe(true);
    const denied = await s.verify(ok, { allowedSuites: ['ed25519', 'hybrid-ed25519-ml-dsa-65'] });
    expect(denied.allow).toBe(false);
    expect(denied.checks.leaf_signature).toBe('fail');
  });

  it('allowedSuites also constrains delegation hops', () => {
    const s = setup({ bindPq: true });
    const hop = attenuate(s.grant, [{ type: 'task' }], s.A.secretKey, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: s.agentPq });
    expect(verifyChain([s.grant, hop], s.grant.issuer).ok).toBe(true);
    expect(verifyChain([s.grant, hop], s.grant.issuer, { allowedSuites: ['ed25519'] }).ok).toBe(false);
  });

  it('the default policy still accepts plain Ed25519', async () => {
    const s = setup({ bindPq: false });
    const p = signPCActnSuite(s.body(), { alg: 'ed25519', edLeafSecret: s.A.secretKey });
    expect((await s.verify(p)).allow).toBe(true);
    expect((await s.verify(p, { allowedSuites: ['hybrid-ed25519-ml-dsa-65'] })).allow).toBe(false);
  });
});
