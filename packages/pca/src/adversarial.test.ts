/**
 * ADVERSARIAL SECURITY BATTERY (companion to docs/specs/pca-security-review-internal.md).
 *
 * Every test here is an ATTACK that MUST be rejected/aborted. A passing suite means every
 * defense held: each `it(...)` asserts the forgery/replay/downgrade/widening/etc. is caught.
 * Uses the REAL library APIs (no mocks of the crypto) so the proof is of the shipped code.
 *
 * Cross-referenced by `§ <name>` in the review doc. Where an attack class is structurally
 * out of a library's reach (counter/nonce replay storage, key-custody topology, MPC MAC-forge
 * which lives in @atlasauth/pca-mpc), that is called out inline and in the final report.
 */
import { describe, expect, it } from 'vitest';
import { p384 } from '@noble/curves/p384';

import { b64u, unb64u } from './hash';
import { encodeKey, generateKeyPair, sign, verify, verifyB64u } from './keys';
import { mlDsa65Keygen } from './pq';
import { L, decodeSafePoint, frostAggregate, frostCommit, frostSign, frostTrustedDealerKeygen, scalarToBytes } from './frost';
import { frostDkgSimulate } from './frost-dkg';
import { attenuate, budgetAllocCaveat, type Capability, delegate, mintRoot, verifyChain } from './capability';
import { commitPlan, conditionsDigest, merkleProof, paramsDigest, planLeaf, verifyInclusion } from './merkle';
import {
  type PCActn,
  PCACTN_MAX_LIFETIME_MS,
  buildPCActn,
  decodePCActn,
  signPCActn,
  signPCActnSuite,
  thresholdMessage,
  verifyPCActnCore,
} from './pcactn';
import { type Signer, assembleThreshold, signShare, verifyThreshold } from './threshold';
import {
  TransparencyLedger,
  cosignTreeHead,
  detectEquivocation,
  signTreeHead,
  verifyHeadConsistency,
  verifyWitnessCosignatures,
} from './ledger';
import { RevocationSet, checkRevocationEpoch, signRevocationEpoch, verifyNonMembership } from './revocation';
import { mintGrant } from './envelope';
import { type DecideInput, decide } from './policy-vm';
import { DEFAULT_RISK_POLICY } from './risk';
import {
  BondLedger,
  DEFAULT_BOND_POLICY,
  InMemoryBondAccount,
  bondAmount,
  computeSlashSplit,
  verifySettlement,
} from './bond-settlement';
import {
  adjudicateDispute,
  openOptimistic,
  verifyClaim,
  verifyFraudProof,
  type DisputableInput,
  type ObjectiveOracle,
  type OracleResolution,
} from './optimistic';
import { actionCommitment, createAttestedComplianceProver, createGroth16SnarkBackend, createZkVerifier } from './zk';
import { actionDigest as judgeActionDigest, signJudgeVerdict, verifyJudgeVerdict, verifySemanticThreshold } from './semantic-threshold';
import { combineCaution, combineSignedCaution, signCaution, verifyCaution } from './agent-native';
import { attestationRegistry, createAttestationVerifier, createDevAttestor } from './attestation';
import { SEV_SNP_POLICY_DEBUG_BIT, checkSevSnpPolicy, ecdsaP384PublicKey, parseSevSnpReport, serializeSevSnpReport, toHex, verifySevSnpReportSignature } from './hardware-sevsnp';

const NOW = 1_800_000_000_000;

// ---- shared PCActn fixture (mirrors pcactn.test.ts build()) ------------------------------
function buildChainAndActn() {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const S = generateKeyPair();
  const grant = mintRoot({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), caveats: [{ type: 'ttl', secs: 60 }] });
  const c1 = attenuate(grant, [{ type: 'x' }], A.secretKey);
  const sub = delegate(c1, encodeKey(S.publicKey), [], A.secretKey);
  const nodes = [
    { id: 'n1', verb: 'revoke_session', resource: 'sess/1', params_digest: paramsDigest({ a: 1 }), reversibility_class: 'R1', pre: { a: 1 } },
    { id: 'n2', verb: 'read', resource: 'acct', params_digest: paramsDigest({ b: 2 }), reversibility_class: 'R0' },
  ];
  const plan = commitPlan(nodes);
  const body = (idx: 0 | 1) => {
    const n = nodes[idx]!;
    return {
      ver: 2,
      action: { verb: n.verb, resource: n.resource, params_digest: n.params_digest, reversibility_class: n.reversibility_class },
      grant_ref: grant.id,
      cap_chain: [grant, c1, sub],
      plan: { root: plan.root, inclusion_proof: plan.proofFor(n.id), node_id: n.id, conditions_digest: conditionsDigest(n.pre, undefined) },
      attestation: { quote_digest: 'q', epoch: 1, model_id: 'm', measurement: 'x', operator: 'o' },
      provenance: { causal_hash: 'c', taint_level: 0, trusted_refs: [] },
      freshness: { beacon_ref: 'b', epoch: 1, accumulator_witness: 'w' },
      counter: 7,
      risk_claim: { r: 0.1, inputs: {} },
      aud: 'rs-1',
      iat: NOW,
      exp: NOW + 60_000,
    } satisfies Omit<PCActn, 'sig'>;
  };
  const mk = (idx: 0 | 1) => signPCActn(body(idx), S.secretKey);
  return { P, A, S, grant, c1, sub, nodes, plan, body, mk };
}

// =====================================================================================
// § signature-forgery  — Ed25519-strict: forgery, non-canonical S, small-order
// =====================================================================================
describe('§ signature-forgery (Ed25519-strict)', () => {
  const kp = generateKeyPair();
  const msg = new TextEncoder().encode('authorize transfer');
  const sig = sign(kp.secretKey, msg);

  it('a signature from the wrong key is rejected', () => {
    const other = generateKeyPair();
    expect(verify(other.publicKey, msg, sig)).toBe(false);
    expect(verifyB64u(encodeKey(other.publicKey), msg, b64u(sig))).toBe(false);
  });

  it('a signature over a different message is rejected (no cross-message reuse)', () => {
    expect(verify(kp.publicKey, new TextEncoder().encode('authorize OTHER transfer'), sig)).toBe(false);
  });

  it('NON-CANONICAL S (S + L) is rejected by strict RFC-8032 verification', () => {
    // Malleate: S' = S + L. Permissive (ZIP-215) verifiers accept it; strict must not.
    const forged = sig.slice();
    let s = 0n;
    for (let i = 0; i < 32; i++) s |= BigInt(forged[32 + i]!) << BigInt(8 * i); // little-endian scalar
    const sPrime = s + L; // S < L, so S + L < 2L < 2^253: fits in 32 bytes, non-canonical (>= L)
    for (let i = 0; i < 32; i++) forged[32 + i] = Number((sPrime >> BigInt(8 * i)) & 0xffn);
    expect(verify(kp.publicKey, msg, forged)).toBe(false);
  });

  it('a SMALL-ORDER public key is rejected', () => {
    const identity = new Uint8Array(32);
    identity[0] = 1; // y = 1, the order-1 identity point
    expect(verify(identity, msg, sig)).toBe(false);
    // the canonical order-2 point (y = p-1) too
    const order2 = new Uint8Array(32).fill(0xff);
    order2[31] = 0x7f;
    expect(verify(order2, msg, sig)).toBe(false);
  });

  it('a non-canonical base64url signature/key is rejected by verifyB64u (wrong length / alphabet)', () => {
    expect(verifyB64u(encodeKey(kp.publicKey), msg, b64u(sig) + 'A')).toBe(false); // over-length
    expect(verifyB64u('not canonical!!', msg, b64u(sig))).toBe(false);
  });
});

// =====================================================================================
// § wire-canonical-form  — malleability of the serialized/signed object
// =====================================================================================
describe('§ wire-canonical-form (canonical malleability)', () => {
  it('strictParse rejects a DUPLICATE key (ambiguous signed object)', () => {
    expect(() => decodePCActn('{"a":1,"a":2}')).toThrow(/duplicate key/);
  });
  it('strictParse rejects exponent numbers, trailing fractional zero, and trailing bytes', () => {
    expect(() => decodePCActn('{"r":1e3}')).toThrow(/exponent/);
    expect(() => decodePCActn('{"r":1.50}')).toThrow(/trailing fractional zero/);
    expect(() => decodePCActn('{"a":1} x')).toThrow(/trailing/);
  });
  it('an UNKNOWN top-level field is a wire failure', async () => {
    const { grant, mk } = buildChainAndActn();
    const p = { ...mk(0), smuggled: 'unsigned-field' } as unknown as PCActn;
    const r = await verifyPCActnCore(p, { grant, nowEpoch: NOW, audience: 'rs-1' });
    expect(r.allow).toBe(false);
    expect(r.checks.wire).toBe('fail');
  });
  it('a NON-CANONICAL base64url fixed-length field (grant_ref) is a wire failure', async () => {
    const { grant, mk } = buildChainAndActn();
    const p = { ...mk(0), grant_ref: mk(0).grant_ref + 'A' } as unknown as PCActn; // wrong length
    const r = await verifyPCActnCore(p, { grant, nowEpoch: NOW, audience: 'rs-1' });
    expect(r.allow).toBe(false);
    expect(r.checks.wire).toBe('fail');
  });
  it('a tampered signed number that cannot encode canonically is rejected on the wire', async () => {
    const { grant, mk } = buildChainAndActn();
    const p = { ...mk(0), risk_claim: { r: 1e-9, inputs: {} } } as unknown as PCActn; // sub-1e-6 magnitude
    const r = await verifyPCActnCore(p, { grant, nowEpoch: NOW, audience: 'rs-1' });
    expect(r.allow).toBe(false);
    expect(r.checks.wire).toBe('fail');
  });
});

// =====================================================================================
// § replay  — freshness binding (aud / iat / exp). Counter/nonce monotonicity is RS state (F-2).
// =====================================================================================
describe('§ replay (freshness binding)', () => {
  it('an audience MISMATCH is rejected (cross-instance replay)', async () => {
    const { grant, mk } = buildChainAndActn();
    const r = await verifyPCActnCore(mk(0), { grant, nowEpoch: NOW, audience: 'rs-OTHER' });
    expect(r.allow).toBe(false);
    expect(r.checks.audience).toBe('fail');
  });
  it('FAIL-CLOSED: a verifier that forgets its audience rejects an aud-bearing PCActn', async () => {
    const { grant, mk } = buildChainAndActn();
    const r = await verifyPCActnCore(mk(0), { grant, nowEpoch: NOW }); // audience omitted
    expect(r.allow).toBe(false);
    expect(r.checks.audience).toBe('fail');
  });
  it('an EXPIRED PCActn (now > exp) is rejected', async () => {
    const { grant, mk } = buildChainAndActn();
    const r = await verifyPCActnCore(mk(0), { grant, nowEpoch: NOW + 120_000, audience: 'rs-1' });
    expect(r.allow).toBe(false);
    expect(r.checks.validity).toBe('fail');
  });
  it('a FUTURE-dated PCActn (iat beyond skew) is rejected', async () => {
    const { grant, mk } = buildChainAndActn();
    const r = await verifyPCActnCore(mk(0), { grant, nowEpoch: NOW - 120_000, audience: 'rs-1' });
    expect(r.allow).toBe(false);
    expect(r.checks.validity).toBe('fail');
  });
  it('an over-LIFETIME window (exp - iat > max) is rejected', async () => {
    const { grant, body, S } = buildChainAndActn();
    const long = signPCActn({ ...body(0), exp: NOW + PCACTN_MAX_LIFETIME_MS + 1 }, S.secretKey);
    const r = await verifyPCActnCore(long, { grant, nowEpoch: NOW, audience: 'rs-1' });
    expect(r.allow).toBe(false);
    expect(r.checks.validity).toBe('fail');
  });
  it('a NEGATIVE counter is rejected (type gate; monotonic anti-replay is RS state, see F-2)', async () => {
    const { grant, body, S } = buildChainAndActn();
    const neg = signPCActn({ ...body(0), counter: -1 }, S.secretKey);
    const r = await verifyPCActnCore(neg, { grant, nowEpoch: NOW, audience: 'rs-1' });
    expect(r.allow).toBe(false);
    expect(r.checks.counter).toBe('fail');
  });
});

// =====================================================================================
// § downgrade  — alg/suite downgrade + threshold downgrade
// =====================================================================================
describe('§ downgrade (suite + threshold)', () => {
  it('stripping the signed `alg`/`pq_pk` from an ml-dsa-65 PCActn fails closed on the wire', async () => {
    const { grant, body } = buildChainAndActn();
    const mlDsa = mlDsa65Keygen(new Uint8Array(32).fill(3));
    const signed = signPCActnSuite(body(0), { alg: 'ml-dsa-65', mlDsa });
    // sanity: the real ml-dsa object verifies its leaf signature
    const good = await verifyPCActnCore(signed, { grant, nowEpoch: NOW, audience: 'rs-1' });
    expect(good.checks.leaf_signature).toBe('pass');
    // DOWNGRADE: drop alg + pq_pk. `sig` is now a 3309-byte ML-DSA sig under an absent (=> ed25519) suite
    // whose wire rule demands a 64-byte sig and forbids pq_pk ⇒ wire fail.
    const { alg: _a, pq_pk: _p, ...downgraded } = signed as PCActn & { pq_pk?: string };
    void _a; void _p;
    const r = await verifyPCActnCore(downgraded as PCActn, { grant, nowEpoch: NOW, audience: 'rs-1' });
    expect(r.allow).toBe(false);
    expect(r.checks.wire).toBe('fail');
  });
  it('an UNKNOWN signature alg fails closed on the wire', async () => {
    const { grant, mk } = buildChainAndActn();
    const p = { ...mk(0), alg: 'ed448-fantasy' } as unknown as PCActn;
    const r = await verifyPCActnCore(p, { grant, nowEpoch: NOW, audience: 'rs-1' });
    expect(r.allow).toBe(false);
    expect(r.checks.wire).toBe('fail');
  });
  it('a t=2 verifier REJECTS a t=1 (agent-only) signature — no threshold downgrade', () => {
    const agent = generateKeyPair();
    const guardian = generateKeyPair();
    const signerSet: Signer[] = [
      { role: 'agent', publicKey: encodeKey(agent.publicKey) },
      { role: 'guardian', publicKey: encodeKey(guardian.publicKey) },
    ];
    const message = new TextEncoder().encode('high-risk action');
    const agentShare = signShare('agent', agent.secretKey, message);
    // only the agent signed: at t=2 this must be refused
    const v2 = verifyThreshold(assembleThreshold([agentShare]), message, signerSet, 2);
    expect(v2.ok).toBe(false);
    expect(v2.count).toBe(1);
    // the same evidence is sufficient only at t=1
    expect(verifyThreshold(assembleThreshold([agentShare]), message, signerSet, 1).ok).toBe(true);
  });
  it('one key cannot fill two role slots (signer-set collapse rejected)', () => {
    const k = generateKeyPair();
    const dup: Signer[] = [
      { role: 'agent', publicKey: encodeKey(k.publicKey) },
      { role: 'guardian', publicKey: encodeKey(k.publicKey) },
    ];
    const message = new TextEncoder().encode('m');
    const share = signShare('agent', k.secretKey, message);
    expect(verifyThreshold(assembleThreshold([share]), message, dup, 2).ok).toBe(false);
  });
});

// =====================================================================================
// § capability-widening  — delegation can only narrow authority
// =====================================================================================
describe('§ capability-widening (attenuation integrity)', () => {
  function roots() {
    const P = generateKeyPair();
    const A = generateKeyPair();
    const grant = mintRoot({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), caveats: [{ type: 'scope', v: 'read' }] });
    return { P, A, grant };
  }
  it('a child that DROPS a parent caveat is rejected', () => {
    const { A, grant } = roots();
    const child = attenuate(grant, [{ type: 'limit', n: 5 }], A.secretKey);
    const widened: Capability = { ...child, caveats: [] }; // drop everything
    expect(verifyChain([grant, widened]).ok).toBe(false);
  });
  it('a child that ALTERS a parent caveat is rejected', () => {
    const { A, grant } = roots();
    const child = attenuate(grant, [], A.secretKey);
    const tampered: Capability = { ...child, caveats: [{ type: 'scope', v: 'admin' }] }; // read -> admin
    expect(verifyChain([grant, tampered]).ok).toBe(false);
  });
  it('a hop issued by a key that is NOT the parent holder is rejected', () => {
    const { A, grant } = roots();
    const mallory = generateKeyPair();
    // mallory delegates as if she held the grant
    const forged = delegate(grant, encodeKey(mallory.publicKey), [{ type: 'x' }], mallory.secretKey);
    void A;
    expect(verifyChain([grant, forged]).ok).toBe(false);
  });
  it('BUDGET widening (child allocates more than its parent carried) is rejected', () => {
    const { A, grant } = roots();
    const c1 = attenuate(grant, [budgetAllocCaveat(10)], A.secretKey);
    const c2 = attenuate(c1, [budgetAllocCaveat(100)], A.secretKey); // 100 > 10: widening
    expect(verifyChain([grant, c1, c2]).ok).toBe(false);
  });
  it('a FORGED hop body (caveats changed without re-signing) fails the body-digest/signature check', () => {
    const { A, grant } = roots();
    const child = attenuate(grant, [{ type: 'limit', n: 5 }], A.secretKey);
    const forged: Capability = { ...child, caveats: [...child.caveats, { type: 'extra', smuggled: true }] };
    expect(verifyChain([grant, forged]).ok).toBe(false);
  });
});

// =====================================================================================
// § plan-inclusion-forgery  — an action must be a committed node of the signed plan
// =====================================================================================
describe('§ plan-inclusion-forgery', () => {
  it('reusing a valid inclusion proof for a SWAPPED action fails verifyInclusion', () => {
    const nodes = [
      { id: 'n1', verb: 'revoke_session', resource: 'sess/1' },
      { id: 'n2', verb: 'read', resource: 'acct' },
    ];
    const plan = commitPlan(nodes);
    const proof = plan.proofFor('n1');
    const honestLeaf = planLeaf('n1', { verb: 'revoke_session', resource: 'sess/1' }, conditionsDigest());
    expect(verifyInclusion(plan.root, proof, honestLeaf)).toBe(true);
    // swap the resource to a privileged target but keep the proof
    const forgedLeaf = planLeaf('n1', { verb: 'revoke_session', resource: 'sess/ALL' }, conditionsDigest());
    expect(verifyInclusion(plan.root, proof, forgedLeaf)).toBe(false);
  });
  it('a proof whose index/size shape does not match is rejected', () => {
    const nodes = [{ id: 'n1', verb: 'a', resource: 'r1' }, { id: 'n2', verb: 'b', resource: 'r2' }];
    const plan = commitPlan(nodes);
    const leaf = planLeaf('n1', { verb: 'a', resource: 'r1' }, conditionsDigest());
    const good = plan.proofFor('n1');
    const bad = { ...good, index: good.index, size: good.size + 1 }; // lie about tree size
    expect(verifyInclusion(plan.root, bad, leaf)).toBe(false);
  });
  it('at the full verifier: a tampered action breaks plan_inclusion', async () => {
    const { grant, mk } = buildChainAndActn();
    const p = mk(0);
    p.action = { ...p.action, resource: 'sess/ALL' };
    const r = await verifyPCActnCore(p, { grant, nowEpoch: NOW, audience: 'rs-1' });
    expect(r.allow).toBe(false);
    expect(r.checks.plan_inclusion).toBe('fail');
  });
});

// =====================================================================================
// § threshold / FROST custody  — sub-threshold + forged share + bad commitment
// =====================================================================================
describe('§ frost-custody (FROST threshold signatures)', () => {
  function keygenAndQuorum(signerIds: number[]) {
    const kg = frostTrustedDealerKeygen(2, 3);
    const byId = new Map(kg.participantShares.map((s) => [s.identifier, s]));
    const message = new TextEncoder().encode('release guardian share');
    const commits = signerIds.map((id) => frostCommit(byId.get(id)!));
    const commitments = commits.map((c) => c.commitment);
    const sigShares = signerIds.map((id, i) =>
      frostSign(id, byId.get(id)!.share, kg.groupPublicKey, { hiding: commits[i]!.hidingNonce, binding: commits[i]!.bindingNonce }, message, commitments),
    );
    return { kg, byId, message, commitments, sigShares };
  }

  it('a valid t=2 aggregate verifies as a plain Ed25519 signature (baseline)', () => {
    const { kg, message, commitments, sigShares } = keygenAndQuorum([1, 3]);
    const sig = frostAggregate(message, commitments, sigShares, kg.groupPublicKey);
    expect(verify(kg.groupPublicKey, message, sig)).toBe(true);
  });

  it('a SUB-THRESHOLD (1-of-2) aggregate is refused — it does not verify', () => {
    const kg = frostTrustedDealerKeygen(2, 3);
    const byId = new Map(kg.participantShares.map((s) => [s.identifier, s]));
    const message = new TextEncoder().encode('insufficient quorum');
    const c1 = frostCommit(byId.get(1)!);
    const only = [c1.commitment];
    const s1 = frostSign(1, byId.get(1)!.share, kg.groupPublicKey, { hiding: c1.hidingNonce, binding: c1.bindingNonce }, message, only);
    expect(() => frostAggregate(message, only, [s1], kg.groupPublicKey)).toThrow(/does not verify/);
  });

  it('a FORGED signature share is caught and the bad participant named', () => {
    const { kg, message, commitments, sigShares } = keygenAndQuorum([1, 3]);
    const vss = kg.participantShares.map((s) => ({ identifier: s.identifier, publicKey: s.publicKey }));
    const forged = [sigShares[0]!, { identifier: 3, sigShare: scalarToBytes(12345n) }];
    expect(() => frostAggregate(message, commitments, forged, kg.groupPublicKey, { verificationShares: vss })).toThrow(/participant 3/);
    // even without the per-share check, the aggregate refuses to return an invalid signature
    expect(() => frostAggregate(message, commitments, forged, kg.groupPublicKey)).toThrow(/does not verify/);
  });

  it('a small-order / identity commitment point is rejected by decodeSafePoint', () => {
    const identity = new Uint8Array(32);
    identity[0] = 1;
    expect(() => decodeSafePoint(identity)).toThrow();
  });
});

// =====================================================================================
// § dkg-abort  — no-dealer DKG (malicious-secure MPC for key generation)
// =====================================================================================
describe('§ dkg-abort (no-dealer FROST DKG)', () => {
  it('an EQUIVOCATING dealer makes dkgFinalize ABORT (does not commit to a key)', () => {
    expect(() => frostDkgSimulate(2, 3, { equivocateEchoFor: 1 })).toThrow(/echo-broadcast agreement failed/);
  });
  it('a CHEATING dealer is disqualified; the run finalizes over the honest set only', () => {
    const dkg = frostDkgSimulate(2, 3, { cheaters: [3] });
    expect(dkg.qualified).toEqual([1, 2]);
    expect(dkg.complaints.length).toBeGreaterThan(0);
    expect(dkg.participantShares.map((s) => s.identifier).sort()).toEqual([1, 2]);
  });
});

// =====================================================================================
// § transparency-equivocation  — split-view + C2SP witness threshold
// =====================================================================================
describe('§ transparency-equivocation (log + witnesses)', () => {
  function ledgerAt(principal: string, entries: number) {
    const l = new TransparencyLedger(principal);
    const { mk } = buildChainAndActn();
    for (let i = 0; i < entries; i++) l.append(mk(0), { salt: `salt-${i}` });
    return l;
  }

  it('two validly-witnessed heads at the same size with different roots prove EQUIVOCATION', () => {
    const witness = generateKeyPair();
    const a = ledgerAt('principal-1', 3).witnessHead(witness.secretKey);
    const b = ledgerAt('principal-1', 3).witnessHead(witness.secretKey);
    // same principal+size, but distinct content ⇒ distinct roots (salts differ across the two ledgers only
    // if content differs; force a divergent root via a tampered copy):
    const bForked = { ...b, root: a.root === b.root ? b.root + 'x' : b.root };
    if (a.root !== bForked.root) {
      expect(detectEquivocation(a, bForked, encodeKey(witness.publicKey))).toBe(true);
    } else {
      // identical roots are NOT equivocation (sanity)
      expect(detectEquivocation(a, b, encodeKey(witness.publicKey))).toBe(false);
    }
  });

  it('the witness-threshold is FAIL-CLOSED: below k, unknown, duplicate, and mis-bound cosigs do not count', () => {
    const guardian = generateKeyPair();
    const w1 = generateKeyPair();
    const w2 = generateKeyPair();
    const stranger = generateKeyPair();
    const head = { instance_id: 'ins-1', principal: 'p', size: 2, root: b64u(unb64u('A'.repeat(43))), prev_root: '', timestamp: NOW };
    const sth = signTreeHead(guardian.secretKey, head);
    const cosignFor = (kp: { secretKey: Uint8Array }) => cosignTreeHead(sth, kp.secretKey);
    const trusted = [encodeKey(w1.publicKey), encodeKey(w2.publicKey)];

    // only ONE valid trusted cosig, threshold 2 ⇒ false
    expect(verifyWitnessCosignatures({ ...sth, witnesses: [cosignFor(w1)] }, { witnessKeys: trusted, threshold: 2 })).toBe(false);
    // a DUPLICATE of the same trusted witness counts once ⇒ still 1 < 2
    expect(verifyWitnessCosignatures({ ...sth, witnesses: [cosignFor(w1), cosignFor(w1)] }, { witnessKeys: trusted, threshold: 2 })).toBe(false);
    // an UNKNOWN witness does not count toward the trusted threshold
    expect(verifyWitnessCosignatures({ ...sth, witnesses: [cosignFor(w1), cosignFor(stranger)] }, { witnessKeys: trusted, threshold: 2 })).toBe(false);
    // a MIS-BOUND cosig (signed over a different root) does not count
    const otherRoot = cosignTreeHead({ ...sth, root: sth.root === '' ? 'z' : sth.root + '', size: 99 }, w2.secretKey);
    expect(verifyWitnessCosignatures({ ...sth, witnesses: [cosignFor(w1), otherRoot] }, { witnessKeys: trusted, threshold: 2 })).toBe(false);
    // two distinct valid trusted cosigs ⇒ true (the only accepting case)
    expect(verifyWitnessCosignatures({ ...sth, witnesses: [cosignFor(w1), cosignFor(w2)] }, { witnessKeys: trusted, threshold: 2 })).toBe(true);
  });

  it('a FORGED prev_root on adjacent heads breaks verifyHeadConsistency (hash-chain enforcement)', () => {
    const guardian = generateKeyPair();
    const l = ledgerAt('p2', 1);
    const older = signTreeHead(guardian.secretKey, { instance_id: 'ins', principal: 'p2', size: 1, root: l.rootAt(1), prev_root: '', timestamp: NOW });
    l.append(buildChainAndActn().mk(0), { salt: 'salt-extra' });
    const proof = l.consistencyProof(1, 2);
    // honest adjacent head: prev_root === older.root
    const honest = signTreeHead(guardian.secretKey, { instance_id: 'ins', principal: 'p2', size: 2, root: l.rootAt(2), prev_root: older.root, timestamp: NOW + 1 });
    expect(verifyHeadConsistency(older, honest, proof, encodeKey(guardian.publicKey))).toBe(true);
    // forged adjacent head: prev_root lies
    const forged = signTreeHead(guardian.secretKey, { instance_id: 'ins', principal: 'p2', size: 2, root: l.rootAt(2), prev_root: 'forged-prev', timestamp: NOW + 1 });
    expect(verifyHeadConsistency(older, forged, proof, encodeKey(guardian.publicKey))).toBe(false);
  });
});

// =====================================================================================
// § revocation-bypass  — accumulator + signed epoch
// =====================================================================================
describe('§ revocation-bypass', () => {
  it('a revoked id has NO valid non-membership proof', () => {
    const set = new RevocationSet(['cap-a', 'cap-b', 'cap-c']);
    // cannot even construct one
    expect(() => set.nonMembershipProof('cap-b')).toThrow(/revoked/);
    // a fabricated proof using bracketing neighbours fails verification for the revoked id
    const forged = { size: set.size, lo: { id: 'cap-a', proof: set.membershipProof('cap-a') }, hi: { id: 'cap-c', proof: set.membershipProof('cap-c') } };
    expect(verifyNonMembership(set.root, forged, 'cap-b')).toBe(false);
  });
  it('an honest non-membership proof verifies (baseline)', () => {
    const set = new RevocationSet(['cap-a', 'cap-c']);
    expect(verifyNonMembership(set.root, set.nonMembershipProof('cap-b'), 'cap-b')).toBe(true);
  });
  it('a STALE signed epoch (now > not_after) is rejected', () => {
    const guardian = generateKeyPair();
    const set = new RevocationSet(['cap-x']);
    const ep = signRevocationEpoch(guardian.secretKey, { instance_id: 'ins', grant_ref: 'g', epoch: 5, set_size: set.size, root: set.root, issued_at: NOW, not_after: NOW + 60_000 });
    const r = checkRevocationEpoch(ep, { guardianPublic: encodeKey(guardian.publicKey), now: NOW + 120_000 });
    expect(r.ok).toBe(false);
  });
  it('an epoch ROLLBACK (older than the pinned epoch) is rejected', () => {
    const guardian = generateKeyPair();
    const set = new RevocationSet(['cap-x']);
    const ep = signRevocationEpoch(guardian.secretKey, { instance_id: 'ins', grant_ref: 'g', epoch: 3, set_size: set.size, root: set.root, issued_at: NOW, not_after: NOW + 60_000 });
    const r = checkRevocationEpoch(ep, { guardianPublic: encodeKey(guardian.publicKey), now: NOW + 1_000, lastAcceptedEpoch: 7 });
    expect(r.ok).toBe(false);
  });
  it('a pre-revocation PCActn (freshness.epoch < revocation epoch) is rejected', () => {
    const guardian = generateKeyPair();
    const set = new RevocationSet(['cap-x']);
    const ep = signRevocationEpoch(guardian.secretKey, { instance_id: 'ins', grant_ref: 'g', epoch: 9, set_size: set.size, root: set.root, issued_at: NOW, not_after: NOW + 60_000 });
    const r = checkRevocationEpoch(ep, { guardianPublic: encodeKey(guardian.publicKey), now: NOW + 1_000, pcactnEpoch: 4 });
    expect(r.ok).toBe(false);
  });
  it('an epoch signed by the WRONG guardian is rejected', () => {
    const guardian = generateKeyPair();
    const mallory = generateKeyPair();
    const set = new RevocationSet([]);
    const ep = signRevocationEpoch(mallory.secretKey, { instance_id: 'ins', grant_ref: 'g', epoch: 1, set_size: 0, root: set.root, issued_at: NOW, not_after: NOW + 60_000 });
    expect(checkRevocationEpoch(ep, { guardianPublic: encodeKey(guardian.publicKey), now: NOW }).ok).toBe(false);
  });
});

// =====================================================================================
// § bonds  — under-collateralization, griefing, slash-split, settlement tamper, dispute game
// =====================================================================================
describe('§ bonds (optimistic economics)', () => {
  const G = generateKeyPair();
  const gpk = encodeKey(G.publicKey);

  it('§ bond-undercollateralization: an under-collateralized open is REFUSED and nothing is locked', () => {
    const L1 = new BondLedger({ guardianSecret: G.secretKey, accounts: new InMemoryBondAccount({ alice: 1000 }), bondPolicy: { ...DEFAULT_BOND_POLICY, floor: 5, k: 1 } });
    const required = bondAmount(L1.bondPolicy, 100);
    expect(required).toBe(100);
    expect(() => L1.openBond({ claimId: 'u1', amount: 5, depositor: 'alice', exposure: 100, at: NOW })).toThrow(/below the required/);
    expect(L1.bondStatus('u1')).toBe('none');
    expect(L1.balanceOf('alice')).toBe(1000);
  });

  it('§ bond-griefing: open-count and aggregate-amount caps are enforced', () => {
    const L2 = new BondLedger({ guardianSecret: G.secretKey, accounts: new InMemoryBondAccount({ alice: 1000 }), bondPolicy: { ...DEFAULT_BOND_POLICY, maxOpenClaims: 2, maxOpenAmount: 50 } });
    L2.openBond({ claimId: 'g1', amount: 20, depositor: 'alice', at: NOW });
    L2.openBond({ claimId: 'g2', amount: 20, depositor: 'alice', at: NOW });
    expect(() => L2.openBond({ claimId: 'g3', amount: 1, depositor: 'alice', at: NOW })).toThrow(/cap/);
    L2.releaseBond({ claimId: 'g1', at: NOW });
    expect(() => L2.openBond({ claimId: 'g4', amount: 31, depositor: 'alice', at: NOW })).toThrow(/aggregate/);
  });

  it('§ slash-split: an over-allocated split (> 10000 bps) is REFUSED', () => {
    expect(() => computeSlashSplit(100, { challengerBps: 7000, victimBps: 4000 }, { challengerAccount: 'chal', victimAccount: 'pool', treasuryAccount: 'treasury' })).toThrow(/exceed/);
    // a valid split conserves the amount exactly
    const ok = computeSlashSplit(100, { challengerBps: 5000, victimBps: 4000 }, { challengerAccount: 'chal', victimAccount: 'pool', treasuryAccount: 'treasury' });
    expect(ok.challengerReward + ok.victimCompensation + ok.treasuryRemainder).toBe(100);
  });

  it('§ settlement-tamper: any mutated field breaks verifySettlement', () => {
    const L3 = new BondLedger({ guardianSecret: G.secretKey, accounts: new InMemoryBondAccount({ alice: 1000 }) });
    const rec = L3.openBond({ claimId: 't1', amount: 100, depositor: 'alice', at: NOW });
    expect(verifySettlement(rec, gpk)).toBe(true);
    expect(verifySettlement({ ...rec, amount: 999 }, gpk)).toBe(false);
    expect(verifySettlement({ ...rec, to: 'mallory' }, gpk)).toBe(false);
    expect(verifySettlement(rec, encodeKey(generateKeyPair().publicKey))).toBe(false);
  });
});

// =====================================================================================
// § dispute-understated-risk + fraud-proof fabrication (contestable dispute game)
// =====================================================================================
describe('§ dispute-understated-risk / fraud-proof-fabrication', () => {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const fresh = { B: 1, tau: NOW, asOf: NOW };
  const GRANT = mintGrant({
    principalSecret: P.secretKey,
    principalPublic: encodeKey(P.publicKey),
    holder: encodeKey(A.publicKey),
    goal: 'secure my account',
    envelope: { predicates: [{ verb: 'revoke_session', resource: '/acct/*' }], caveats: [{ type: 'expires', at: 9e12 }], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
  }).grant;
  const actn = (verb: string, rc = 'reversible') =>
    buildPCActn({ aud: 'test-aud', grant: GRANT, chain: [GRANT], plan: [{ id: 'n1', verb, resource: '/acct/1/s', reversibility_class: rc }], nodeId: 'n1', counter: 1, signerSecret: A.secretKey });
  const di = (p: PCActn, risk: Partial<DecideInput['risk']> = {}): DecideInput => ({
    grant: GRANT,
    chain: [GRANT],
    action: { action: { verb: p.action.verb, resource: p.action.resource, params: {}, reversibility_class: p.action.reversibility_class } },
    risk: { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0, ...risk },
    budget: fresh,
    now: NOW,
    nodeId: p.plan.node_id,
  });
  const stubOracle = (res: Partial<OracleResolution> & { valid: boolean }): ObjectiveOracle => ({ resolve: (input: DisputableInput) => ({ input, ...res }) });

  it('the dispute game SLASHES an agent that understated a numeric risk input (blastRadius)', () => {
    const p = actn('revoke_session', 'reversible');
    const snap = di(p, { blastRadius: 0 }); // agent baked blastRadius=0 (r=0), claimed r=0
    const claim = openOptimistic(p, { bondRef: 'bond-bl', claimedR: 0, serverNow: NOW }, A.secretKey);
    const oracle = stubOracle({ valid: true, value: 1 }); // truthful blast radius = 1 ⇒ r rises past the claim
    const v = adjudicateDispute({ claim, dispute: { pcactn_digest: claim.pcactn_digest, bond_ref: claim.bond_ref, input: 'blastRadius' }, grant: GRANT, openSnapshot: snap, oracle });
    expect(v.outcome).toBe('agent-fraud');
    expect(v.fraudulent).toBe(true);
    expect(v.slashBondRef).toBe('bond-bl');
  });

  it('the dispute game SLASHES an agent that declared a catalog-irreversible verb as reversible', () => {
    const p = actn('revoke_session', 'reversible');
    const snap = di(p);
    const claim = openOptimistic(p, { bondRef: 'bond-rc', claimedR: 0, serverNow: NOW }, A.secretKey);
    const oracle = stubOracle({ valid: true, class: 'irreversible' });
    const v = adjudicateDispute({ claim, dispute: { pcactn_digest: claim.pcactn_digest, bond_ref: claim.bond_ref, input: 'reversibility_class' }, grant: GRANT, openSnapshot: snap, oracle });
    expect(v.outcome).toBe('agent-fraud');
    expect(v.fraudulent).toBe(true);
    expect(v.adjudicated.optimisticAllowed).toBe(false);
  });

  it('a FABRICATED fraud proof (asserted decision not reproducible) is rejected on recomputation', () => {
    const p = actn('revoke_session');
    const snap = di(p);
    const d = decide(snap); // genuinely compliant
    const claim = openOptimistic(p, { bondRef: 'bond-fab', claimedR: d.r, serverNow: NOW }, A.secretKey);
    const forged = {
      pcactn_digest: claim.pcactn_digest,
      bond_ref: claim.bond_ref,
      claimed_r: claim.claimed_r,
      kind: 'policy-denied' as const,
      decision: { releaseGuardianShare: false, r: 1, optimisticAllowed: false }, // a denial that did not happen
      evidence: (() => { const { grant: _g, ...rest } = snap; void _g; return rest; })(),
      r_margin: 1e-9,
      reason: 'fabricated',
    };
    expect(verifyFraudProof(claim, forged, GRANT, snap)).toMatchObject({ fraudulent: false });
  });

  it('a verified claim cannot be reused for a DIFFERENT action (digest binding)', () => {
    const p = actn('revoke_session');
    const claim = openOptimistic(p, { bondRef: 'b', claimedR: 0, challengeWindowMs: 5000, issuedAt: NOW, serverNow: NOW }, A.secretKey);
    const other = actn('revoke_session', 'rate_limited'); // different digest
    expect(verifyClaim(claim, other, encodeKey(A.publicKey), { serverNow: NOW }).ok).toBe(false);
  });
});

// =====================================================================================
// § zk-tampering  — attested-VM mode binding + Groth16 malformed/mis-bound rejection
// =====================================================================================
describe('§ zk-tampering', () => {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const GRANT = mintGrant({
    principalSecret: P.secretKey,
    principalPublic: encodeKey(P.publicKey),
    holder: encodeKey(A.publicKey),
    goal: 'g',
    envelope: { predicates: [{ verb: 'revoke_session', resource: '/acct/*' }], caveats: [{ type: 'expires', at: 9e12 }], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
  }).grant;
  const p = buildPCActn({ aud: 'rs', grant: GRANT, chain: [GRANT], plan: [{ id: 'n1', verb: 'revoke_session', resource: '/acct/1', reversibility_class: 'reversible' }], nodeId: 'n1', counter: 1, signerSecret: A.secretKey });
  const decideInput: DecideInput = {
    grant: GRANT,
    chain: [GRANT],
    action: { action: { verb: 'revoke_session', resource: '/acct/1', params: {}, reversibility_class: 'reversible' } },
    risk: { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 },
    budget: { B: 1, tau: NOW, asOf: NOW },
    now: NOW,
    nodeId: 'n1',
  };
  const prover = createAttestedComplianceProver(generateKeyPair().secretKey);
  const statement = prover.prove({ pcactn: p, decideInput, issued_at: NOW, expires_at: NOW + 60_000 });

  it('a VALID compliance statement is accepted (baseline)', async () => {
    const hook = createZkVerifier({ trustedProverKeys: [prover.publicKey], now: () => NOW });
    const r = await hook({ pcactn: { ...p, zk_compliance: statement }, grant: GRANT, nowEpoch: NOW });
    expect(r).toMatchObject({ enforced: true, ok: true });
  });
  it('a statement mis-bound to a DIFFERENT action is rejected', async () => {
    const hook = createZkVerifier({ trustedProverKeys: [prover.publicKey], now: () => NOW });
    const tampered = { ...statement, action_commit: actionCommitment({ ...p, action: { ...p.action, resource: '/acct/EVIL' } } as PCActn) };
    const r = await hook({ pcactn: { ...p, zk_compliance: tampered }, grant: GRANT, nowEpoch: NOW });
    expect(r).toMatchObject({ enforced: true, ok: false });
  });
  it('a statement from an UNTRUSTED prover is rejected', async () => {
    const hook = createZkVerifier({ trustedProverKeys: [], now: () => NOW });
    const r = await hook({ pcactn: { ...p, zk_compliance: statement }, grant: GRANT, nowEpoch: NOW });
    expect(r).toMatchObject({ enforced: true, ok: false });
  });
  it('a TAMPERED field (r) breaks the statement signature', async () => {
    const hook = createZkVerifier({ trustedProverKeys: [prover.publicKey], now: () => NOW });
    const r = await hook({ pcactn: { ...p, zk_compliance: { ...statement, r: statement.r + 0.5 } }, grant: GRANT, nowEpoch: NOW });
    expect(r).toMatchObject({ enforced: true, ok: false });
  });
  it('an EXPIRED statement is rejected', async () => {
    const late = createAttestedComplianceProver(generateKeyPair().secretKey);
    const expired = late.prove({ pcactn: p, decideInput, issued_at: NOW - 10_000, expires_at: NOW - 5_000 });
    const hook = createZkVerifier({ trustedProverKeys: [late.publicKey], now: () => NOW });
    const r = await hook({ pcactn: { ...p, zk_compliance: expired }, grant: GRANT, nowEpoch: NOW });
    expect(r).toMatchObject({ enforced: true, ok: false });
  });

  // Groth16 backend malformed/mis-bound rejection — reachable WITHOUT snarkjs (all checks precede loadGroth16).
  it('the Groth16 backend rejects a malformed / mis-bound / non-allow proof without needing a real proof', async () => {
    const backend = createGroth16SnarkBackend({ verificationKey: {} });
    const publicInputs = { action_commit: statement.action_commit, policy_commit: statement.policy_commit, plan_commit: statement.plan_commit };
    const ctx = { pcactn: p, grant: GRANT } as never;
    // wrong system tag
    expect(await backend.verify({ proof: { system: 'nope', circuit: 'pca-compliance-v1', proof: {}, publicSignals: ['0', '0', '0', '0', '0', '0', '1'] }, publicInputs, ctx })).toBe(false);
    // allow signal != 1
    expect(await backend.verify({ proof: { system: 'groth16-bn254', circuit: 'pca-compliance-v1', proof: {}, publicSignals: ['0', '0', '0', '0', '0', '0', '0'] }, publicInputs, ctx })).toBe(false);
    // mismatched binding tag (shaPolicy = 0, not commitmentField(policy_commit))
    expect(await backend.verify({ proof: { system: 'groth16-bn254', circuit: 'pca-compliance-v1', proof: {}, publicSignals: ['0', '0', '0', '0', '0', '0', '1'] }, publicInputs, ctx })).toBe(false);
  });
});

// =====================================================================================
// § semantic-threshold  — k-of-n judge ensemble + conformal gate
// =====================================================================================
describe('§ semantic-threshold', () => {
  const action = { verb: 'wire_money', resource: 'acct/1', params_digest: paramsDigest({}), reversibility_class: 'irreversible' };
  const aDigest = judgeActionDigest(action);
  const goal = b64u(unb64u('A'.repeat(43)));
  const judges = [generateKeyPair(), generateKeyPair(), generateKeyPair()];
  const keys = judges.map((j) => encodeKey(j.publicKey));
  const verdict = (j: { secretKey: Uint8Array }, faithful: boolean, score: number) =>
    signJudgeVerdict(j.secretKey, { actionDigest: aDigest, goalCommitment: goal, faithful, score });

  it('a SUB-QUORUM (k not met) is rejected', () => {
    const verdicts = [verdict(judges[0]!, true, 0.9), verdict(judges[1]!, true, 0.9)]; // 2 agree
    const r = verifySemanticThreshold(verdicts, { judgeKeys: keys, k: 3, goalCommitment: goal, actionDigest: aDigest });
    expect(r.ok).toBe(false);
    expect(r.agreeCount).toBe(2);
  });
  it('an UNKNOWN judge key does not count toward the quorum', () => {
    const stranger = generateKeyPair();
    const verdicts = [verdict(judges[0]!, true, 0.9), verdict(judges[1]!, true, 0.9), verdict(stranger, true, 0.9)];
    const r = verifySemanticThreshold(verdicts, { judgeKeys: keys, k: 3, goalCommitment: goal, actionDigest: aDigest });
    expect(r.ok).toBe(false); // only 2 of the 3 are trusted
  });
  it('a MIS-BOUND verdict (wrong actionDigest) does not count', () => {
    const wrong = signJudgeVerdict(judges[2]!.secretKey, { actionDigest: judgeActionDigest({ ...action, resource: 'acct/EVIL' }), goalCommitment: goal, faithful: true, score: 0.9 });
    const verdicts = [verdict(judges[0]!, true, 0.9), verdict(judges[1]!, true, 0.9), wrong];
    const r = verifySemanticThreshold(verdicts, { judgeKeys: keys, k: 3, goalCommitment: goal, actionDigest: aDigest });
    expect(r.ok).toBe(false);
  });
  it('a TAMPERED score breaks the verdict signature', () => {
    const v = verdict(judges[0]!, true, 0.9);
    expect(verifyJudgeVerdict({ ...v, score: 0.1 }, { actionDigest: aDigest, goalCommitment: goal })).toBe(false);
  });
  it('the CONFORMAL gate denies when agreement is below the calibrated cutoff', () => {
    // 3 judges agree with a LOW score; calibration demands a high cutoff ⇒ deny despite quorum.
    const verdicts = judges.map((j) => verdict(j, true, 0.3));
    const calibration = { alpha: 0.1, samples: [
      { score: 0.4, faithful: false }, { score: 0.5, faithful: false }, { score: 0.6, faithful: false },
      { score: 0.7, faithful: false }, { score: 0.8, faithful: false }, { score: 0.9, faithful: false },
    ] };
    const r = verifySemanticThreshold(verdicts, { judgeKeys: keys, k: 3, goalCommitment: goal, actionDigest: aDigest, calibration });
    expect(r.agreeCount).toBe(3);
    expect(r.ok).toBe(false); // aggregateScore 0.3 does not exceed the conformal cutoff
  });
});

// =====================================================================================
// § taint-downgrade  — agent-declared provenance/caution cannot LOWER the server's risk
// =====================================================================================
describe('§ taint-downgrade (agent-declared provenance is monotone)', () => {
  it('under-reporting caution gains the agent NOTHING (effectiveRisk clamps to serverRisk)', () => {
    expect(combineCaution(0, 0.7)).toBe(0.7); // declared 0 (confident) ⇒ no downgrade
    expect(combineCaution(0.9, 0.3)).toBe(0.9); // can only RAISE
    expect(combineCaution(undefined, 0.5)).toBe(0.5);
    expect(combineCaution(Number.NaN, 0.5)).toBe(0.5);
  });
  it('a FORGED / mis-bound signed caution degrades to serverRisk (never below it)', () => {
    const holder = generateKeyPair();
    const actionDigest = b64u(unb64u('A'.repeat(43)));
    const claim = signCaution({ action_digest: actionDigest, caution: 0.2, holder: encodeKey(holder.publicKey) }, holder.secretKey);
    // valid + bound ⇒ honoured, but 0.2 < serverRisk 0.6 ⇒ still clamps to 0.6
    expect(combineSignedCaution(claim, actionDigest, 0.6, encodeKey(holder.publicKey))).toMatchObject({ effectiveRisk: 0.6, honoured: true });
    // tampered caution breaks the signature ⇒ not honoured, degrades to serverRisk
    const tampered = { ...claim, caution: 0.0 };
    const r = combineSignedCaution(tampered, actionDigest, 0.6, encodeKey(holder.publicKey));
    expect(r.honoured).toBe(false);
    expect(r.effectiveRisk).toBe(0.6);
    // bound to a DIFFERENT action ⇒ not honoured
    expect(combineSignedCaution(claim, b64u(new Uint8Array(32).fill(9)), 0.6, encodeKey(holder.publicKey)).honoured).toBe(false);
    // signed by a DIFFERENT holder than expected ⇒ rejected
    expect(verifyCaution(claim, actionDigest, encodeKey(generateKeyPair().publicKey))).toBe(false);
  });
});

// =====================================================================================
// § attestation-replay  — software attestation (trusted-key assertion; see F-4)
// =====================================================================================
describe('§ attestation-replay (software)', () => {
  const attestor = createDevAttestor(generateKeyPair().secretKey);
  const A = generateKeyPair();
  const HOLDER = encodeKey(A.publicKey);
  const NONCE = 'nonce-epoch-1';
  const mkCtx = (quoteDigest: string) => ({ pcactn: { attestation: { quote_digest: quoteDigest }, grant_ref: 'g' } as unknown as PCActn, grant: {} as never, nowEpoch: NOW });
  const doc = attestor.attest({ model_id: 'gpt-x', weights_digest: 'w1', runtime_measurement: 'm1', operator: 'acme', nonce: NONCE, issued_at: NOW - 1000, expires_at: NOW + 60_000, holder_pub: HOLDER, grant_ref: 'g', epoch: 1 });
  const expectedBinding = () => ({ holderPub: HOLDER, grantRef: 'g', epoch: 1, nonce: NONCE, nonceIssuedAt: NOW - 1000 });

  it('FAIL-CLOSED by default: no server-issued binding ⇒ the hook rejects', async () => {
    const verifier = createAttestationVerifier({ trustedAttestorKeys: [attestor.publicKey], resolveDocument: attestationRegistry([doc]), now: () => NOW });
    const r = await verifier(mkCtx(NONCE));
    expect(r).toMatchObject({ enforced: true, ok: false });
  });
  it('a TAMPERED attestation document (mutated measurement) fails the signature', async () => {
    const tampered = { ...doc, weights_digest: 'w-EVIL' };
    const verifier = createAttestationVerifier({ trustedAttestorKeys: [attestor.publicKey], resolveDocument: () => tampered, expectedBinding, now: () => NOW });
    const r = await verifier(mkCtx(NONCE));
    expect(r).toMatchObject({ enforced: true, ok: false });
  });
  it('a document whose nonce does NOT bind this PCActn is rejected (replay to another action)', async () => {
    const verifier = createAttestationVerifier({ trustedAttestorKeys: [attestor.publicKey], resolveDocument: () => doc, expectedBinding, now: () => NOW });
    const r = await verifier(mkCtx('a-different-nonce'));
    expect(r).toMatchObject({ enforced: true, ok: false });
  });
  it('an EXPIRED document is rejected', async () => {
    const stale = attestor.attest({ model_id: 'gpt-x', weights_digest: 'w1', runtime_measurement: 'm1', operator: 'acme', nonce: NONCE, issued_at: NOW - 10_000, expires_at: NOW - 5_000, holder_pub: HOLDER, grant_ref: 'g', epoch: 1 });
    const verifier = createAttestationVerifier({ trustedAttestorKeys: [attestor.publicKey], resolveDocument: () => stale, expectedBinding, now: () => NOW });
    const r = await verifier(mkCtx(NONCE));
    expect(r).toMatchObject({ enforced: true, ok: false });
  });
});

// =====================================================================================
// § sevsnp-policy  — hardware attestation policy + report-signature (MOCK root; see F-4)
// =====================================================================================
describe('§ sevsnp-policy (hardware)', () => {
  it('a DEBUG-enabled report is rejected by the measurement policy', () => {
    const meas = new Uint8Array(48).fill(7);
    const debugReport = parseSevSnpReport(serializeSevSnpReport({ measurement: meas, policy: SEV_SNP_POLICY_DEBUG_BIT }));
    const policy = { measurements: [toHex(meas)] };
    const reason = checkSevSnpPolicy(debugReport, policy);
    expect(reason).toMatch(/DEBUG/);
    // same report without the debug bit passes the policy (proves it is the bit, not something else)
    const clean = parseSevSnpReport(serializeSevSnpReport({ measurement: meas, policy: 0n }));
    expect(checkSevSnpPolicy(clean, policy)).toBeNull();
  });
  it("a report whose signature does not verify under the VCEK key is rejected", () => {
    const report = parseSevSnpReport(serializeSevSnpReport({ measurement: new Uint8Array(48).fill(1) })); // zero signature
    const vcek = ecdsaP384PublicKey(p384.getPublicKey(p384.utils.randomPrivateKey(), false));
    expect(verifySevSnpReportSignature(report, vcek)).toBe(false);
  });
});
