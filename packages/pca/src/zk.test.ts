import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  type ComplianceStatement,
  type Groth16ComplianceProof,
  type PolicyVmComplianceProof,
  type SnarkBackend,
  POLICYVM_PUBLIC_SIGNAL,
  POLICYVM_REVERSIBILITY_ORDER,
  POLICYVM_SAMPLE_PROOF_PATH,
  POLICYVM_VKEY_PATH,
  actionCommitment,
  commitmentField,
  createAttestedComplianceProver,
  createGroth16SnarkBackend,
  createPolicyVmSnarkBackend,
  createZkVerifier,
  decodePolicyVmPublic,
  policyCommitment,
  policyVmCommitmentFromAction,
  policyVmStructHash,
  proveGroth16Compliance,
  quantizeActionStruct,
  quantizePlanStruct,
  quantizePolicyStruct,
  quantizePolicyVmInputs,
  verifyPolicyVmProof,
  type QuantizableAction,
} from './zk';
import { hashCanonical } from './hash';
import { mintGrant, readEnvelope } from './envelope';
import { buildPCActn, type PCActn, type VerifyContext } from './pcactn';
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
  principalSecret: P.secretKey,
  principalPublic: encodeKey(P.publicKey),
  holder: encodeKey(A.publicKey),
  goal: 'secure my account',
  envelope: {
    predicates: [{ verb: 'revoke_session', resource: '/acct/*' }],
    caveats: [{ type: 'expires', at: 9e12 }],
    agent_binding: {},
    risk_policy: DEFAULT_RISK_POLICY,
  },
}).grant;

const NODES: PlanNode[] = [{ id: 'n1', verb: 'revoke_session', resource: '/acct/1/s', reversibility_class: 'reversible' }];

function actn(verb = 'revoke_session'): PCActn {
  const nodes: PlanNode[] = [{ id: 'n1', verb, resource: '/acct/1/s', reversibility_class: 'reversible' }];
  return buildPCActn({ aud: 'test-aud', grant: GRANT, chain: [GRANT], plan: nodes, nodeId: 'n1', counter: 1, signerSecret: A.secretKey });
}

function decideInputFor(p: PCActn): DecideInput {
  return {
    grant: GRANT,
    chain: [GRANT],
    action: { action: { verb: p.action.verb, resource: p.action.resource, params: {}, reversibility_class: p.action.reversibility_class } },
    plan: NODES,
    risk: { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 },
    budget: fresh,
    now: NOW,
    nodeId: p.plan.node_id,
  };
}

function prove(p: PCActn, prover = createAttestedComplianceProver(generateKeyPair().secretKey)) {
  const statement = prover.prove({ pcactn: p, decideInput: decideInputFor(p), issued_at: NOW - 1000, expires_at: NOW + 60_000 });
  return { statement, prover };
}

describe('attested compliance prover / verifier (§9B)', () => {
  it('a valid attested-compliance statement verifies', async () => {
    const p = actn();
    const { statement, prover } = prove(p);
    p.zk_compliance = statement;
    const verify = createZkVerifier({ trustedProverKeys: [prover.publicKey], policyCommitments: [policyCommitment(GRANT)], now: () => NOW });
    expect(await verify({ pcactn: p, grant: GRANT })).toEqual({ enforced: true, ok: true });
  });

  it('the prover refuses to prove a non-compliant action', () => {
    const p = actn('exfiltrate'); // not permitted
    expect(() => prove(p)).toThrow(/not compliant/);
  });

  it('tampering the action breaks the commitment binding', async () => {
    const p = actn();
    const { statement, prover } = prove(p);
    p.zk_compliance = statement;
    p.action = { ...p.action, resource: '/acct/EVIL' }; // action no longer matches the proof's commitment
    const verify = createZkVerifier({ trustedProverKeys: [prover.publicKey], policyCommitments: [policyCommitment(GRANT)], now: () => NOW });
    const res = await verify({ pcactn: p, grant: GRANT });
    expect(res).toMatchObject({ enforced: true, ok: false });
    expect((res as { reason: string }).reason).toMatch(/does not bind to this action/);
  });

  it('tampering the statement breaks the signature', async () => {
    const p = actn();
    const { statement, prover } = prove(p);
    p.zk_compliance = { ...statement, r: 0.99 } as ComplianceStatement;
    const verify = createZkVerifier({ trustedProverKeys: [prover.publicKey], policyCommitments: [policyCommitment(GRANT)], now: () => NOW });
    const res = await verify({ pcactn: p, grant: GRANT });
    expect(res).toMatchObject({ enforced: true, ok: false });
    expect((res as { reason: string }).reason).toMatch(/signature does not verify/);
  });

  it('an untrusted prover key is rejected', async () => {
    const p = actn();
    const { statement } = prove(p);
    p.zk_compliance = statement;
    const verify = createZkVerifier({ trustedProverKeys: [createAttestedComplianceProver(generateKeyPair().secretKey).publicKey], policyCommitments: [policyCommitment(GRANT)], now: () => NOW });
    const res = await verify({ pcactn: p, grant: GRANT });
    expect(res).toMatchObject({ enforced: true, ok: false });
    expect((res as { reason: string }).reason).toMatch(/not trusted/);
  });

  it('an expired statement is rejected', async () => {
    const p = actn();
    const prover = createAttestedComplianceProver(generateKeyPair().secretKey);
    p.zk_compliance = prover.prove({ pcactn: p, decideInput: decideInputFor(p), issued_at: NOW - 10_000, expires_at: NOW - 5_000 });
    const verify = createZkVerifier({ trustedProverKeys: [prover.publicKey], policyCommitments: [policyCommitment(GRANT)], now: () => NOW });
    const res = await verify({ pcactn: p, grant: GRANT });
    expect(res).toMatchObject({ enforced: true, ok: false });
    expect((res as { reason: string }).reason).toMatch(/expired/);
  });

  it('PRIVACY: the verifier checks compliance without the plaintext policy or plan', async () => {
    const p = actn();
    const { statement, prover } = prove(p);
    p.zk_compliance = statement;

    // The RS is configured with ONLY the policy commitment (a bare hash) and the trusted prover key.
    // It is handed a grant object that carries NO envelope — it literally cannot read the policy.
    const blindGrant = {} as unknown as Capability;
    expect(readEnvelope(blindGrant)).toBeNull();

    const verify = createZkVerifier({
      trustedProverKeys: [prover.publicKey],
      policyCommitments: [policyCommitment(GRANT)], // just the hash; no predicates/caveats/plan in hand
      now: () => NOW,
    });
    // Verifies "authorized" using only commitments, with no access to P, Π or the reasoning.
    expect(await verify({ pcactn: p, grant: blindGrant })).toEqual({ enforced: true, ok: true });

    // And a statement that commits to a DIFFERENT policy is rejected (wrong policy commitment).
    const verifyWrong = createZkVerifier({ trustedProverKeys: [prover.publicKey], policyCommitments: ['some-other-policy-commit'], now: () => NOW });
    expect(await verifyWrong({ pcactn: p, grant: blindGrant })).toMatchObject({ enforced: true, ok: false });
  });

  it('SNARK seam: delegates to the backend with commitments as public inputs', async () => {
    const p = actn();
    const { statement } = prove(p);
    p.zk_compliance = statement; // in SNARK mode the proof would be a circuit proof; shape is opaque here
    let seen: { action_commit: string; policy_commit: string; plan_commit: string } | undefined;
    const backend: SnarkBackend = {
      verify: ({ publicInputs }) => {
        seen = publicInputs;
        return true;
      },
    };
    const verify = createZkVerifier({ trustedProverKeys: [], policyCommitments: [policyCommitment(GRANT)], snarkBackend: backend, now: () => NOW });
    expect(await verify({ pcactn: p, grant: GRANT })).toEqual({ enforced: true, ok: true });
    expect(seen).toEqual({ action_commit: actionCommitment(p), policy_commit: policyCommitment(GRANT), plan_commit: p.plan.root });

    // A rejecting backend fails the hook.
    const reject: SnarkBackend = { verify: () => false };
    const verify2 = createZkVerifier({ trustedProverKeys: [], policyCommitments: [policyCommitment(GRANT)], snarkBackend: reject, now: () => NOW });
    expect(await verify2({ pcactn: p, grant: GRANT })).toMatchObject({ enforced: true, ok: false });
  });

  it('no proof present is rejected', async () => {
    const p = actn();
    const verify = createZkVerifier({ trustedProverKeys: [], policyCommitments: [policyCommitment(GRANT)], now: () => NOW });
    const res = await verify({ pcactn: p, grant: GRANT });
    expect(res).toMatchObject({ enforced: true, ok: false });
    expect((res as { reason: string }).reason).toMatch(/no zk_compliance/);
  });
});

// REAL Groth16 proofs (circuits/compliance.circom). These generate and verify actual zk-SNARK proofs
// via snarkjs against the committed trusted-setup fixtures in circuits/build — no stubs, no mocks.
describe('groth16 SNARK proof-of-compliance (§9B, REAL proofs)', () => {
  const backend = createGroth16SnarkBackend();
  const PROOF_TIMEOUT = 60_000;

  // A satisfying compliance witness (hidden from the RS): verb == planVerb, risk <= budget.
  const okWitness = { verb: 7, resource: 42, planVerb: 7, policySalt: 111, planSalt: 222, actionSalt: 333, risk: 3, budget: 10 };

  function proofFor(p: PCActn, override: Partial<typeof okWitness> = {}) {
    return proveGroth16Compliance({
      action_commit: actionCommitment(p),
      policy_commit: policyCommitment(GRANT),
      plan_commit: p.plan.root,
      ...okWitness,
      ...override,
    });
  }

  function verifierFor(policyCommits: string[] = [policyCommitment(GRANT)]) {
    return createZkVerifier({ trustedProverKeys: [], policyCommitments: policyCommits, snarkBackend: backend, now: () => NOW });
  }

  it('a valid Groth16 proof for a satisfying witness verifies', async () => {
    const p = actn();
    p.zk_compliance = await proofFor(p);
    // Sanity: it really is a Groth16 envelope with 7 public signals and allow == 1.
    const env = p.zk_compliance as Groth16ComplianceProof;
    expect(env.system).toBe('groth16-bn254');
    expect(env.publicSignals).toHaveLength(7);
    expect(env.publicSignals[6]).toBe('1');
    expect(await verifierFor()({ pcactn: p, grant: GRANT })).toEqual({ enforced: true, ok: true });
  }, PROOF_TIMEOUT);

  it('a non-satisfying witness (deny: risk > budget) is UNPROVABLE', async () => {
    const p = actn();
    await expect(proofFor(p, { risk: 50, budget: 10 })).rejects.toThrow();
  }, PROOF_TIMEOUT);

  it('a non-satisfying witness (action verb not in the committed plan) is UNPROVABLE', async () => {
    const p = actn();
    await expect(proofFor(p, { verb: 7, planVerb: 9 })).rejects.toThrow();
  }, PROOF_TIMEOUT);

  it('a tampered proof fails verification', async () => {
    const p = actn();
    const proof = (await proofFor(p)) as Groth16ComplianceProof;
    const tampered = JSON.parse(JSON.stringify(proof)) as Groth16ComplianceProof;
    const pi = (tampered.proof as { pi_a: string[] }).pi_a;
    pi[0] = (BigInt(pi[0]!) ^ 1n).toString(); // flip one bit of a proof group element
    p.zk_compliance = tampered;
    const res = await verifierFor()({ pcactn: p, grant: GRANT });
    expect(res).toMatchObject({ enforced: true, ok: false });
  }, PROOF_TIMEOUT);

  it('BINDING: a proof is rejected for a DIFFERENT action commitment', async () => {
    const pA = actn();
    const proofA = await proofFor(pA); // bound to actionCommitment(pA)
    const pB = actn();
    pB.action = { ...pB.action, resource: '/acct/OTHER' }; // actionCommitment(pB) now differs
    pB.zk_compliance = proofA;
    const res = await verifierFor()({ pcactn: pB, grant: GRANT });
    expect(res).toMatchObject({ enforced: true, ok: false });
  }, PROOF_TIMEOUT);

  it('BINDING: a proof is rejected for a DIFFERENT policy commitment', async () => {
    const p = actn();
    p.zk_compliance = await proofFor(p); // bound to policyCommitment(GRANT)
    const res = await verifierFor([hashCanonical({ a: 'different-policy' })])({ pcactn: p, grant: GRANT });
    expect(res).toMatchObject({ enforced: true, ok: false });
  }, PROOF_TIMEOUT);

  it('a direct backend call binds: swapping a commitment field is rejected', async () => {
    const p = actn();
    const env = await proofFor(p);
    const good = { action_commit: actionCommitment(p), policy_commit: policyCommitment(GRANT), plan_commit: p.plan.root };
    expect(await backend.verify({ proof: env, publicInputs: good, ctx: { pcactn: p, grant: GRANT } })).toBe(true);
    // commitmentField of a different policy commit no longer matches the proof's bound shaPolicy signal.
    const bad = { ...good, policy_commit: hashCanonical({ a: 'nope' }) };
    expect(commitmentField(bad.policy_commit)).not.toBe(commitmentField(good.policy_commit));
    expect(await backend.verify({ proof: env, publicInputs: bad, ctx: { pcactn: p, grant: GRANT } })).toBe(false);
  }, PROOF_TIMEOUT);

  it('PRIVACY: verifies using ONLY commitments, with no plaintext policy/plan in hand', async () => {
    const p = actn();
    p.zk_compliance = await proofFor(p);
    const blindGrant = {} as unknown as Capability; // carries no envelope — the RS cannot read the policy
    expect(await verifierFor()({ pcactn: p, grant: blindGrant })).toEqual({ enforced: true, ok: true });
  }, PROOF_TIMEOUT);

  it('a malformed Groth16 envelope is rejected (fails closed)', async () => {
    const p = actn();
    p.zk_compliance = { system: 'groth16-bn254', circuit: 'pca-compliance-v1', proof: { pi_a: ['1'] }, publicSignals: ['1', '2'] };
    const res = await verifierFor()({ pcactn: p, grant: GRANT });
    expect(res).toMatchObject({ enforced: true, ok: false });
  }, PROOF_TIMEOUT);
});

// FULL Policy-VM Groth16 proof (circuits/policyvm.circom, ~151.6k constraints). These verify the
// COMMITTED sample proof against the COMMITTED verifying key fully OFFLINE — real snarkjs Groth16, no
// wasm/zkey, no network, no trusted setup needed to VERIFY. The sample proves the full statement:
// sha256-in-circuit commitments + the fixed-point Policy VM decision => allow.
describe('full Policy-VM SNARK proof-of-compliance (§9B, committed fixture, REAL proof)', () => {
  const vkey = JSON.parse(readFileSync(POLICYVM_VKEY_PATH(), 'utf8')) as object;
  const sample = JSON.parse(readFileSync(POLICYVM_SAMPLE_PROOF_PATH(), 'utf8')) as PolicyVmComplianceProof;
  const ctx = { pcactn: {} as PCActn, grant: {} as Capability } as unknown as VerifyContext;
  const pub = { action_commit: '', policy_commit: '', plan_commit: '' };

  it('the committed sample proof verifies against the committed verifying key', async () => {
    expect(sample.system).toBe('groth16-bn254');
    expect(sample.circuit).toBe('pca-policyvm-v1');
    expect(sample.publicSignals).toHaveLength(15);
    expect(await verifyPolicyVmProof(sample, { verificationKey: vkey })).toBe(true);
  });

  it('the proven public statement is release at t=1, auto-admit, r=0', () => {
    const d = decodePolicyVmPublic(sample.publicSignals);
    expect(d.allow).toBe('1');
    expect(d.admit).toBe('1');
    expect(d.t).toBe('1');
    expect(d.r).toBe('0');
    expect(d.now).toBe('1000000000');
    expect(d.allocChild).toBe('500000');
  });

  it('BINDING: sha256 is proven IN-CIRCUIT — the public hash halves equal sha256(fixed struct)', () => {
    const d = decodePolicyVmPublic(sample.publicSignals);
    // action struct = [verb, resource, reversibility, paramScalar]
    expect(policyVmStructHash([7, 42, 0, 100])).toEqual(d.actionHash);
    // plan struct = [planVerb, planResource, semanticDist, planSalt]
    expect(policyVmStructHash([7, 42, 0, 12345])).toEqual(d.planHash);
    // policy struct = the 20 quantized policy fields (DEFAULT_RISK_POLICY at S=1e6 + caveat/chain bounds)
    expect(
      policyVmStructHash([
        250000, 200000, 200000, 200000, 100000, 50000, // weights alpha..zeta
        250000, 600000, // theta1, theta2
        1000000, 1000000, // kappa, budgetB
        7, 42, 1000, // policyVerb, policyResource, policyParamBound
        9000000000000, 0, // expiresAt, notBefore
        1000000, 16, 2, 100, // maxBlast, maxDepth, revMax, rateMax
        1000000, // allocParent
      ]),
    ).toEqual(d.policyHash);
  });

  it('a tampered proof element is rejected', async () => {
    const tampered = JSON.parse(JSON.stringify(sample)) as PolicyVmComplianceProof;
    const pi = (tampered.proof as { pi_a: string[] }).pi_a;
    pi[0] = (BigInt(pi[0]!) ^ 1n).toString(); // flip one bit of a proof group element
    expect(await verifyPolicyVmProof(tampered, { verificationKey: vkey })).toBe(false);
  });

  it('a tampered public signal is rejected (the proof binds every public signal)', async () => {
    const tampered = JSON.parse(JSON.stringify(sample)) as PolicyVmComplianceProof;
    tampered.publicSignals[POLICYVM_PUBLIC_SIGNAL.now] = '999';
    expect(await verifyPolicyVmProof(tampered, { verificationKey: vkey })).toBe(false);
  });

  it('allow != 1 is rejected (fail-closed, before running the SNARK)', async () => {
    const denied = JSON.parse(JSON.stringify(sample)) as PolicyVmComplianceProof;
    denied.publicSignals[POLICYVM_PUBLIC_SIGNAL.allow] = '0';
    expect(await verifyPolicyVmProof(denied, { verificationKey: vkey })).toBe(false);
  });

  it('a malformed envelope is rejected (fails closed)', async () => {
    expect(await verifyPolicyVmProof({ system: 'groth16-bn254', circuit: 'pca-policyvm-v1', proof: null, publicSignals: [] }, { verificationKey: vkey })).toBe(false);
    expect(await verifyPolicyVmProof({ system: 'nope' }, { verificationKey: vkey })).toBe(false);
    expect(await verifyPolicyVmProof(null, { verificationKey: vkey })).toBe(false);
  });

  it('the backend verifies and BINDS the in-circuit struct hashes', async () => {
    const backend = createPolicyVmSnarkBackend({ verificationKey: vkey, expectActionHash: policyVmStructHash([7, 42, 0, 100]) });
    expect(await backend.verify({ proof: sample, publicInputs: pub, ctx })).toBe(true);

    // A wrong expected action struct (different verb) no longer matches the proof's bound hash halves.
    const wrong = createPolicyVmSnarkBackend({ verificationKey: vkey, expectActionHash: policyVmStructHash([9, 42, 0, 100]) });
    expect(await wrong.verify({ proof: sample, publicInputs: pub, ctx })).toBe(false);
  });
});

// §9B — the proof↔action BINDING gap closed: the RS deterministically quantizes the LIVE canonical action
// to the circuit's fixed struct and binds the committed proof's public hash halves to it. These run fully
// offline against the committed sample proof + verifying key (real snarkjs Groth16, no wasm/zkey/network).
describe('policy-VM proof↔action binding via deterministic quantization (§9B)', () => {
  const vkey = JSON.parse(readFileSync(POLICYVM_VKEY_PATH(), 'utf8')) as object;
  const sample = JSON.parse(readFileSync(POLICYVM_SAMPLE_PROOF_PATH(), 'utf8')) as PolicyVmComplianceProof;
  const ctx = { pcactn: {} as PCActn, grant: {} as Capability } as unknown as VerifyContext;
  const pub = { action_commit: '', policy_commit: '', plan_commit: '' };

  // The quantization catalog the committed sample proof's prover used (codes 7 / 42, param scalar 100).
  const QOPTS = { verbCodes: { revoke_session: 7 }, resourceCodes: { '/acct/1/s': 42 }, paramScalarField: 'amount' } as const;
  // Action A: the live canonical action that quantizes to the sample's committed struct [7, 42, 0, 100].
  const actionA: QuantizableAction = { verb: 'revoke_session', resource: '/acct/1/s', reversibility_class: 'reversible', params: { amount: 100 } };
  // Action B: a DIFFERENT live action (different verb/resource/params) → a different quantized struct.
  const actionB: QuantizableAction = { verb: 'exfiltrate', resource: '/acct/EVIL', reversibility_class: 'irreversible', params: { amount: 999 } };

  it('quantizeActionStruct derives the circuit struct from the live canonical action (deterministic)', () => {
    expect(quantizeActionStruct(actionA, QOPTS)).toEqual([7n, 42n, 0n, 100n]);
    // Deterministic: same action → same struct, every time.
    expect(quantizeActionStruct(actionA, QOPTS)).toEqual(quantizeActionStruct(actionA, QOPTS));
    // The reversibility index follows the canonical order (reversible=0, rate_limited=1, irreversible=2).
    expect(POLICYVM_REVERSIBILITY_ORDER).toEqual(['reversible', 'rate_limited', 'irreversible']);
    expect(quantizeActionStruct({ ...actionA, reversibility_class: 'irreversible' }, QOPTS)[2]).toBe(2n);
  });

  it('policyVmCommitmentFromAction(A) EQUALS the committed proof public hash halves — the proof is bound to A', () => {
    const d = decodePolicyVmPublic(sample.publicSignals);
    expect(policyVmCommitmentFromAction(actionA, QOPTS)).toEqual(d.actionHash);
    // A DIFFERENT action quantizes to a different struct → a different commitment (no collision with A).
    expect(policyVmCommitmentFromAction(actionB, QOPTS)).not.toEqual(d.actionHash);
  });

  it('BINDING: the sample proof VERIFIES + BINDS when the RS-quantized commitment matches the live action', async () => {
    const backend = createPolicyVmSnarkBackend({ verificationKey: vkey, expectActionHash: policyVmCommitmentFromAction(actionA, QOPTS) });
    expect(await backend.verify({ proof: sample, publicInputs: pub, ctx })).toBe(true);
  });

  it('REPLAY DENIED: the SAME valid proof (minted for A) is REJECTED when presented for a different action B', async () => {
    // The Groth16 proof itself is valid (it verifies with A's binding above), but when the RS recomputes the
    // expected action commitment from action B, the proof's public halves no longer match → fail-closed deny.
    const backend = createPolicyVmSnarkBackend({ verificationKey: vkey, expectActionHash: policyVmCommitmentFromAction(actionB, QOPTS) });
    expect(await backend.verify({ proof: sample, publicInputs: pub, ctx })).toBe(false);
  });

  it('a single changed action param flips the binding (DENY): same verb/resource, paramScalar differs', async () => {
    const actionAprime: QuantizableAction = { ...actionA, params: { amount: 101 } }; // 100 → 101
    const backend = createPolicyVmSnarkBackend({ verificationKey: vkey, expectActionHash: policyVmCommitmentFromAction(actionAprime, QOPTS) });
    expect(await backend.verify({ proof: sample, publicInputs: pub, ctx })).toBe(false);
  });

  it('content-addressed fallback (no catalog) is deterministic and distinct per string', () => {
    const s1 = quantizeActionStruct({ verb: 'a', resource: 'x' });
    const s2 = quantizeActionStruct({ verb: 'a', resource: 'x' });
    const s3 = quantizeActionStruct({ verb: 'b', resource: 'x' });
    expect(s1).toEqual(s2); // deterministic
    expect(s1[0]).not.toBe(s3[0]); // different verb → different code
    for (const code of [s1[0], s1[1]]) expect(code >= 0n && code < 1n << 64n).toBe(true); // uint64 domain
  });

  it('FAIL CLOSED: an unquantizable action throws (unknown class, strict-catalog miss, bad scalar, non-string)', () => {
    // unknown reversibility class
    expect(() => quantizeActionStruct({ verb: 'v', resource: 'r', reversibility_class: 'teleport' })).toThrow(/unknown reversibility/i);
    // strict-catalog miss (verb not in the explicit catalog, and content-addressing disabled)
    expect(() => quantizeActionStruct(actionA, { ...QOPTS, strictCatalog: true, verbCodes: {} })).toThrow(/catalog/i);
    // param scalar not a non-negative integer
    expect(() => quantizeActionStruct({ verb: 'v', resource: 'r', params: { amount: -5 } }, { paramScalarField: 'amount' })).toThrow(/paramScalar/i);
    expect(() => quantizeActionStruct({ verb: 'v', resource: 'r', params: { amount: 1.5 } }, { paramScalarField: 'amount' })).toThrow(/paramScalar/i);
    // non-string verb (defeats the type system at the boundary)
    expect(() => quantizeActionStruct({ verb: 42 as unknown as string, resource: 'r' })).toThrow(/string/i);
    // paramScalar out of uint64 range
    expect(() => quantizeActionStruct({ verb: 'v', resource: 'r', params: { amount: 1n << 64n } }, { paramScalarField: 'amount' })).toThrow(/uint64/i);
  });

  it('the umbrella quantizePolicyVmInputs reproduces the committed sample action/plan/policy structs', () => {
    const d = decodePolicyVmPublic(sample.publicSignals);
    const q = quantizePolicyVmInputs(
      {
        action: actionA,
        plan: { verb: 'revoke_session', resource: '/acct/1/s', semanticDist: 0, planSalt: 12345 },
        policy: {
          weights: { alpha: 250000, beta: 200000, gamma: 200000, delta: 200000, epsilon: 100000, zeta: 50000 },
          theta1: 250000,
          theta2: 600000,
          kappa: 1000000,
          budgetB: 1000000,
          policyVerb: 'revoke_session',
          policyResource: '/acct/1/s',
          policyParamBound: 1000,
          expiresAt: 9000000000000,
          notBefore: 0,
          maxBlast: 1000000,
          maxDepth: 16,
          revMax: 'irreversible',
          rateMax: 100,
          allocParent: 1000000,
        },
      },
      QOPTS,
    );
    expect(q.action).toEqual([7n, 42n, 0n, 100n]);
    expect(policyVmStructHash(q.action)).toEqual(d.actionHash);
    expect(policyVmStructHash(q.plan!)).toEqual(d.planHash);
    expect(policyVmStructHash(q.policy!)).toEqual(d.policyHash);
    // and the standalone struct quantizers agree with the umbrella
    expect(quantizePlanStruct({ verb: 'revoke_session', resource: '/acct/1/s', semanticDist: 0, planSalt: 12345 }, QOPTS)).toEqual(q.plan);
    expect(quantizePolicyStruct(
      {
        weights: { alpha: 250000, beta: 200000, gamma: 200000, delta: 200000, epsilon: 100000, zeta: 50000 },
        theta1: 250000, theta2: 600000, kappa: 1000000, budgetB: 1000000,
        policyVerb: 'revoke_session', policyResource: '/acct/1/s', policyParamBound: 1000,
        expiresAt: 9000000000000, notBefore: 0, maxBlast: 1000000, maxDepth: 16, revMax: 'irreversible', rateMax: 100, allocParent: 1000000,
      },
      QOPTS,
    )).toEqual(q.policy);
  });
});
