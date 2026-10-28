/**
 * T8 (0.5): assurance labels. For every advanced feature (attestation, zk compliance, PQ signatures, threshold), weaker,
 * missing, invalid, expired, unlabelled, preview or unsupported evidence never yields a high-assurance success; the report
 * says what each pass rests on; and without the new options the output is unchanged.
 */
import { describe, expect, it, vi } from 'vitest';
import {
  type AssuranceReport,
  type AssuranceRequirement,
  assuranceLabelOf,
  assuranceReport,
  multiRootLevel,
  refreshAssurance,
  setAssuranceLabel,
  signatureLevel,
  unmetAssurance,
} from './assurance';
import { MAX_ATTESTATION_AGE_MS, type AttestationDocument, type HardwareAttestationVerifier, createAttestationVerifier, createDevAttestor, createMultiRootVerifier } from './attestation';
import { createAmdSnpVerifier } from './attest-amd-snp';
import { createIntelDcapVerifier } from './attest-intel-dcap';
import { createNvidiaSpdmVerifier } from './attest-nvidia-spdm';
import { createPufVerifier } from './attest-puf';
import { mintRoot, type Capability } from './capability';
import { mintGrant } from './envelope';
import { encodeKey, generateKeyPair } from './keys';
import type { PlanNode } from './merkle';
import { type Hook, type PCActn, type VerifyContext, buildPCActn, signPCActn, signPCActnSuite, verifyPCActnCore } from './pcactn';
import type { DecideInput } from './policy-vm';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from './pq';
import { DEFAULT_RISK_POLICY } from './risk';
import { createThresholdVerifier } from './threshold';
import { type SnarkBackend, createAttestedComplianceProver, createGroth16SnarkBackend, createPolicyVmSnarkBackend, createZkVerifier, policyVmStructHash } from './zk';
import { authorize, type AuthorizeOptions } from './server/authorize';
import { authorizeExecution } from './server/authorize-execution';
import { memoryPcaStore, requirePCA, type PcaStateStore } from './server/require-pca';
import { type PcaVerdict, type VerifyPCActnOptions, verifyPCActn } from './server/verify';
import { principalDirect } from './test-support/provenance';

const NOW = 1_000_000_000;
const AUD = 'rs-assurance';
const NONCE = 'q3Vx8mZ0aT7bLk2RwYp9Hs';
const P = generateKeyPair();
const A = generateKeyPair();
const HOLDER = encodeKey(A.publicKey);
const NODES: PlanNode[] = [{ id: 'n1', verb: 'read', resource: '/acct/1', reversibility_class: 'reversible' }];
const LOW = { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 };
const ENVELOPE = { predicates: [{ verb: 'read', resource: '/acct/*' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY };
const GRANT: Capability = mintGrant({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: HOLDER, goal: 'read my account', envelope: ENVELOPE }).grant;
const OK: Hook = () => ({ enforced: true, ok: true });

let counter = 0;
function actn(o: { grant?: Capability; quote?: string; extra?: Record<string, unknown> } = {}): PCActn {
  const grant = o.grant ?? GRANT;
  const p = buildPCActn({
    aud: AUD,
    grant,
    chain: [grant],
    plan: NODES,
    nodeId: 'n1',
    counter: ++counter,
    signerSecret: A.secretKey,
    now: NOW,
    attestation: { quote_digest: o.quote ?? NONCE, epoch: 1, model_id: 'gpt-x', measurement: 'm-launch-1', operator: 'acme-cloud' },
  });
  if (!o.extra) return p;
  const { sig: _sig, ...body } = p;
  return signPCActn({ ...body, ...o.extra } as never, A.secretKey);
}

const base = (o: Partial<VerifyPCActnOptions> = {}): VerifyPCActnOptions => ({
  grant: GRANT,
  now: NOW,
  audience: AUD,
  context: { params: {}, plan: NODES, planAuthorized: true, risk: LOW, budget: { B: 1, tau: NOW, asOf: NOW } },
  ...o,
  hooks: { revocation: OK, ...o.hooks },
});

/** Exact outcome: allow, the `assurance` check, the failing checks, and the decisive assurance reason. */
const settle = (v: PcaVerdict) => ({
  allow: v.allow,
  assurance: v.checks.assurance,
  failed: Object.entries(v.checks).filter(([, s]) => s === 'fail').map(([k]) => k).sort(),
  why: v.reasons.find((r) => r.startsWith('assurance:')),
});

// ---- attestation fixtures ------------------------------------------------------------------------------------------
const attestor = createDevAttestor(generateKeyPair().secretKey);
const CLAIMS = { model_id: 'gpt-x', weights_digest: 'w-sha-1', runtime_measurement: 'm-launch-1', operator: 'acme-cloud', nonce: NONCE, issued_at: NOW - 1000, expires_at: NOW + 60_000 };
const docFor = (p: PCActn, over: Partial<typeof CLAIMS> = {}): AttestationDocument => attestor.attest({ ...CLAIMS, ...over, holder_pub: HOLDER, grant_ref: p.grant_ref, epoch: 1 });
const expectedFor = (issued = NOW - 1000) => (ctx: VerifyContext) => ({ holderPub: HOLDER, grantRef: ctx.pcactn.grant_ref, epoch: 1, nonce: NONCE, nonceIssuedAt: issued });
const MEASURED = { model_id: 'gpt-x', weights_digest: 'w-sha-1', runtime_measurement: 'm-launch-1', operator: 'acme-cloud' };
const hwOk = (label?: { level: string; vendor?: string }): HardwareAttestationVerifier => {
  const v: HardwareAttestationVerifier = { verify: () => ({ ok: true, bound: true, measured: MEASURED }) };
  return label ? setAssuranceLabel(v, label) : v;
};
const softHook = (doc: () => AttestationDocument | undefined, issued?: number) =>
  createAttestationVerifier({ trustedAttestorKeys: [attestor.publicKey], resolveDocument: doc, expectedBinding: expectedFor(issued), now: () => NOW });
const hwHook = (hw: HardwareAttestationVerifier, doc: () => AttestationDocument | undefined, issued?: number) =>
  createAttestationVerifier({ trustedAttestorKeys: [], hardwareVerifier: hw, resolveDocument: doc, expectedBinding: expectedFor(issued), now: () => NOW });

describe('assurance report: what an attestation pass rests on', () => {
  it('software, hardware, multi-root and unlabelled verifiers are labelled from the configuration, not the document', async () => {
    const p = actn();
    const doc = docFor(p);
    const level = async (hook: Hook) => (await verifyPCActn(p, base({ hooks: { attestation: hook }, assurance: true }))).assurance?.attestation;
    expect(await level(softHook(() => doc))).toEqual({ outcome: 'pass', level: 'software' });
    expect(await level(hwHook(hwOk({ level: 'hardware', vendor: 'test-tee' }), () => doc))).toEqual({ outcome: 'pass', level: 'hardware', vendor: 'test-tee' });
    expect(await level(hwHook(hwOk(), () => doc))).toEqual({ outcome: 'pass', level: 'unknown' });
    const two = createMultiRootVerifier({ roots: [{ id: 'amd', verifier: hwOk({ level: 'hardware' }) }, { id: 'intel', verifier: hwOk({ level: 'hardware' }) }], threshold: 2 });
    expect(await level(hwHook(two, () => doc))).toEqual({ outcome: 'pass', level: 'multi_root', vendor: 'multi-root:amd+intel' });
    // a document claiming hardware mode does not make a software verifier hardware
    expect(assuranceLabelOf(softHook(() => ({ ...doc, mode: 'hardware' })))).toEqual({ level: 'software' });
  });

  it('the self-declared-nonce opt-out is never labelled above unknown', () => {
    const hook = createAttestationVerifier({ trustedAttestorKeys: [attestor.publicKey], insecure_selfDeclaredNonce: true });
    expect(assuranceLabelOf(hook)).toEqual({ level: 'unknown', vendor: 'insecure-self-declared-nonce' });
  });

  it('the library hardware roots carry their vendor; PUF and PQ-software roots are software', () => {
    expect(assuranceLabelOf(createAmdSnpVerifier({ family: 'genoa', binding: 'report-data', policy: { measurements: ['aa'] } } as never))).toEqual({ level: 'hardware', vendor: 'amd-sev-snp' });
    expect(assuranceLabelOf(createIntelDcapVerifier({ binding: 'report-data', policy: { mrtds: ['a'.repeat(96)] } } as never))).toEqual({ level: 'hardware', vendor: 'intel-dcap' });
    expect(assuranceLabelOf(createNvidiaSpdmVerifier({ rootSpkiSha256: ['aa'], policy: { measurements: { 1: 'aa' } } } as never))).toEqual({ level: 'hardware', vendor: 'nvidia-spdm' });
    expect(assuranceLabelOf(createPufVerifier({ resolveEnrollment: () => undefined, policy: { measurements: ['aa'] } } as never))).toEqual({ level: 'software', vendor: 'puf' });
  });

  it('multiRootLevel: the fewest hardware roots any accepted quorum can contain', () => {
    const hw = { verifier: hwOk({ level: 'hardware' }) };
    const sw = { verifier: hwOk({ level: 'software' }) };
    const un = { verifier: hwOk() };
    expect(multiRootLevel([hw, hw], 2)).toBe('multi_root');
    expect(multiRootLevel([hw, hw], 1)).toBe('hardware');
    expect(multiRootLevel([hw, hw, sw], 2)).toBe('hardware'); // sw + one hw is an accepted quorum
    expect(multiRootLevel([hw, sw], 1)).toBe('software'); // sw alone is an accepted quorum
    expect(multiRootLevel([{ ...hw, required: true }, sw], 1)).toBe('hardware'); // the required hw root is always there
    expect(multiRootLevel([{ ...hw, required: true }, { ...hw, required: true }, sw], 1)).toBe('multi_root');
    expect(multiRootLevel([hw, un], 1)).toBe('unknown');
    expect(multiRootLevel([sw, sw], 2)).toBe('software');
  });
});

describe('requireAssurance: attestation never yields a high-assurance success on weaker / missing / invalid / expired evidence', () => {
  const p = actn();
  const doc = docFor(p);
  const run = (hook: Hook | undefined, req: AssuranceRequirement, pc: PCActn = p) => verifyPCActn(pc, base({ hooks: hook ? { attestation: hook } : {}, requireAssurance: req }));
  const HW = hwOk({ level: 'hardware', vendor: 'test-tee' });

  it('software evidence never satisfies hardware; hardware satisfies hardware and software', async () => {
    expect(settle(await run(softHook(() => doc), { attestation: 'hardware' }))).toEqual({
      allow: false,
      assurance: 'fail',
      failed: ['assurance'],
      why: 'assurance: hardware attestation required but the evidence is software',
    });
    expect(settle(await run(softHook(() => doc), { attestation: 'software' }))).toEqual({ allow: true, assurance: 'pass', failed: [], why: undefined });
    expect(settle(await run(hwHook(HW, () => doc), { attestation: 'hardware' }))).toEqual({ allow: true, assurance: 'pass', failed: [], why: undefined });
    expect(settle(await run(hwHook(HW, () => doc), { attestation: 'multi_root' }))).toEqual({
      allow: false,
      assurance: 'fail',
      failed: ['assurance'],
      why: 'assurance: multi_root attestation required but the evidence is hardware',
    });
  });

  it('an unlabelled hardware verifier satisfies no level', async () => {
    for (const level of ['software', 'hardware'] as const) {
      expect(settle(await run(hwHook(hwOk(), () => doc), { attestation: level }))).toEqual({
        allow: false,
        assurance: 'fail',
        failed: ['assurance'],
        why: `assurance: ${level} attestation required but the evidence is unknown`,
      });
    }
  });

  it.each([
    ['missing document', () => hwHook(HW, () => undefined)],
    ['expired nonce', () => hwHook(HW, () => doc, NOW - MAX_ATTESTATION_AGE_MS - 1)],
    ['invalid report', () => hwHook(setAssuranceLabel<HardwareAttestationVerifier>({ verify: () => ({ ok: false, reason: 'bad report' }) }, { level: 'hardware' }), () => doc)],
    ['expired software document', () => softHook(() => docFor(p, { issued_at: NOW - 10_000, expires_at: NOW - 5_000 }))],
  ])('%s: denied, and the report carries no level', async (_name, hook) => {
    const v = await run(hook(), { attestation: 'software' });
    expect(v.allow).toBe(false);
    expect(v.checks.assurance).toBe('fail');
    expect(v.assurance?.attestation?.level).toBeUndefined();
    expect(v.assurance?.attestation?.outcome).not.toBe('pass');
  });

  it('wrong nonce (the PCActn binds another quote): denied', async () => {
    const other = actn({ quote: 'Zz9yXw8vUt7sRq6pOn5mLk' });
    const v = await run(hwHook(HW, () => doc), { attestation: 'software' }, other);
    expect(settle(v)).toEqual({ allow: false, assurance: 'fail', failed: ['assurance', 'attestation'], why: 'assurance: software attestation required but the attestation check is fail' });
  });

  it('no attestation verifier at all: denied', async () => {
    expect(settle(await run(undefined, { attestation: 'software' }))).toEqual({
      allow: false,
      assurance: 'fail',
      failed: ['assurance'],
      why: 'assurance: software attestation required but the attestation check is not-enforced',
    });
  });

  it('the enforce.attestation gate verifier is the one labelled', async () => {
    const v = await verifyPCActn(p, base({ enforce: { attestation: { verifier: hwHook(HW, () => doc) } }, hooks: { attestation: softHook(() => doc) }, requireAssurance: { attestation: 'hardware' } }));
    expect(settle(v)).toEqual({ allow: true, assurance: 'pass', failed: [], why: undefined });
  });
});

// ---- zk fixtures ---------------------------------------------------------------------------------------------------
const prover = createAttestedComplianceProver(generateKeyPair().secretKey);
function decideInputFor(p: PCActn): DecideInput {
  return { grant: GRANT, chain: [GRANT], action: { action: { verb: p.action.verb, resource: p.action.resource, params: {}, reversibility_class: p.action.reversibility_class } }, plan: NODES, risk: LOW, budget: { B: 1, tau: NOW, asOf: NOW }, now: NOW, nodeId: p.plan.node_id };
}
function withStatement(expiresAt = NOW + 60_000): PCActn {
  const p0 = actn();
  const st = prover.prove({ pcactn: p0, decideInput: decideInputFor(p0), issued_at: NOW - 1000, expires_at: expiresAt });
  const { sig: _sig, ...body } = p0;
  return signPCActn({ ...body, zk_compliance: st } as never, A.secretKey);
}
const backend = (ok: boolean, level?: string): SnarkBackend => {
  const b: SnarkBackend = { verify: () => ok };
  return level ? setAssuranceLabel(b, { level }) : b;
};

describe('assurance: zk compliance (SNARK vs attested VM)', () => {
  const vm = () => createZkVerifier({ trustedProverKeys: [prover.publicKey], now: () => NOW });
  const snark = (b: SnarkBackend) => createZkVerifier({ trustedProverKeys: [], snarkBackend: b, now: () => NOW });
  const run = (p: PCActn, zk: Hook | undefined, req?: AssuranceRequirement) => verifyPCActn(p, base({ hooks: zk ? { zk } : {}, ...(req ? { requireAssurance: req } : { assurance: true }) }));

  it('labels: attested-VM mode, the library SNARK backends, an unbound Policy-VM backend', () => {
    expect(assuranceLabelOf(vm())).toEqual({ level: 'attested_vm' });
    expect(assuranceLabelOf(createGroth16SnarkBackend())).toEqual({ level: 'groth16', ceremony: 'single-party' });
    expect(assuranceLabelOf(snark(createGroth16SnarkBackend()))).toEqual({ level: 'groth16', ceremony: 'single-party' });
    expect(assuranceLabelOf(snark(backend(true)))).toEqual({ level: 'unknown' });
    // without the action / policy / plan struct hashes a valid proof may be for another compliant action
    expect(assuranceLabelOf(createPolicyVmSnarkBackend())).toEqual({ level: 'unknown', vendor: 'policyvm-unbound', ceremony: 'single-party' });
    const h = policyVmStructHash([1, 2, 3]);
    expect(assuranceLabelOf(createPolicyVmSnarkBackend({ expectActionHash: h, expectPolicyHash: h }))).toEqual({ level: 'unknown', vendor: 'policyvm-unbound', ceremony: 'single-party' });
    expect(assuranceLabelOf(createPolicyVmSnarkBackend({ expectActionHash: h, expectPolicyHash: h, expectPlanHash: h }))).toEqual({ level: 'policyvm_snark', ceremony: 'single-party' });
  });

  it('an attested-VM statement is reported as attested_vm and never satisfies { zk: snark } or { zk: proof }', async () => {
    const p = withStatement();
    expect((await run(p, vm())).assurance?.zk_compliance).toEqual({ outcome: 'pass', level: 'attested_vm' });
    expect(settle(await run(p, vm(), { zk: 'attested_vm' }))).toEqual({ allow: true, assurance: 'pass', failed: [], why: undefined });
    for (const zk of ['snark', 'proof'] as const) {
      expect(settle(await run(p, vm(), { zk }))).toEqual({ allow: false, assurance: 'fail', failed: ['assurance'], why: `assurance: zk compliance (${zk}) required but the evidence is attested_vm` });
    }
  });

  it('a labelled SNARK satisfies snark; a STARK satisfies proof but not snark', async () => {
    const p = withStatement();
    expect(settle(await run(p, snark(backend(true, 'groth16')), { zk: 'snark' }))).toEqual({ allow: true, assurance: 'pass', failed: [], why: undefined });
    expect(settle(await run(p, snark(backend(true, 'stark')), { zk: 'proof' }))).toEqual({ allow: true, assurance: 'pass', failed: [], why: undefined });
    expect(settle(await run(p, snark(backend(true, 'stark')), { zk: 'snark' })).why).toBe('assurance: zk compliance (snark) required but the evidence is stark');
  });

  it.each([
    ['an unlabelled backend', () => withStatement(), () => snark(backend(true)), ['assurance'], 'assurance: zk compliance (attested_vm) required but the evidence is unknown'],
    ['a rejected proof', () => withStatement(), () => snark(backend(false, 'groth16')), ['assurance', 'zk_compliance'], 'assurance: zk compliance (attested_vm) required but the zk_compliance check is fail'],
    ['an expired statement', () => withStatement(NOW - 1), () => vm(), ['assurance', 'zk_compliance'], 'assurance: zk compliance (attested_vm) required but the zk_compliance check is fail'],
    ['a proof with no verifier', () => withStatement(), () => undefined, ['assurance', 'zk_compliance'], 'assurance: zk compliance (attested_vm) required but the zk_compliance check is fail'],
    ['no proof at all', () => actn(), () => vm(), ['assurance'], 'assurance: zk compliance (attested_vm) required but there is no zk_compliance evidence'],
  ])('%s never satisfies even the weakest zk requirement', async (_n, mk, zk, failed, why) => {
    expect(settle(await run(mk(), zk(), { zk: 'attested_vm' }))).toEqual({ allow: false, assurance: 'fail', failed, why });
  });
});

// ---- PQ signature fixtures -----------------------------------------------------------------------------------------
const principalMl = mlDsa65Keygen(new Uint8Array(32).fill(21));
const holderMl = mlDsa65Keygen(new Uint8Array(32).fill(22));
const HYBRID = 'hybrid-ed25519-ml-dsa-65' as const;
const PQ_GRANT: Capability = mintRoot({
  principalSecret: P.secretKey,
  principalPublic: encodeKey(P.publicKey),
  holder: HOLDER,
  holderPq: encodeMlDsaPublicKey(holderMl.publicKey),
  caveats: GRANT.caveats,
  suite: { alg: HYBRID, mlDsa: principalMl },
});
function pqActn(leafPq: boolean): PCActn {
  const p = actn({ grant: PQ_GRANT });
  if (!leafPq) return p;
  const { sig: _sig, ...body } = p;
  return signPCActnSuite(body as never, { alg: HYBRID, edLeafSecret: A.secretKey, mlDsa: holderMl });
}

describe('assurance: post-quantum vs Ed25519 signatures', () => {
  const run = (p: PCActn, o: Partial<VerifyPCActnOptions> = {}) => verifyPCActn(p, base({ grant: PQ_GRANT, ...o }));

  it('signatureLevel classifies the registry', () => {
    expect([undefined, 'ed25519', 'ml-dsa-65', HYBRID, 'slh-dsa-sha2-128f', 'nope', 7].map(signatureLevel)).toEqual(['ed25519', 'ed25519', 'pq', 'hybrid', 'pq', 'unknown', 'unknown']);
  });

  it('a hybrid chain and hybrid leaf are reported as hybrid and satisfy { signature: pq }', async () => {
    const v = await run(pqActn(true), { requireAssurance: { signature: 'pq' } });
    expect(settle(v)).toEqual({ allow: true, assurance: 'pass', failed: [], why: undefined });
    expect(v.assurance?.leaf_signature).toEqual({ outcome: 'pass', level: 'hybrid', suites: [HYBRID] });
    expect(v.assurance?.cap_chain).toEqual({ outcome: 'pass', level: 'hybrid', suites: [HYBRID] });
  });

  it('an Ed25519 leaf under a PQ root, or an all-Ed25519 proof, never satisfies { signature: pq }', async () => {
    expect(settle(await run(pqActn(false), { requireAssurance: { signature: 'pq' } }))).toEqual({ allow: false, assurance: 'fail', failed: ['assurance'], why: 'assurance: post-quantum signatures required but leaf_signature is ed25519' });
    expect(settle(await verifyPCActn(actn(), base({ requireAssurance: { signature: 'pq' } })))).toEqual({ allow: false, assurance: 'fail', failed: ['assurance'], why: 'assurance: post-quantum signatures required but leaf_signature is ed25519' });
  });

  it('allowUnboundPq voids the PQ label', async () => {
    const v = await run(pqActn(true), { allowUnboundPq: true, requireAssurance: { signature: 'pq' } });
    expect(settle(v)).toEqual({ allow: false, assurance: 'fail', failed: ['assurance'], why: 'assurance: post-quantum signatures required but leaf_signature is unbound_pq' });
  });

  it('an invalid PQ signature yields no level and denies', async () => {
    const p = pqActn(true);
    const v = await run({ ...p, counter: p.counter + 1 }, { requireAssurance: { signature: 'pq' } });
    expect(v.allow).toBe(false);
    expect(v.assurance?.leaf_signature).toEqual({ outcome: 'fail' });
    expect(v.reasons).toContain('assurance: post-quantum signatures required but the leaf_signature check is fail');
  });
});

describe('assurance: threshold multisig vs FROST (preview)', () => {
  const signerSet = [{ role: 'agent' as const, publicKey: HOLDER }];
  const run = (threshold: Hook | undefined, req?: AssuranceRequirement) => verifyPCActn(actn(), base({ hooks: threshold ? { threshold } : {}, ...(req ? { requireAssurance: req } : { assurance: true }) }));

  it('the default scheme is multisig; a declared FROST key is preview', async () => {
    expect((await run(createThresholdVerifier({ signerSet, t: 1 }))).assurance?.threshold).toEqual({ outcome: 'pass', level: 'multisig', t: 1 });
    expect((await run(createThresholdVerifier({ signerSet, t: 1, scheme: 'frost' }))).assurance?.threshold).toEqual({ outcome: 'pass', level: 'frost', preview: true, t: 1 });
    expect(assuranceLabelOf(createThresholdVerifier({ signerSet, t: 1, scheme: 'mpc' }))).toEqual({ level: 'mpc', preview: true });
  });

  it('FROST never satisfies a multisig requirement, and preview denies unless allowed or listed', async () => {
    const frost = createThresholdVerifier({ signerSet, t: 1, scheme: 'frost_dkg' });
    expect(settle(await run(frost, { threshold: ['multisig'] })).why).toBe('assurance: threshold (multisig) required but the scheme is frost_dkg');
    expect(settle(await run(frost, { signature: undefined }))).toEqual({ allow: false, assurance: 'fail', failed: ['assurance'], why: 'assurance: threshold rests on preview crypto (frost_dkg); set allowPreview or list the scheme to accept it' });
    expect(settle(await run(frost, { allowPreview: true }))).toEqual({ allow: true, assurance: 'pass', failed: [], why: undefined });
    expect(settle(await run(frost, { threshold: ['multisig', 'frost_dkg'] }))).toEqual({ allow: true, assurance: 'pass', failed: [], why: undefined });
    expect(settle(await run(createThresholdVerifier({ signerSet, t: 1 }), { threshold: ['multisig'] }))).toEqual({ allow: true, assurance: 'pass', failed: [], why: undefined });
  });

  it('a rejected or absent threshold proof never satisfies a threshold requirement', async () => {
    const rejected = await run(createThresholdVerifier({ signerSet, t: 2 }), { threshold: ['multisig'] });
    expect(rejected.allow).toBe(false);
    expect(rejected.assurance?.threshold).toEqual({ outcome: 'fail' });
    expect(rejected.reasons).toContain('assurance: threshold (multisig) required but the threshold check is fail');
    const none = await run(undefined, { threshold: ['multisig'] });
    expect(none.allow).toBe(false);
    expect(none.checks.assurance).toBe('fail');
    expect(none.assurance?.threshold?.level).toBeUndefined();
  });
});

describe('unsupported: reported, never a pass', () => {
  const bonded = () => actn({ extra: { bond_ref: 'bond-1' } });

  it('a bond is unsupported in the report; without a requirement the decision is unchanged', async () => {
    const v = await verifyPCActn(bonded(), base({ assurance: true, allowUnsupported: ['bond'] }));
    expect(v.allow).toBe(true);
    expect(v.checks.bond).toBe('unsupported'); // 0.5 (B7): a status of its own, never a pass
    expect(v.assurance?.bond).toEqual({ outcome: 'unsupported', reason: 'bond verification is not implemented by this verifier' });
  });

  it('any requirement denies an unsupported feature', async () => {
    expect(settle(await verifyPCActn(bonded(), base({ requireAssurance: {} })))).toEqual({
      allow: false,
      assurance: 'fail',
      failed: ['assurance'],
      why: 'assurance: unsupported: bond (bond verification is not implemented by this verifier); a high-assurance policy never accepts it',
    });
  });

  it('refreshAssurance keeps unsupported and drops the level of a check that stopped passing', () => {
    const r: AssuranceReport = { bond: { outcome: 'unsupported', reason: 'x' }, attestation: { outcome: 'pass', level: 'hardware' }, counter: { outcome: 'pass' } };
    expect(refreshAssurance(r, { bond: 'fail', attestation: 'pass', counter: 'fail', principal: 'pass' })).toEqual({
      bond: { outcome: 'unsupported', reason: 'x' },
      attestation: { outcome: 'pass', level: 'hardware' },
      counter: { outcome: 'fail' },
      principal: { outcome: 'pass' },
    });
  });

  it('unmetAssurance on an empty requirement passes a plain report', () => {
    expect(unmetAssurance(assuranceReport({ checks: { audience: 'pass' } }), {})).toBeUndefined();
  });
});

describe('opt-in: without the new options nothing changes', () => {
  it('verifyPCActn and verifyPCActnCore add no member and no check', async () => {
    const p = actn();
    const v = await verifyPCActn(p, base());
    expect('assurance' in v).toBe(false);
    expect('assurance' in v.checks).toBe(false);
    const c = await verifyPCActnCore(p, { insecureSkipPlanRootCheck: true, grant: GRANT, audience: AUD, nowEpoch: NOW });
    expect(Object.keys(c).sort()).toEqual(['allow', 'checks']);
  });

  it('a verdict that stopped early still reports its outcomes when asked', async () => {
    const v = await verifyPCActn('not a pcactn', base({ assurance: true }));
    expect(v.allow).toBe(false);
    expect(v.assurance).toEqual({ malformed: { outcome: 'fail' } });
  });
});

describe('verifyPCActnCore: assurance and requireAssurance', () => {
  it('reports the attestation level and denies a weaker one', async () => {
    const p = actn();
    const doc = docFor(p);
    const core = (o: object) => verifyPCActnCore(p, { insecureSkipPlanRootCheck: true, grant: GRANT, audience: AUD, nowEpoch: NOW, hooks: { attestation: softHook(() => doc) }, ...o });
    const reported = await core({ assurance: true });
    expect(reported.allow).toBe(true);
    expect(reported.assurance?.attestation).toEqual({ outcome: 'pass', level: 'software' });
    expect(reported.assurance?.leaf_signature).toEqual({ outcome: 'pass', level: 'ed25519', suites: ['ed25519'] });
    const denied = await core({ requireAssurance: { attestation: 'hardware' } });
    expect({ allow: denied.allow, assurance: denied.checks.assurance, reason: denied.reason }).toEqual({
      allow: false,
      assurance: 'fail',
      reason: 'assurance: hardware attestation required but the evidence is software',
    });
    const met = await core({ requireAssurance: { attestation: 'software' } });
    expect({ allow: met.allow, assurance: met.checks.assurance }).toEqual({ allow: true, assurance: 'pass' });
  });
});

// ---- the guards and authorize --------------------------------------------------------------------------------------
const spyStore = (): PcaStateStore & { puts: ReturnType<typeof vi.fn> } => {
  const s = memoryPcaStore();
  const puts = vi.fn((k: string, v: Parameters<PcaStateStore['put']>[1]) => s.put(k, v));
  return { get: (k: string) => s.get(k), put: puts, puts, scope: 'process' };
};

describe('requirePCA: an unmet requirement denies before any state is written', () => {
  it('no replay / budget write on an assurance denial; the report follows the final checks', async () => {
    const p = actn();
    const doc = docFor(p);
    const store = spyStore();
    const guard = (req: AssuranceRequirement) =>
      requirePCA({
        audience: AUD,
        resolveGrant: async () => GRANT,
        budgetStore: store,
        insecureAllowUnboundOperation: true,
        hooks: { revocation: OK, attestation: softHook(() => doc) },
        now: () => NOW,
        context: () => ({ params: {}, plan: NODES, planAuthorized: true, risk: LOW, budget: { B: 1, tau: NOW, asOf: NOW } }),
        requireAssurance: req,
      });
    const denied = await guard({ attestation: 'hardware' })({ headers: {}, body: { pcactn: p } });
    expect({ ok: denied.ok, status: (denied as { status?: number }).status, assurance: denied.verdict.checks.assurance }).toEqual({ ok: false, status: 403, assurance: 'fail' });
    expect(store.puts).not.toHaveBeenCalled();
    const ok = await guard({ attestation: 'software' })({ headers: {}, body: { pcactn: p } });
    expect(ok.ok).toBe(true);
    expect(store.puts).toHaveBeenCalled();
    expect(ok.verdict.assurance?.replay).toEqual({ outcome: 'pass' });
    // the same proof again: the counter now fails, and the report follows it
    const replay = await guard({ attestation: 'software' })({ headers: {}, body: { pcactn: p } });
    expect(replay.ok).toBe(false);
    expect(replay.verdict.assurance?.replay).toEqual({ outcome: 'fail' });
    expect(replay.verdict.assurance?.attestation).toEqual({ outcome: 'pass', level: 'software' });
  });
});

describe('authorize: every result carries assurance; requireAssurance is enforced', () => {
  const op = { verb: 'read', resource: '/acct/1', params: {} };
  const opts = (o: Partial<AuthorizeOptions> = {}): AuthorizeOptions => ({
    provenance: principalDirect(),
    audience: AUD,
    resolveGrant: async () => GRANT,
    budgetStore: memoryPcaStore(),
    hooks: { revocation: OK },
    plan: 'single-step',
    now: () => NOW,
    context: () => ({ risk: LOW, budget: { B: 1, tau: NOW, asOf: NOW } }),
    ...o,
  });

  it('the report is on the result (verdict shape unchanged unless asked)', async () => {
    const r = await authorize({ operation: op, pcactn: actn() }, opts());
    expect(r.allow).toBe(true);
    expect(r.assurance.leaf_signature).toEqual({ outcome: 'pass', level: 'ed25519', suites: ['ed25519'] });
    expect(r.assurance.replay).toEqual({ outcome: 'pass' });
    expect('assurance' in r.verdict).toBe(false);
    const asked = await authorize({ operation: op, pcactn: actn() }, opts({ assurance: true }));
    expect(asked.verdict.assurance).toEqual(asked.assurance);
  });

  it('a refusal before verification reports its check', async () => {
    const r = await authorize({ operation: op, pcactn: actn() }, opts({ budgetStore: undefined as never }));
    expect(r.allow).toBe(false);
    expect(r.assurance).toEqual({ authorize_config: { outcome: 'fail' } });
  });

  it('software attestation never satisfies a hardware requirement through authorize; hardware does', async () => {
    const p = actn();
    const doc = docFor(p);
    const soft = await authorize({ operation: op, pcactn: p }, opts({ hooks: { revocation: OK, attestation: softHook(() => doc) }, requireAssurance: { attestation: 'hardware' } }));
    expect(soft.allow).toBe(false);
    expect((soft as { reason: string }).reason).toBe('assurance: hardware attestation required but the evidence is software');
    const hw = await authorize({ operation: op, pcactn: p }, opts({ hooks: { revocation: OK, attestation: hwHook(hwOk({ level: 'hardware' }), () => doc) }, requireAssurance: { attestation: 'hardware' } }));
    expect(hw.allow).toBe(true);
    expect(hw.assurance.attestation).toEqual({ outcome: 'pass', level: 'hardware' });
  });

  it('authorizeExecution forwards requireAssurance and returns the report', async () => {
    const run = (req?: AssuranceRequirement) =>
      authorizeExecution(actn(), { verb: 'read', resource: '/acct/1', params: {} }, { provenance: principalDirect(), audience: AUD, grant: GRANT, state: memoryPcaStore(), isRevoked: () => false, now: () => NOW, risk: () => LOW, ...(req ? { requireAssurance: req } : {}) });
    const ok = await run();
    expect(ok.allow).toBe(true);
    expect(ok.assurance?.leaf_signature).toEqual({ outcome: 'pass', level: 'ed25519', suites: ['ed25519'] });
    const denied = await run({ signature: 'pq' });
    expect({ allow: denied.allow, kind: (denied as { kind?: string }).kind, reason: (denied as { reason?: string }).reason }).toEqual({
      allow: false,
      kind: 'policy',
      reason: 'assurance: post-quantum signatures required but leaf_signature is ed25519',
    });
  });
});
