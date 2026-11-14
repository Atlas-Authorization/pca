/**
 * Attested-VM compliance mode with the prover key bound to hardware evidence (0.5).
 * The hardware verifier here is a labelled double that behaves like a vendor verifier: it accepts only a quote whose
 * report_data binds the prover key it was enrolled with. The real SEV-SNP verifier is exercised with recorded Genoa
 * evidence at the end (a real quote that binds some other key must not vouch for this prover).
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { type ComplianceStatement, createAttestedComplianceProver, createZkVerifier, policyCommitment, proverKeyBinding } from './zk';
import { assuranceLabelOf, assuranceReport, setAssuranceLabel, unmetAssurance } from './assurance';
import { attestationBindingB64u, type ExpectedAttestationBinding, type HardwareAttestationResult, type HardwareAttestationVerifier } from './attestation';
import { createAmdSnpVerifier, pemToDer, type AmdSnpEvidence } from './attest-amd-snp';
import { parseSevSnpReport, toHex } from './hardware-sevsnp';
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
  principalSecret: P.secretKey,
  principalPublic: encodeKey(P.publicKey),
  holder: encodeKey(A.publicKey),
  goal: 'secure my account',
  envelope: { predicates: [{ verb: 'revoke_session', resource: '/acct/*' }], caveats: [{ type: 'expires', at: 9e12 }], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
}).grant;
const NODES: PlanNode[] = [{ id: 'n1', verb: 'revoke_session', resource: '/acct/1/s', reversibility_class: 'reversible' }];
const actn = (): PCActn => buildPCActn({ aud: 'a', grant: GRANT, chain: [GRANT], plan: NODES, nodeId: 'n1', counter: 1, signerSecret: A.secretKey });
const decideInputFor = (p: PCActn): DecideInput => ({
  grant: GRANT, chain: [GRANT],
  action: { action: { verb: p.action.verb, resource: p.action.resource, params: {}, reversibility_class: p.action.reversibility_class } },
  plan: NODES, risk: { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 },
  budget: fresh, now: NOW, nodeId: p.plan.node_id,
});

const MEAS = 'aa'.repeat(48);
const EPOCH = 7;
const NONCE = 'srv-prover-nonce-0123456789abcdef';
const prover = createAttestedComplianceProver(generateKeyPair().secretKey);
const signed = (): PCActn => {
  const p = actn();
  p.zk_compliance = prover.prove({ pcactn: p, decideInput: decideInputFor(p), issued_at: NOW - 1000, expires_at: NOW + 60_000 });
  return p;
};

/** A labelled double: accepts only a quote bound to `enrolledKey`, reporting `result` otherwise-ok fields. */
function hw(enrolledKey: string, over: Partial<HardwareAttestationResult> = {}, label: { level: string; vendor?: string } | null = { level: 'hardware', vendor: 'amd-sev-snp' }): HardwareAttestationVerifier & { calls: ExpectedAttestationBinding[]; stubs: unknown[] } {
  const calls: ExpectedAttestationBinding[] = [];
  const stubs: unknown[] = [];
  const v = {
    calls, stubs,
    verify({ expected, document }: { expected: ExpectedAttestationBinding; document: unknown }): HardwareAttestationResult {
      calls.push(expected); stubs.push(document);
      if (attestationBindingB64u(expected) !== attestationBindingB64u(proverKeyBinding(enrolledKey, EPOCH, NONCE))) return { ok: false, reason: 'report_data does not bind the expected value' };
      return { ok: true, bound: true, measured: { model_id: 'm', weights_digest: 'w', runtime_measurement: MEAS, operator: 'o' }, ...over };
    },
  };
  return (label ? setAssuranceLabel(v, label) : v) as never;
}
const zk = (verifier: HardwareAttestationVerifier, extra: Record<string, unknown> = {}) =>
  createZkVerifier({
    trustedProverKeys: [prover.publicKey], policyCommitments: [policyCommitment(GRANT)], now: () => NOW,
    proverAttestation: { hardwareVerifier: verifier, expectedBinding: (k) => proverKeyBinding(k, EPOCH, NONCE), measurements: [MEAS] },
    ...extra,
  });
const OK = { enforced: true, ok: true };
const deny = (reason: string) => ({ enforced: true, ok: false, reason });

describe('attested-VM mode bound to hardware evidence', () => {
  it('passes when the quote binds the prover key and the measurement is allowlisted; the verifier gets the prover key', async () => {
    const v = hw(prover.publicKey);
    expect(await zk(v)({ pcactn: signed(), grant: GRANT })).toEqual(OK);
    expect(v.calls).toEqual([{ holderPub: prover.publicKey, grantRef: 'atlas-pca/zk-prover/v1', epoch: EPOCH, nonce: NONCE }]);
    expect(v.stubs).toEqual([{ attestor: prover.publicKey, mode: 'hardware' }]);
  });

  it('the label is attested_vm_hw with the hardware vendor; without proverAttestation it stays attested_vm', () => {
    expect(assuranceLabelOf(zk(hw(prover.publicKey)))).toEqual({ level: 'attested_vm_hw', vendor: 'hardware-bound:amd-sev-snp' });
    expect(assuranceLabelOf(zk(hw(prover.publicKey, {}, { level: 'multi_root' })))).toEqual({ level: 'attested_vm_hw', vendor: 'hardware-bound:multi_root' });
    expect(assuranceLabelOf(createZkVerifier({ trustedProverKeys: [prover.publicKey], now: () => NOW }))).toEqual({ level: 'attested_vm' });
  });

  it.each([
    ['a quote that binds another key', hw(generateKeyPair().publicKey.toString()), 'prover hardware evidence invalid: report_data does not bind the expected value'],
    ['an invalid quote', hw(prover.publicKey, { ok: false, reason: 'cert chain invalid' }), 'prover hardware evidence invalid: cert chain invalid'],
    ['an invalid quote with no reason', hw(prover.publicKey, { ok: false }), 'prover hardware evidence invalid: no reason given'],
    ['a valid quote that is not reported bound', hw(prover.publicKey, { bound: false }), 'prover hardware evidence does not bind the prover key'],
    ['a valid quote with bound omitted', hw(prover.publicKey, { bound: undefined }), 'prover hardware evidence does not bind the prover key'],
    ['no measured identity', hw(prover.publicKey, { measured: undefined }), 'prover hardware evidence carries no measured identity'],
    ['a non-allowlisted VM measurement', hw(prover.publicKey, { measured: { model_id: 'm', weights_digest: 'w', runtime_measurement: 'bb'.repeat(48), operator: 'o' } }), 'prover VM measurement is not allowlisted'],
  ])('denies %s', async (_n, v, reason) => {
    expect(await zk(v)({ pcactn: signed(), grant: GRANT })).toEqual(deny(reason));
  });

  it('denies when the verifier throws or resolves nothing (fail closed)', async () => {
    const boom = setAssuranceLabel({ verify: () => { throw new Error('collateral fetch failed'); } }, { level: 'hardware' });
    expect(await zk(boom as never)({ pcactn: signed(), grant: GRANT })).toEqual(deny('zk verification error (fail closed): collateral fetch failed'));
    const none = setAssuranceLabel({ verify: () => undefined }, { level: 'hardware' });
    expect(await zk(none as never)({ pcactn: signed(), grant: GRANT })).toEqual(deny('prover hardware evidence invalid: no result'));
    expect(await zk(hw(prover.publicKey), { proverAttestation: { hardwareVerifier: hw(prover.publicKey), expectedBinding: () => { throw new Error('no nonce'); }, measurements: [MEAS] } })({ pcactn: signed(), grant: GRANT })).toEqual(deny('zk verification error (fail closed): no nonce'));
  });

  it('refuses a software, unlabelled or missing-label hardware verifier, and an empty measurement allowlist, at construction', () => {
    const base = { trustedProverKeys: [prover.publicKey], now: () => NOW };
    const pa = (hardwareVerifier: HardwareAttestationVerifier, measurements: string[] = [MEAS]) => ({ hardwareVerifier, expectedBinding: (k: string) => proverKeyBinding(k, EPOCH, NONCE), measurements });
    for (const v of [hw(prover.publicKey, {}, { level: 'software' }), hw(prover.publicKey, {}, null), hw(prover.publicKey, {}, { level: 'unknown' })]) {
      expect(() => createZkVerifier({ ...base, proverAttestation: pa(v) })).toThrow('proverAttestation.hardwareVerifier must carry a hardware or multi_root assurance label');
    }
    expect(() => createZkVerifier({ ...base, proverAttestation: pa(hw(prover.publicKey), []) })).toThrow('proverAttestation.measurements must be a non-empty allowlist');
    expect(() => createZkVerifier({ ...base, proverAttestation: pa(hw(prover.publicKey), ['']) })).toThrow('proverAttestation.measurements must be a non-empty allowlist');
    expect(() => createZkVerifier({ ...base, proverAttestation: { ...pa(hw(prover.publicKey)), expectedBinding: undefined as never } })).toThrow('proverAttestation.expectedBinding must be a function');
  });

  it('the measurement allowlist is snapshotted: emptying the caller array afterwards does not accept-all', async () => {
    const measurements = ['bb'.repeat(48)];
    const v = zk(hw(prover.publicKey), { proverAttestation: { hardwareVerifier: hw(prover.publicKey), expectedBinding: (k: string) => proverKeyBinding(k, EPOCH, NONCE), measurements } });
    measurements.length = 0;
    expect(await v({ pcactn: signed(), grant: GRANT })).toEqual(deny('prover VM measurement is not allowlisted'));
  });
});

describe('prover key revocation, rotation and statement freshness', () => {
  it('a revoked prover key is denied even while still listed as trusted; the replacement key passes', async () => {
    const next = createAttestedComplianceProver(generateKeyPair().secretKey);
    const trustedProverKeys = [prover.publicKey, next.publicKey];
    const mk = (revokedProverKeys: string[]) => createZkVerifier({ trustedProverKeys, revokedProverKeys, policyCommitments: [policyCommitment(GRANT)], now: () => NOW });
    expect(await mk([prover.publicKey])({ pcactn: signed(), grant: GRANT })).toEqual(deny('prover key is revoked'));
    const p = actn();
    p.zk_compliance = next.prove({ pcactn: p, decideInput: decideInputFor(p), issued_at: NOW - 1000, expires_at: NOW + 60_000 });
    expect(await mk([prover.publicKey])({ pcactn: p, grant: GRANT })).toEqual(OK);
    expect(await mk([])({ pcactn: signed(), grant: GRANT })).toEqual(OK);
  });

  it('a revoked set that is not an array revokes nothing but does not widen trust', async () => {
    const v = createZkVerifier({ trustedProverKeys: [], revokedProverKeys: 'x' as never, policyCommitments: [policyCommitment(GRANT)], now: () => NOW });
    expect(await v({ pcactn: signed(), grant: GRANT })).toEqual(deny('prover key is not trusted'));
  });

  it('a statement is bound to its action, plan and policy and to its validity window (replay)', async () => {
    const v = zk(hw(prover.publicKey));
    const p = signed();
    // replay on another action
    expect(await v({ pcactn: { ...p, action: { ...p.action, resource: '/acct/2/s' } }, grant: GRANT })).toEqual(deny('statement does not bind to this action'));
    // replay on another plan root
    expect(await v({ pcactn: { ...p, plan: { ...p.plan, root: 'other-root' } }, grant: GRANT })).toEqual(deny('statement does not bind to this plan commitment'));
    // expired / not yet valid
    expect(await createZkVerifier({ trustedProverKeys: [prover.publicKey], now: () => NOW + 60_001 })({ pcactn: p, grant: GRANT })).toEqual(deny('compliance statement expired'));
    expect(await createZkVerifier({ trustedProverKeys: [prover.publicKey], now: () => NOW - 1001 })({ pcactn: p, grant: GRANT })).toEqual(deny('compliance statement not yet valid'));
    // a body field edited after signing
    expect(await v({ pcactn: { ...p, zk_compliance: { ...(p.zk_compliance as ComplianceStatement), expires_at: NOW + 9e9 } }, grant: GRANT })).toEqual(deny('compliance statement signature does not verify'));
  });

  it('hardware evidence is not consulted for a statement that already fails (no expensive call on a bad statement)', async () => {
    const v = hw(prover.publicKey);
    const p = signed();
    await zk(v)({ pcactn: { ...p, action: { ...p.action, resource: '/x' } }, grant: GRANT });
    expect(v.calls).toEqual([]);
  });
});

describe('assurance requirement { zk: attested_vm_hardware }', () => {
  const rep = (level?: string) => assuranceReport({ checks: { zk_compliance: 'pass' }, hooks: { zk: level ? setAssuranceLabel(() => ({}), { level }) : (() => ({})) } });
  const req = { zk: 'attested_vm_hardware' } as const;
  it('is met by a hardware-bound statement and by real proofs; not by an unbound statement or an unlabelled hook', () => {
    expect(unmetAssurance(rep('attested_vm_hw'), req)).toBeUndefined();
    expect(unmetAssurance(rep('groth16'), req)).toBeUndefined();
    expect(unmetAssurance(rep('attested_vm'), req)).toBe('assurance: zk compliance (attested_vm_hardware) required but the prover key is not bound to hardware evidence');
    expect(unmetAssurance(rep(), req)).toBe('assurance: zk compliance (attested_vm_hardware) required but the prover key is not bound to hardware evidence');
  });
  it('a hardware-bound statement still does not satisfy { zk: proof } or { zk: snark }', () => {
    expect(unmetAssurance(rep('attested_vm_hw'), { zk: 'proof' })).toBe('assurance: zk compliance (proof) required but the evidence is attested_vm_hw');
    expect(unmetAssurance(rep('attested_vm_hw'), { zk: 'snark' })).toBe('assurance: zk compliance (snark) required but the evidence is attested_vm_hw');
    expect(unmetAssurance(rep('attested_vm_hw'), { zk: 'attested_vm' })).toBeUndefined();
  });
  it('a missing or failed zk check never meets it', () => {
    expect(unmetAssurance(assuranceReport({ checks: {} }), req)).toBe('assurance: zk compliance (attested_vm_hardware) required but there is no zk_compliance evidence');
    expect(unmetAssurance(assuranceReport({ checks: { zk_compliance: 'fail' } }), req)).toBe('assurance: zk compliance (attested_vm_hardware) required but the zk_compliance check is fail');
  });
});

describe('with the real SEV-SNP verifier and recorded Genoa evidence', () => {
  const fx = (f: string) => readFileSync(resolve(__dirname, '..', 'fixtures', 'real-azure-maa', f));
  const HCL = new Uint8Array(fx('sevsnp-hcl-report.bin'));
  const REPORT = HCL.slice(32, 32 + 1184);
  const AMD = JSON.parse(fx('sevsnp-amd-certs.json').toString('utf8')) as { vcekCert: string; certificateChain: string };
  const EVIDENCE: AmdSnpEvidence = { report: REPORT, vcekDer: pemToDer(AMD.vcekCert), askArkPem: AMD.certificateChain, runtimeData: new Uint8Array(fx('sevsnp-runtime-data.json')) };
  const SNP_MEAS = toHex(parseSevSnpReport(REPORT).measurement);
  const RECORDED: ExpectedAttestationBinding = { holderPub: 'pca-realsilicon-azure-tdx-holder', grantRef: 'grant_pca_azure_maa_realsilicon', epoch: 1, nonce: 'srv-nonce-maa-5d3b8e1f9a27c604' };
  const snp = () => createAmdSnpVerifier({ family: 'genoa', binding: 'azure-runtime-data', policy: { measurements: [SNP_MEAS] }, resolveEvidence: () => EVIDENCE });
  const cfg = (expectedBinding: (k: string) => ExpectedAttestationBinding) => zk(snp(), { now: () => Date.parse('2026-10-09T00:30:00Z'), proverAttestation: { hardwareVerifier: snp(), expectedBinding, measurements: [SNP_MEAS] } });
  const stmtAt = (): PCActn => {
    const p = actn();
    p.zk_compliance = prover.prove({ pcactn: p, decideInput: decideInputFor(p), issued_at: Date.parse('2026-10-09T00:29:00Z'), expires_at: Date.parse('2026-10-09T01:00:00Z') });
    return p;
  };

  it('a genuine quote that binds some other key does NOT vouch for this prover', async () => {
    const r = await cfg((k) => proverKeyBinding(k, EPOCH, NONCE))({ pcactn: stmtAt(), grant: GRANT });
    expect(r).toMatchObject({ enforced: true, ok: false });
    expect((r as { reason: string }).reason).toContain('prover hardware evidence invalid: ');
    expect((r as { reason: string }).reason).toContain('does not bind');
  });

  it('the same verifier accepts when the expected binding is the one the recorded quote carries (wiring check)', async () => {
    expect(await cfg(() => RECORDED)({ pcactn: stmtAt(), grant: GRANT })).toEqual(OK);
  });

  it('an allowlist that omits the recorded VM measurement denies', async () => {
    const v = cfg(() => RECORDED);
    const c = createZkVerifier({ trustedProverKeys: [prover.publicKey], now: () => Date.parse('2026-10-09T00:30:00Z'), proverAttestation: { hardwareVerifier: snp(), expectedBinding: () => RECORDED, measurements: ['cc'.repeat(48)] } });
    expect(await v({ pcactn: stmtAt(), grant: GRANT })).toEqual(OK);
    expect(await c({ pcactn: stmtAt(), grant: GRANT })).toEqual(deny('prover VM measurement is not allowlisted'));
  });
});
