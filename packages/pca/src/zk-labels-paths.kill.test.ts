/**
 * zk.ts: ceremony circuit ids per backend, assurance labels with partial pins, v2 prover plumbing and paths, and the
 * attested-VM configuration / hardware-evidence refusals. snarkjs is replaced by a recording fake.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const h = vi.hoisted(() => {
  const st = { calls: [] as Array<{ fn: string; args: unknown[] }> };
  const api = {
    verify: async (...args: unknown[]) => {
      st.calls.push({ fn: 'verify', args });
      return true;
    },
    fullProve: async (...args: unknown[]) => {
      st.calls.push({ fn: 'fullProve', args });
      return { proof: { p: 7 }, publicSignals: ['4'] };
    },
  };
  return { st, api };
});
vi.mock('snarkjs', () => ({ groth16: h.api }));

import { assuranceLabelOf, setAssuranceLabel } from './assurance';
import type { HardwareAttestationResult, HardwareAttestationVerifier } from './attestation';
import { mintGrant } from './envelope';
import { encodeKey, generateKeyPair } from './keys';
import { buildPCActn, type PCActn, type VerifyContext } from './pcactn';
import { type DecideInput } from './policy-vm';
import { DEFAULT_RISK_POLICY, type TrustBudget } from './risk';
import type { Capability } from './capability';
import type { PlanNode } from './merkle';
import { transcriptSha256, vkId, type CeremonyTranscript } from './zk-ceremony';
import {
  POLICYVM_BOUND_PUBLIC_SIGNAL,
  POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT,
  POLICYVM_BOUND_SAMPLE_PROOF_PATH,
  POLICYVM_BOUND_VKEY_PATH,
  POLICYVM_BOUND_WASM_PATH,
  POLICYVM_BOUND_ZKEY_PATH,
  createAttestedComplianceProver,
  createGroth16SnarkBackend,
  createPolicyVmBoundSnarkBackend,
  createPolicyVmSnarkBackend,
  createPolicyVmSnarkBackendBls12381,
  createZkVerifier,
  policyCommitment,
  provePolicyVmBoundCompliance,
} from './zk';

const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const ctx0 = {} as VerifyContext;
beforeEach(() => {
  h.st.calls = [];
});

// ---- ceremony evidence is checked against each backend's own circuit id ------------------------------------------------
const VK = { protocol: 'groth16', curve: 'bn128', nPublic: 1 };
const evidenceFor = (circuit: string) => {
  const t: CeremonyTranscript = {
    version: 1, circuit, curve: 'bn128', r1csSha256: sha('r'), ptauSha256: sha('p'), initZkeySha256: sha('z0'), minContributions: 2,
    contributions: [
      { index: 0, name: 'alice', prevZkeySha256: sha('z0'), zkeySha256: sha('z1') },
      { index: 1, name: 'bob', prevZkeySha256: sha('z1'), zkeySha256: sha('z2') },
    ],
    beacon: { hashHex: sha('block'), iterationsExp: 10, prevZkeySha256: sha('z2'), zkeySha256: sha('zf') },
    finalZkeySha256: sha('zf'), vkId: vkId(VK),
  };
  return { transcript: t, sha256: transcriptSha256(t) };
};

describe('ceremony label per circuit', () => {
  it('the compliance backend accepts a pca-compliance-v1 transcript', () => {
    expect(assuranceLabelOf(createGroth16SnarkBackend({ verificationKey: VK, ceremony: evidenceFor('pca-compliance-v1') }))).toEqual({ level: 'groth16', ceremony: 'multi-party' });
  });
  it('the risk-bound backend accepts a pca-policyvm-v2 transcript', () => {
    expect(assuranceLabelOf(createPolicyVmBoundSnarkBackend({ verificationKey: VK, ceremony: evidenceFor('pca-policyvm-v2') }))).toEqual({ level: 'unknown', vendor: 'policyvm-unbound', ceremony: 'multi-party' });
  });
});

describe('Policy-VM label needs all three struct-hash pins', () => {
  const d = { hi: '1', lo: '2' };
  const unbound = { level: 'unknown', vendor: 'policyvm-unbound', ceremony: 'single-party' };
  it.each([
    ['plan only', { expectPlanHash: d }],
    ['action + plan', { expectActionHash: d, expectPlanHash: d }],
    ['policy + plan', { expectPolicyHash: d, expectPlanHash: d }],
  ])('%s is unbound', (_n, pins) => {
    expect(assuranceLabelOf(createPolicyVmSnarkBackend(pins))).toEqual(unbound);
  });
  it('all three is policyvm_snark', () => {
    expect(assuranceLabelOf(createPolicyVmSnarkBackend({ expectActionHash: d, expectPolicyHash: d, expectPlanHash: d }))).toEqual({ level: 'policyvm_snark', ceremony: 'single-party' });
  });
});

// ---- v2 envelope through the BLS12-381 backend (it only takes pca-policyvm-v1) -----------------------------------------
const v1 = JSON.parse(readFileSync(`${__dirname}/../circuits/policyvm_sample_proof.json`, 'utf8')) as { proof: object };
function v2Env() {
  const vals: Record<string, string> = {
    actionHi: '11', actionLo: '12', policyHi: '21', policyLo: '22', planHi: '31', planLo: '32',
    r: '65000', t: '1', admit: '1', riskHi: '41', riskLo: '42',
    allow: '1', now: '1000000000', blast: '0', delegationDepth: '0', recentCount: '0', allocChild: '500000',
  };
  const ps = new Array<string>(POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT);
  for (const [k, i] of Object.entries(POLICYVM_BOUND_PUBLIC_SIGNAL)) ps[i] = vals[k]!;
  return { system: 'groth16-bn254', circuit: 'pca-policyvm-v2', proof: JSON.parse(JSON.stringify(v1.proof)) as object, publicSignals: ps };
}

describe('BLS12-381 Policy-VM backend refuses a risk-bound envelope', () => {
  it('false without reaching snarkjs (the bound backend accepts the same envelope)', async () => {
    const bls = createPolicyVmSnarkBackendBls12381({ verificationKey: { k: 1 } });
    expect(await bls.verify({ proof: v2Env(), publicInputs: { action_commit: '', policy_commit: '', plan_commit: '' }, ctx: ctx0 })).toBe(false);
    expect(h.st.calls).toEqual([]);
    const bound = createPolicyVmBoundSnarkBackend({ verificationKey: { k: 1 } });
    expect(await bound.verify({ proof: v2Env(), publicInputs: { action_commit: '', policy_commit: '', plan_commit: '' }, ctx: ctx0 })).toBe(true);
    expect(h.st.calls).toHaveLength(1);
  });
});

// ---- v2 prover -------------------------------------------------------------------------------------------------------
describe('provePolicyVmBoundCompliance', () => {
  it('stringifies the witness, uses the dev-setup fixtures by default and returns the v2 envelope', async () => {
    const out = await provePolicyVmBoundCompliance({ a: 1, b: 2n, c: 'x' });
    expect(out).toEqual({ system: 'groth16-bn254', circuit: 'pca-policyvm-v2', proof: { p: 7 }, publicSignals: ['4'] });
    expect(h.st.calls).toHaveLength(1);
    const [input, wasm, zkey] = h.st.calls[0]!.args as [unknown, string, string];
    expect(input).toEqual({ a: '1', b: '2', c: 'x' });
    expect(wasm.endsWith('/src/../circuits/build/policyvm_bound_js/policyvm_bound.wasm')).toBe(true);
    expect(zkey.endsWith('/src/../circuits/build/policyvm_bound_final.zkey')).toBe(true);
  });
  it('explicit fixture paths win', async () => {
    await provePolicyVmBoundCompliance({}, { wasmPath: '/w.wasm', zkeyPath: '/k.zkey' });
    expect(h.st.calls[0]!.args).toEqual([{}, '/w.wasm', '/k.zkey']);
  });
  it('the v2 fixture paths are the documented locations', () => {
    expect(POLICYVM_BOUND_SAMPLE_PROOF_PATH().endsWith('/src/../circuits/build/policyvm_bound_sample_proof.json')).toBe(true);
    expect(POLICYVM_BOUND_WASM_PATH().endsWith('/src/../circuits/build/policyvm_bound_js/policyvm_bound.wasm')).toBe(true);
    expect(POLICYVM_BOUND_ZKEY_PATH().endsWith('/src/../circuits/build/policyvm_bound_final.zkey')).toBe(true);
    expect(POLICYVM_BOUND_VKEY_PATH().endsWith('/src/../circuits/build/policyvm_bound_vkey.json')).toBe(true);
  });
});

// ---- attested-VM mode --------------------------------------------------------------------------------------------------
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
const hwDouble = (over: Partial<HardwareAttestationResult> = {}): HardwareAttestationVerifier =>
  setAssuranceLabel({
    verify: (): HardwareAttestationResult => ({ ok: true, bound: true, measured: { model_id: 'm', weights_digest: 'w', runtime_measurement: MEAS, operator: 'o' }, ...over }),
  }, { level: 'hardware', vendor: 'amd-sev-snp' }) as never;
const deny = (reason: string) => ({ enforced: true, ok: false, reason });

describe('attested-VM configuration and evidence', () => {
  const cfg = (measurements: unknown) => () =>
    createZkVerifier({ trustedProverKeys: [], proverAttestation: { hardwareVerifier: hwDouble(), expectedBinding: () => ({}) as never, measurements: measurements as string[] } });
  const MSG = 'createZkVerifier: proverAttestation.measurements must be a non-empty allowlist';
  it('every allowlist entry must be a non-empty string', () => {
    expect(cfg([MEAS, ''])).toThrow(new TypeError(MSG));
    expect(cfg([MEAS, 5])).toThrow(new TypeError(MSG));
    expect(cfg([5])).toThrow(new TypeError(MSG));
    expect(cfg([MEAS])).not.toThrow();
  });

  it('a measured identity that is not a string is "no measured identity", not "not allowlisted"', async () => {
    const prover = createAttestedComplianceProver(generateKeyPair().secretKey);
    const p = actn();
    p.zk_compliance = prover.prove({ pcactn: p, decideInput: decideInputFor(p), issued_at: NOW - 1000, expires_at: NOW + 60_000 });
    const z = createZkVerifier({
      trustedProverKeys: [prover.publicKey], policyCommitments: [policyCommitment(GRANT)], now: () => NOW,
      proverAttestation: { hardwareVerifier: hwDouble({ measured: { model_id: 'm', weights_digest: 'w', runtime_measurement: 5 as unknown as string, operator: 'o' } }), expectedBinding: () => ({}) as never, measurements: [MEAS] },
    });
    expect(await z({ pcactn: p, grant: GRANT })).toEqual(deny('prover hardware evidence carries no measured identity'));
  });

  it('without a revocation list nothing is revoked, whatever the trusted key is called', async () => {
    const odd = ['Stry', 'ker was here'].join('');
    const p = actn();
    p.zk_compliance = { v: 1, mode: 'attested-vm', released: true, prover: odd, sig: 'x' } as never;
    const z = createZkVerifier({ trustedProverKeys: [odd], now: () => NOW });
    expect(await z({ pcactn: p, grant: GRANT })).toEqual(deny('compliance statement signature does not verify'));
  });
});
