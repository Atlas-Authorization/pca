// RT-07 regression: the Policy-VM Groth16 verifier must let the caller pin the public context
// (now, recentCount, blast, delegationDepth, allocChild, r, t, admit). A proof is valid for whatever
// context the prover chose unless the verifier says what it expects. PoC:
// proof-of-concept from the red-team round (not published)
import { readFileSync } from 'node:fs';
import { beforeAll, describe, expect, it } from 'vitest';
import { useSingleThreadSnarkCurvesInWorkerThreads } from './test-support/snarkjs-single-thread';
import {
  POLICYVM_PUBLIC_SIGNAL,
  POLICYVM_SAMPLE_PROOF_PATH,
  POLICYVM_VKEY_PATH,
  createPolicyVmSnarkBackend,
  policyVmContextMatches,
  verifyPolicyVmProof,
  type PolicyVmComplianceProof,
} from './zk';

// snarkjs single-threaded when this file runs in a worker thread (Stryker's vitest runner): see test-support/snarkjs-single-thread.ts
beforeAll(useSingleThreadSnarkCurvesInWorkerThreads);

const vkey = JSON.parse(readFileSync(POLICYVM_VKEY_PATH(), 'utf8')) as object;
const sample = JSON.parse(readFileSync(POLICYVM_SAMPLE_PROOF_PATH(), 'utf8')) as PolicyVmComplianceProof;
// sample context: now=1000000000 blast=0 delegationDepth=0 recentCount=0 allocChild=500000 r=0 t=1 admit=1

describe('RT-07 Policy-VM public-context pinning', () => {
  it('unpinned verification still accepts the sample (backward compatible)', async () => {
    expect(await verifyPolicyVmProof(sample, { verificationKey: vkey })).toBe(true);
  });

  it('the sample is rejected when the verifier clock is not the proof now (the PoC)', async () => {
    const wallClock = 1_790_000_000_000;
    expect(await verifyPolicyVmProof(sample, { verificationKey: vkey, expect: { now: wallClock } })).toBe(false);
    expect(
      await verifyPolicyVmProof(sample, { verificationKey: vkey, expect: { now: { min: wallClock - 60_000, max: wallClock + 60_000 } } }),
    ).toBe(false);
  });

  it('accepts exact and window pins that match', async () => {
    const o = (e: object) => verifyPolicyVmProof(sample, { verificationKey: vkey, expect: e });
    expect(await o({ now: 1_000_000_000 })).toBe(true);
    expect(await o({ now: '1000000000', recentCount: 0n, blast: 0, delegationDepth: 0, allocChild: 500000, r: 0, t: 1 })).toBe(true);
    expect(await o({ now: { min: 999_999_000, max: 1_000_001_000 } })).toBe(true);
    expect(await o({ requireAdmit: true, requireTier1: true })).toBe(true);
  });

  it('rejects each mismatched pin', async () => {
    const o = (e: object) => verifyPolicyVmProof(sample, { verificationKey: vkey, expect: e });
    expect(await o({ recentCount: 5 })).toBe(false);
    expect(await o({ blast: 1 })).toBe(false);
    expect(await o({ delegationDepth: 1 })).toBe(false);
    expect(await o({ allocChild: 500001 })).toBe(false);
    expect(await o({ r: 1 })).toBe(false);
    expect(await o({ t: 2 })).toBe(false);
    expect(await o({ now: { min: 5, max: 1 } })).toBe(false); // inverted window
    expect(await o({ now: 1.5 })).toBe(false); // not an integer pin
    expect(await o({ now: 'abc' })).toBe(false);
  });

  it('a throwing expectation provider fails closed; a function provider tracks a live clock', async () => {
    expect(await verifyPolicyVmProof(sample, { verificationKey: vkey, expect: () => { throw new Error('x'); } })).toBe(false);
    let clock = 1_000_000_000;
    const opts = { verificationKey: vkey, expect: () => ({ now: { min: clock - 10, max: clock + 10 } }) };
    expect(await verifyPolicyVmProof(sample, opts)).toBe(true);
    clock = 2_000_000_000;
    expect(await verifyPolicyVmProof(sample, opts)).toBe(false);
  });

  it('requireAdmit / requireTier1 reject non-admitted and higher-tier signals', () => {
    const ps = [...sample.publicSignals];
    ps[POLICYVM_PUBLIC_SIGNAL.admit] = '0';
    expect(policyVmContextMatches(ps, { requireAdmit: true })).toBe(false);
    expect(policyVmContextMatches(ps, {})).toBe(true);
    const ps2 = [...sample.publicSignals];
    ps2[POLICYVM_PUBLIC_SIGNAL.t] = '2';
    expect(policyVmContextMatches(ps2, { requireTier1: true })).toBe(false);
  });

  it('a field-negative / oversized context signal is rejected even with no pins', () => {
    const P = POLICYVM_PUBLIC_SIGNAL;
    const bn254R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    for (const idx of [P.now, P.blast, P.delegationDepth, P.recentCount, P.allocChild]) {
      const ps = [...sample.publicSignals];
      ps[idx] = (bn254R - 5n).toString(); // "now = -5" in the field
      expect(policyVmContextMatches(ps)).toBe(false);
      ps[idx] = (1n << 64n).toString();
      expect(policyVmContextMatches(ps)).toBe(false);
      ps[idx] = '007';
      expect(policyVmContextMatches(ps)).toBe(false);
    }
    expect(policyVmContextMatches([...sample.publicSignals])).toBe(true);
  });

  it('the SnarkBackend honours the pins (the previously-impossible case)', async () => {
    const good = createPolicyVmSnarkBackend({ verificationKey: vkey, expect: { now: { min: 999_999_000, max: 1_000_001_000 }, recentCount: 0, requireAdmit: true } });
    const stale = createPolicyVmSnarkBackend({ verificationKey: vkey, expect: () => ({ now: 1_790_000_000_000 }) });
    const arg = { proof: sample } as unknown as Parameters<typeof good.verify>[0];
    expect(await good.verify(arg)).toBe(true);
    expect(await stale.verify(arg)).toBe(false);
  });
});
