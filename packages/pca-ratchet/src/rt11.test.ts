import { describe, expect, it } from 'vitest';
import { b64u, generateKeyPair } from '@atlasauth/pca';
import {
  RISK_SCALE,
  RiskQuantizer,
  addCommitments,
  budgetCeilingUnits,
  commitRisk,
  deriveRatchetRoot,
  issueRiskCommitment,
  leafNullifier,
  memorySpentLeafStore,
  proveBudget,
  riskToUnits,
  signAtLeaf,
  verifyAttestedBudget,
  verifyBudget,
  verifyLeafSignature,
  verifyLeafSignatureOnce,
  verifyRiskAttestation,
} from './index';

const enc = (s: string) => new TextEncoder().encode(s);

describe('RT-11 reuse detection', () => {
  const { rootCommitment, state } = deriveRatchetRoot(crypto.getRandomValues(new Uint8Array(32)), 3);
  it('signature carries the leaf nullifier and a forged one fails verification', () => {
    const a = signAtLeaf(state, 2, enc('m'));
    expect(a.signature.nullifier).toBe(leafNullifier(rootCommitment, 2));
    expect(verifyLeafSignature(rootCommitment, 2, enc('m'), a.signature)).toBe(true);
    expect(verifyLeafSignature(rootCommitment, 2, enc('m'), { ...a.signature, nullifier: leafNullifier(rootCommitment, 3) })).toBe(false);
    expect(verifyLeafSignature(rootCommitment, 2, enc('m'), { ...a.signature, nullifier: undefined } as never)).toBe(false);
  });
  it('the PoC: a holder who kept the old state signs twice; the verifier-side spent set catches it', async () => {
    const store = memorySpentLeafStore();
    const a = signAtLeaf(state, 3, enc('pay alice 10'));
    const b = signAtLeaf(state, 3, enc('pay mallory 10000'));
    expect(verifyLeafSignature(rootCommitment, 3, enc('pay mallory 10000'), b.signature)).toBe(true); // stateless verify still passes
    expect(await verifyLeafSignatureOnce(rootCommitment, 3, enc('pay alice 10'), a.signature, store)).toEqual({ ok: true });
    const r = await verifyLeafSignatureOnce(rootCommitment, 3, enc('pay mallory 10000'), b.signature, store);
    expect(r.ok).toBe(false);
    expect(r).toMatchObject({ reason: 'equivocation' });
    const again = await verifyLeafSignatureOnce(rootCommitment, 3, enc('pay alice 10'), a.signature, store);
    expect(again).toMatchObject({ ok: false, reason: 'replay' });
  });
  it('invalid signatures never burn a leaf; a throwing store denies', async () => {
    const store = memorySpentLeafStore();
    const a = signAtLeaf(state, 1, enc('x'));
    expect(await verifyLeafSignatureOnce(rootCommitment, 1, enc('y'), a.signature, store)).toMatchObject({ reason: 'invalid' });
    expect(await verifyLeafSignatureOnce(rootCommitment, 1, enc('x'), a.signature, store)).toEqual({ ok: true });
    const bad = { claim: () => { throw new Error('down'); } };
    expect(await verifyLeafSignatureOnce(rootCommitment, 1, enc('x'), a.signature, bad)).toMatchObject({ reason: 'store-error' });
  });
});

describe('RT-11 rounding', () => {
  it('sub-resolution risks are never 0 units', () => {
    expect(riskToUnits(0.0004)).toBe(1n);
    expect(riskToUnits(0)).toBe(0n);
    expect(riskToUnits(0.3)).toBe(300n); // float noise keeps the exact unit
    expect(riskToUnits(0.0005)).toBe(1n);
    expect(riskToUnits(1)).toBe(1000n);
  });
  it('the PoC: 5000 x 0.0004 (true total 2.0) no longer fits a 1-unit ceiling', () => {
    const risks = Array.from({ length: 5000 }, () => riskToUnits(0.0004));
    const cs = risks.map((r) => commitRisk(r));
    const sum = addCommitments(cs.map((c) => c.commitment));
    expect(risks.reduce<bigint>((a, b) => a + BigInt(b), 0n) >= 2000n).toBe(true);
    // 5000 units exceeds ceiling 1 (and any ceiling below 5000): the prover cannot honestly prove it
    let ok = false;
    try {
      ok = verifyBudget(sum, 1, proveBudget(risks, cs.map((c) => c.blinding), 1));
    } catch {
      ok = false;
    }
    expect(ok).toBe(false);
  });
  it('RiskQuantizer carries the remainder: total is ceil of the true sum', () => {
    const q = new RiskQuantizer();
    let total = 0n;
    for (let i = 0; i < 5000; i++) total += q.next(0.0004);
    expect(total).toBe(2000n); // true total 2.0 * SCALE
    expect(q.totalUnits).toBe(total);
    const q2 = new RiskQuantizer();
    expect(q2.next(0.0004)).toBe(1n);
    expect(q2.next(0.0004)).toBe(0n);
    expect(RISK_SCALE).toBe(1000);
    expect(budgetCeilingUnits({ bMax: 1, kappa: 1 })).toBe(1000n);
  });
});

describe('RT-11 commitments bound to the action', () => {
  const auth = generateKeyPair();
  const pub = b64u(auth.publicKey);
  it('the PoC: a prover cannot commit 0 for an authority-computed risk', () => {
    const items = [issueRiskCommitment(600n, 'act-1', auth.secretKey), issueRiskCommitment(300n, 'act-2', auth.secretKey)];
    const bp = proveBudget([600n, 300n], items.map((i) => i.blinding), 1000);
    expect(verifyAttestedBudget(items, ['act-1', 'act-2'], pub, 1000, bp)).toBe(true);
    // prover swaps in its own 0 commitment for act-1 (no authority signature for it)
    const lie = commitRisk(0n);
    const forged = { ...items[0]!, commitment: lie.commitment };
    const bp2 = proveBudget([0n, 300n], [lie.blinding, items[1]!.blinding], 1000);
    expect(verifyAttestedBudget([forged, items[1]!], ['act-1', 'act-2'], pub, 1000, bp2)).toBe(false);
  });
  it('an attestation is bound to its action and to its authority', () => {
    const it1 = issueRiskCommitment(10n, 'act-1', auth.secretKey);
    expect(verifyRiskAttestation(it1.commitment, it1.attestation, pub)).toBe(true);
    expect(verifyRiskAttestation(it1.commitment, { ...it1.attestation, actionDigest: 'act-2' }, pub)).toBe(false);
    expect(verifyRiskAttestation(it1.commitment, it1.attestation, b64u(generateKeyPair().publicKey))).toBe(false);
    const bp = proveBudget([10n], [it1.blinding], 1000);
    expect(verifyAttestedBudget([it1], ['act-2'], pub, 1000, bp)).toBe(false); // wrong action in the verifier's list
    expect(verifyAttestedBudget([it1], [], pub, 1000, bp)).toBe(false);
  });
});
