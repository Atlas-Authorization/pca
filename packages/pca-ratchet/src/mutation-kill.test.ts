/** Mutation kills for @atlasauth/pca-ratchet: error codes/messages, boundaries, byte layouts and verifier shape checks. */
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { describe, expect, it } from 'vitest';
import { b64u } from '@atlasauth/pca';
import {
  AccumulatorError, MAX_PROVABLE_CEILING, N_BITS, RatchetError, RISK_SCALE, RiskQuantizer, addCommitments, availableLeaves, budgetCeilingUnits, commitRisk,
  counterToLeafIndex, deriveRatchetRoot, isLeafAvailable, leafIndexForAction, leafIndexToCounter, leafNullifier, openCommitment, proveBudget, proveRiskRange,
  riskToUnits, signAtLeaf, verifyBudget, verifyLeafSignature, verifyRiskRange, MAX_RATCHET_DEPTH,
} from './index';
import { issueRiskCommitment, memorySpentLeafStore, verifyAttestedBudget, verifyLeafSignatureOnce, verifyRiskAttestation } from './binding';
import { bytesToNumberLE, decodePoint, decodeScalar, encodeScalar, numberToBytesLE, L } from './group';
import { verifyBoundedBudget } from './accumulator';

const err = (f: () => unknown): Error & { code?: string } => { try { f(); } catch (e) { return e as Error; } throw new Error('no throw'); };
const seed = (n: number) => new Uint8Array(32).fill(n);
const msg = (s: string) => new TextEncoder().encode(s);

describe('ratchet.ts', () => {
  it('errors carry name, code and exact message', () => {
    for (const d of [0, -1, 1.5, NaN, 21, MAX_RATCHET_DEPTH + 1]) {
      const e = err(() => deriveRatchetRoot(seed(1), d));
      expect(e).toBeInstanceOf(RatchetError);
      expect(e.name).toBe('RatchetError');
      expect(e.code).toBe('invalid_depth');
      expect(e.message).toBe(`depth must be an integer in [1, ${MAX_RATCHET_DEPTH}]`);
    }
    for (const s of [new Uint8Array(31), 'x'.repeat(40) as never, null as never, [] as never]) {
      const e = err(() => deriveRatchetRoot(s, 2));
      expect(e.code).toBe('invalid_seed');
      expect(e.message).toBe('seed must be a Uint8Array of at least 32 bytes');
    }
    expect(() => deriveRatchetRoot(new Uint8Array(32), 1)).not.toThrow();
    expect(deriveRatchetRoot(seed(1), 1).state.leafCount).toBe(2);
  });
  it('signing: range, puncture and state hygiene', () => {
    const { rootCommitment, state } = deriveRatchetRoot(seed(3), 2);
    for (const i of [-1, 4, 1.5, NaN]) {
      const e = err(() => signAtLeaf(state, i, msg('m')));
      expect(e.code).toBe('leaf_out_of_range');
      expect(e.message).toBe(`leaf ${i} is out of range [0, 4)`);
    }
    const before = [...state.leafPubKeys];
    const { signature, newState } = signAtLeaf(state, 1, msg('m'));
    expect([...state.leafPubKeys]).toEqual(before);
    expect(state.covering.size).toBe(1);
    expect(isLeafAvailable(state, 1)).toBe(true);
    expect(isLeafAvailable(newState, 1)).toBe(false);
    expect(availableLeaves(newState)).toEqual([0, 2, 3]);
    const e = err(() => signAtLeaf(newState, 1, msg('m')));
    expect(e.code).toBe('leaf_punctured');
    expect(e.message).toBe('leaf 1 is already punctured (spent) and cannot sign');
    expect(signature.nullifier).toBe(leafNullifier(rootCommitment, 1));
    expect(signature.leafPubKey).toBe(state.leafPubKeys[1]);
    expect(newState.leafPubKeys).toBe(state.leafPubKeys);
  });
  it('nullifier layout', () => {
    const root = 'cm9vdA';
    const dom = new TextEncoder().encode('atlas-pca-ratchet/nullifier/v1\0');
    const r = new TextEncoder().encode(root);
    const buf = new Uint8Array(dom.length + 4 + r.length + 8);
    buf.set(dom); new DataView(buf.buffer).setUint32(dom.length, r.length, false); buf.set(r, dom.length + 4);
    new DataView(buf.buffer).setBigUint64(dom.length + 4 + r.length, 258n, false);
    expect(leafNullifier(root, 258)).toBe(b64u(sha256(buf)));
    expect(leafNullifier(root, 1)).not.toBe(leafNullifier(root, 257));
  });
  it('verifyLeafSignature: shape checks and bindings', () => {
    const { rootCommitment, state } = deriveRatchetRoot(seed(5), 3);
    const m = msg('hello');
    const { signature: s } = signAtLeaf(state, 6, m);
    expect(verifyLeafSignature(rootCommitment, 6, m, s)).toBe(true);
    for (const bad of [null, undefined, 5, 'x']) expect(verifyLeafSignature(rootCommitment, 6, m, bad as never)).toBe(false);
    for (const f of ['nullifier', 'edSig', 'leafPubKey'] as const) expect(verifyLeafSignature(rootCommitment, 6, m, { ...s, [f]: 5 } as never)).toBe(false);
    for (const mp of [null, 5, 'x', undefined]) expect(verifyLeafSignature(rootCommitment, 6, m, { ...s, merklePath: mp } as never)).toBe(false);
    expect(verifyLeafSignature(rootCommitment, 6, m, { ...s, merklePath: { ...s.merklePath, index: 7 } })).toBe(false);
    expect(verifyLeafSignature(rootCommitment, 5, m, s)).toBe(false);
    expect(verifyLeafSignature(rootCommitment, 6, msg('other'), s)).toBe(false);
    expect(verifyLeafSignature(deriveRatchetRoot(seed(6), 3).rootCommitment, 6, m, s)).toBe(false);
    expect(verifyLeafSignature(rootCommitment, 6, m, { ...s, nullifier: leafNullifier(rootCommitment, 5) })).toBe(false);
  });
});

describe('group.ts', () => {
  it('byte codecs', () => {
    expect(err(() => numberToBytesLE(-1n, 32)).message).toBe('numberToBytesLE: negative');
    expect(numberToBytesLE(0n, 32)).toEqual(new Uint8Array(32));
    expect(err(() => numberToBytesLE(256n, 1)).message).toBe('numberToBytesLE: overflow');
    expect(err(() => numberToBytesLE(1n << 40n, 4)).message).toBe('numberToBytesLE: overflow');
    expect(numberToBytesLE(255n, 1)).toEqual(Uint8Array.of(255));
    expect(numberToBytesLE(0x0102n, 3)).toEqual(Uint8Array.of(2, 1, 0));
    expect(bytesToNumberLE(Uint8Array.of(1))).toBe(1n);
    expect(bytesToNumberLE(Uint8Array.of(2, 1))).toBe(258n);
    expect(bytesToNumberLE(new Uint8Array(0))).toBe(0n);
  });
  it('decoders', () => {
    expect(err(() => decodePoint('nope')).message).toBe('decodePoint: not a canonical 32-byte base64url string');
    expect(err(() => decodePoint(b64u(new Uint8Array(31)))).message).toBe('decodePoint: not a canonical 32-byte base64url string');
    expect(err(() => decodeScalar('nope')).message).toBe('decodeScalar: not a canonical 32-byte base64url string');
    expect(err(() => decodeScalar(b64u(numberToBytesLE(L, 32)))).message).toBe('decodeScalar: non-canonical scalar (>= L)');
    expect(err(() => decodeScalar(b64u(numberToBytesLE(L + 1n, 32)))).message).toBe('decodeScalar: non-canonical scalar (>= L)');
    expect(decodeScalar(b64u(numberToBytesLE(L - 1n, 32)))).toBe(L - 1n);
    expect(decodeScalar(encodeScalar(5n))).toBe(5n);
  });
});

describe('accumulator.ts', () => {
  it('value validation: code, name and message', () => {
    const e1 = err(() => commitRisk(-1n));
    expect(e1).toBeInstanceOf(AccumulatorError);
    expect(e1.name).toBe('AccumulatorError');
    expect(e1.code).toBe('invalid_value');
    expect(e1.message).toBe('risk/budget must be >= 0');
    for (const bad of [-1, 1.5, NaN, Infinity]) {
      const e = err(() => commitRisk(bad));
      expect(e.code).toBe('invalid_value');
      expect(e.message).toBe('risk/budget must be a non-negative integer');
    }
    expect(() => commitRisk(0)).not.toThrow();
    expect(() => commitRisk(0n)).not.toThrow();
  });
  it('commitments open only to their value and blinding', () => {
    const c = commitRisk(7n, 5n);
    expect(openCommitment(c.commitment, 7n, 5n)).toBe(true);
    expect(openCommitment(c.commitment, 7, 5n)).toBe(true);
    expect(openCommitment(c.commitment, 8n, 5n)).toBe(false);
    expect(openCommitment(c.commitment, 7n, 6n)).toBe(false);
    expect(openCommitment(c.commitment, -1n, 5n)).toBe(false);
    expect(openCommitment('nope', 7n, 5n)).toBe(false);
    const a = commitRisk(3n), b = commitRisk(4n);
    expect(openCommitment(addCommitments([a.commitment, b.commitment]), 7n, a.blinding + b.blinding)).toBe(true);
  });
  const mk = (risks: bigint[]) => risks.map((r) => commitRisk(r));
  it('proveBudget refuses ragged inputs', () => {
    const e = err(() => proveBudget([1n, 2n], [1n], 10n));
    expect(e.code).toBe('length_mismatch');
    expect(e.message).toBe('risks and blindings must have equal length');
  });
  it('budget proofs: ceilings, clamping and shape checks', () => {
    const cs = mk([3n, 4n]);
    const sum = addCommitments(cs.map((c) => c.commitment));
    const proof = proveBudget([3n, 4n], cs.map((c) => c.blinding), 10n);
    expect(verifyBudget(sum, 10n, proof)).toBe(true);
    expect(verifyBudget(sum, 11n, proof)).toBe(false);
    expect(verifyBudget(sum, 9n, proof)).toBe(false);
    // the proof ceiling is clamped to the provable maximum
    const big = proveBudget([3n, 4n], cs.map((c) => c.blinding), MAX_PROVABLE_CEILING + 5n);
    expect(verifyBudget(sum, MAX_PROVABLE_CEILING, big)).toBe(true);
    expect(verifyBudget(sum, MAX_PROVABLE_CEILING + 100n, big)).toBe(true);
    // shape
    expect(verifyBudget(sum, 10n, null as never)).toBe(false);
    expect(verifyBudget(sum, 10n, 'x' as never)).toBe(false);
    expect(verifyBudget(sum, 10n, { ...proof, n: N_BITS - 1 })).toBe(false);
    expect(verifyBudget(sum, 10n, { ...proof, bitCommitments: proof.bitCommitments.slice(1) })).toBe(false);
    expect(verifyBudget(sum, 10n, { ...proof, or: proof.or.slice(1) })).toBe(false);
    expect(verifyBudget(sum, 10n, { ...proof, bitCommitments: 'x' as never })).toBe(false);
    expect(verifyBudget(sum, 10n, { ...proof, or: 'x' as never })).toBe(false);
    expect(verifyBudget(sum, 10n, { ...proof, agg: null as never })).toBe(false);
    expect(verifyBudget(sum, 10n, { ...proof, agg: 5 as never })).toBe(false);
    expect(verifyBudget(sum, -1n, proof)).toBe(false);
    expect(verifyBudget('nope', 10n, proof)).toBe(false);
    // over budget cannot be proved (the slack is negative)
    const over = proveBudget([8n, 9n], mk([8n, 9n]).map((c) => c.blinding), 10n);
    expect(verifyBudget(addCommitments(mk([8n, 9n]).map((c) => c.commitment)), 10n, over)).toBe(false);
  });
  it('risk range proofs and the bounded-budget composition', () => {
    const c = commitRisk(5n);
    const rp = proveRiskRange(5n, c.blinding);
    expect(verifyRiskRange(c.commitment, rp)).toBe(true);
    expect(verifyRiskRange(commitRisk(5n).commitment, rp)).toBe(false);
    expect(verifyRiskRange(c.commitment, null as never)).toBe(false);
    expect(verifyRiskRange('nope', rp)).toBe(false);
    const cs = [commitRisk(2n), commitRisk(3n)];
    const rps = cs.map((x, i) => proveRiskRange(BigInt(i + 2), x.blinding));
    const bp = proveBudget([2n, 3n], cs.map((x) => x.blinding), 10n);
    const comm = cs.map((x) => x.commitment);
    expect(verifyBoundedBudget(comm, rps, 10n, bp)).toBe(true);
    expect(verifyBoundedBudget(comm, rps.slice(1), 10n, bp)).toBe(false);
    expect(verifyBoundedBudget(comm.slice(1), rps, 10n, bp)).toBe(false);
    expect(verifyBoundedBudget('x' as never, rps, 10n, bp)).toBe(false);
    expect(verifyBoundedBudget(comm, 'x' as never, 10n, bp)).toBe(false);
    expect(verifyBoundedBudget(comm, [rps[1]!, rps[0]!], 10n, bp)).toBe(false);
    expect(verifyBoundedBudget(comm, rps, 4n, bp)).toBe(false);
    expect(verifyBoundedBudget([], [], 10n, proveBudget([], [], 10n))).toBe(true);
  });
});

describe('adapters.ts', () => {
  it('counter / leaf index mapping and its refusals', () => {
    expect(counterToLeafIndex(0, 1)).toBe(0);
    expect(counterToLeafIndex(1, 1)).toBe(1);
    expect(counterToLeafIndex(2 ** MAX_RATCHET_DEPTH - 1, MAX_RATCHET_DEPTH)).toBe(2 ** MAX_RATCHET_DEPTH - 1);
    for (const d of [0, -1, 1.5, NaN, MAX_RATCHET_DEPTH + 1]) {
      const e = err(() => counterToLeafIndex(0, d));
      expect(e).toBeInstanceOf(RatchetError);
      expect(e.code).toBe('invalid_depth');
      expect(e.message).toBe(`depth must be an integer in [1, ${MAX_RATCHET_DEPTH}]`);
    }
    for (const c of [-1, 1.5, NaN, 2 ** 53]) {
      const e = err(() => counterToLeafIndex(c, 4));
      expect(e.code).toBe('leaf_out_of_range');
      expect(e.message).toBe('counter must be a non-negative safe integer');
    }
    const cap = err(() => counterToLeafIndex(16, 4));
    expect(cap.code).toBe('leaf_out_of_range');
    expect(cap.message).toBe('counter 16 exceeds the ratchet capacity 2^4');
    expect(counterToLeafIndex(15, 4)).toBe(15);
    expect(leafIndexForAction({ counter: 3 }, 2)).toBe(3);
    expect(err(() => leafIndexForAction({ counter: 4 }, 2)).code).toBe('leaf_out_of_range');
    expect(leafIndexToCounter(0)).toBe(0);
    expect(leafIndexToCounter(9)).toBe(9);
    for (const i of [-1, 1.5, NaN, 2 ** 53]) {
      const e = err(() => leafIndexToCounter(i));
      expect(e.code).toBe('leaf_out_of_range');
      expect(e.message).toBe('leafIndex must be a non-negative safe integer');
    }
  });
  it('riskToUnits rounds up except for float noise', () => {
    expect(RISK_SCALE).toBe(1000);
    expect(riskToUnits(0)).toBe(0n);
    expect(riskToUnits(0.001)).toBe(1n);
    expect(riskToUnits(0.0014)).toBe(2n);
    expect(riskToUnits(0.0012)).toBe(2n);
    expect(riskToUnits(0.3)).toBe(300n);
    expect(riskToUnits(0.1 + 0.2)).toBe(300n);
    expect(riskToUnits(1)).toBe(1000n);
    expect(riskToUnits(1_000_000.0000001)).toBe(1_000_000_000n);
    expect(riskToUnits(1_000_000.002)).toBe(1_000_000_002n);
    for (const bad of [-0.001, NaN, Infinity, -Infinity]) {
      const e = err(() => riskToUnits(bad));
      expect(e).toBeInstanceOf(AccumulatorError);
      expect(e.code).toBe('invalid_value');
      expect(e.message).toBe('risk must be a finite number >= 0');
    }
  });
  it('RiskQuantizer never under-counts and rejects bad input', () => {
    const q = new RiskQuantizer();
    expect(q.next(0.0005)).toBe(1n);
    expect(q.next(0.0005)).toBe(0n);
    expect(q.next(0.0005)).toBe(1n);
    expect(q.totalUnits).toBe(2n);
    expect(new RiskQuantizer().next(0)).toBe(0n);
    for (const bad of [-1, NaN, Infinity]) {
      const e = err(() => new RiskQuantizer().next(bad));
      expect(e.code).toBe('invalid_value');
      expect(e.message).toBe('risk must be a finite number >= 0');
    }
    const q2 = new RiskQuantizer();
    let sum = 0n;
    for (let i = 0; i < 100; i++) sum += q2.next(0.0003);
    expect(sum).toBe(q2.totalUnits);
    expect(q2.totalUnits).toBe(30n);
  });
  it('budgetCeilingUnits', () => {
    expect(budgetCeilingUnits({ bMax: 10, kappa: 2 })).toBe(5000n);
    expect(budgetCeilingUnits({ bMax: 0, kappa: 2 })).toBe(0n);
    expect(budgetCeilingUnits({ bMax: 1, kappa: 3 })).toBe(333n);
    expect(budgetCeilingUnits({ bMax: -5, kappa: 2 })).toBe(0n);
    expect(budgetCeilingUnits({ bMax: 5, kappa: 0 })).toBe(0n);
    const e = err(() => budgetCeilingUnits({ bMax: Infinity, kappa: 1 }));
    expect(e.code).toBe('invalid_value');
    expect(e.message).toBe('safety bound (bMax/kappa) must be finite and >= 0');
    expect(err(() => budgetCeilingUnits({ bMax: NaN, kappa: 1 })).code).toBe('invalid_value');
  });
});

describe('binding.ts', () => {
  const { rootCommitment, state } = deriveRatchetRoot(seed(9), 3);
  const sign = (i: number, m: string) => signAtLeaf(state, i, msg(m)).signature;
  it('one-time use: first, replay, equivocation, invalid, store error', async () => {
    const store = memorySpentLeafStore();
    const s = sign(2, 'a');
    expect(await verifyLeafSignatureOnce(rootCommitment, 2, msg('a'), s, store)).toStrictEqual({ ok: true });
    expect(await verifyLeafSignatureOnce(rootCommitment, 2, msg('a'), s, store)).toStrictEqual({ ok: false, reason: 'replay', nullifier: leafNullifier(rootCommitment, 2) });
    const s2 = sign(2, 'b');
    expect(await verifyLeafSignatureOnce(rootCommitment, 2, msg('b'), s2, store)).toStrictEqual({
      ok: false,
      reason: 'equivocation',
      nullifier: leafNullifier(rootCommitment, 2),
      firstMessageDigest: `${b64u(sha256(msg('a')))}@2`,
      secondMessageDigest: `${b64u(sha256(msg('b')))}@2`,
    });
    let claims = 0;
    const counting = { claim: () => { claims++; return { first: true as const }; } };
    expect(await verifyLeafSignatureOnce(rootCommitment, 3, msg('x'), s, counting)).toStrictEqual({ ok: false, reason: 'invalid' });
    expect(claims).toBe(0);
    const throwing = { claim: () => { throw new Error('db down'); } };
    expect(await verifyLeafSignatureOnce(rootCommitment, 2, msg('a'), s, throwing)).toStrictEqual({ ok: false, reason: 'store-error' });
    const rejecting = { claim: () => Promise.reject(new Error('db down')) };
    expect(await verifyLeafSignatureOnce(rootCommitment, 2, msg('a'), s, rejecting)).toStrictEqual({ ok: false, reason: 'store-error' });
    // different leaves are independent
    expect((await verifyLeafSignatureOnce(rootCommitment, 4, msg('a'), sign(4, 'a'), store)).ok).toBe(true);
  });
  it('risk attestation: exact signed bytes and shape checks', () => {
    const sk = ed25519.utils.randomPrivateKey();
    const pk = b64u(ed25519.getPublicKey(sk));
    const r = issueRiskCommitment(5n, 'digest-1', sk);
    const dom = new TextEncoder().encode('atlas-pca-ratchet/risk-attestation/v1\0');
    const a = new TextEncoder().encode('digest-1'), c = new TextEncoder().encode(r.commitment);
    const m = new Uint8Array(dom.length + 4 + a.length + 4 + c.length);
    const dv = new DataView(m.buffer);
    m.set(dom); dv.setUint32(dom.length, a.length, false); m.set(a, dom.length + 4);
    dv.setUint32(dom.length + 4 + a.length, c.length, false); m.set(c, dom.length + 8 + a.length);
    expect(r.attestation).toEqual({ actionDigest: 'digest-1', sig: b64u(ed25519.sign(m, sk)) });
    expect(verifyRiskAttestation(r.commitment, r.attestation, pk)).toBe(true);
    expect(verifyRiskAttestation(r.commitment, { ...r.attestation, actionDigest: 'digest-2' }, pk)).toBe(false);
    expect(verifyRiskAttestation(commitRisk(5n).commitment, r.attestation, pk)).toBe(false);
    for (const bad of [null, undefined, 5, 'x', { actionDigest: 5, sig: 'x' }, { actionDigest: 'a', sig: 5 }]) expect(verifyRiskAttestation(r.commitment, bad as never, pk)).toBe(false);
    expect(verifyRiskAttestation(r.commitment, r.attestation, b64u(new Uint8Array(32)))).toBe(false);
  });
  it('attested budgets bind every item to its action and to the authority', () => {
    const sk = ed25519.utils.randomPrivateKey();
    const pk = b64u(ed25519.getPublicKey(sk));
    const items = [issueRiskCommitment(2n, 'a1', sk), issueRiskCommitment(3n, 'a2', sk)];
    const bp = proveBudget([2n, 3n], items.map((i) => i.blinding), 10n);
    const V = (its: unknown, digests: unknown, key = pk, b: bigint = 10n) => verifyAttestedBudget(its as never, digests as never, key, b, bp);
    expect(V(items, ['a1', 'a2'])).toBe(true);
    expect(V(items, ['a1'])).toBe(false);
    expect(V(items, ['a1', 'a2', 'a3'])).toBe(false);
    expect(V(items, ['a2', 'a1'])).toBe(false);
    expect(V(items, 'x')).toBe(false);
    expect(V('x', ['a1', 'a2'])).toBe(false);
    expect(V(items, ['a1', 'a2'], b64u(ed25519.getPublicKey(ed25519.utils.randomPrivateKey())))).toBe(false);
    expect(V(items, ['a1', 'a2'], pk, 4n)).toBe(false);
    // matching digest but a forged attestation signature
    const forged = [{ ...items[0]!, attestation: { actionDigest: 'a1', sig: b64u(new Uint8Array(64)) } }, items[1]];
    expect(V(forged, ['a1', 'a2'])).toBe(false);
    // missing attestation fails closed
    expect(V([{ ...items[0]!, attestation: undefined }, items[1]], ['a1', 'a2'])).toBe(false);
    expect(V([items[0]!, { ...items[1]!, rangeProof: items[0]!.rangeProof }], ['a1', 'a2'])).toBe(false);
  });
});
