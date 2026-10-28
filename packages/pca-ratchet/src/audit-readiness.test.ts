import { describe, expect, it } from 'vitest';
import {
  AccumulatorError,
  RatchetError,
  availableLeaves,
  commitRisk,
  deriveRatchetRoot,
  leafNullifier,
  memorySpentLeafStore,
  proveBudget,
  signAtLeaf,
  verifyBudget,
  verifyLeafSignature,
  verifyLeafSignatureOnce,
  type SpentLeafStore,
} from './index';

// Audit-readiness: the fail-closed table of the README, one exact outcome per row.
const seed = (n: number): Uint8Array => new Uint8Array(32).fill(n);
const msg = (s: string): Uint8Array => new TextEncoder().encode(s);
const codeOf = (f: () => unknown): string | undefined => {
  try {
    f();
  } catch (e) {
    return (e as RatchetError).code;
  }
  return undefined;
};

describe('ratchet fail-closed table: construction and signing refusals carry exact codes', () => {
  it('depth outside [1, max] or fractional -> invalid_depth; short or non-byte seed -> invalid_seed', () => {
    expect(codeOf(() => deriveRatchetRoot(seed(1), 0))).toBe('invalid_depth');
    expect(codeOf(() => deriveRatchetRoot(seed(1), 1.5))).toBe('invalid_depth');
    expect(codeOf(() => deriveRatchetRoot(seed(1), Number.NaN))).toBe('invalid_depth');
    expect(codeOf(() => deriveRatchetRoot(new Uint8Array(31), 2))).toBe('invalid_seed');
    expect(codeOf(() => deriveRatchetRoot('x'.repeat(40) as unknown as Uint8Array, 2))).toBe('invalid_seed');
  });

  it('a skipped-ahead, negative, fractional or past-the-end leaf -> leaf_out_of_range, state untouched', () => {
    const { state } = deriveRatchetRoot(seed(2), 3);
    for (const i of [-1, 8, 1.5, Number.NaN, Infinity]) {
      expect(codeOf(() => signAtLeaf(state, i, msg('m')))).toBe('leaf_out_of_range');
    }
    expect(availableLeaves(state)).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
  });

  it('spending leaves out of order leaves exactly the unspent leaves; each spent leaf -> leaf_punctured', () => {
    const { state } = deriveRatchetRoot(seed(3), 3);
    let s = state;
    for (const i of [6, 0, 3]) s = signAtLeaf(s, i, msg(`a${i}`)).newState;
    expect(availableLeaves(s)).toEqual([1, 2, 4, 5, 7]);
    for (const i of [6, 0, 3]) expect(codeOf(() => signAtLeaf(s, i, msg('again')))).toBe('leaf_punctured');
  });
});

describe('ratchet fail-closed table: verifier outcomes are exact', () => {
  it('a state rolled back to a backup signs the same leaf again; the verifier store reports replay then equivocation, never ok', async () => {
    const { rootCommitment, state } = deriveRatchetRoot(seed(4), 3);
    const store = memorySpentLeafStore();
    const a = signAtLeaf(state, 2, msg('pay 1'));
    const b = signAtLeaf(state, 2, msg('pay 2')); // old state kept: rollback
    const n = leafNullifier(rootCommitment, 2);
    expect(await verifyLeafSignatureOnce(rootCommitment, 2, msg('pay 1'), a.signature, store)).toEqual({ ok: true });
    expect(await verifyLeafSignatureOnce(rootCommitment, 2, msg('pay 1'), a.signature, store)).toEqual({ ok: false, reason: 'replay', nullifier: n });
    const eq = await verifyLeafSignatureOnce(rootCommitment, 2, msg('pay 2'), b.signature, store);
    expect(eq).toMatchObject({ ok: false, reason: 'equivocation', nullifier: n });
    // the live state after the first spend refuses the leaf outright
    expect(codeOf(() => signAtLeaf(a.newState, 2, msg('pay 3')))).toBe('leaf_punctured');
  });

  it('a nullifier from another root, a missing nullifier or a non-object signature -> invalid, and invalid never claims a leaf', async () => {
    const { rootCommitment, state } = deriveRatchetRoot(seed(5), 3);
    const other = deriveRatchetRoot(seed(6), 3);
    const { signature } = signAtLeaf(state, 1, msg('m'));
    const store = memorySpentLeafStore();
    const foreign = { ...signature, nullifier: leafNullifier(other.rootCommitment, 1) };
    const missing = { ...signature, nullifier: undefined as unknown as string };
    expect(verifyLeafSignature(rootCommitment, 1, msg('m'), foreign)).toBe(false);
    expect(verifyLeafSignature(rootCommitment, 1, msg('m'), missing)).toBe(false);
    expect(verifyLeafSignature(rootCommitment, 1, msg('m'), null as never)).toBe(false);
    expect(await verifyLeafSignatureOnce(rootCommitment, 1, msg('m'), foreign, store)).toEqual({ ok: false, reason: 'invalid' });
    // the leaf was never burned by the invalid attempts
    expect(await verifyLeafSignatureOnce(rootCommitment, 1, msg('m'), signature, store)).toEqual({ ok: true });
  });

  it('a spent-leaf store that throws or rejects -> store-error (deny)', async () => {
    const { rootCommitment, state } = deriveRatchetRoot(seed(7), 2);
    const { signature } = signAtLeaf(state, 0, msg('m'));
    const sync: SpentLeafStore = { claim: () => { throw new Error('down'); } };
    const async_: SpentLeafStore = { claim: () => Promise.reject(new Error('down')) };
    expect(await verifyLeafSignatureOnce(rootCommitment, 0, msg('m'), signature, sync)).toEqual({ ok: false, reason: 'store-error' });
    expect(await verifyLeafSignatureOnce(rootCommitment, 0, msg('m'), signature, async_)).toEqual({ ok: false, reason: 'store-error' });
  });
});

describe('ratchet fail-closed table: budget proofs', () => {
  it('negative, fractional or mismatched-length inputs -> typed AccumulatorError', () => {
    const c = commitRisk(5);
    const code = (f: () => unknown): string | undefined => {
      try {
        f();
      } catch (e) {
        return e instanceof AccumulatorError ? e.code : 'other';
      }
      return undefined;
    };
    expect(code(() => commitRisk(-1))).toBe('invalid_value');
    expect(code(() => commitRisk(1.5))).toBe('invalid_value');
    expect(code(() => proveBudget([5], [], 10))).toBe('length_mismatch');
    expect(code(() => proveBudget([5], [c.blinding], -1))).toBe('invalid_value');
  });

  it('over-budget, wrong ceiling, malformed commitment and a truncated proof all verify false', () => {
    const c = commitRisk(8);
    const proof = proveBudget([8], [c.blinding], 10);
    expect(verifyBudget(c.commitment, 10, proof)).toBe(true);
    expect(verifyBudget(c.commitment, 7, proof)).toBe(false);
    expect(verifyBudget('not-a-point', 10, proof)).toBe(false);
    expect(verifyBudget(c.commitment, 10, { ...proof, or: proof.or.slice(1) })).toBe(false);
    expect(verifyBudget(c.commitment, 10, null as never)).toBe(false);
    // a prover that builds a proof for an over-budget total either refuses or yields a proof the verifier rejects
    let accepted = false;
    try {
      accepted = verifyBudget(c.commitment, 7, proveBudget([8], [c.blinding], 7));
    } catch (e) {
      expect(e).toBeInstanceOf(AccumulatorError);
    }
    expect(accepted).toBe(false);
  });
});
