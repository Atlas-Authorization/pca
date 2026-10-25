/**
 * r13 mutation kills for verified-decision.ts: pqBindingErrorVerified's exact outcome for every (suite, policy,
 * commitment, key) combination, and hookTInt's saturation at the safe-integer extremes.
 */
import { describe, expect, it } from 'vitest';
import { holderPqCommitment } from './capability';
import { hookTInt, pqBindingErrorVerified } from './verified-decision';

/** Run f, capturing its value or its error (name + message), so a mutant that throws fails an assertion, not an error. */
const settle = <T>(f: () => T) => {
  try {
    return { ok: true as const, value: f() };
  } catch (e) {
    return { ok: false as const, error: { name: (e as Error)?.name, message: (e as Error)?.message } };
  }
};
/** Async form of settle. */
const settleAsync = async <T>(f: () => Promise<T>) => {
  try {
    return { ok: true as const, value: await f() };
  } catch (e) {
    return { ok: false as const, error: { name: (e as Error)?.name, message: (e as Error)?.message } };
  }
};

const PK = 'pq-key-A';
const COMMIT = holderPqCommitment(PK);
const MISMATCH = "L: pq_pk does not match the signer's committed holder_pq (F-2)";
const NO_COMMIT = "L: suite 'ml-dsa-65' needs a PQ key bound to the signer, but the signer's holder carries no holder_pq commitment (unbound PQ keys are rejected; F-2)";

describe('pqBindingErrorVerified', () => {
  it('a matching committed key passes', () => {
    expect(settle(() => pqBindingErrorVerified('ml-dsa-65', PK, COMMIT, 'L', undefined))).toEqual({ ok: true, value: undefined });
    expect(settle(() => pqBindingErrorVerified('ml-dsa-65', PK, COMMIT, 'L', {}))).toEqual({ ok: true, value: undefined });
  });
  it('a different or non-string key is a mismatch', () => {
    expect(settle(() => pqBindingErrorVerified('ml-dsa-65', 'pq-key-B', COMMIT, 'L', undefined))).toEqual({ ok: true, value: MISMATCH });
    expect(settle(() => pqBindingErrorVerified('ml-dsa-65', 5, COMMIT, 'L', undefined))).toEqual({ ok: true, value: MISMATCH });
    expect(settle(() => pqBindingErrorVerified('ml-dsa-65', undefined, COMMIT, 'L', undefined))).toEqual({ ok: true, value: MISMATCH });
    // a number whose string form is the committed key is still not a key
    expect(settle(() => pqBindingErrorVerified('ml-dsa-65', 5, holderPqCommitment('5'), 'L', undefined))).toEqual({ ok: true, value: MISMATCH });
  });
  it('no commitment is refused unless unbound keys are allowed', () => {
    expect(settle(() => pqBindingErrorVerified('ml-dsa-65', PK, undefined, 'L', undefined))).toEqual({ ok: true, value: NO_COMMIT });
    expect(settle(() => pqBindingErrorVerified('ml-dsa-65', PK, undefined, 'L', { allowUnboundPq: true }))).toEqual({ ok: true, value: undefined });
    expect(settle(() => pqBindingErrorVerified('ml-dsa-65', 'pq-key-B', COMMIT, 'L', { allowUnboundPq: true }))).toEqual({ ok: true, value: undefined });
  });
  it('a suite without a PQ key, or an unknown suite, is never bound', () => {
    expect(settle(() => pqBindingErrorVerified('ed25519', 'x', COMMIT, 'L', undefined))).toEqual({ ok: true, value: undefined });
    expect(settle(() => pqBindingErrorVerified(undefined, 'x', undefined, 'L', undefined))).toEqual({ ok: true, value: undefined });
    expect(settle(() => pqBindingErrorVerified('bogus', 'x', COMMIT, 'L', undefined))).toEqual({ ok: true, value: undefined });
  });
});

describe('hookTInt', () => {
  it('floors, saturates and drops NaN / non-numbers', () => {
    expect(settle(() => hookTInt(5))).toEqual({ ok: true, value: 5 });
    expect(settle(() => hookTInt(2.7))).toEqual({ ok: true, value: 2 });
    expect(settle(() => hookTInt(-2.5))).toEqual({ ok: true, value: -3 });
    expect(settle(() => hookTInt(Infinity))).toEqual({ ok: true, value: Number.MAX_SAFE_INTEGER });
    expect(settle(() => hookTInt(1e300))).toEqual({ ok: true, value: Number.MAX_SAFE_INTEGER });
    expect(settle(() => hookTInt(-Infinity))).toEqual({ ok: true, value: -Number.MAX_SAFE_INTEGER });
    expect(settle(() => hookTInt(-1e300))).toEqual({ ok: true, value: -Number.MAX_SAFE_INTEGER });
    expect(settle(() => hookTInt(NaN))).toEqual({ ok: true, value: undefined });
    expect(settle(() => hookTInt('3'))).toEqual({ ok: true, value: undefined });
  });
});
