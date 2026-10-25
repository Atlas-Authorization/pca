/**
 * r13 mutation kills for receipt.ts: the exact hashed receipt body (domain, checks / null, outcome), every
 * verifyReceiptChain refusal, and receiptHead of an empty log.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { hashCanonical } from './hash';
import { pcactnDigest, type PCActn } from './pcactn';
import { appendReceipt, receiptFor, receiptHead, verifyReceiptChain } from './receipt';

/** Run f, capturing its value or its error (name + message), so a throwing mutant fails an assertion. */
const settle = <T>(f: () => T) => {
  try {
    return { ok: true as const, value: f() };
  } catch (e) {
    return { ok: false as const, error: { name: (e as Error)?.name, message: (e as Error)?.message } };
  }
};
const P = (n: number) => ({ iat: 1000 + n, action: { verb: 'v', resource: `r${n}` } }) as unknown as PCActn;

describe('receiptFor', () => {
  it('hashes the documented body (checks present)', () => {
    const r = receiptFor('prev', 3, P(1), { allow: true, checks: { a: 'pass' } as never });
    expect(r).toEqual({ seq: 3, at: 1001, actionDigest: pcactnDigest(P(1)), verb: 'v', resource: 'r1', outcome: 'allow', checks: { a: 'pass' }, prev: 'prev', hash: r.hash });
    expect(r.hash).toBe(hashCanonical({ d: 'atlas-pca/receipt/v1', seq: 3, at: 1001, actionDigest: pcactnDigest(P(1)), verb: 'v', resource: 'r1', outcome: 'allow', checks: { a: 'pass' }, prev: 'prev' }));
  });
  it('a deny without checks hashes checks: null', () => {
    const r = receiptFor('', 0, P(2), { allow: false } as never, 7);
    expect(r.outcome).toBe('deny');
    expect('checks' in r).toBe(false);
    expect(r.hash).toBe(hashCanonical({ d: 'atlas-pca/receipt/v1', seq: 0, at: 7, actionDigest: pcactnDigest(P(2)), verb: 'v', resource: 'r2', outcome: 'deny', checks: null, prev: '' }));
  });
});

describe('verifyReceiptChain / receiptHead', () => {
  let log: ReturnType<typeof appendReceipt> = [];
  beforeEach(() => {
    log = [P(0), P(1), P(2)].reduce((l, p) => appendReceipt(l, p, { allow: true } as never), [] as ReturnType<typeof appendReceipt>);
  });
  it('a well-formed chain verifies and its head is the last hash', () => {
    expect(verifyReceiptChain(log)).toEqual({ ok: true });
    expect(receiptHead(log)).toBe(log[2]!.hash);
    expect(settle(() => receiptHead([]))).toEqual({ ok: true, value: '' });
  });
  it('seq out of order', () => {
    expect(verifyReceiptChain([log[0]!, log[2]!])).toEqual({ ok: false, brokenAt: 2, reason: 'seq 2 out of order (expected 1)' });
  });
  it('a broken prev link (even with a self-consistent hash)', () => {
    const forged = receiptFor('bogus', 1, P(1), { allow: true } as never);
    expect(verifyReceiptChain([log[0]!, forged])).toEqual({ ok: false, brokenAt: 1, reason: 'prev link mismatch at seq 1' });
  });
  it('a tampered body', () => {
    expect(verifyReceiptChain([log[0]!, { ...log[1]!, verb: 'x' }])).toEqual({ ok: false, brokenAt: 1, reason: 'hash mismatch at seq 1 (tampered body)' });
  });
});
