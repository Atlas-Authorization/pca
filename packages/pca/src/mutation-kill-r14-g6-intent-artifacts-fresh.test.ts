/**
 * r14 g6: intent-artifacts.ts module-level constants and helpers (static mutants), checked on a freshly evaluated module
 * (vi.resetModules + dynamic import), so a mutant applied at module load is visible to these assertions.
 */
import { describe, expect, it, vi } from 'vitest';
import { b64u, sha256, utf8 } from './hash';
import { publicKeyOf } from './keys';

async function fresh() {
  vi.resetModules();
  return import('./intent-artifacts');
}
const t = (re: RegExp, xs: string[]) => xs.map((x) => re.test(x));

describe('intent-artifacts patterns (fresh module)', () => {
  it('INTENT_NAME_RE: a lowercase letter then 0..63 of [a-z0-9_]', async () => {
    const m = await fresh();
    expect(t(m.INTENT_NAME_RE, ['a', 'ab', 'a_1', 'a' + 'b'.repeat(63), 'a' + 'b'.repeat(64), 'Xa', '1ab', 'ab-', ' a', 'a b', ''])).toEqual([
      true, true, true, true, false, false, false, false, false, false, false,
    ]);
  });
  it('DATA_CLASS_RE: dotted lowercase class names', async () => {
    const m = await fresh();
    expect(t(m.DATA_CLASS_RE, ['a', 'ab', 'abc', 'pii.contact', 'a.b1', 'pii.contact.x', 'payment.instrument_meta', '1a', 'a.', 'A', 'a..b', 'x pii', 'pii.Contact', '.a'])).toEqual([
      true, true, true, true, true, true, true, false, false, false, false, false, false, false,
    ]);
  });
  it('PARAM_SEGMENT_RE: 1..64 of [A-Za-z0-9_-]', async () => {
    const m = await fresh();
    expect(t(m.PARAM_SEGMENT_RE, ['a', 'ab', 'ok_1-X', 'a'.repeat(64), 'a'.repeat(65), '', ' ab', 'ab ', 'a.b', 'a b'])).toEqual([
      true, true, true, true, false, false, false, false, false, false,
    ]);
  });
});

describe('intent-artifacts helpers (fresh module)', () => {
  it('isPathSegment refuses the prototype names', async () => {
    const m = await fresh();
    expect(['ok', '__proto__', 'constructor', 'prototype', 'a b'].map((s) => m.isPathSegment(s))).toEqual([true, false, false, false, false]);
  });
  it('isPlainObject, isSafeInt, utf8Len, isBoundedString, isDigest', async () => {
    const m = await fresh();
    expect([{}, Object.create(null), [], null, new Date(), 5].map((v) => m.isPlainObject(v))).toEqual([true, true, false, false, false, false]);
    expect([1, 0, -0, 1.5, Number.MAX_SAFE_INTEGER + 1, '1'].map((v) => m.isSafeInt(v))).toEqual([true, true, false, false, false, false]);
    expect([m.utf8Len('abc'), m.utf8Len('é'), m.utf8Len('')]).toEqual([3, 2, 0]);
    expect([m.isBoundedString('ab', 2), m.isBoundedString('abc', 2), m.isBoundedString('', 2), m.isBoundedString(5, 2), m.isBoundedString('é', 1)]).toEqual([true, false, false, false, false]);
    const d = b64u(sha256(utf8('x')));
    expect([m.isDigest(d), m.isDigest(d + 'A'), m.isDigest(5), m.isDigest(b64u(new Uint8Array(31)))]).toEqual([true, false, false, false]);
  });
  it('isScalar, scalarEq, pinPqOk, isClock', async () => {
    const m = await fresh();
    expect(['s', true, 3, 1.5, null, {}].map((v) => m.isScalar(v))).toEqual([true, true, true, false, false, false]);
    expect([m.scalarEq(1, 1), m.scalarEq(1, '1'), m.scalarEq('a', 'a'), m.scalarEq(true, 1)]).toEqual([true, false, true, false]);
    expect([undefined, 'x', '', null, 5].map((v) => m.pinPqOk(v))).toEqual([true, true, false, false, false]);
    expect([5, 1.5, '5', -0].map((v) => m.isClock(v))).toEqual([true, false, false, false]);
  });
  it('publicKeyB64u and ownGet', async () => {
    const m = await fresh();
    const sk = sha256(utf8('r14-g6'));
    expect(m.publicKeyB64u(sk)).toBe(b64u(publicKeyOf(sk)));
    expect([m.ownGet({ a: 1 }, 'a'), m.ownGet({} as Record<string, unknown>, 'toString'), m.ownGet(null, 'a'), m.ownGet(undefined, 'a')]).toEqual([1, undefined, undefined, undefined]);
  });
});
