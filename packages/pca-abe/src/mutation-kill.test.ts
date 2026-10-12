/** Mutation kills for @atlasauth/pca-abe: policy normalisation, secret sharing, AEAD and wire helpers. */
import { describe, expect, it } from 'vitest';
import { MAX_POLICY_DEPTH, MAX_POLICY_NODES, normalizePolicy, policyAttributes, satisfies, type ThresholdTree } from './policy';
import { lagrangeAtZero, randomSecret, recoverSecret, splitSecret } from './sss';
import { open, seal } from './aead';
import { b64u, isObject, isPosInt, isString, unb64u } from './wire';
import { Attr } from './attributes';

const err = (f: () => unknown): Error => { try { f(); } catch (e) { return e as Error; } throw new Error('no throw'); };
const N = (p: unknown) => normalizePolicy(p);
const R = (reason: string) => ({ ok: false, reason });
/** The normalised tree of a policy that must normalise (fails the test, with the reason, if it does not). */
const treeOf = (p: unknown): ThresholdTree => {
  const r = normalizePolicy(p);
  if (!r.ok) throw new Error(`expected a valid policy, got: ${r.reason}`);
  return r.tree;
};
const leaf = (a: string) => ({ attr: a });

describe('normalizePolicy', () => {
  it('leaf and gates', () => {
    expect(N(leaf('a'))).toEqual({ ok: true, tree: { kind: 'leaf', attr: 'a' } });
    expect(N({ allOf: [leaf('a'), leaf('b')] })).toEqual({ ok: true, tree: { kind: 'gate', t: 2, of: [{ kind: 'leaf', attr: 'a' }, { kind: 'leaf', attr: 'b' }] } });
    expect(N({ anyOf: [leaf('a'), leaf('b'), leaf('c')] })).toMatchObject({ ok: true, tree: { kind: 'gate', t: 1 } });
    expect(N({ threshold: 2, of: [leaf('a'), leaf('b'), leaf('c')] })).toMatchObject({ ok: true, tree: { kind: 'gate', t: 2 } });
    expect(N({ threshold: 3, of: [leaf('a'), leaf('b'), leaf('c')] })).toMatchObject({ ok: true, tree: { t: 3 } });
  });
  it('reasons', () => {
    for (const bad of [null, 5, 'x', [], undefined]) expect(N(bad)).toEqual(R('policy: not an object'));
    for (const a of ['', 5, null]) expect(N({ attr: a })).toEqual(R("policy: 'attr' must be a non-empty string"));
    expect(N({ attr: 'a\ud800' })).toEqual(R("policy: 'attr' is not well-formed UTF-16"));
    for (const k of ['allOf', 'anyOf', 'threshold', 'of']) expect(N({ attr: 'a', [k]: [] })).toEqual(R("policy: a leaf must not mix 'attr' with a gate"));
    expect(N({ allOf: [leaf('a')], anyOf: [leaf('a')] })).toEqual(R('policy: ambiguous node (allOf, anyOf); a gate must use exactly one of allOf/anyOf/threshold'));
    expect(N({ allOf: [leaf('a')], threshold: 1, of: [leaf('a')] })).toEqual(R('policy: ambiguous node (allOf, threshold); a gate must use exactly one of allOf/anyOf/threshold'));
    expect(N({ anyOf: [leaf('a')], of: [leaf('a')] })).toEqual(R('policy: ambiguous node (anyOf, of); a gate must use exactly one of allOf/anyOf/threshold'));
    for (const v of [[], 'x', null, undefined]) {
      expect(N({ allOf: v })).toEqual(R("policy: 'allOf' must be a non-empty array"));
      expect(N({ anyOf: v })).toEqual(R("policy: 'anyOf' must be a non-empty array"));
      expect(N({ threshold: 1, of: v })).toEqual(R("policy: 'of' must be a non-empty array"));
    }
    for (const t of [0, -1, 1.5, '1', NaN]) expect(N({ threshold: t, of: [leaf('a')] })).toEqual(R("policy: 'threshold' must be a positive integer"));
    expect(N({ threshold: 3, of: [leaf('a'), leaf('b')] })).toEqual(R('policy: threshold 3 exceeds the number of branches (2)'));
    expect(N({})).toEqual(R('policy: unknown policy node (expected attr/allOf/anyOf/threshold)'));
    expect(N({ of: [leaf('a')] })).toEqual(R('policy: unknown policy node (expected attr/allOf/anyOf/threshold)'));
    expect(N({ allOf: [leaf('a'), 5] })).toEqual(R('policy.allOf[1]: not an object'));
    expect(N({ anyOf: [{ allOf: [{ attr: '' }] }] })).toEqual(R("policy.anyOf[0].allOf[0]: 'attr' must be a non-empty string"));
    expect(N({ threshold: 1, of: [leaf('a'), {}] })).toEqual(R('policy.of[1]: unknown policy node (expected attr/allOf/anyOf/threshold)'));
  });
  it('depth bound is exact', () => {
    const nest = (d: number): unknown => (d === 0 ? leaf('a') : { allOf: [nest(d - 1)] });
    expect(N(nest(MAX_POLICY_DEPTH)).ok).toBe(true);
    const r = N(nest(MAX_POLICY_DEPTH + 1)) as { ok: false; reason: string };
    expect(r.ok).toBe(false);
    expect(r.reason).toContain(`policy`);
    expect(r.reason).toContain(`nested deeper than ${MAX_POLICY_DEPTH} gates`);
  });
  it('node bound is exact', () => {
    const wide = (n: number) => ({ allOf: Array.from({ length: n }, (_, i) => leaf(`a${i}`)) });
    expect(N(wide(MAX_POLICY_NODES - 1)).ok).toBe(true);
    expect(N(wide(MAX_POLICY_NODES))).toEqual(R(`policy too large (> ${MAX_POLICY_NODES} nodes)`));
  });
  it('satisfies / policyAttributes', () => {
    const t = treeOf({ threshold: 2, of: [leaf('a'), leaf('b'), { anyOf: [leaf('c'), leaf('d')] }] });
    expect(satisfies(t, new Set(['a']))).toBe(false);
    expect(satisfies(t, new Set(['a', 'b']))).toBe(true);
    expect(satisfies(t, new Set(['a', 'd']))).toBe(true);
    expect(satisfies(t, new Set(['c', 'd']))).toBe(false);
    expect(satisfies(t, new Set())).toBe(false);
    expect([...policyAttributes(t)].sort()).toEqual(['a', 'b', 'c', 'd']);
    const into = new Set(['z']);
    expect(policyAttributes(t, into)).toBe(into);
    expect(into.has('z') && into.has('a')).toBe(true);
  });
});

describe('secret sharing', () => {
  it('splitSecret bounds', () => {
    for (const [t, n] of [[0, 3], [4, 3], [1.5, 3], [2, 2.5], [1, 0], [-1, 3]] as const) expect(err(() => splitSecret(5n, t, n)).message).toBe(`splitSecret: need 1 <= t(${t}) <= n(${n})`);
    expect(splitSecret(5n, 1, 1)).toEqual([{ x: 1n, y: 5n }]);
    expect(splitSecret(5n, 3, 3).map((s) => s.x)).toEqual([1n, 2n, 3n]);
    expect(splitSecret(5n, 1, 4).every((s) => s.y === 5n)).toBe(true);
  });
  it('recovery: exactly t shares, any subset, order-insensitive; t-1 reveals nothing useful', () => {
    const s = randomSecret().scalar;
    const sh = splitSecret(s, 3, 5);
    expect(recoverSecret([sh[0]!, sh[2]!, sh[4]!])).toBe(s);
    expect(recoverSecret([sh[4]!, sh[1]!, sh[3]!])).toBe(s);
    expect(recoverSecret(sh)).toBe(s);
    expect(recoverSecret([sh[0]!, sh[1]!])).not.toBe(s);
    expect(recoverSecret([])).toBeNull();
    expect(recoverSecret([sh[0]!, sh[0]!])).toBeNull();
    expect(recoverSecret([{ x: 0n, y: 5n }])).toBeNull();
  });
  it('lagrange coefficients at zero', () => {
    expect(lagrangeAtZero([])).toBeNull();
    expect(lagrangeAtZero([0n, 1n])).toBeNull();
    expect(lagrangeAtZero([1n, 1n])).toBeNull();
    expect(lagrangeAtZero([1n])).toEqual([1n]);
    const c = lagrangeAtZero([1n, 2n])!;
    const R_ = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;
    expect(c[0]).toBe(2n);
    expect(c[1]).toBe(R_ - 1n);
    expect(lagrangeAtZero([1n, 1n + R_])).toBeNull();
    expect(lagrangeAtZero([R_, 1n])).toBeNull();
  });
  it('randomSecret bytes are the 32-byte big-endian scalar', () => {
    const r = randomSecret();
    expect(r.bytes.length).toBe(32);
    expect(BigInt('0x' + Buffer.from(r.bytes).toString('hex'))).toBe(r.scalar);
  });
});

describe('aead', () => {
  const key = new Uint8Array(32).fill(7);
  const aad = new TextEncoder().encode('aad');
  const pt = new TextEncoder().encode('secret');
  it('round trip and tamper detection on every field', () => {
    const s = seal(key, pt, aad);
    expect(s.iv.length).toBe(12);
    expect(s.tag.length).toBe(16);
    expect(s.ct.length).toBe(pt.length);
    expect(open(key, s, aad)).toEqual(pt);
    expect(open(key, { ...s, ct: Uint8Array.from(s.ct, (b, i) => (i === 0 ? b ^ 1 : b)) }, aad)).toBeNull();
    expect(open(key, { ...s, tag: Uint8Array.from(s.tag, (b, i) => (i === 0 ? b ^ 1 : b)) }, aad)).toBeNull();
    expect(open(key, { ...s, iv: Uint8Array.from(s.iv, (b, i) => (i === 0 ? b ^ 1 : b)) }, aad)).toBeNull();
    expect(open(key, s, new TextEncoder().encode('aae'))).toBeNull();
    expect(open(new Uint8Array(32).fill(8), s, aad)).toBeNull();
    expect(open(key.subarray(0, 31), s, aad)).toBeNull();
    expect(open(new Uint8Array(33), s, aad)).toBeNull();
    expect(open(key, { ...s, iv: s.iv.subarray(0, 11) }, aad)).toBeNull();
    expect(open(key, { ...s, iv: new Uint8Array(13) }, aad)).toBeNull();
    expect(open(key, { ...s, tag: s.tag.subarray(0, 15) }, aad)).toBeNull();
    expect(open(key, { ...s, tag: new Uint8Array(17) }, aad)).toBeNull();
  });
  it('seal key length and fresh IVs', () => {
    expect(err(() => seal(new Uint8Array(31), pt, aad)).message).toBe('aead.seal: key must be 32 bytes');
    expect(err(() => seal(new Uint8Array(33), pt, aad)).message).toBe('aead.seal: key must be 32 bytes');
    expect(Buffer.from(seal(key, pt, aad).iv).equals(Buffer.from(seal(key, pt, aad).iv))).toBe(false);
    expect(open(key, seal(key, new Uint8Array(0), aad), aad)).toEqual(new Uint8Array(0));
  });
});

describe('wire helpers', () => {
  it('unb64u is canonical and strict', () => {
    expect(unb64u('')).toEqual(new Uint8Array(0));
    expect(unb64u(b64u(Uint8Array.of(1, 2, 3)))).toEqual(Uint8Array.of(1, 2, 3));
    for (const bad of [5, null, undefined, 'a+b', 'a/b', 'ab=', 'a b', 'A', 'QUJD\n', 'QR']) expect(unb64u(bad)).toBeNull();
    expect(unb64u('QQ')).toEqual(Uint8Array.of(0x41));
    expect(unb64u('QR')).toBeNull(); // non-zero trailing bits
  });
  it('type guards', () => {
    expect(isObject({})).toBe(true);
    for (const x of [null, [], 5, 'x', undefined]) expect(isObject(x)).toBe(false);
    expect(isString('')).toBe(true);
    expect(isString(5)).toBe(false);
    expect(isPosInt(1)).toBe(true);
    for (const x of [0, -1, 1.5, '1', NaN, Infinity, null]) expect(isPosInt(x)).toBe(false);
  });
  it('attribute names', () => {
    expect(Attr.holder('k')).toBe('holder:k');
    expect(Attr.verb('v')).toBe('verb:v');
    expect(Attr.resource('r')).toBe('resource:r');
    expect(Attr.scope('s')).toBe('scope:s');
    expect(Attr.act('v', 'r')).toBe('act:["v","r"]');
  });
});
