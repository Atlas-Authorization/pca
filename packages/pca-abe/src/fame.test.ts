import { describe, expect, it } from 'vitest';
import {
  type AbeCiphertext,
  type Policy,
  PcaEncryptionError,
  decrypt,
  decryptText,
  encryptForPolicy,
  keygenForAttributes,
  normalizePolicy,
  parseCiphertext,
  satisfies,
  setup,
} from './index';
import { buildRows, firstRepeatedAttribute, reconstructionWeights } from './fame';
import { R, frMul, frAdd } from './bls';
import { lagrangeAtZero } from './sss';

const PT = 'top-secret tool result \u{1f510}';
const leaf = (a: string): Policy => ({ attr: a });
const tree = (p: Policy) => {
  const n = normalizePolicy(p);
  if (!n.ok) throw new Error(n.reason);
  return n.tree;
};

describe('FAME CP-ABE: access structures', () => {
  const { mpk, msk } = setup();
  const P: Policy = { allOf: [leaf('holder:x'), { anyOf: [leaf('verb:read'), leaf('verb:write')] }, { threshold: 2, of: [leaf('d'), leaf('e'), leaf('f')] }] };
  const { ciphertext } = encryptForPolicy(mpk, P, PT);

  it('decrypts for every satisfying set and refuses every other, matching the boolean oracle', () => {
    const universe = ['holder:x', 'verb:read', 'verb:write', 'd', 'e', 'f', 'other'];
    const t = tree(P);
    for (let mask = 0; mask < 1 << universe.length; mask += 7) {
      const attrs = universe.filter((_, i) => mask & (1 << i));
      const want = satisfies(t, new Set(attrs));
      expect(decryptText(keygenForAttributes(msk, attrs), ciphertext), attrs.join(',')).toBe(want ? PT : null);
    }
  });

  it('a key from another master cannot decrypt', () => {
    const other = setup();
    expect(decryptText(keygenForAttributes(other.msk, ['holder:x', 'verb:read', 'd', 'e']), ciphertext)).toBeNull();
  });

  it('collusion: attribute components of two keys do not combine, whole or by component', () => {
    const k1 = keygenForAttributes(msk, ['holder:x', 'd']);
    const k2 = keygenForAttributes(msk, ['verb:read', 'e']);
    expect(decryptText({ ...k1, attrs: { ...k1.attrs, ...k2.attrs } }, ciphertext)).toBeNull();
    expect(decryptText({ ...k2, attrs: { ...k1.attrs, ...k2.attrs } }, ciphertext)).toBeNull();
  });

  it('a key holding a relabelled component does not decrypt', () => {
    const k = keygenForAttributes(msk, ['holder:x', 'd', 'e', 'verb:read']);
    const swapped = { ...k, attrs: { ...k.attrs, 'verb:write': k.attrs['verb:read']!, 'verb:read': k.attrs['holder:x']! } };
    expect(decryptText(swapped, ciphertext)).toBeNull();
  });

  it('every key is freshly randomised: two keys for the same attributes share no component', () => {
    const a = keygenForAttributes(msk, ['holder:x']);
    const b = keygenForAttributes(msk, ['holder:x']);
    expect(a.k0).not.toEqual(b.k0);
    expect(a.attrs['holder:x']).not.toEqual(b.attrs['holder:x']);
  });
});

describe('FAME CP-ABE: span program', () => {
  it('every row has 1 in the secret column and the tree weights solve sum w_i M_i = e1', () => {
    const t = tree({ allOf: [leaf('a'), { threshold: 2, of: [leaf('b'), leaf('c'), leaf('d')] }, { anyOf: [leaf('e'), leaf('f')] }] });
    const rows = buildRows(t);
    expect(rows.map((r) => r.attr)).toEqual(['a', 'b', 'c', 'd', 'e', 'f']);
    for (const r of rows) expect(r.vec.get(0)).toBe(1n);
    const w = reconstructionWeights(t, (x) => ['a', 'b', 'd', 'f'].includes(x));
    expect(w).not.toBeNull();
    const total = new Map<number, bigint>();
    for (const [i, wi] of w!) for (const [j, m] of rows[i]!.vec) total.set(j, (((total.get(j) ?? 0n) + wi * m) % R + R) % R);
    expect(total.get(0)).toBe(1n);
    for (const [j, v] of total) if (j !== 0) expect(v).toBe(0n);
  });
  it('an unsatisfied attribute set yields no weights', () => {
    expect(reconstructionWeights(tree({ allOf: [leaf('a'), leaf('b')] }), (x) => x === 'a')).toBeNull();
  });
  it('reports a repeated attribute', () => {
    expect(firstRepeatedAttribute(tree({ anyOf: [leaf('a'), { allOf: [leaf('b'), leaf('a')] }] }))).toBe('a');
    expect(firstRepeatedAttribute(tree({ anyOf: [leaf('a'), leaf('b')] }))).toBeNull();
  });
});

describe('FAME CP-ABE: the Lagrange coefficients satisfy the moment equations used by the Lean span-program proof', () => {
  it('sum_i lambda_i * x_i^k = [k = 0] for every k < number of points, for several point sets', () => {
    for (const xs of [[1n], [1n, 2n], [2n, 3n, 5n], [1n, 3n, 4n, 7n, 9n], [4n, 5n, 6n, 7n]]) {
      const lam = lagrangeAtZero(xs);
      expect(lam).not.toBeNull();
      for (let k = 0; k < xs.length; k++) {
        let acc = 0n;
        xs.forEach((x, i) => {
          let pw = 1n;
          for (let e = 0; e < k; e++) pw = frMul(pw, x);
          acc = frAdd(acc, frMul(lam![i]!, pw));
        });
        expect(acc, `points ${xs.join(',')} moment ${k}`).toBe(k === 0 ? 1n : 0n);
      }
    }
  });
});

describe('FAME CP-ABE: missing X gives Y (fail-closed table)', () => {
  const { mpk, msk } = setup();
  const { ciphertext: ct } = encryptForPolicy(mpk, leaf('a'), PT);
  const key = keygenForAttributes(msk, ['a']);
  const flip = (s: string): string => {
    const b = Buffer.from(s, 'base64url');
    b[0] = (b[0] ?? 0) ^ 1;
    return b.toString('base64url');
  };

  const rows: [string, () => unknown][] = [
    ['ciphertext missing entirely', () => decrypt(key, undefined)],
    ['ciphertext not an object', () => decrypt(key, 42)],
    ['ciphertext of the old format (v1)', () => decrypt(key, { ...ct, v: 1 })],
    ['ciphertext with a wrong algorithm', () => decrypt(key, { ...ct, alg: 'bsw07-cpabe-bls12381-type3/lsss/aes-256-gcm' })],
    ['ciphertext without rows', () => decrypt(key, { ...ct, rows: undefined })],
    ['ciphertext with an extra row', () => decrypt(key, { ...ct, rows: [...ct.rows, ct.rows[0]] })],
    ['ciphertext with a short row', () => decrypt(key, { ...ct, rows: [[ct.rows[0]![0], ct.rows[0]![1]]] })],
    ['ciphertext with a row point off the curve', () => decrypt(key, { ...ct, rows: [[flip(ct.rows[0]![0]), ct.rows[0]![1], ct.rows[0]![2]]] })],
    ['ciphertext with a flipped C0', () => decrypt(key, { ...ct, ct0: [flip(ct.ct0[0]), ct.ct0[1], ct.ct0[2]] })],
    ['ciphertext with a tampered tree', () => decrypt(key, { ...ct, tree: { kind: 'leaf', attr: 'b' } })],
    ['ciphertext with a tampered payload', () => decrypt(key, { ...ct, ct: flip(ct.ct) })],
    ['ciphertext with a tampered tag', () => decrypt(key, { ...ct, tag: flip(ct.tag) })],
    ['ciphertext with an unknown tree node kind', () => decrypt(key, { ...ct, tree: { kind: 'x' } })],
    ['ciphertext with a repeated attribute in the tree', () => decrypt(key, { ...ct, tree: { kind: 'gate', t: 1, of: [{ kind: 'leaf', attr: 'a' }, { kind: 'leaf', attr: 'a' }] }, rows: [ct.rows[0], ct.rows[0]] })],
    ['key missing', () => decrypt(undefined as never, ct)],
    ['key with no K0', () => decrypt({ ...key, k0: undefined } as never, ct)],
    ['key with a K0 of the wrong length', () => decrypt({ ...key, k0: [key.k0[0], key.k0[1]] } as never, ct)],
    ['key with no attributes object', () => decrypt({ ...key, attrs: undefined } as never, ct)],
    ['key whose only attribute component is malformed', () => decrypt({ ...key, attrs: { a: { k: ['x', 'y', 'z'] } } } as never, ct)],
    ['key with inherited (not own) attributes', () => decrypt({ ...key, attrs: Object.create(key.attrs) } as never, ct)],
    ['key of the wrong version', () => decrypt({ ...key, v: 1 } as never, ct)],
  ];
  for (const [name, run] of rows) it(`${name} -> null, never a throw`, () => expect(run()).toBeNull());

  it('encrypt: invalid policy -> PcaEncryptionError', () => {
    expect(() => encryptForPolicy(mpk, { allOf: [] } as never, PT)).toThrow(PcaEncryptionError);
    expect(() => encryptForPolicy(mpk, { attr: '' }, PT)).toThrow(PcaEncryptionError);
  });
  it('encrypt: an attribute named by two leaves -> PcaEncryptionError (single-use attributes)', () => {
    expect(() => encryptForPolicy(mpk, { anyOf: [leaf('a'), leaf('a')] }, PT)).toThrow(/more than one leaf/);
  });
  it('encrypt: malformed public key -> PcaEncryptionError', () => {
    expect(() => encryptForPolicy(undefined as never, leaf('a'), PT)).toThrow(PcaEncryptionError);
    expect(() => encryptForPolicy({ ...mpk, v: 1 } as never, leaf('a'), PT)).toThrow(/invalid master public key/);
    expect(() => encryptForPolicy({ ...mpk, h: [mpk.h[0]] } as never, leaf('a'), PT)).toThrow(/invalid master public key/);
    expect(() => encryptForPolicy({ ...mpk, t: [mpk.t[0], 'AAAA'] } as never, leaf('a'), PT)).toThrow(/invalid master public key/);
  });
  it('keygen: malformed master secret key -> PcaEncryptionError', () => {
    expect(() => keygenForAttributes(undefined as never, ['a'])).toThrow(/invalid master secret key/);
    expect(() => keygenForAttributes({ ...msk, a: ['AAAA', 'AAAA'] } as never, ['a'])).toThrow(/invalid master secret key/);
    expect(() => keygenForAttributes({ ...msk, g: [msk.g[0], msk.g[1]] } as never, ['a'])).toThrow(/invalid master secret key/);
  });
  it('parseCiphertext accepts a fresh ciphertext and round-trips through JSON', () => {
    const parsed = parseCiphertext(JSON.parse(JSON.stringify(ct)) as unknown) as AbeCiphertext;
    expect(parsed).toEqual(ct);
  });
});
