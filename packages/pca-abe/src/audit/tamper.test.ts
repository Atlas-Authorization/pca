import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  type AbeCiphertext,
  MAX_POLICY_NODES,
  decrypt,
  encryptForPolicy,
  keygenForAttributes,
  parseCiphertext,
  setup,
} from '../index';
import { b64, clone, flipBit, leaves } from './_helpers';

const PT = new TextEncoder().encode('malleability target \u{1f510}');
const policy = { allOf: [{ attr: 'a' }, { anyOf: [{ attr: 'b' }, { attr: 'c' }] }] };

function fixture() {
  const { mpk, msk } = setup();
  const key = keygenForAttributes(msk, ['a', 'b', 'c']);
  const { ciphertext } = encryptForPolicy(mpk, policy, PT);
  expect(decrypt(key, ciphertext)).toEqual(PT);
  return { mpk, msk, key, ciphertext };
}

describe('ciphertext integrity: every single-bit change anywhere is rejected (CCA-style mutation oracle)', () => {
  it('flipping one bit of salt / iv / ct / tag / c0 / any leaf C / any leaf Cp returns null, never throws', () => {
    const { key, ciphertext } = fixture();
    const mutations: [string, (c: AbeCiphertext) => void][] = [
      ['salt', (c) => (c.salt = flipBit(c.salt, 5))],
      ['iv', (c) => (c.iv = flipBit(c.iv, 3))],
      ['ct', (c) => (c.ct = flipBit(c.ct, 9))],
      ['tag', (c) => (c.tag = flipBit(c.tag, 17))],
      ['c0', (c) => (c.c0 = flipBit(c.c0, 21))],
    ];
    const nLeaves = leaves(ciphertext.kem).length;
    for (let i = 0; i < nLeaves; i++) {
      mutations.push([`leaf${i}.c`, (c) => { const l = leaves(c.kem)[i]!; l.c = flipBit(l.c, 11 + i); }]);
      mutations.push([`leaf${i}.cp`, (c) => { const l = leaves(c.kem)[i]!; l.cp = flipBit(l.cp, 7 + i); }]);
      mutations.push([`leaf${i}.attr`, (c) => { const l = leaves(c.kem)[i]!; l.attr = l.attr + 'x'; }]);
    }
    for (const [name, mutate] of mutations) {
      const c = clone(ciphertext);
      mutate(c);
      expect(() => decrypt(key, c), name).not.toThrow();
      expect(decrypt(key, c), name).toBeNull();
    }
  });

  it('flipping a stride of bits across tag, iv and the first leaf Cp is rejected', () => {
    const { key, ciphertext } = fixture();
    const lf = leaves(ciphertext.kem)[0]!;
    for (let bit = 0; bit < 128; bit += 7) {
      const c = clone(ciphertext);
      c.tag = flipBit(c.tag, bit);
      expect(decrypt(key, c)).toBeNull();
    }
    for (let bit = 0; bit < 96; bit += 7) {
      const c = clone(ciphertext);
      c.iv = flipBit(c.iv, bit);
      expect(decrypt(key, c)).toBeNull();
    }
    for (let bit = 0; bit < 384; bit += 19) {
      const c = clone(ciphertext);
      const l = leaves(c.kem)[0]!;
      l.cp = flipBit(lf.cp, bit);
      expect(decrypt(key, c)).toBeNull();
    }
  });

  it('structure tampering (threshold downgrade, branch reorder/relabel, dropped branch, swapped alg/version) is rejected', () => {
    const { key, ciphertext } = fixture();
    const attempts: [string, (c: AbeCiphertext) => void][] = [
      ['downgrade AND to 1-of-2', (c) => { if (c.kem.kind === 'gate') c.kem.t = 1; }],
      ['reverse branch order', (c) => { if (c.kem.kind === 'gate') c.kem.of.reverse(); }],
      ['relabel branch indices', (c) => { if (c.kem.kind === 'gate') for (const b of c.kem.of) b.i += 1; }],
      ['drop a branch', (c) => { if (c.kem.kind === 'gate') c.kem.of.pop(); }],
      ['alg swap', (c) => ((c as { alg: string }).alg = 'none')],
      ['version bump', (c) => ((c as { v: number }).v = 2)],
    ];
    for (const [name, f] of attempts) {
      const c = clone(ciphertext);
      f(c);
      expect(decrypt(key, c), name).toBeNull();
    }
  });

  it('a partial-key holder cannot downgrade the gate to learn the secret: a=only, t:=1 yields null', () => {
    const { msk, ciphertext } = fixture();
    const partial = keygenForAttributes(msk, ['a']);
    const c = clone(ciphertext);
    if (c.kem.kind === 'gate') c.kem.t = 1;
    expect(decrypt(partial, c)).toBeNull();
  });

  it('splicing a leaf or whole subtree from another ciphertext of the SAME policy fails', () => {
    const { mpk, msk, key, ciphertext } = fixture();
    const other = encryptForPolicy(mpk, policy, new TextEncoder().encode('other')).ciphertext;
    expect(decrypt(keygenForAttributes(msk, ['a', 'b']), other)).not.toBeNull();
    const c = clone(ciphertext);
    const l0 = leaves(c.kem)[0]!;
    const o0 = leaves(other.kem)[0]!;
    l0.c = o0.c;
    l0.cp = o0.cp;
    expect(decrypt(key, c)).toBeNull();
    const d = clone(ciphertext);
    d.kem = clone(other).kem;
    expect(decrypt(key, d)).toBeNull(); // header from B with body/tag from A
  });

  it('body/tag/iv from one ciphertext cannot be transplanted onto another header', () => {
    const { mpk, key, ciphertext } = fixture();
    const other = encryptForPolicy(mpk, policy, PT).ciphertext;
    for (const field of ['iv', 'ct', 'tag', 'salt'] as const) {
      const c = clone(ciphertext);
      c[field] = other[field];
      expect(decrypt(key, c), field).toBeNull();
    }
  });

  it('truncated / extended / empty AEAD fields and wrong-length IV are rejected', () => {
    const { key, ciphertext } = fixture();
    const trunc = (s: string, n: number) => b64(new Uint8Array(Buffer.from(s, 'base64url')).slice(0, n));
    const ext = (s: string) => b64(new Uint8Array([...Buffer.from(s, 'base64url'), 0]));
    for (const [f, mut] of [
      ['tag', (c: AbeCiphertext) => (c.tag = trunc(c.tag, 4))],
      ['tag-ext', (c: AbeCiphertext) => (c.tag = ext(c.tag))],
      ['tag-empty', (c: AbeCiphertext) => (c.tag = '')],
      ['iv-short', (c: AbeCiphertext) => (c.iv = trunc(c.iv, 8))],
      ['iv-ext', (c: AbeCiphertext) => (c.iv = ext(c.iv))],
      ['ct-trunc', (c: AbeCiphertext) => (c.ct = trunc(c.ct, 3))],
      ['ct-empty', (c: AbeCiphertext) => (c.ct = '')],
      ['salt-empty', (c: AbeCiphertext) => (c.salt = '')],
    ] as const) {
      const c = clone(ciphertext);
      mut(c);
      expect(decrypt(key, c), f).toBeNull();
    }
  });

  it('non-canonical base64url (padding, standard alphabet, trailing bits, whitespace) is rejected', () => {
    const { key, ciphertext } = fixture();
    const c1 = clone(ciphertext);
    c1.tag = c1.tag + '=';
    expect(decrypt(key, c1)).toBeNull();
    const c2 = clone(ciphertext);
    c2.ct = c2.ct + '\n';
    expect(decrypt(key, c2)).toBeNull();
    const c3 = clone(ciphertext);
    c3.iv = c3.iv.replace(/[-_]/g, '+');
    // only changes anything when the alphabet char appears; force one:
    c3.iv = c3.iv.slice(0, -1) + '+';
    expect(decrypt(key, c3)).toBeNull();
    // trailing-bit variation: last char of a 12-byte (16 char, no slack) IV has none; use the 16-byte tag (22 chars, 4 slack bits).
    const c4 = clone(ciphertext);
    const last = c4.tag.slice(-1);
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const alt = alphabet[(alphabet.indexOf(last) + 1) % 64]!;
    c4.tag = c4.tag.slice(0, -1) + alt; // differs only in unused trailing bits OR in data bits; either way must fail
    expect(decrypt(key, c4)).toBeNull();
  });

  it('extra top-level fields are ignored (documented: parseCiphertext re-builds the object); they do not change the plaintext', () => {
    const { key, ciphertext } = fixture();
    const c = { ...clone(ciphertext), evil: 'x', __proto__: { y: 1 } } as unknown;
    expect(decrypt(key, c)).toEqual(PT);
    const parsed = parseCiphertext(c);
    expect(parsed).not.toBeNull();
    expect(Object.keys(parsed!).sort()).toEqual(['alg', 'c0', 'ct', 'iv', 'kem', 'salt', 'tag', 'v']);
  });

  it('the plaintext is bound to the whole header: re-encrypting the same plaintext gives unrelated ciphertexts (fresh salt, s, shares, IV)', () => {
    const { mpk } = fixture();
    const a = encryptForPolicy(mpk, policy, PT).ciphertext;
    const b = encryptForPolicy(mpk, policy, PT).ciphertext;
    expect(a.salt).not.toBe(b.salt);
    expect(a.iv).not.toBe(b.iv);
    expect(a.ct).not.toBe(b.ct);
    const ua = [a.c0, ...leaves(a.kem).map((l) => l.c)];
    const ub = [b.c0, ...leaves(b.kem).map((l) => l.c)];
    expect(ua.some((u) => ub.includes(u))).toBe(false);
    // every leaf inside ONE ciphertext also carries a fresh share, even for the same attribute
    const dup = encryptForPolicy(mpk, { allOf: [{ attr: 'a' }, { attr: 'a' }] }, PT).ciphertext;
    const du = leaves(dup.kem);
    expect(du[0]!.c).not.toBe(du[1]!.c);
    expect(du[0]!.cp).not.toBe(du[1]!.cp);
  });
});

describe('malformed and hostile ciphertexts never throw and never decrypt', () => {
  it('fuzz: arbitrary JSON values', () => {
    const { key } = fixture();
    fc.assert(
      fc.property(fc.anything({ maxDepth: 4 }), (x) => {
        expect(() => decrypt(key, x)).not.toThrow();
        return decrypt(key, x) === null;
      }),
      { numRuns: 400 },
    );
  });

  it('fuzz: structurally valid ciphertexts with random field contents', () => {
    const { key, ciphertext } = fixture();
    fc.assert(
      fc.property(fc.string(), fc.string(), fc.string(), fc.string(), (salt, iv, ct, tag) => {
        const c = { ...clone(ciphertext), salt, iv, ct, tag };
        expect(() => decrypt(key, c)).not.toThrow();
        return decrypt(key, c) === null;
      }),
      { numRuns: 200 },
    );
  });

  it('hostile keys: null, wrong shapes, non-point strings, giant maps', () => {
    const { ciphertext } = fixture();
    const keys: unknown[] = [
      null,
      undefined,
      {},
      { attrs: null },
      { attrs: [] },
      { d: 'AAAA', attrs: {} },
      { d: 5, attrs: { a: { dj: 'AAAA', dpj: 'AAAA' } } },
      { attrs: { a: { dj: 'AAAA', dpj: 'AAAA' } } },
      { d: '!!!', attrs: { a: 5, b: null, c: {} } },
      { d: '', attrs: { a: '!!!', b: '', c: 'AAAA' } },
      { attrs: Object.fromEntries(Array.from({ length: 2000 }, (_, i) => [`k${i}`, { dj: 'AAAA', dpj: 'AAAA' }])) },
    ];
    for (const k of keys) {
      expect(() => decrypt(k as never, ciphertext)).not.toThrow();
      expect(decrypt(k as never, ciphertext)).toBeNull();
    }
  });

  it('DoS bound: a ciphertext claiming far more nodes than any policy may have is refused at parse time', () => {
    const { key, ciphertext } = fixture();
    const lf = leaves(ciphertext.kem)[0]!;
    const c = clone(ciphertext);
    c.kem = {
      kind: 'gate',
      t: 1,
      of: Array.from({ length: MAX_POLICY_NODES * 4 }, (_, i) => ({ i: i + 1, sub: { kind: 'leaf', attr: 'a', c: lf.c, cp: lf.cp } })),
    };
    expect(parseCiphertext(c)).toBeNull();
    const t0 = performance.now();
    expect(decrypt(key, c)).toBeNull();
    expect(performance.now() - t0).toBeLessThan(500);
  });

  it('decrypt never throws on over-deep nesting (the canonical-AAD depth limit must not leak out as an exception)', () => {
    const { key, ciphertext } = fixture();
    const lf = leaves(ciphertext.kem)[0]!;
    let node: AbeCiphertext['kem'] = { kind: 'leaf', attr: 'a', c: lf.c, cp: lf.cp };
    for (let i = 0; i < 40; i++) node = { kind: 'gate', t: 1, of: [{ i: 1, sub: node }] };
    const c = { ...clone(ciphertext), kem: node };
    expect(() => decrypt(key, c)).not.toThrow();
    expect(decrypt(key, c)).toBeNull();
  });

  it('branch indices must be the canonical 1..n sequence (duplicate / zero / huge / out-of-order indices are refused)', () => {
    const { ciphertext } = fixture();
    const g = (mut: (c: AbeCiphertext) => void) => { const c = clone(ciphertext); mut(c); return parseCiphertext(c); };
    expect(g((c) => { if (c.kem.kind === 'gate') c.kem.of[1]!.i = c.kem.of[0]!.i; })).toBeNull();
    expect(g((c) => { if (c.kem.kind === 'gate') c.kem.of[1]!.i = 2 ** 60; })).toBeNull();
    expect(g((c) => { if (c.kem.kind === 'gate') c.kem.of[0]!.i = 0; })).toBeNull();
    expect(g((c) => { if (c.kem.kind === 'gate') c.kem.of.reverse(); })).toBeNull();
    expect(g(() => undefined)).not.toBeNull();
  });
});

describe('payload edge cases', () => {
  it('empty and large plaintexts round-trip; plaintext length is the only thing the ciphertext reveals about the payload', () => {
    const { mpk, msk } = setup();
    const key = keygenForAttributes(msk, ['a']);
    for (const n of [0, 1, 15, 16, 17, 4096, 70000]) {
      const pt = new Uint8Array(n).map((_, i) => i & 0xff);
      const { ciphertext } = encryptForPolicy(mpk, { attr: 'a' }, pt);
      expect(decrypt(key, ciphertext)).toEqual(pt);
      expect(Buffer.from(ciphertext.ct, 'base64url').length).toBe(n);
    }
  });
});
