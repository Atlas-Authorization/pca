/** Mutation kills for abe.ts: key/ciphertext shape validation, exact errors, wire constants and key hygiene. */
import { describe, expect, it } from 'vitest';
import { ABE_ALG, PcaEncryptionError, decrypt, decryptText, encryptForPolicy, keygenForAttributes, keygenForCapability, parseCiphertext, rerandomizeKey, setup } from './abe';
import { MAX_POLICY_DEPTH, MAX_POLICY_NODES } from './policy';
import { b64u } from './wire';

const err = (f: () => unknown): Error => { try { f(); } catch (e) { return e as Error; } throw new Error('no throw'); };
const clone = <T,>(x: T): T => JSON.parse(JSON.stringify(x));
const pol = { allOf: [{ attr: 'a' }, { threshold: 1, of: [{ attr: 'b' }, { attr: 'c' }] }] };
/** Built inside each test so Stryker's per-test coverage attributes setup/keygen/encrypt mutants to it. */
function fx() {
  const { mpk, msk } = setup();
  const { ciphertext: ct } = encryptForPolicy(mpk, pol, 'hello');
  const key = keygenForAttributes(msk, ['a', 'b']);
  return { mpk, msk, ct, key };
}

describe('constants and shapes', () => {
  it('curve tags and error name', () => {
    const { mpk, msk, key } = fx();
    expect(mpk.curve).toBe('bls12-381'); expect(msk.curve).toBe('bls12-381'); expect(key.curve).toBe('bls12-381');
    expect(rerandomizeKey(mpk, key).curve).toBe('bls12-381');
    expect(new PcaEncryptionError('x').name).toBe('PcaEncryptionError');
  });
  it('master secret / public key validation', () => {
    const { mpk, msk } = fx();
    const m = 'invalid master secret key';
    for (const bad of [null, undefined, {}, { ...msk, alpha: 5 }, { ...msk, beta: 5 }, { ...msk, alpha: b64u(new Uint8Array(32)) }, { ...msk, beta: b64u(new Uint8Array(32)) }, { ...msk, alpha: b64u(new Uint8Array(32).fill(255)) }]) {
      expect(err(() => keygenForAttributes(bad as never, ['a'])).message).toBe(m);
    }
    const p = 'invalid master public key';
    for (const bad of [null, undefined, {}, { ...mpk, h: 5 }, { ...mpk, f: 5 }, { ...mpk, egga: 5 }, { ...mpk, h: 'x!' }, { ...mpk, f: 'AA' }, { ...mpk, egga: 'AA' }]) {
      expect(err(() => encryptForPolicy(bad as never, { attr: 'a' }, 'x')).message).toBe(p);
    }
    const other = setup();
    expect(err(() => encryptForPolicy({ ...mpk, h: other.mpk.h }, { attr: 'a' }, 'x')).message).toBe(p);
    expect(err(() => encryptForPolicy({ ...mpk, h: other.mpk.h }, { attr: 'a' }, 'x')).message).toBe(p); // second call must not be served from a memo
    expect(() => encryptForPolicy(mpk, { attr: 'a' }, 'x')).not.toThrow();
  });
  it('mpk memo evicts the oldest entry beyond its bound yet stays correct', () => {
    fx();
    const ms = Array.from({ length: 20 }, () => setup().mpk);
    for (const m of ms) expect(() => encryptForPolicy(m, { attr: 'a' }, 'x')).not.toThrow();
    for (const m of ms.slice(0, 3)) expect(() => encryptForPolicy(m, { attr: 'a' }, 'x')).not.toThrow();
  });
  it('keygen skips bad attribute names; capability keys carry the holder', () => {
    const { msk } = fx();
    const k = keygenForAttributes(msk, ['ok', '', 5 as never, 'bad\ud800', 'ok', 'ok2']);
    expect(Object.keys(k.attrs).sort()).toEqual(['ok', 'ok2']);
    const cap = { id: 'i', issuer: 'p', holder: 'h1', caveats: [], parent: undefined } as never;
    const kc = keygenForCapability(msk, cap, ['x', '', 5 as never]);
    expect(kc.holder).toBe('h1');
    expect(Object.keys(kc.attrs)).toContain('x');
    expect(Object.keys(kc.attrs)).toContain('holder:h1');
    expect(Object.keys(kc.attrs)).not.toContain('');
    expect(keygenForCapability(msk, { ...(cap as object), holder: 5 } as never).holder).toBeUndefined();
    expect(keygenForCapability(msk, cap).holder).toBe('h1');
  });
  it('rerandomize: subset, holder, errors', () => {
    const { mpk, msk, ct, key } = fx();
    const k2 = { ...keygenForAttributes(msk, ['a', 'b']), holder: 'h' };
    expect(rerandomizeKey(mpk, k2).holder).toBe('h');
    expect(rerandomizeKey(mpk, { ...k2, holder: 5 } as never).holder).toBeUndefined();
    expect(Object.keys(rerandomizeKey(mpk, k2, ['a']).attrs)).toEqual(['a']);
    expect(err(() => rerandomizeKey(mpk, k2, ['zzz'])).message).toBe('subset names an attribute the key does not hold');
    for (const bad of [null, {}, { ...k2, d: 5 }, { ...k2, d: 'AA' }, { ...k2, attrs: null }]) expect(err(() => rerandomizeKey(mpk, bad as never)).message).toBe('invalid decryption key');
    expect(decrypt(rerandomizeKey(mpk, key), ct)).not.toBeNull();
    const broken = { ...key, attrs: { a: { dj: 5, dpj: 5 }, b: key.attrs.b } } as never;
    expect(decrypt(broken, ct)).toBeNull();
  });
  it('encrypt errors and plaintext types', () => {
    const { mpk, msk, ct } = fx();
    expect(err(() => encryptForPolicy(mpk, { attr: '' }, 'x')).message).toBe("invalid policy: policy: 'attr' must be a non-empty string");
    expect(decryptText(keygenForAttributes(msk, ['a']), encryptForPolicy(mpk, { attr: 'a' }, 'héllo').ciphertext)).toBe('héllo');
    expect(decrypt(keygenForAttributes(msk, ['a']), encryptForPolicy(mpk, { attr: 'a' }, Uint8Array.of(1, 2, 3)).ciphertext)).toEqual(Uint8Array.of(1, 2, 3));
    expect(ct.alg).toBe(ABE_ALG);
  });
});

describe('parseCiphertext rejects every malformed field', () => {
  it('non-objects', () => {
    fx(); for (const x of [null, [], 5, 'x', undefined]) expect(parseCiphertext(x)).toBeNull(); });
  it('accepts the genuine ciphertext', () => {
    const { ct, key } = fx();
    expect(parseCiphertext(clone(ct))).not.toBeNull();
    expect(decrypt(key, clone(ct))).toEqual(new TextEncoder().encode('hello'));
  });
  it.each([
    ['version', (c: any) => { c.v = 2; }], ['alg', (c: any) => { c.alg = 'x'; }],
    ...(['salt', 'c0', 'iv', 'ct', 'tag'] as const).flatMap((f) => [[`${f} type`, (c: any) => { c[f] = 5; }], [`${f} encoding`, (c: any) => { c[f] = 'a+b'; }]] as [string, (c: any) => void][]),
    ['kem missing', (c: any) => { delete c.kem; }], ['kem kind', (c: any) => { c.kem.kind = 'x'; }],
    ['gate t zero', (c: any) => { c.kem.t = 0; }], ['gate t > of', (c: any) => { c.kem.t = 9; }], ['gate of empty', (c: any) => { c.kem.of = []; }], ['gate of type', (c: any) => { c.kem.of = 'x'; }],
    ['gate t type', (c: any) => { c.kem.t = '1'; }],
    ['branch index', (c: any) => { c.kem.of[0].i = 2; }], ['branch not object', (c: any) => { c.kem.of[0] = 5; }], ['branch i type', (c: any) => { c.kem.of[0].i = 'x'; }],
    ['branch sub', (c: any) => { c.kem.of[0].sub = null; }], ['leaf attr', (c: any) => { c.kem.of[0].sub.attr = 5; }], ['leaf c', (c: any) => { c.kem.of[0].sub.c = 5; }],
    ['leaf cp', (c: any) => { c.kem.of[0].sub.cp = 5; }], ['leaf c enc', (c: any) => { c.kem.of[0].sub.c = '!'; }], ['leaf cp enc', (c: any) => { c.kem.of[0].sub.cp = '!'; }],
  ] as [string, (c: any) => void][])('%s', (_n, f) => {
    const { ct, key } = fx();
    const mut = (g: (c: any) => void) => { const c = clone(ct) as any; g(c); return c; };
    expect(parseCiphertext(mut(f))).toBeNull();
    expect(decrypt(key, mut(f))).toBeNull();
  });
  it('depth and node budgets are exact', () => {
    const { ct } = fx();
    const leaf = clone((ct as any).kem.of[0].sub);
    const nest = (d: number): any => (d === 0 ? leaf : { kind: 'gate', t: 1, of: [{ i: 1, sub: nest(d - 1) }] });
    const withKem = (kem: unknown) => ({ ...(clone(ct) as any), kem });
    expect(parseCiphertext(withKem(nest(MAX_POLICY_DEPTH)))).not.toBeNull();
    expect(parseCiphertext(withKem(nest(MAX_POLICY_DEPTH + 1)))).toBeNull();
    const wide = (n: number) => ({ kind: 'gate', t: 1, of: Array.from({ length: n }, (_, k) => ({ i: k + 1, sub: leaf })) });
    expect(parseCiphertext(withKem(wide(MAX_POLICY_NODES - 1)))).not.toBeNull();
    expect(parseCiphertext(withKem(wide(MAX_POLICY_NODES)))).toBeNull();
  });
  it('threshold gates only consult as many branches as needed, and fail when short', () => {
    const { msk, ct, key } = fx();
    const k = keygenForAttributes(msk, ['a', 'c']);
    expect(decrypt(k, ct)).not.toBeNull();
    expect(decrypt(keygenForAttributes(msk, ['a']), ct)).toBeNull();
    expect(decrypt(keygenForAttributes(msk, ['b', 'c']), ct)).toBeNull();
    expect(decrypt(null as never, ct)).toBeNull();
    expect(decrypt({ ...key, attrs: 5 } as never, ct)).toBeNull();
  });
});
