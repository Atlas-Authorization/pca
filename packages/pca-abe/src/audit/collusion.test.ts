import { describe, expect, it } from 'vitest';
import { bls12_381 as bls } from '@noble/curves/bls12-381';
import {
  type DecryptionKey,
  type Policy,
  decrypt,
  encryptForPolicy,
  keygenForAttributes,
  rerandomizeKey,
  setup,
} from '../index';
import { b64 } from './_helpers';

/**
 * Collusion / key-handling audit.
 *
 * Construction: Bethencourt-Sahai-Waters CP-ABE (IEEE S&P 2007) with a fresh per-key randomiser r
 * (D = g^((alpha+r)/beta), D_j = g^r * H(j)^r_j, D'_j = g^r_j), type-3 adaptation. Components of keys issued
 * to different users carry different r and must not combine. These tests are the regression for the
 * previous construction (d_A = s*H1(A), identical for every holder), where the pooling attack succeeded.
 */

const PT = new TextEncoder().encode('collusion target');
const AND2: Policy = { allOf: [{ attr: 'verb:read' }, { attr: 'scope:finance' }] };

/** Naive pooling: attribute components from both keys, D from the first. */
function pool(a: DecryptionKey, b: DecryptionKey): DecryptionKey {
  return { ...a, attrs: { ...a.attrs, ...b.attrs } };
}

describe('collusion resistance (per-user key randomiser)', () => {
  it('two separately issued keys with disjoint attributes can NOT pool to decrypt an AND policy neither satisfies (either D)', () => {
    const { mpk, msk } = setup();
    const { ciphertext } = encryptForPolicy(mpk, AND2, PT);
    const alice = keygenForAttributes(msk, ['verb:read']);
    const bob = keygenForAttributes(msk, ['scope:finance']);
    expect(decrypt(alice, ciphertext)).toBeNull();
    expect(decrypt(bob, ciphertext)).toBeNull();
    expect(decrypt(pool(alice, bob), ciphertext)).toBeNull();
    expect(decrypt(pool(bob, alice), ciphertext)).toBeNull();
  });

  it('control: ONE key holding both attributes decrypts the same ciphertext', () => {
    const { mpk, msk } = setup();
    const { ciphertext } = encryptForPolicy(mpk, AND2, PT);
    expect(decrypt(keygenForAttributes(msk, ['verb:read', 'scope:finance']), ciphertext)).toEqual(PT);
  });

  it('mixing individual components of two keys fails: each of D, D_j, D\'_j swapped in from another user breaks decryption', () => {
    const { mpk, msk } = setup();
    const { ciphertext } = encryptForPolicy(mpk, AND2, PT);
    const a = keygenForAttributes(msk, ['verb:read', 'scope:finance']);
    const b = keygenForAttributes(msk, ['verb:read', 'scope:finance']);
    expect(decrypt(a, ciphertext)).toEqual(PT);
    expect(decrypt(b, ciphertext)).toEqual(PT);
    const attr = (k: DecryptionKey, n: string) => k.attrs[n] as { dj: string; dpj: string };
    const mixes: DecryptionKey[] = [
      { ...a, d: b.d },
      { ...a, attrs: { ...a.attrs, 'verb:read': attr(b, 'verb:read') } },
      { ...a, attrs: { ...a.attrs, 'scope:finance': { dj: attr(b, 'scope:finance').dj, dpj: attr(a, 'scope:finance').dpj } } },
      { ...a, attrs: { ...a.attrs, 'scope:finance': { dj: attr(a, 'scope:finance').dj, dpj: attr(b, 'scope:finance').dpj } } },
      { ...a, attrs: { 'verb:read': attr(a, 'verb:read'), 'scope:finance': attr(b, 'scope:finance') } },
    ];
    for (const m of mixes) expect(decrypt(m, ciphertext)).toBeNull();
  });

  it('threshold gates: a 2-of-3 policy is not met by one attribute from each of two users (and no pair of users with one attribute each pools)', () => {
    const { mpk, msk } = setup();
    const { ciphertext } = encryptForPolicy(mpk, { threshold: 2, of: [{ attr: 'a' }, { attr: 'b' }, { attr: 'c' }] }, PT);
    const ka = keygenForAttributes(msk, ['a']);
    const kb = keygenForAttributes(msk, ['b']);
    const kc = keygenForAttributes(msk, ['c']);
    for (const [x, y] of [[ka, kb], [kb, kc], [ka, kc], [kb, ka]] as const) expect(decrypt(pool(x, y), ciphertext)).toBeNull();
    expect(decrypt(pool(pool(ka, kb), kc), ciphertext)).toBeNull();
  });

  it('nested policy: users who each satisfy a different branch of an AND cannot pool', () => {
    const { mpk, msk } = setup();
    const policy: Policy = { allOf: [{ anyOf: [{ attr: 'x1' }, { attr: 'x2' }] }, { anyOf: [{ attr: 'y1' }, { attr: 'y2' }] }] };
    const { ciphertext } = encryptForPolicy(mpk, policy, PT);
    const u = keygenForAttributes(msk, ['x2']);
    const v = keygenForAttributes(msk, ['y1']);
    expect(decrypt(pool(u, v), ciphertext)).toBeNull();
    expect(decrypt(keygenForAttributes(msk, ['x2', 'y1']), ciphertext)).toEqual(PT);
  });

  it('keys are randomised: the same attributes yield different key material for each issuance', () => {
    const { msk } = setup();
    const k1 = keygenForAttributes(msk, ['verb:read', 'scope:x']);
    const k2 = keygenForAttributes(msk, ['scope:x', 'verb:read']);
    expect(k1.d).not.toBe(k2.d);
    for (const n of ['verb:read', 'scope:x']) {
      expect(k1.attrs[n]?.dj).not.toBe(k2.attrs[n]?.dj);
      expect(k1.attrs[n]?.dpj).not.toBe(k2.attrs[n]?.dpj);
    }
  });

  it('re-randomisation: a re-randomised key still decrypts, shares no component with the original, and cannot pool with it', () => {
    const { mpk, msk } = setup();
    const { ciphertext } = encryptForPolicy(mpk, AND2, PT);
    const k = keygenForAttributes(msk, ['verb:read', 'scope:finance']);
    const k2 = rerandomizeKey(mpk, k);
    expect(decrypt(k2, ciphertext)).toEqual(PT);
    expect(k2.d).not.toBe(k.d);
    for (const n of ['verb:read', 'scope:finance']) {
      expect(k2.attrs[n]?.dj).not.toBe(k.attrs[n]?.dj);
      expect(k2.attrs[n]?.dpj).not.toBe(k.attrs[n]?.dpj);
    }
    // mixing old and new components (different effective randomisers) fails
    expect(decrypt({ ...k, d: k2.d }, ciphertext)).toBeNull();
    expect(decrypt({ ...k2, attrs: { ...k2.attrs, 'verb:read': k.attrs['verb:read'] as { dj: string; dpj: string } } }, ciphertext)).toBeNull();
  });

  it('delegation: a re-randomised SUBSET key decrypts only what the subset satisfies, and cannot name an attribute it lacks', () => {
    const { mpk, msk } = setup();
    const k = keygenForAttributes(msk, ['verb:read', 'scope:finance', 'extra']);
    const sub = rerandomizeKey(mpk, k, ['verb:read']);
    expect(Object.keys(sub.attrs)).toEqual(['verb:read']);
    expect(decrypt(sub, encryptForPolicy(mpk, { attr: 'verb:read' }, PT).ciphertext)).toEqual(PT);
    expect(decrypt(sub, encryptForPolicy(mpk, AND2, PT).ciphertext)).toBeNull();
    expect(() => rerandomizeKey(mpk, k, ['not-held'])).toThrow();
  });

  it('collusion across DIFFERENT masters never works (keys from another authority are useless)', () => {
    const a = setup();
    const b = setup();
    const { ciphertext } = encryptForPolicy(a.mpk, { allOf: [{ attr: 'x' }, { attr: 'y' }] }, PT);
    const kx = keygenForAttributes(a.msk, ['x']);
    const ky = keygenForAttributes(b.msk, ['y']);
    expect(decrypt(pool(kx, ky), ciphertext)).toBeNull();
    expect(decrypt(keygenForAttributes(b.msk, ['x', 'y']), ciphertext)).toBeNull();
  });

  it('a key cannot be relabelled to another attribute (D_j is bound to H(j))', () => {
    const { mpk, msk } = setup();
    const { ciphertext } = encryptForPolicy(mpk, { attr: 'scope:admin' }, PT);
    const k = keygenForAttributes(msk, ['scope:user']);
    const relabelled: DecryptionKey = { ...k, attrs: { 'scope:admin': k.attrs['scope:user'] as { dj: string; dpj: string } } };
    expect(decrypt(relabelled, ciphertext)).toBeNull();
  });

  it('group-operation forgeries do not mint new attribute components (sum / difference / double / negation of D_A, D_B as D_C)', () => {
    const { mpk, msk } = setup();
    const k = keygenForAttributes(msk, ['A', 'B']);
    const g1 = (n: string) => bls.G1.ProjectivePoint.fromHex(Buffer.from((k.attrs[n] as { dj: string }).dj, 'base64url'));
    const dA = g1('A');
    const dB = g1('B');
    const dpA = (k.attrs['A'] as { dpj: string }).dpj;
    for (const f of [dA.add(dB), dA.subtract(dB), dA.double(), dA.negate()]) {
      const { ciphertext } = encryptForPolicy(mpk, { attr: 'C' }, PT);
      const key: DecryptionKey = { ...k, attrs: { C: { dj: b64(f.toRawBytes(true)), dpj: dpA } } };
      expect(decrypt(key, ciphertext)).toBeNull();
    }
  });

  it('a threshold gate cannot be satisfied by repeating one attribute key under several labels', () => {
    const { mpk, msk } = setup();
    const { ciphertext } = encryptForPolicy(mpk, { threshold: 2, of: [{ attr: 'a' }, { attr: 'b' }, { attr: 'c' }] }, PT);
    const ka = keygenForAttributes(msk, ['a']);
    const ca = ka.attrs['a'] as { dj: string; dpj: string };
    expect(decrypt({ ...ka, attrs: { a: ca, b: ca, c: ca } }, ciphertext)).toBeNull();
  });

  it('exhaustive: over all subsets of 4 attributes, ONE key decrypts a 2-of-4 policy iff it has >= 2 attributes; and every pair of disjoint single-attribute keys fails', () => {
    const { mpk, msk } = setup();
    const names = ['p', 'q', 'r', 's'];
    const { ciphertext } = encryptForPolicy(mpk, { threshold: 2, of: names.map((attr) => ({ attr })) }, PT);
    for (let mask = 0; mask < 16; mask++) {
      const have = names.filter((_, i) => (mask >> i) & 1);
      const got = decrypt(keygenForAttributes(msk, have), ciphertext);
      expect(got !== null, `subset ${have.join(',')}`).toBe(have.length >= 2);
    }
    const singles = names.map((n) => keygenForAttributes(msk, [n]));
    for (let i = 0; i < singles.length; i++)
      for (let j = 0; j < singles.length; j++)
        if (i !== j) expect(decrypt(pool(singles[i] as DecryptionKey, singles[j] as DecryptionKey), ciphertext), `${i},${j}`).toBeNull();
  });
});
