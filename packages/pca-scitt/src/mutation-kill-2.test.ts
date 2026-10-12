/** Round-2 mutation kills for the SCITT adapter (key encodings, signer-key mismatch, CWT issuer claim, receipt VDS, over-long paths). */
import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { b64u } from '@atlasauth/pca';
import {
  CborTag, TransparencyService, checkStatement, decode, encode, signStatement, verifyReceipt, verifyConsistencyProof,
  HDR_CWT_CLAIMS, HDR_VDS, CWT_ISS, type CborKey, type CborValue,
} from './index';
import { leafHash, rootFromInclusionPath, verifyConsistencyPath, treeHash } from './rfc9162';

const hex = (u: Uint8Array) => Buffer.from(u).toString('hex');
const ed = generateKeyPairSync('ed25519');
const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const M = (...kv: [CborKey, CborValue][]) => new Map<CborKey, CborValue>(kv);

describe('scitt round 2', () => {
  it('integer map key 0 encodes as the unsigned zero head', () => {
    expect(hex(encode(M([0, 1])))).toBe('a10001');
    expect(hex(encode(M([-1, 1], [0, 2])))).toBe('a2000220' + '01');
  });
  it('a signer key of the wrong type makes the signature check throw internally and report bad signature', () => {
    const es = signStatement({ a: 1 }, { alg: 'ES256', key: ec.privateKey, issuer: 'i' });
    expect(checkStatement(es, ed.publicKey)).toStrictEqual({ ok: false, reason: 'bad signature' });
    const edst = signStatement({ a: 1 }, { alg: 'EdDSA', key: ed.privateKey, issuer: 'i' });
    expect(checkStatement(edst, ec.publicKey)).toStrictEqual({ ok: false, reason: 'bad signature' });
  });
  it('the receipt carries the TS issuer in the protected CWT claims only when configured', () => {
    const claims = (r: Uint8Array) => {
      const tag = decode(r) as CborTag;
      const prot = decode((tag.value as CborValue[])[0] as Uint8Array) as Map<CborKey, CborValue>;
      return prot.get(HDR_CWT_CLAIMS);
    };
    const st = signStatement({ a: 1 }, { alg: 'EdDSA', key: ed.privateKey, issuer: 'i' });
    const withIss = new TransparencyService({ alg: 'EdDSA', key: ed.privateKey, issuer: 'ts.example' }).register(st);
    expect(claims(withIss.receipt)).toStrictEqual(M([CWT_ISS, 'ts.example']));
    const without = new TransparencyService({ alg: 'EdDSA', key: ed.privateKey }).register(st);
    expect(claims(without.receipt)).toBeUndefined();
  });
  it('a receipt whose protected VDS is not RFC9162_SHA256 is rejected even with only a pinned root', () => {
    const svc = new TransparencyService({ alg: 'EdDSA', key: ed.privateKey });
    const st = signStatement({ a: 1 }, { alg: 'EdDSA', key: ed.privateKey, issuer: 'i' });
    const { receipt, root } = svc.register(st);
    expect(verifyReceipt(receipt, st, { treeRoot: root })).toBe(true);
    const tag = decode(receipt) as CborTag;
    const [prot, unprot, pay, sig] = tag.value as CborValue[];
    const pm = decode(prot as Uint8Array) as Map<CborKey, CborValue>;
    pm.set(HDR_VDS, 2);
    const forged = encode(new CborTag(18, [encode(pm), unprot!, pay!, sig!]));
    expect(verifyReceipt(forged, st, { treeRoot: root })).toBe(false);
  });
  it('a path longer than the tree needs is invalid (single-leaf tree has an empty path)', () => {
    const l = leafHash(new Uint8Array([1]));
    expect(rootFromInclusionPath(l, 0, 1, [])).toStrictEqual(l);
    expect(rootFromInclusionPath(l, 0, 1, [l])).toBeNull();
    expect(rootFromInclusionPath(l, 1, 2, [l, l])).toBeNull();
  });
  it('consistency: a second tree smaller than the first is refused', () => {
    const lv = [1, 2, 3, 4, 5].map((i) => leafHash(new Uint8Array([i])));
    const r = treeHash(lv);
    expect(verifyConsistencyPath(5, 3, r, r, [r])).toBe(false);
    expect(verifyConsistencyPath(5, 4, r, r, [r, r])).toBe(false);
    expect(verifyConsistencyProof(encode([5, 3, [r]]), b64u(r), b64u(r))).toBe(false);
  });
});
