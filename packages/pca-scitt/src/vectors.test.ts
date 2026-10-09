/**
 * Official vectors and cross-implementation checks for pca-scitt. Provenance (source, commit, sha256) is
 * recorded inside each fixture file:
 *   cbor-appendix-a.json      RFC 8949 Appendix A (cbor/test-vectors)
 *   cose-wg-examples.json     cose-wg/Examples: sign1-tests, ecdsa-examples, eddsa-examples
 *   rfc9162-ct-vectors.json   transparency-dev/merkle: CT 8-leaf tree + 196 inclusion/consistency probes
 *   pycose.json / ours.json   independent-library cross-checks (pycose 1.1.0, cbor2 5.6.5, pymerkle 6.1.0)
 */
import { createPublicKey, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  CborTag,
  type CborValue,
  checkStatement,
  decode,
  encode,
  verifyConsistencyProof,
  verifyReceipt,
  verifyStatement,
} from './index';
import {
  consistencyPath,
  emptyRoot,
  inclusionPath,
  leafHash,
  nodeHash,
  rootFromInclusionPath,
  treeHash,
  verifyConsistencyPath,
  verifyInclusionPath,
} from './rfc9162';

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };
function load(name: string): { [k: string]: Json } {
  const raw: unknown = JSON.parse(readFileSync(resolve(__dirname, '..', 'fixtures', name), 'utf8'));
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) throw new Error(`bad fixture ${name}`);
  return raw as { [k: string]: Json };
}
function arr(v: Json | undefined): Json[] {
  if (!Array.isArray(v)) throw new Error('expected array');
  return v;
}
function obj(v: Json | undefined): { [k: string]: Json } {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) throw new Error('expected object');
  return v;
}
function str(v: Json | undefined): string {
  if (typeof v !== 'string') throw new Error('expected string');
  return v;
}
function num(v: Json | undefined): number {
  if (typeof v !== 'number') throw new Error('expected number');
  return v;
}
const hex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'hex'));
const toHex = (b: Uint8Array): string => Buffer.from(b).toString('hex');

// ---------------------------------------------------------------------------------------------
describe('RFC 8949 Appendix A (cbor/test-vectors appendix_a.json)', () => {
  const vectors = arr(load('cbor-appendix-a.json').vectors).map(obj);

  /** Convert a decoded value to the JSON shape the vector file uses (maps with text keys become objects). */
  function toJson(v: CborValue): Json | undefined {
    if (v === null || typeof v === 'boolean' || typeof v === 'number' || typeof v === 'string') return v;
    if (Array.isArray(v)) return v.map((x) => toJson(x) as Json);
    if (v instanceof Map) {
      if ([...v.keys()].some((k) => typeof k !== 'string')) return undefined;
      return Object.fromEntries([...v].map(([k, x]) => [String(k), toJson(x) as Json]));
    }
    return undefined; // bstr / tag: compared by re-encoding only
  }

  it('has all 82 vectors', () => expect(vectors.length).toBe(82));

  it('decodes and re-encodes every in-profile vector byte-for-byte, and its value matches the vector', () => {
    let accepted = 0;
    for (const v of vectors) {
      const h = str(v.hex);
      let value: CborValue;
      try {
        value = decode(hex(h));
      } catch {
        continue;
      }
      accepted++;
      expect(v.roundtrip, `vector ${h} is deterministic`).toBe(true);
      expect(toHex(encode(value)), `re-encode ${h}`).toBe(h);
      const j = toJson(value);
      if (j !== undefined && !(v.decoded === undefined)) {
        if (typeof v.decoded === 'string' && typeof j !== 'string') continue; // diagnostic-notation entries
        expect(j, `value of ${h}`).toEqual(v.decoded);
      }
    }
    expect(accepted).toBe(42);
  });

  it('rejects every out-of-profile vector with a stated reason (never mis-decodes it)', () => {
    const reasons = new Map<string, number>();
    for (const v of vectors) {
      const h = str(v.hex);
      try {
        decode(hex(h));
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        reasons.set(msg, (reasons.get(msg) ?? 0) + 1);
        if (/^(5f|7f|9f|bf)/.test(h)) expect(msg).toMatch(/indefinite/);
        if (/^f[0-9a-f]/.test(h) && !['f4', 'f5', 'f6'].includes(h)) expect(msg).toMatch(/unsupported simple\/float/);
        if (['1bffffffffffffffff', '3bffffffffffffffff'].includes(h)) expect(msg).toMatch(/out of safe range/);
      }
    }
    expect(reasons.get('cbor: unsupported simple/float value')).toBe(27);
    expect(reasons.get('cbor: unsupported additional information (indefinite/reserved)')).toBe(11);
    expect(reasons.get('cbor: integer out of safe range')).toBe(2);
  });

  it('keeps bignum tags 2 and 3 (RFC 8949 section 3.4.3) as tagged byte strings', () => {
    const pos = decode(hex('c249010000000000000000'));
    expect(pos).toBeInstanceOf(CborTag);
    expect((pos as CborTag).tag).toBe(2);
    expect((decode(hex('c349010000000000000000')) as CborTag).tag).toBe(3);
  });

  it('rejects non-deterministic encodings (RFC 8949 section 4.2.1)', () => {
    expect(() => decode(hex('1800'))).toThrow(/non-minimal/); // 0 in two bytes
    expect(() => decode(hex('190001'))).toThrow(/non-minimal/);
    expect(() => decode(hex('a2616201616101'))).toThrow(/canonically ordered/); // {"b":1,"a":1}: unsorted
    expect(() => decode(hex('a201020102'))).toThrow(/canonically ordered|duplicate/); // duplicate key 1
    expect(() => decode(hex('0000'))).toThrow(/trailing/);
    expect(() => decode(hex('83010203').slice(0, 3))).toThrow(/unexpected end/);
    expect(() => decode(hex('62c328'))).toThrow(); // invalid UTF-8
  });

  it('keeps a leading U+FEFF in a text string instead of silently stripping it', () => {
    const withBom = '﻿abc';
    const bytes = encode(withBom);
    expect(decode(bytes)).toBe(withBom);
    expect(toHex(encode(decode(bytes)))).toBe(toHex(bytes));
  });

  it('refuses to encode a lone surrogate or an unsafe integer', () => {
    expect(() => encode('\ud800')).toThrow(/lone surrogate/);
    expect(() => encode(2 ** 53)).toThrow(/safe-integer/);
  });

  it('rejects a negative integer that does not fit a safe integer', () => {
    expect(() => decode(hex('3b001fffffffffffff'))).toThrow(/out of safe range/); // -2^53
  });
});

// ---------------------------------------------------------------------------------------------
describe('COSE_Sign1: cose-wg/Examples', () => {
  const vectors = arr(load('cose-wg-examples.json').vectors).map(obj);
  const byFile = (f: string): { [k: string]: Json } => {
    const v = vectors.find((x) => x.file === f);
    if (v === undefined) throw new Error(`missing ${f}`);
    return v;
  };
  function keyOf(v: { [k: string]: Json }): KeyObject {
    const k = obj(v.key);
    if (k.kty === 'EC') return createPublicKey({ key: { kty: 'EC', crv: str(k.crv), x: str(k.x), y: str(k.y) }, format: 'jwk' });
    return createPublicKey({ key: { kty: 'OKP', crv: str(k.crv), x: Buffer.from(str(k.x_hex), 'hex').toString('base64url') }, format: 'jwk' });
  }
  const run = (f: string): ReturnType<typeof checkStatement> => {
    const v = byFile(f);
    return checkStatement(hex(str(v.cbor_hex)), keyOf(v));
  };

  it('accepts the official ES256 and EdDSA (Ed25519, Ed448) COSE_Sign1 messages', () => {
    expect(run('ecdsa-sig-01.json')).toEqual({ ok: true });
    expect(run('eddsa-sig-01.json')).toEqual({ ok: true });
    expect(run('eddsa-sig-02.json')).toEqual({ ok: true });
  });

  it('reports unsupported algorithms (ES384, ES512) instead of accepting them', () => {
    for (const f of ['ecdsa-sig-02.json', 'ecdsa-sig-03.json', 'ecdsa-sig-04.json']) {
      expect(run(f), f).toEqual({ ok: false, reason: 'unsupported alg' });
    }
  });

  it('rejects the official negative cases with the specific reason', () => {
    expect(run('sign-fail-01.json')).toMatchObject({ ok: false, reason: expect.stringContaining('not a COSE_Sign1 (tag 18)') }); // wrong CBOR tag
    expect(run('sign-fail-02.json')).toEqual({ ok: false, reason: 'bad signature' }); // changed signature
    expect(run('sign-fail-03.json')).toEqual({ ok: false, reason: 'unsupported alg' }); // alg changed to an unknown integer
    expect(run('sign-fail-04.json')).toEqual({ ok: false, reason: 'unsupported alg' }); // alg changed to a text value
    expect(run('sign-fail-06.json')).toEqual({ ok: false, reason: 'bad signature' }); // protected attribute added
    expect(run('sign-fail-07.json')).toEqual({ ok: false, reason: 'bad signature' }); // protected attribute removed
  });

  it('is deliberately stricter than the RFC on three "pass" cases and says why', () => {
    // alg only in the UNPROTECTED header: an attacker could swap it, so it is refused.
    expect(run('sign-pass-01.json')).toEqual({ ok: false, reason: 'missing alg header' });
    // signed over non-empty external_aad: statements here always use an empty one.
    expect(run('sign-pass-02.json')).toEqual({ ok: false, reason: 'bad signature' });
    // untagged COSE_Sign1: only the tag-18 form is accepted.
    expect(run('sign-pass-03.json')).toMatchObject({ ok: false, reason: expect.stringContaining('not a COSE_Sign1 (tag 18)') });
  });

  it('rejects a valid message under the wrong public key', () => {
    const v = byFile('eddsa-sig-01.json');
    const other = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.alloc(32, 7).toString('base64url') }, format: 'jwk' });
    expect(checkStatement(hex(str(v.cbor_hex)), other)).toEqual({ ok: false, reason: 'bad signature' });
    expect(verifyStatement(hex(str(v.cbor_hex)), other)).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------
describe('RFC 9162 Merkle: transparency-dev/merkle vectors', () => {
  const fx = load('rfc9162-ct-vectors.json');
  const inputs = arr(fx.leaf_inputs_hex).map((x) => hex(str(x)));
  const roots = obj(fx.root_hashes_hex_by_tree_size);

  it('reproduces the empty-tree, leaf and node hashes', () => {
    const h = obj(fx.hasher_vectors);
    expect(toHex(emptyRoot())).toBe(str(h.empty_root));
    expect(toHex(leafHash(new TextEncoder().encode('L123456')))).toBe(str(h.leaf_L123456));
    expect(toHex(nodeHash(new TextEncoder().encode('N123'), new TextEncoder().encode('N456')))).toBe(str(h.node_N123_N456));
  });

  it('reproduces the root of every prefix of the 8-leaf CT tree', () => {
    for (let n = 0; n <= 8; n++) {
      expect(toHex(treeHash(inputs.slice(0, n).map(leafHash))), `size ${n}`).toBe(str(roots[String(n)]));
    }
  });

  it('generates inclusion paths and consistency paths that verify against those roots', () => {
    const leaves = inputs.map(leafHash);
    for (let n = 1; n <= 8; n++) {
      const root = hex(str(roots[String(n)]));
      for (let i = 0; i < n; i++) {
        expect(verifyInclusionPath(leaves[i]!, i, n, inclusionPath(leaves.slice(0, n), i), root), `incl ${i}/${n}`).toBe(true);
      }
      for (let m = 1; m <= n; m++) {
        expect(verifyConsistencyPath(m, n, hex(str(roots[String(m)])), root, consistencyPath(leaves.slice(0, n), m)), `cons ${m}->${n}`).toBe(true);
      }
    }
  });

  const incl = arr(fx.inclusion_probes).map(obj);
  const cons = arr(fx.consistency_probes).map(obj);

  it(`agrees with all ${incl.length} official inclusion probes (valid and invalid)`, () => {
    let accepted = 0;
    for (const p of incl) {
      const got = verifyInclusionPath(hex(str(p.leafHash)), num(p.leafIdx), num(p.treeSize), arr(p.proof).map((x) => hex(str(x))), hex(str(p.root)));
      expect(got, `${str(p.file)}: ${str(p.desc)}`).toBe(p.wantErr === false);
      if (got) accepted++;
    }
    expect(accepted).toBe(incl.filter((p) => p.wantErr === false).length);
    expect(accepted).toBeGreaterThan(0);
  });

  it(`agrees with all ${cons.length} official consistency probes (valid and invalid)`, () => {
    let accepted = 0;
    for (const p of cons) {
      const r1 = hex(str(p.root1));
      const r2 = hex(str(p.root2));
      const got = verifyConsistencyPath(num(p.size1), num(p.size2), r1, r2, arr(p.proof).map((x) => hex(str(x))));
      // The reference accepts non-hash placeholder roots when sizes are equal; this verifier requires 32-byte SHA-256 roots.
      const want = p.wantErr === false && r1.length === 32 && r2.length === 32;
      expect(got, `${str(p.file)}: ${str(p.desc)}`).toBe(want);
      if (got) accepted++;
    }
    expect(accepted).toBeGreaterThan(0);
  });

  it('rejects an inclusion proof with an out-of-range index, a short or long path, and a wrong leaf', () => {
    const leaves = inputs.map(leafHash);
    const root = treeHash(leaves);
    const path = inclusionPath(leaves, 5);
    expect(verifyInclusionPath(leaves[5]!, 5, 8, path, root)).toBe(true);
    expect(verifyInclusionPath(leaves[5]!, 8, 8, path, root)).toBe(false);
    expect(verifyInclusionPath(leaves[5]!, 5, 8, path.slice(1), root)).toBe(false);
    expect(verifyInclusionPath(leaves[5]!, 5, 8, [...path, path[0]!], root)).toBe(false);
    expect(verifyInclusionPath(leaves[4]!, 5, 8, path, root)).toBe(false);
    expect(rootFromInclusionPath(leaves[5]!, 5, 8, [new Uint8Array(31)])).toBeNull();
  });
});

// ---------------------------------------------------------------------------------------------
describe('cross-implementation: pycose 1.1.0 / cbor2 5.6.5 / pymerkle 6.1.0', () => {
  it('accepts COSE_Sign1 statements signed by pycose (EdDSA and ES256)', () => {
    for (const s of arr(load('pycose.json').statements).map(obj)) {
      const k = obj(s.public_jwk);
      const key = createPublicKey({ key: { kty: str(k.kty), crv: str(k.crv), x: str(k.x), ...(k.y !== undefined ? { y: str(k.y) } : {}) }, format: 'jwk' });
      const bytes = new Uint8Array(Buffer.from(str(s.statement), 'base64'));
      expect(checkStatement(bytes, key), str(s.alg)).toEqual({ ok: true });
      const tampered = bytes.slice();
      tampered[tampered.length - 1] = (tampered[tampered.length - 1] ?? 0) ^ 1;
      expect(checkStatement(tampered, key)).toEqual({ ok: false, reason: 'bad signature' });
    }
  });

  const ours = arr(load('ours.json').variants).map(obj);
  const keyOf = (j: Json | undefined): KeyObject => {
    const k = obj(j);
    return createPublicKey({ key: { kty: str(k.kty), crv: str(k.crv), x: str(k.x), ...(k.y !== undefined ? { y: str(k.y) } : {}) }, format: 'jwk' });
  };

  it('still verifies receipts that pycose + pymerkle verified independently, and rejects tampering', () => {
    for (const v of ours) {
      const tsKey = keyOf(v.ts_jwk);
      const issuerKey = keyOf(v.issuer_jwk);
      const entries = arr(v.entries).map(obj);
      const receipts = arr(v.final_receipts).map((r) => new Uint8Array(Buffer.from(str(r), 'base64')));
      expect(entries.length).toBe(9);
      entries.forEach((e, i) => {
        const statement = new Uint8Array(Buffer.from(str(e.statement), 'base64'));
        const receipt = receipts[i]!;
        expect(verifyReceipt(receipt, statement, { verificationKey: tsKey, statementKey: issuerKey, treeRoot: str(v.final_root) })).toBe(true);
        // a receipt never verifies a different statement
        const other = new Uint8Array(Buffer.from(str(entries[(i + 1) % 9]!.statement), 'base64'));
        expect(verifyReceipt(receipt, other, { verificationKey: tsKey })).toBe(false);
        // wrong pinned root
        expect(verifyReceipt(receipt, statement, { treeRoot: str(entries[0]!.root_at_registration) })).toBe(false); // size-1 root is not the final root
      });
    }
  });

  it('verifies the consistency proofs between logged roots, and rejects swapped roots or a corrupted proof', () => {
    for (const v of ours) {
      for (const c of arr(v.consistency).map(obj)) {
        const proof = new Uint8Array(Buffer.from(str(c.proof), 'base64'));
        const oldRoot = str(c.old_root);
        const newRoot = str(c.new_root);
        expect(verifyConsistencyProof(proof, oldRoot, newRoot)).toBe(true);
        if (num(c.old_size) !== num(c.new_size)) {
          expect(verifyConsistencyProof(proof, newRoot, oldRoot)).toBe(false);
          const bad = proof.slice();
          bad[bad.length - 1] = (bad[bad.length - 1] ?? 0) ^ 1;
          expect(verifyConsistencyProof(bad, oldRoot, newRoot)).toBe(false);
        }
      }
    }
  });
});

describe('receipt encoding (RFC 9942)', () => {
  const v = arr(load('ours.json').variants).map(obj)[0]!;
  const tsKey = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: str(obj(v.ts_jwk).x) }, format: 'jwk' });
  const statement = new Uint8Array(Buffer.from(str(obj(arr(v.entries)[3])!.statement), 'base64'));
  const receipt = new Uint8Array(Buffer.from(str(arr(v.final_receipts)[3]), 'base64'));

  it('emits a detached payload (nil), as RFC 9942 section 4.4 recommends', () => {
    const top = decode(receipt) as CborTag;
    expect(top.tag).toBe(18);
    expect((top.value as CborValue[])[2]).toBeNull();
  });

  it('also accepts a receipt that embeds the root, and rejects one that embeds a different root', () => {
    const top = decode(receipt) as CborTag;
    const parts = [...(top.value as CborValue[])];
    const root = Buffer.from(str(v.final_root), 'base64url');
    const embedded = encode(new CborTag(18, [parts[0]!, parts[1]!, new Uint8Array(root), parts[3]!]));
    expect(verifyReceipt(embedded, statement, { verificationKey: tsKey })).toBe(true);
    const wrong = encode(new CborTag(18, [parts[0]!, parts[1]!, new Uint8Array(32), parts[3]!]));
    expect(verifyReceipt(wrong, statement, { verificationKey: tsKey })).toBe(false);
  });

  it('fails closed without an anchor and on a truncated receipt', () => {
    expect(verifyReceipt(receipt, statement, {})).toBe(false);
    expect(verifyReceipt(receipt.slice(0, receipt.length - 3), statement, { verificationKey: tsKey })).toBe(false);
  });
});
