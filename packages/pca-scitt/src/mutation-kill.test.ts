/** Mutation-kill tests for the SCITT adapter: canonical CBOR, COSE_Sign1, inclusion-proof codec, receipts and the transparency service. */
import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { b64u } from '@atlasauth/pca';
import {
  CborTag,
  TransparencyService,
  buildReceipt,
  checkStatement,
  decode,
  decodeInclusionProof,
  encode,
  encodeInclusionProof,
  signStatement,
  statementLeaf,
  statementPayload,
  verifyConsistencyProof,
  verifyReceipt,
  verifyStatement,
  type CborKey,
  type CborValue,
} from './index';
import { leafHash, treeHash } from './rfc9162';

const hex = (u: Uint8Array) => Buffer.from(u).toString('hex');
const unhex = (h: string) => new Uint8Array(Buffer.from(h, 'hex'));
const ed = generateKeyPairSync('ed25519');
const ed2 = generateKeyPairSync('ed25519');
const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const thrown = (f: () => unknown): Error => {
  try {
    f();
  } catch (e) {
    return e as Error;
  }
  throw new Error('no throw');
};
const M = (...kv: [CborKey, CborValue][]) => new Map<CborKey, CborValue>(kv);

describe('CBOR encoder (RFC 8949 deterministic)', () => {
  it.each([
    [0, '00'], [1, '01'], [10, '0a'], [23, '17'], [24, '1818'], [25, '1819'], [100, '1864'], [255, '18ff'], [256, '190100'], [1000, '1903e8'],
    [65535, '19ffff'], [65536, '1a00010000'], [1000000, '1a000f4240'], [4294967295, '1affffffff'], [4294967296, '1b0000000100000000'],
    [1000000000000, '1b000000e8d4a51000'], [Number.MAX_SAFE_INTEGER, '1b001fffffffffffff'],
    [-1, '20'], [-10, '29'], [-24, '37'], [-25, '3818'], [-100, '3863'], [-256, '38ff'], [-257, '390100'], [-1000, '3903e7'], [-65536, '39ffff'], [-65537, '3a00010000'],
    [-4294967296, '3affffffff'], [-4294967297, '3b0000000100000000'], [-Number.MAX_SAFE_INTEGER, '3b001ffffffffffffe'],
    [false, 'f4'], [true, 'f5'], [null, 'f6'],
    ['', '60'], ['a', '6161'], ['IETF', '6449455446'], ['"\\', '62225c'], ['ü', '62c3bc'], ['水', '63e6b0b4'], ['𐅑', '64f0908591'], ['x'.repeat(24), `7818${'78'.repeat(24)}`],
    [new Uint8Array(0), '40'], [Uint8Array.of(1, 2, 3, 4), '4401020304'], [new Uint8Array(24), `5818${'00'.repeat(24)}`],
    [[], '80'], [[1, 2, 3], '83010203'], [[1, [2, 3], [4, 5]], '8301820203820405'],
    [M(), 'a0'], [M([1, 2], [3, 4]), 'a201020304'], [M(['a', 1], ['b', [2, 3]]), 'a26161016162820203'],
    [new CborTag(1, 1363896240), 'c11a514b67b0'], [new CborTag(18, [new Uint8Array(0)]), 'd28140'],
  ] as [CborValue, string][])('%j -> %s', (v, h) => {
    expect(hex(encode(v))).toBe(h);
    expect(decode(unhex(h))).toStrictEqual(v);
  });
  it('arrays of 24 and 256 elements use the longer heads', () => {
    expect(hex(encode(new Array(24).fill(0)).slice(0, 2))).toBe('9818');
    expect(hex(encode(new Array(256).fill(0)).slice(0, 3))).toBe('990100');
    const m = new Map<CborKey, CborValue>();
    for (let i = 0; i < 24; i++) m.set(i, 0);
    expect(hex(encode(m).slice(0, 2))).toBe('b818');
  });
  it('map keys are sorted bytewise (shorter encodings first), independent of insertion order', () => {
    expect(hex(encode(M(['bb', 1], ['a', 2], [10, 3], [-1, 4], [1, 5])))).toBe(hex(encode(M([1, 5], [10, 3], [-1, 4], ['a', 2], ['bb', 1]))));
    expect(hex(encode(M(['bb', 1], ['a', 2], [10, 3], [-1, 4], [1, 5])))).toBe('a5' + '01' + '05' + '0a' + '03' + '20' + '04' + '6161' + '02' + '626262' + '01');
    expect(hex(encode(M(['b', 1], ['a', 2])))).toBe('a2616102616201');
  });
  it('rejects what it cannot encode deterministically', () => {
    for (const n of [1.5, NaN, Infinity, -0.5, 2 ** 53, -(2 ** 53)]) expect(thrown(() => encode(n)).message).toBe('cbor: only safe-integer numbers are supported');
    expect(thrown(() => encode('a\ud800b')).message).toBe('cbor: text string contains a lone surrogate');
    expect(thrown(() => encode('\udc00')).message).toBe('cbor: text string contains a lone surrogate');
    expect(thrown(() => encode('a\ud800')).message).toBe('cbor: text string contains a lone surrogate');
    expect(thrown(() => encode(M(['\ud800', 1]))).message).toBe('cbor: text string contains a lone surrogate');
    expect(thrown(() => encode(M([1.5, 1]))).message).toBe('cbor: bad integer map key');
    expect(thrown(() => encode(M([2 ** 53, 1]))).message).toBe('cbor: bad integer map key');
    expect(hex(encode(M([1, 1], [1, 3])))).toBe('a10103');
    expect(thrown(() => encode(new CborTag(-1, 0))).message).toBe('cbor: bad tag');
    expect(thrown(() => encode(new CborTag(1.5, 0))).message).toBe('cbor: bad tag');
    expect(thrown(() => encode(undefined as never)).message).toBe('cbor: unsupported value');
    expect(thrown(() => encode({} as never)).message).toBe('cbor: unsupported value');
    expect(thrown(() => encode(Symbol('x') as never)).message).toBe('cbor: unsupported value');
    // a string key and the equal-bytes integer cannot collide, but two distinct keys that encode identically are refused
    const a = new Map<CborKey, CborValue>([['a', 1]]);
    expect(encode(a).length).toBe(4);
    expect(encode(new CborTag(0, 'x')).length).toBeGreaterThan(0);
  });
});

describe('CBOR decoder (strict)', () => {
  const bad = (h: string) => thrown(() => decode(unhex(h))).message;
  it('truncated input', () => {
    expect(bad('')).toBe('cbor: unexpected end of input');
    expect(bad('18')).toBe('cbor: unexpected end of input');
    expect(bad('1901')).toBe('cbor: unexpected end of input');
    expect(bad('1a000100')).toBe('cbor: unexpected end of input');
    expect(bad('1b00000001000000')).toBe('cbor: unexpected end of input');
    expect(bad('440102')).toBe('cbor: unexpected end of input');
    expect(bad('6261')).toBe('cbor: unexpected end of input');
    expect(bad('8201')).toBe('cbor: unexpected end of input');
    expect(bad('a101')).toBe('cbor: unexpected end of input');
    expect(bad('c1')).toBe('cbor: unexpected end of input');
    expect(Object.getPrototypeOf(decode(unhex('4401020304')))).toBe(Uint8Array.prototype);
    expect(bad('5affffffff')).toBe('cbor: unexpected end of input'); // a huge declared length is not trusted
    expect(hex(decode(unhex('42ffff')) as Uint8Array)).toBe('ffff');
  });
  it('trailing data and non-minimal integers', () => {
    expect(bad('0000')).toBe('cbor: trailing bytes');
    expect(bad('f6f6')).toBe('cbor: trailing bytes');
    for (const h of ['1800', '1817', '190000', '1900ff', '1a00000000', '1a0000ffff', '1b0000000000000000', '1b00000000ffffffff', '3800', '3817']) expect(bad(h)).toBe('cbor: non-minimal integer');
    for (const h of ['1818', '190100', '1a00010000', '1b0000000100000000']) expect(() => decode(unhex(h))).not.toThrow();
    expect(bad('1b0020000000000000')).toBe('cbor: integer out of safe range');
    expect(bad('1bffffffffffffffff')).toBe('cbor: integer out of safe range');
    expect(bad('3b001fffffffffffff')).toBe('cbor: integer out of safe range');
    expect(decode(unhex('3b001ffffffffffffe'))).toBe(-Number.MAX_SAFE_INTEGER);
    expect(decode(unhex('1b001fffffffffffff'))).toBe(Number.MAX_SAFE_INTEGER);
  });
  it('unsupported items', () => {
    for (const h of ['f93c00', 'fa47c35000', 'fb3ff0000000000000', 'f800', 'f820']) expect(bad(h)).toBe('cbor: unsupported simple/float value');
    for (const h of ['f7', 'f0', 'f3', 'e0', 'ff']) expect(bad(h)).toBe('cbor: unsupported simple/float value');
    expect(decode(unhex('f4'))).toBe(false);
    expect(decode(unhex('f5'))).toBe(true);
    expect(decode(unhex('f6'))).toBeNull();
    for (const h of ['1c', '1d', '1e', '1f', '5f', '7f', '9f', 'bf', '3c']) expect(bad(h)).toBe('cbor: unsupported additional information (indefinite/reserved)');
    expect(bad('62c328')).toMatch(/UTF-8|encoded data|invalid/i);
    expect(bad('61ff')).toMatch(/UTF-8|encoded data|invalid/i);
  });
  it('map keys: type, order and duplicates', () => {
    expect(bad('a1420102')).toBe('cbor: map key must be int or text');
    expect(bad('a1f601')).toBe('cbor: map key must be int or text');
    expect(bad('a18001')).toBe('cbor: map key must be int or text');
    expect(bad('a20201 0102'.replace(' ', ''))).toBe('cbor: map keys not canonically ordered / duplicate');
    expect(bad('a201010101')).toBe('cbor: map keys not canonically ordered / duplicate');
    expect(bad('a2616101616101')).toBe('cbor: map keys not canonically ordered / duplicate');
    expect(bad('a2626262016161' + '01')).toBe('cbor: map keys not canonically ordered / duplicate');
    expect(decode(unhex('a201020304'))).toStrictEqual(M([1, 2], [3, 4]));
    expect(decode(unhex('a2616101626262' + '02'))).toStrictEqual(M(['a', 1], ['bb', 2]));
    expect(decode(unhex('a20102' + '2003'))).toStrictEqual(M([1, 2], [-1, 3]));
    expect(bad('a22003' + '0102')).toBe('cbor: map keys not canonically ordered / duplicate');
    expect(decode(unhex('a1a0a0'.slice(0, 2) + '0100'))).toBeInstanceOf(Map);
  });
  it('negative integers and tags', () => {
    expect(decode(unhex('20'))).toBe(-1);
    expect(decode(unhex('3863'))).toBe(-100);
    expect(decode(unhex('c11a514b67b0'))).toStrictEqual(new CborTag(1, 1363896240));
    expect(decode(unhex('d82a41ff'))).toStrictEqual(new CborTag(42, Uint8Array.of(0xff)));
  });
  it('round-trips nested values exactly', () => {
    const v: CborValue = M(['k', [1, -1, 'x', null, true, Uint8Array.of(9), M([5, 'v'])]], [7, new CborTag(3, [])]);
    expect(decode(encode(v))).toStrictEqual(v);
  });
});

const payload = { claim: 'x', n: 1 };
const stmt = (o: Record<string, unknown> = {}) => signStatement(payload, { alg: 'EdDSA', key: ed.privateKey, issuer: 'iss.example', ...o } as never);

describe('signStatement / checkStatement', () => {
  it('protected header: alg, content type, CWT claims', () => {
    const top = decode(stmt({ subject: 'sub' })) as CborTag;
    expect(top.tag).toBe(18);
    const [prot, unprot, pl, sig] = top.value as [Uint8Array, Map<CborKey, CborValue>, Uint8Array, Uint8Array];
    expect(decode(prot)).toStrictEqual(M([1, -8], [3, 'application/pca+json'], [15, M([1, 'iss.example'], [2, 'sub'])]));
    expect(unprot.size).toBe(0);
    expect(new TextDecoder().decode(pl)).toBe('{"claim":"x","n":1}');
    expect(sig.length).toBe(64);
    const noSub = decode(stmt()) as CborTag;
    expect(decode((noSub.value as Uint8Array[])[0] as Uint8Array)).toStrictEqual(M([1, -8], [3, 'application/pca+json'], [15, M([1, 'iss.example'])]));
    const ct = decode(stmt({ contentType: 'text/x' })) as CborTag;
    expect((decode((ct.value as Uint8Array[])[0] as Uint8Array) as Map<number, CborValue>).get(3)).toBe('text/x');
    const es = decode(signStatement(payload, { alg: 'ES256', key: ec.privateKey, issuer: 'i' })) as CborTag;
    expect((decode((es.value as Uint8Array[])[0] as Uint8Array) as Map<number, CborValue>).get(1)).toBe(-7);
  });
  it('verifies, exposes payload and leaf, and refuses tampering with exact reasons', () => {
    const s = stmt();
    expect(checkStatement(s, ed.publicKey)).toStrictEqual({ ok: true });
    expect(verifyStatement(s, ed.publicKey)).toBe(true);
    expect(verifyStatement(s, ed2.publicKey)).toBe(false);
    expect(checkStatement(s, ed2.publicKey)).toStrictEqual({ ok: false, reason: 'bad signature' });
    expect(new TextDecoder().decode(statementPayload(s))).toBe('{"claim":"x","n":1}');
    expect(statementLeaf(s)).toBe(b64u(s));
    const flip = Uint8Array.from(s);
    flip[flip.length - 1] = (flip[flip.length - 1] ?? 0) ^ 1;
    expect(checkStatement(flip, ed.publicKey)).toStrictEqual({ ok: false, reason: 'bad signature' });
    const r = checkStatement(new Uint8Array([0xa0]), ed.publicKey);
    expect(r).toStrictEqual({ ok: false, reason: 'malformed: cose: not a COSE_Sign1 (tag 18)' });
    expect(checkStatement(new Uint8Array(0), ed.publicKey)).toStrictEqual({ ok: false, reason: 'malformed: cbor: unexpected end of input' });
  });
  const cose = (items: CborValue[]) => encode(new CborTag(18, items));
  it('malformed COSE_Sign1 shapes', () => {
    const P = encode(M([1, -8]));
    const sig = new Uint8Array(64);
    const m = (b: Uint8Array) => (checkStatement(b, ed.publicKey) as { reason: string }).reason;
    expect(m(encode(new CborTag(17, [P, M(), null, sig])))).toBe('malformed: cose: not a COSE_Sign1 (tag 18)');
    expect(m(encode([P, M(), null, sig]))).toBe('malformed: cose: not a COSE_Sign1 (tag 18)');
    expect(m(cose([P, M(), new Uint8Array(1)]))).toBe('malformed: cose: malformed COSE_Sign1 array');
    expect(m(cose([P, M(), new Uint8Array(1), sig, 0]))).toBe('malformed: cose: malformed COSE_Sign1 array');
    expect(m(encode(new CborTag(18, 5)))).toBe('malformed: cose: malformed COSE_Sign1 array');
    expect(m(cose(['x', M(), new Uint8Array(1), sig]))).toBe('malformed: cose: protected must be a bstr');
    expect(m(cose([P, [], new Uint8Array(1), sig]))).toBe('malformed: cose: unprotected must be a map');
    expect(m(cose([P, M(), 'p', sig]))).toBe('malformed: cose: payload must be a bstr or nil');
    expect(m(cose([P, M(), new Uint8Array(1), 'sig']))).toBe('malformed: cose: signature must be a bstr');
    expect(m(cose([encode([1]), M(), new Uint8Array(1), sig]))).toBe('malformed: cbor: expected a map');
    expect(m(cose([P, M(), null, sig]))).toBe('detached payload');
    expect(m(cose([new Uint8Array(0), M(), new Uint8Array(1), sig]))).toBe('missing alg header');
    expect(m(cose([encode(M([1, -99])), M(), new Uint8Array(1), sig]))).toBe('unsupported alg');
    expect(m(cose([encode(M([1, 'EdDSA'])), M(), new Uint8Array(1), sig]))).toBe('unsupported alg');
    expect(m(cose([encode(M([3, 'x'])), M(), new Uint8Array(1), sig]))).toBe('missing alg header');
    expect(m(cose([P, M(), new Uint8Array(1), sig]))).toBe('bad signature');
    expect(m(cose([P, M(), new Uint8Array(1), new Uint8Array(0)]))).toBe('bad signature');
    expect(() => statementPayload(cose([P, M(), null, sig]))).toThrow('cose: statement payload is detached');
    expect(() => statementPayload(new Uint8Array([0xa0]))).toThrow('cose: not a COSE_Sign1 (tag 18)');
  });
  it('ES256: signatures are 64 bytes and low-S; high-S is refused unless allowHighS', () => {
    const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    const HALF = N >> 1n;
    let sawHighFlip = 0;
    for (let i = 0; i < 40; i++) {
      const s = signStatement({ i }, { alg: 'ES256', key: ec.privateKey, issuer: 'i' });
      const top = decode(s) as CborTag;
      const sig = (top.value as Uint8Array[])[3] as Uint8Array;
      expect(sig.length).toBe(64);
      const sv = BigInt(`0x${hex(sig.subarray(32))}`);
      expect(sv > 0n && sv <= HALF).toBe(true);
      expect(checkStatement(s, ec.publicKey)).toStrictEqual({ ok: true });
      // flip to the high-S twin
      const hi = Uint8Array.from(sig);
      hi.set(unhex((N - sv).toString(16).padStart(64, '0')), 32);
      const parts = [...(top.value as CborValue[])];
      parts[3] = hi;
      const hs = encode(new CborTag(18, parts));
      expect(checkStatement(hs, ec.publicKey)).toStrictEqual({ ok: false, reason: 'non-canonical signature (high-S)' });
      expect(verifyStatement(hs, ec.publicKey)).toBe(false);
      expect(checkStatement(hs, ec.publicKey, { allowHighS: true })).toStrictEqual({ ok: true });
      expect(checkStatement(hs, ec.publicKey, { allowHighS: false })).toStrictEqual({ ok: false, reason: 'non-canonical signature (high-S)' });
      sawHighFlip++;
    }
    expect(sawHighFlip).toBe(40);
    // structural ES256 refusals: wrong length, r = 0, s = 0, r >= N
    const s = signStatement({ a: 1 }, { alg: 'ES256', key: ec.privateKey, issuer: 'i' });
    const top = decode(s) as CborTag;
    const parts = top.value as CborValue[];
    const orig = parts[3] as Uint8Array;
    const withSig = (sig: Uint8Array) => encode(new CborTag(18, [parts[0] as CborValue, parts[1] as CborValue, parts[2] as CborValue, sig]));
    const r0 = Uint8Array.from(orig);
    r0.fill(0, 0, 32);
    const s0 = Uint8Array.from(orig);
    s0.fill(0, 32);
    const rN = Uint8Array.from(orig);
    rN.set(unhex(N.toString(16).padStart(64, '0')), 0);
    for (const bad of [orig.subarray(0, 63), Uint8Array.of(...orig, 0), r0, s0, rN]) {
      expect(checkStatement(withSig(Uint8Array.from(bad)), ec.publicKey, { allowHighS: false }).ok).toBe(false);
    }
    expect(checkStatement(withSig(orig.slice()), ec.publicKey).ok).toBe(true);
    expect((checkStatement(withSig(orig.subarray(0, 63)), ec.publicKey, { allowHighS: true }) as { reason: string }).reason).toBe('bad signature');
    expect((checkStatement(withSig(r0), ec.publicKey) as { reason: string }).reason).toBe('bad signature');
    expect((checkStatement(withSig(s0), ec.publicKey) as { reason: string }).reason).toBe('bad signature');
    // s exactly N/2 is canonical (<=), N/2 + 1 is not; both fail verification but with different reasons
    const sH = Uint8Array.from(orig);
    sH.set(unhex(HALF.toString(16).padStart(64, '0')), 32);
    expect((checkStatement(withSig(sH), ec.publicKey) as { reason: string }).reason).toBe('bad signature');
    const sH1 = Uint8Array.from(orig);
    sH1.set(unhex((HALF + 1n).toString(16).padStart(64, '0')), 32);
    expect((checkStatement(withSig(sH1), ec.publicKey) as { reason: string }).reason).toBe('bad signature');
    // r = N-1 is in range
    const rMax = Uint8Array.from(orig);
    rMax.set(unhex((N - 1n).toString(16).padStart(64, '0')), 0);
    expect((checkStatement(withSig(rMax), ec.publicKey) as { reason: string }).reason).toBe('bad signature');
    expect(checkStatement(stmt(), ec.publicKey).ok).toBe(false);
  });
});

describe('inclusion proof codec', () => {
  const svc = () => {
    const t = new TransparencyService({ alg: 'EdDSA', key: ed.privateKey, issuer: 'ts' });
    for (let i = 0; i < 7; i++) t.appendAndReceipt({ i }, { alg: 'EdDSA', key: ed.privateKey, issuer: 'i' });
    return t;
  };
  it('encode / decode round-trips every (index, size) with the right sibling sides', () => {
    for (let n = 1; n <= 20; n++) {
      const t = new TransparencyService({ alg: 'EdDSA', key: ed.privateKey });
      for (let i = 0; i < n; i++) t.register(signStatement({ i }, { alg: 'EdDSA', key: ed.privateKey, issuer: 'i' }));
      for (let i = 0; i < n; i++) {
        const { receipt } = t.getReceipt(i);
        const cose = decode(receipt) as CborTag;
        const proofBytes = ((((cose.value as CborValue[])[1] as Map<number, CborValue>).get(396) as Map<number, CborValue>).get(-1) as Uint8Array[])[0] as Uint8Array;
        const proof = decodeInclusionProof(proofBytes);
        expect([proof.index, proof.size]).toEqual([i, n]);
        expect(hex(encodeInclusionProof(proof))).toBe(hex(proofBytes));
        // sides: replay the path and compare to the tree root
        let h = leafHash(t.snapshot().length ? Buffer.from(t.snapshot()[i] as string, 'base64url') : new Uint8Array());
        for (const step of proof.path) {
          const sib = Buffer.from(step.hash, 'base64url');
          h = step.side === 'L' ? leafHashNode(sib, h) : leafHashNode(h, sib);
        }
        expect(b64u(h)).toBe(t.root);
      }
    }
  });
  it('decode errors have exact messages', () => {
    const h = b64u(new Uint8Array(32));
    const path = [new Uint8Array(32)];
    const msg = (v: CborValue) => thrown(() => decodeInclusionProof(encode(v))).message;
    expect(msg(5)).toBe('scitt: malformed inclusion proof');
    expect(msg([2, 1])).toBe('scitt: malformed inclusion proof');
    expect(msg([2, 1, [], 0])).toBe('scitt: malformed inclusion proof');
    expect(msg(['2', 1, path])).toBe('scitt: proof size/index must be integers');
    expect(msg([2, '1', path])).toBe('scitt: proof size/index must be integers');
    expect(msg([0, 0, []])).toBe('scitt: proof size/index out of range');
    expect(msg([2, 2, path])).toBe('scitt: proof size/index out of range');
    expect(msg([2, -1, path])).toBe('scitt: proof size/index out of range');
    expect(msg([2, 3, path])).toBe('scitt: proof size/index out of range');
    expect(msg([2, 1, 'x'])).toBe('scitt: inclusion path must be an array');
    expect(msg([2, 1, []])).toBe('scitt: inclusion path length does not match (index,size)');
    expect(msg([2, 1, [new Uint8Array(32), new Uint8Array(32)]])).toBe('scitt: inclusion path length does not match (index,size)');
    expect(msg([2, 1, [new Uint8Array(31)]])).toBe('scitt: inclusion path entry must be a 32-byte bstr');
    expect(msg([2, 1, [new Uint8Array(33)]])).toBe('scitt: inclusion path entry must be a 32-byte bstr');
    expect(msg([2, 1, ['x']])).toBe('scitt: inclusion path entry must be a 32-byte bstr');
    expect(decodeInclusionProof(encode([1, 0, []]))).toStrictEqual({ index: 0, size: 1, path: [] });
    expect(decodeInclusionProof(encode([2, 1, path]))).toStrictEqual({ index: 1, size: 2, path: [{ side: 'L', hash: h }] });
    expect(decodeInclusionProof(encode([2, 0, path]))).toStrictEqual({ index: 0, size: 2, path: [{ side: 'R', hash: h }] });
    expect(() => encodeInclusionProof({ index: 0, size: 2, path: [{ side: 'R', hash: 'AAAA' }] })).toThrow('scitt: proof step hash is not a 32-byte b64u hash');
    expect(svc().size).toBe(7);
  });
});
function leafHashNode(l: Uint8Array, r: Uint8Array): Uint8Array {
  return treeHash([l, r]);
}

describe('receipts', () => {
  const t = new TransparencyService({ alg: 'EdDSA', key: ed.privateKey, issuer: 'ts.example' });
  const stmts: Uint8Array[] = [];
  for (let i = 0; i < 6; i++) {
    const r = t.appendAndReceipt({ i }, { alg: 'EdDSA', key: ed.privateKey, issuer: 'i' });
    stmts.push(r.statement);
  }
  const got = t.getReceipt(3);
  const st = stmts[3] as Uint8Array;
  const tsKey = ed.publicKey;
  it('verifies with a key, a root, or both; refuses with neither', () => {
    expect(verifyReceipt(got.receipt, st, { verificationKey: tsKey })).toBe(true);
    expect(verifyReceipt(got.receipt, st, { treeRoot: t.root })).toBe(true);
    expect(verifyReceipt(got.receipt, st, { verificationKey: tsKey, treeRoot: t.root })).toBe(true);
    expect(verifyReceipt(got.receipt, st, { verificationKey: tsKey, treeRoot: t.root, statementKey: ed.publicKey })).toBe(true);
    expect(verifyReceipt(got.receipt, st, {})).toBe(false);
    expect(verifyReceipt(got.receipt, st, { statementKey: ed.publicKey })).toBe(false);
    expect(verifyReceipt(got.receipt, st, { verificationKey: ed2.publicKey })).toBe(false);
    expect(verifyReceipt(got.receipt, st, { treeRoot: b64u(new Uint8Array(32)) })).toBe(false);
    expect(verifyReceipt(got.receipt, stmts[2] as Uint8Array, { verificationKey: tsKey })).toBe(false);
    expect(verifyReceipt(got.receipt, st, { verificationKey: tsKey, statementKey: ed2.publicKey })).toBe(false);
    expect(verifyReceipt(got.receipt, st, { treeRoot: t.root, statementKey: ed2.publicKey })).toBe(false);
    expect(verifyReceipt(new Uint8Array([1, 2, 3]), st, { verificationKey: tsKey })).toBe(false);
    expect(verifyReceipt(got.receipt, new Uint8Array([1, 2, 3]), { treeRoot: t.root })).toBe(false);
  });
  it('the receipt header names RFC9162_SHA256, the issuer and carries a detached root', () => {
    const top = decode(got.receipt) as CborTag;
    const [prot, unprot, pl] = top.value as [Uint8Array, Map<number, CborValue>, null];
    expect(decode(prot)).toStrictEqual(M([1, -8], [15, M([1, 'ts.example'])], [395, 1]));
    expect(pl).toBeNull();
    expect((unprot.get(396) as Map<number, CborValue>).get(-1)).toHaveLength(1);
    const anon = new TransparencyService({ alg: 'EdDSA', key: ed.privateKey });
    const r0 = anon.register(stmts[0] as Uint8Array);
    const p0 = decode(((decode(r0.receipt) as CborTag).value as Uint8Array[])[0] as Uint8Array) as Map<number, CborValue>;
    expect([...p0.keys()].sort((a, b) => a - b)).toEqual([1, 395]);
  });
  it('a receipt built for another statement, another size, or with a doctored header is refused', () => {
    const top = decode(got.receipt) as CborTag;
    const [prot, unprot, pl, sig] = top.value as [Uint8Array, Map<number, CborValue>, null, Uint8Array];
    const mk = (parts: CborValue[]) => encode(new CborTag(18, parts));
    const ok = (r: Uint8Array) => verifyReceipt(r, st, { verificationKey: tsKey });
    expect(ok(mk([prot, unprot, pl, sig]))).toBe(true);
    expect(ok(mk([encode(M([1, -8], [395, 2])), unprot, pl, sig]))).toBe(false); // VDS id
    expect(ok(mk([encode(M([1, -8])), unprot, pl, sig]))).toBe(false);
    expect(ok(mk([prot, M(), pl, sig]))).toBe(false); // no proofs map
    expect(ok(mk([prot, M([396, 'x']), pl, sig]))).toBe(false);
    expect(ok(mk([prot, M([396, M()]), pl, sig]))).toBe(false); // no inclusion proof
    expect(ok(mk([prot, M([396, M([-1, []])]), pl, sig]))).toBe(false);
    expect(ok(mk([prot, M([396, M([-1, [5]])]), pl, sig]))).toBe(false);
    expect(ok(mk([prot, unprot, new Uint8Array(31), sig]))).toBe(false); // wrong-size attached root
    expect(ok(mk([prot, unprot, new Uint8Array(32), sig]))).toBe(false); // attached root that is not the computed one
    expect(ok(mk([prot, unprot, pl, new Uint8Array(64)]))).toBe(false);
    expect(ok(mk([prot, unprot, pl, Uint8Array.of(...sig, 0)]))).toBe(false);
    // attached payload equal to the recomputed root is accepted
    const rootBytes = new Uint8Array(Buffer.from(t.root, 'base64url'));
    expect(ok(mk([prot, unprot, rootBytes, sig]))).toBe(true);
    // a proof for another index does not authenticate this statement
    const other = t.getReceipt(2);
    expect(verifyReceipt(other.receipt, st, { verificationKey: tsKey })).toBe(false);
    expect(verifyReceipt(other.receipt, stmts[2] as Uint8Array, { verificationKey: tsKey })).toBe(true);
    // an old receipt stays valid against its own (older) root and key
    const early = new TransparencyService({ alg: 'EdDSA', key: ed.privateKey });
    const r1 = early.register(stmts[0] as Uint8Array);
    early.register(stmts[1] as Uint8Array);
    expect(verifyReceipt(r1.receipt, stmts[0] as Uint8Array, { verificationKey: tsKey, treeRoot: r1.root })).toBe(true);
    expect(verifyReceipt(r1.receipt, stmts[0] as Uint8Array, { treeRoot: early.root })).toBe(false);
  });
  it('allowHighS governs ES256 receipts', () => {
    const es = new TransparencyService({ alg: 'ES256', key: ec.privateKey });
    const s = signStatement({ a: 1 }, { alg: 'ES256', key: ec.privateKey, issuer: 'i' });
    const r = es.register(s);
    expect(verifyReceipt(r.receipt, s, { verificationKey: ec.publicKey, statementKey: ec.publicKey })).toBe(true);
    const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    const top = decode(r.receipt) as CborTag;
    const parts = [...(top.value as CborValue[])];
    const sig = parts[3] as Uint8Array;
    const hi = Uint8Array.from(sig);
    hi.set(unhex((N - BigInt(`0x${hex(sig.subarray(32))}`)).toString(16).padStart(64, '0')), 32);
    parts[3] = hi;
    const hs = encode(new CborTag(18, parts));
    expect(verifyReceipt(hs, s, { verificationKey: ec.publicKey })).toBe(false);
    expect(verifyReceipt(hs, s, { verificationKey: ec.publicKey, allowHighS: false })).toBe(false);
    expect(verifyReceipt(hs, s, { verificationKey: ec.publicKey, allowHighS: true })).toBe(true);
    // allowHighS also reaches the statement check
    const sTop = decode(s) as CborTag;
    const sParts = [...(sTop.value as CborValue[])];
    const ssig = sParts[3] as Uint8Array;
    const shi = Uint8Array.from(ssig);
    shi.set(unhex((N - BigInt(`0x${hex(ssig.subarray(32))}`)).toString(16).padStart(64, '0')), 32);
    sParts[3] = shi;
    const hiStmt = encode(new CborTag(18, sParts));
    expect(verifyReceipt(r.receipt, hiStmt, { treeRoot: r.root, statementKey: ec.publicKey })).toBe(false); // wrong leaf anyway
    const es2 = new TransparencyService({ alg: 'ES256', key: ec.privateKey });
    const r2 = es2.register(hiStmt);
    expect(verifyReceipt(r2.receipt, hiStmt, { verificationKey: ec.publicKey, statementKey: ec.publicKey })).toBe(false);
    expect(verifyReceipt(r2.receipt, hiStmt, { verificationKey: ec.publicKey, statementKey: ec.publicKey, allowHighS: true })).toBe(true);
  });
  it('buildReceipt rejects a root that is not a 32-byte hash', () => {
    const proof = { index: 0, size: 1, path: [] };
    for (const root of ['AAAA', '', b64u(new Uint8Array(33)), '!!!']) {
      expect(thrown(() => buildReceipt(root, proof, { alg: 'EdDSA', key: ed.privateKey })).message).toBe('scitt: tree root is not a 32-byte b64u hash');
    }
    expect(buildReceipt(b64u(new Uint8Array(32)), proof, { alg: 'EdDSA', key: ed.privateKey }).length).toBeGreaterThan(50);
  });
});

describe('TransparencyService', () => {
  it('registers, numbers, snapshots and roots', () => {
    const t = new TransparencyService({ alg: 'EdDSA', key: ed.privateKey });
    expect(t.size).toBe(0);
    expect(t.root).toBe(b64u(treeHash([])));
    const s0 = stmt();
    const r0 = t.register(s0);
    expect([r0.index, t.size]).toEqual([0, 1]);
    expect(r0.root).toBe(t.root);
    expect(t.root).toBe(b64u(leafHash(s0)));
    const r1 = t.appendAndReceipt({ z: 1 }, { alg: 'EdDSA', key: ed.privateKey, issuer: 'i' });
    expect(r1.index).toBe(1);
    expect(r1.statement.length).toBeGreaterThan(10);
    expect(t.snapshot()).toStrictEqual([b64u(s0), b64u(r1.statement)]);
    expect(t.root).toBe(b64u(treeHash([leafHash(s0), leafHash(r1.statement)])));
    // the service keeps a private copy of what was registered
    const mutable = stmt({ issuer: 'm' });
    const copy = Uint8Array.from(mutable);
    t.register(mutable);
    mutable.fill(0);
    expect(t.snapshot()[2]).toBe(b64u(copy));
  });
  it('refuses a detached-payload statement and malformed statements', () => {
    const t = new TransparencyService({ alg: 'EdDSA', key: ed.privateKey });
    const detached = encode(new CborTag(18, [encode(M([1, -8])), M(), null, new Uint8Array(64)]));
    expect(() => t.register(detached)).toThrow('scitt: cannot register a statement with a detached payload');
    expect(() => t.register(new Uint8Array([0xa0]))).toThrow('cose: not a COSE_Sign1 (tag 18)');
    expect(t.size).toBe(0);
  });
  it('getReceipt / consistencyProof range checks and contents', () => {
    const t = new TransparencyService({ alg: 'EdDSA', key: ed.privateKey });
    for (let i = 0; i < 5; i++) t.appendAndReceipt({ i }, { alg: 'EdDSA', key: ed.privateKey, issuer: 'i' });
    for (const i of [-1, 5, 1.5, NaN, Infinity]) expect(() => t.getReceipt(i)).toThrow('getReceipt: index out of range');
    expect(t.getReceipt(0).index).toBe(0);
    expect(t.getReceipt(4).index).toBe(4);
    for (const n of [0, -1, 6, 2.5, NaN]) expect(() => t.consistencyProof(n)).toThrow('consistencyProof: size out of range');
    for (let old = 1; old <= 5; old++) {
      const c = t.consistencyProof(old);
      expect([c.oldSize, c.newSize]).toEqual([old, 5]);
      expect(c.newRoot).toBe(t.root);
      expect(verifyConsistencyProof(c.proof, c.oldRoot, c.newRoot)).toBe(true);
      expect(verifyConsistencyProof(c.proof, c.newRoot, c.oldRoot)).toBe(old === 5);
    }
  });
  it('verifyConsistencyProof refuses malformed proofs and roots', () => {
    const t = new TransparencyService({ alg: 'EdDSA', key: ed.privateKey });
    for (let i = 0; i < 6; i++) t.appendAndReceipt({ i }, { alg: 'EdDSA', key: ed.privateKey, issuer: 'i' });
    const c = t.consistencyProof(3);
    const dec = decode(c.proof) as [number, number, Uint8Array[]];
    const v = (proof: Uint8Array, a = c.oldRoot, b = c.newRoot) => verifyConsistencyProof(proof, a, b);
    expect(v(c.proof)).toBe(true);
    expect(v(encode([3, 6]))).toBe(false);
    expect(v(encode([3, 6, dec[2], 0]))).toBe(false);
    expect(v(encode(['3', 6, dec[2]]))).toBe(false);
    expect(v(encode([3, '6', dec[2]]))).toBe(false);
    expect(v(encode([3, 6, 'x']))).toBe(false);
    expect(v(encode([3, 6, [...dec[2], 'x']]))).toBe(false);
    expect(v(encode([3, 6, [...dec[2], 5]]))).toBe(false);
    expect(v(encode([3, 6, dec[2]]))).toBe(true);
    expect(v(encode(5))).toBe(false);
    expect(v(new Uint8Array([0xff]))).toBe(false);
    expect(v(c.proof, 'AAAA')).toBe(false);
    expect(v(c.proof, c.oldRoot, 'AAAA')).toBe(false);
    expect(v(c.proof, '!!!')).toBe(false);
    expect(v(c.proof, c.oldRoot, '')).toBe(false);
    expect(v(c.proof, b64u(new Uint8Array(32)))).toBe(false);
    expect(v(c.proof, c.oldRoot, b64u(new Uint8Array(32)))).toBe(false);
  });
});
