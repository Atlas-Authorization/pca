/** Mutation-kill suite for sdjwt.ts: codecs, JWK validation, SD-JWT parsing and disclosure processing, every reason string. */
import { createHash, createPrivateKey, generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  Ap2Error,
  ap2KeyPairFromPrivateJwk,
  assertP256Jwk,
  b64uDecode,
  b64uEncode,
  disclosureBuilder,
  generateAp2KeyPair,
  hopSdJwt,
  isObject,
  isSdAlg,
  issuerJwtHashOf,
  jwkThumbprint,
  newSalt,
  parseJson,
  parseJwt,
  parseSdJwtHop,
  processDisclosures,
  sdDigest,
  sdHashOf,
  signJwtEs256,
  signSdJwt,
  verifyHopSignature,
  verifyJwtEs256,
  type JsonObject,
  type SdAlg,
} from './sdjwt';

const enc = (v: unknown): string => Buffer.from(JSON.stringify(v), 'utf8').toString('base64url');
const raw = (v: unknown): string => enc(v);
const throwsMsg = (f: () => unknown): string => {
  try {
    f();
  } catch (e) {
    expect(e).toBeInstanceOf(Ap2Error);
    return (e as Error).message;
  }
  return 'NO THROW';
};

describe('Ap2Error and tiny helpers', () => {
  it('names itself', () => {
    const e = new Ap2Error('boom');
    expect(e.name).toBe('Ap2Error');
    expect(e.message).toBe('boom');
    expect(e instanceof Error).toBe(true);
  });
  it('isObject: plain objects only', () => {
    expect(isObject({})).toBe(true);
    for (const v of [null, [], 'x', 5, undefined, true]) expect(isObject(v)).toBe(false);
  });
  it('isSdAlg accepts the three algorithms only', () => {
    for (const a of ['sha-256', 'sha-384', 'sha-512']) expect(isSdAlg(a)).toBe(true);
    for (const a of ['sha-1', 'SHA-256', 'sha256', '', undefined, 5, null]) expect(isSdAlg(a)).toBe(false);
  });
  it('b64uEncode of strings (UTF-8) and bytes', () => {
    expect(b64uEncode('é')).toBe('w6k');
    expect(b64uEncode('hello')).toBe('aGVsbG8');
    expect(b64uEncode(new Uint8Array([0xff, 0xfe]))).toBe('__4');
    expect(b64uEncode(new Uint8Array([0xc3, 0xa9]))).toBe('w6k');
    expect(b64uEncode(Buffer.from('€', 'utf8'))).toBe('4oKs');
  });
  it('newSalt is 16 random bytes in base64url', () => {
    const a = newSalt();
    expect(a).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(newSalt()).not.toBe(a);
  });
});

describe('b64uDecode', () => {
  it('canonical input round-trips', () => {
    expect(b64uDecode('aGVsbG8', 'x').toString()).toBe('hello');
    expect(b64uDecode('', 'x').length).toBe(0);
  });
  it('alphabet violations anywhere in the string', () => {
    for (const s of ['a+b', '!abc', 'abc!', 'ab c', 'ab=c', 'a/b', 'ab\n']) expect(throwsMsg(() => b64uDecode(s, 'tok')), s).toBe('tok: not base64url');
  });
  it('non-canonical trailing bits', () => {
    expect(throwsMsg(() => b64uDecode('AB', 'tok'))).toBe('tok: non-canonical base64url');
    expect(throwsMsg(() => b64uDecode('aGVsbG9', 'tok'))).toBe('tok: non-canonical base64url');
  });
});

describe('parseJson and duplicate keys', () => {
  it('parses, labels invalid JSON', () => {
    expect(parseJson('{"a":[1,2,{"b":null}]}', 'x')).toEqual({ a: [1, 2, { b: null }] });
    const m = throwsMsg(() => parseJson('{oops', 'lbl'));
    expect(m.startsWith('lbl: invalid JSON (')).toBe(true);
    expect(m.endsWith(')')).toBe(true);
    expect(m.length).toBeGreaterThan('lbl: invalid JSON ()'.length);
  });
  it('duplicate keys at any depth', () => {
    expect(throwsMsg(() => parseJson('{"a":1,"a":2}', 'x'))).toBe('x: duplicate key "a"');
    expect(throwsMsg(() => parseJson('{"a":[1],"a":2}', 'x'))).toBe('x: duplicate key "a"');
    expect(throwsMsg(() => parseJson('{"a":[{"x":1}],"a":2}', 'x'))).toBe('x: duplicate key "a"');
    expect(throwsMsg(() => parseJson('{"a":{"b":1},"c":{"d":1,"d":2}}', 'x'))).toBe('x: duplicate key "d"');
    expect(throwsMsg(() => parseJson('[{"a":1,"a":2}]', 'x'))).toBe('x: duplicate key "a"');
    expect(throwsMsg(() => parseJson('{"a":{"b":1},"a":2}', 'x'))).toBe('x: duplicate key "a"');
    expect(throwsMsg(() => parseJson('{"a":"v","k\\"":1,"k\\"":2}', 'x'))).toBe('x: duplicate key "k\\""');
  });
  it('the same key in different objects or after a closed one is fine', () => {
    expect(parseJson('{"a":{"b":1},"b":2}', 'x')).toEqual({ a: { b: 1 }, b: 2 });
    expect(parseJson('[{"a":1},{"a":2}]', 'x')).toEqual([{ a: 1 }, { a: 2 }]);
    expect(parseJson('{"a":[{"k":1}],"b":[{"k":2}],"c":{"k":3}}', 'x')).toEqual({ a: [{ k: 1 }], b: [{ k: 2 }], c: { k: 3 } });
    expect(parseJson('{"a":["b","c"],"b":1}', 'x')).toEqual({ a: ['b', 'c'], b: 1 });
    expect(parseJson('{"a":"a","b":"a"}', 'x')).toEqual({ a: 'a', b: 'a' });
    expect(parseJson('{"a":[["b"]],"b":1}', 'x')).toEqual({ a: [['b']], b: 1 });
    expect(parseJson('"abc"', 'x')).toBe('abc');
  });
});

describe('sdDigest', () => {
  it('matches the reference digest and algorithm names', () => {
    expect(sdDigest('abc')).toBe(createHash('sha256').update('abc').digest('base64url'));
    expect(sdDigest('abc', 'sha-384')).toBe(createHash('sha384').update('abc').digest('base64url'));
    expect(sdDigest('abc', 'sha-512')).toBe(createHash('sha512').update('abc').digest('base64url'));
    expect(sdDigest('')).toBe(createHash('sha256').update('').digest('base64url'));
  });
  it('ASCII printable only, anchored at both ends', () => {
    const msg = 'digest input must be ASCII';
    for (const s of ['é', 'aé', 'éa', 'a\x1fb', '\x1f', 'a\x7f', '\x7f', 'a ', '\nabc', 'abc\n']) expect(throwsMsg(() => sdDigest(s)), JSON.stringify(s)).toBe(msg);
    expect(() => sdDigest(' ~')).not.toThrow();
  });
});

describe('JWK validation', () => {
  const k = generateAp2KeyPair('kid');
  const j = k.publicJwk;
  const bad = (over: Record<string, unknown>, del: string[] = []) => {
    const o: Record<string, unknown> = { ...j, ...over };
    for (const d of del) delete o[d];
    return throwsMsg(() => assertP256Jwk(o, 'w'));
  };
  it('accepts a real key and returns it', () => {
    expect(assertP256Jwk(j, 'w')).toBe(j);
    expect(assertP256Jwk({ ...j, alg: 'ES256' }, 'w')).toMatchObject({ alg: 'ES256' });
  });
  it('every field has its own message', () => {
    expect(throwsMsg(() => assertP256Jwk(null, 'w'))).toBe('w: JWK must be an object');
    expect(throwsMsg(() => assertP256Jwk([], 'w'))).toBe('w: JWK must be an object');
    expect(bad({ kty: 'RSA' })).toBe('w: JWK must be EC P-256');
    expect(bad({ crv: 'P-384' })).toBe('w: JWK must be EC P-256');
    expect(bad({ x: { toString: () => j.x } })).toBe('w: bad JWK x');
    expect(bad({ y: { toString: () => j.y } })).toBe('w: bad JWK y');
    expect(bad({ x: [j.x] })).toBe('w: bad JWK x');
    expect(bad({ x: 5 })).toBe('w: bad JWK x');
    expect(bad({ x: 'short' })).toBe('w: bad JWK x');
    expect(bad({ x: j.x + 'A' })).toBe('w: bad JWK x');
    expect(bad({ x: j.x.slice(0, 42) + '+' })).toBe('w: bad JWK x');
    expect(bad({ y: 5 })).toBe('w: bad JWK y');
    expect(bad({ y: 'short' })).toBe('w: bad JWK y');
    expect(bad({ y: j.y + 'A' })).toBe('w: bad JWK y');
    expect(bad({ d: 'secret' })).toBe('w: JWK carries private material');
    expect(bad({ alg: 'RS256' })).toBe('w: JWK alg must be ES256');
    expect(bad({ x: 'A'.repeat(43), y: 'A'.repeat(43) })).toBe('w: JWK is not a valid P-256 point');
  });
});

describe('key pairs and thumbprints', () => {
  it('generateAp2KeyPair carries the kid only when given', () => {
    const a = generateAp2KeyPair();
    expect(Object.keys(a.publicJwk).sort()).toEqual(['crv', 'kty', 'x', 'y']);
    expect(a.publicJwk).toMatchObject({ kty: 'EC', crv: 'P-256' });
    const b = generateAp2KeyPair('my-kid');
    expect(b.publicJwk.kid).toBe('my-kid');
  });
  it('ap2KeyPairFromPrivateJwk rebuilds the pair', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = privateKey.export({ format: 'jwk' });
    const pub = publicKey.export({ format: 'jwk' });
    const a = ap2KeyPairFromPrivateJwk({ ...jwk });
    expect(a.publicJwk).toEqual({ kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y });
    expect(Object.keys(a.publicJwk)).not.toContain('kid');
    const b = ap2KeyPairFromPrivateJwk({ ...jwk, kid: 'rebuilt' });
    expect(b.publicJwk).toEqual({ kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y, kid: 'rebuilt' });
    const c = ap2KeyPairFromPrivateJwk({ ...jwk, kid: 5 });
    expect(Object.keys(c.publicJwk)).not.toContain('kid');
    const tok = signJwtEs256({ header: {}, payload: { a: 1 }, privateKey: b.privateKey });
    expect(verifyJwtEs256(parseJwt(tok, 't'), b.publicJwk)).toBe(true);
    expect(createPrivateKey(b.privateKey.export({ format: 'pem', type: 'pkcs8' })).type).toBe('private');
  });
  it('jwkThumbprint is the RFC 7638 SHA-256 over the canonical members', () => {
    const jwk = { kty: 'EC', crv: 'P-256', x: 'X'.repeat(43), y: 'Y'.repeat(43), kid: 'ignored' } as never;
    const expected = createHash('sha256').update(`{"crv":"P-256","kty":"EC","x":"${'X'.repeat(43)}","y":"${'Y'.repeat(43)}"}`, 'utf8').digest('base64url');
    expect(jwkThumbprint(jwk)).toBe(expected);
  });
});

/** An SD-JWT whose header/payload/signature segments are fully under test control. */
const jwtOf = (h: unknown, p: unknown, s = 'AA'): string => `${enc(h)}.${enc(p)}.${s}`;

describe('parseSdJwtHop', () => {
  it('structure errors, each with its own message', () => {
    expect(throwsMsg(() => parseSdJwtHop(''))).toBe('SD-JWT: empty');
    expect(throwsMsg(() => parseSdJwtHop(undefined as never))).toBe('SD-JWT: empty');
    expect(throwsMsg(() => parseSdJwtHop(5 as never))).toBe('SD-JWT: empty');
    expect(throwsMsg(() => parseSdJwtHop('~a.b.c~'))).toBe('SD-JWT: empty issuer JWT');
    expect(throwsMsg(() => parseSdJwtHop('a.b.c'))).toBe('SD-JWT: must end with "~" (a trailing KB-JWT is not an AP2 form)');
    expect(throwsMsg(() => parseSdJwtHop('a.b.c~~~'))).toBe('SD-JWT: empty disclosure segment');
    expect(throwsMsg(() => parseSdJwtHop('a.b.c~d~~'))).toBe('SD-JWT: empty disclosure segment');
    for (const j of ['a.b', 'a.b.c.d', 'a..c', '.b.c', 'a.b.', '..']) expect(throwsMsg(() => parseSdJwtHop(`${j}~`)), j).toBe('SD-JWT: issuer JWT must be header.payload.signature');
  });
  it('segment decoders carry their own labels', () => {
    const ok = (x: string) => enc({ alg: 'ES256' }) + '.' + x;
    expect(throwsMsg(() => parseSdJwtHop(`!!!.${enc({})}.AA~`))).toBe('JWT header: not base64url');
    expect(throwsMsg(() => parseSdJwtHop(`${enc([])}.${enc({})}.AA~`))).toBe('JWT header: must be a JSON object');
    expect(throwsMsg(() => parseSdJwtHop(`${ok('!!!')}.AA~`))).toBe('JWT payload: not base64url');
    expect(throwsMsg(() => parseSdJwtHop(`${ok(enc('str'))}.AA~`))).toBe('JWT payload: must be a JSON object');
    expect(throwsMsg(() => parseSdJwtHop(`${ok(enc({}))}.!!!~`))).toBe('JWT signature: not base64url');
    expect(throwsMsg(() => parseSdJwtHop(`${ok(enc({}))}.AB~`))).toBe('JWT signature: non-canonical base64url');
  });
  it('_sd_alg handling', () => {
    expect(throwsMsg(() => parseSdJwtHop(`${jwtOf({}, { _sd_alg: 'md5' })}~`))).toBe('SD-JWT: unsupported _sd_alg "md5"');
    expect(throwsMsg(() => parseSdJwtHop(`${jwtOf({}, { _sd_alg: 5 })}~`))).toBe('SD-JWT: unsupported _sd_alg 5');
    expect(parseSdJwtHop(`${jwtOf({}, {})}~`).sdAlg).toBe('sha-256');
    for (const a of ['sha-256', 'sha-384', 'sha-512'] as const) expect(parseSdJwtHop(`${jwtOf({}, { _sd_alg: a })}~`).sdAlg).toBe(a);
  });
  it('every field of the parsed hop', () => {
    const jwt = jwtOf({ alg: 'ES256', typ: 'x' }, { a: 1 }, 'AAAA');
    const h = parseSdJwtHop(`${jwt}~d1~d2~`);
    expect(h.raw).toBe(`${jwt}~d1~d2~`);
    expect(h.jwt).toBe(jwt);
    expect(h.header).toEqual({ alg: 'ES256', typ: 'x' });
    expect(h.payload).toEqual({ a: 1 });
    expect(h.disclosures).toEqual(['d1', 'd2']);
    expect(h.signingInput).toBe(jwt.split('.').slice(0, 2).join('.'));
    expect(h.signature).toEqual(Buffer.from('AAAA', 'base64url'));
    expect(hopSdJwt(h)).toBe(`${jwt}~d1~d2~`);
    expect(hopSdJwt({ jwt: 'j', disclosures: [] })).toBe('j~');
  });
  it('sdHashOf / issuerJwtHashOf default to the hop algorithm and accept an override', () => {
    const jwt = jwtOf({ alg: 'ES256' }, { _sd_alg: 'sha-384' });
    const h = parseSdJwtHop(`${jwt}~`);
    expect(sdHashOf(h)).toBe(sdDigest(`${jwt}~`, 'sha-384'));
    expect(issuerJwtHashOf(h)).toBe(sdDigest(jwt, 'sha-384'));
    expect(sdHashOf(h, 'sha-512')).toBe(sdDigest(`${jwt}~`, 'sha-512'));
    expect(issuerJwtHashOf(h, 'sha-512')).toBe(sdDigest(jwt, 'sha-512'));
    expect(sdHashOf(h)).not.toBe(issuerJwtHashOf(h));
  });
});

describe('signatures', () => {
  const k = generateAp2KeyPair();
  const sdjwt = (header: object, payload: JsonObject) => parseSdJwtHop(signSdJwt({ header: header as never, payload, disclosures: [], privateKey: k.privateKey }));
  it('signSdJwt: merged header, ES256 verifies, tamper detected', () => {
    const t = signSdJwt({ header: { typ: 'x', kid: 'kk' }, payload: { a: 1 }, disclosures: ['d1'], privateKey: k.privateKey });
    const h = parseSdJwtHop(t);
    expect(h.header).toEqual({ alg: 'ES256', typ: 'x', kid: 'kk' });
    expect(h.disclosures).toEqual(['d1']);
    expect(verifyHopSignature(h, k.publicJwk)).toBe(true);
    expect(verifyHopSignature(h, generateAp2KeyPair().publicJwk)).toBe(false);
    expect(h.signature.length).toBe(64);
  });
  it('a non-ES256 alg header is refused even with a valid signature over it', () => {
    const header = { alg: 'RS256', typ: 'x' };
    const p = { a: 1 };
    const signingInput = `${enc(header)}.${enc(p)}`;
    const sig = nodeSign('sha256', Buffer.from(signingInput, 'ascii'), { key: k.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    const h = parseSdJwtHop(`${signingInput}.${sig}~`);
    expect(verifyHopSignature(h, k.publicJwk)).toBe(false);
    const jwt = parseJwt(`${signingInput}.${sig}`, 'j');
    expect(verifyJwtEs256(jwt, k.publicJwk)).toBe(false);
    const good = `${enc({ alg: 'ES256' })}.${enc(p)}`;
    const gsig = nodeSign('sha256', Buffer.from(good, 'ascii'), { key: k.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    expect(verifyJwtEs256(parseJwt(`${good}.${gsig}`, 'j'), k.publicJwk)).toBe(true);
    expect(verifyHopSignature(parseSdJwtHop(`${good}.${gsig}~`), k.publicJwk)).toBe(true);
  });
  it('a signature that is not 64 bytes never verifies', () => {
    const t = signSdJwt({ header: { typ: 'x' }, payload: {}, disclosures: [], privateKey: k.privateKey });
    const [h, p, s] = t.split('~')[0]!.split('.') as [string, string, string];
    const sigBytes = Buffer.from(s, 'base64url');
    for (const bytes of [sigBytes.subarray(0, 63), Buffer.concat([sigBytes, Buffer.from([0])]), Buffer.alloc(0)]) {
      const hop = parseSdJwtHop(`${h}.${p}.${bytes.length === 0 ? 'AA' : bytes.toString('base64url')}~`);
      expect(verifyHopSignature(hop, k.publicJwk)).toBe(false);
    }
    expect(verifyHopSignature(sdjwt({ typ: 'x' }, {}), k.publicJwk)).toBe(true);
  });
  it('the verification key is validated first', () => {
    const h = sdjwt({ typ: 'x' }, {});
    expect(throwsMsg(() => verifyHopSignature(h, 'nope' as never))).toBe('verification key: JWK must be an object');
    const jwt = parseJwt(signJwtEs256({ header: {}, payload: {}, privateKey: k.privateKey }), 'j');
    expect(throwsMsg(() => verifyJwtEs256(jwt, 'nope' as never))).toBe('verification key: JWK must be an object');
  });
  it('signJwtEs256: default typ JWT, overridable; compact three-part form', () => {
    const a = signJwtEs256({ header: { kid: 'z' }, payload: { a: 1 }, privateKey: k.privateKey });
    expect(a.split('.').length).toBe(3);
    const pa = parseJwt(a, 'j');
    expect(pa.header).toEqual({ alg: 'ES256', typ: 'JWT', kid: 'z' });
    expect(pa.payload).toEqual({ a: 1 });
    expect(parseJwt(signJwtEs256({ header: { typ: 'custom' }, payload: {}, privateKey: k.privateKey }), 'j').header.typ).toBe('custom');
    expect(pa.signingInput).toBe(a.split('.').slice(0, 2).join('.'));
  });
});

describe('parseJwt', () => {
  it('shape and per-segment labels', () => {
    for (const j of ['a.b', 'a.b.c.d', 'a..c', '.b.c', 'a.b.']) expect(throwsMsg(() => parseJwt(j, 'tok')), j).toBe('tok: must be header.payload.signature');
    expect(throwsMsg(() => parseJwt(`!!!.${enc({})}.AA`, 'tok'))).toBe('tok header: not base64url');
    expect(throwsMsg(() => parseJwt(`${enc({})}.!!!.AA`, 'tok'))).toBe('tok payload: not base64url');
    expect(throwsMsg(() => parseJwt(`${enc({})}.${enc({})}.!!!`, 'tok'))).toBe('tok signature: not base64url');
    expect(throwsMsg(() => parseJwt(`${enc([])}.${enc({})}.AA`, 'tok'))).toBe('tok header: must be a JSON object');
  });
});

describe('disclosures', () => {
  const run = (payload: JsonObject, ds: string[], alg: SdAlg = 'sha-256') => processDisclosures(payload, ds, alg);
  it('disclosureBuilder: default algorithm, salts, forms', () => {
    const b = disclosureBuilder();
    const el = b.element({ a: 1 });
    expect(el['...']).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(b.disclosures.length).toBe(1);
    const d = JSON.parse(Buffer.from(b.disclosures[0] as string, 'base64url').toString()) as unknown[];
    expect(d.length).toBe(2);
    expect(typeof d[0]).toBe('string');
    expect(d[1]).toEqual({ a: 1 });
    expect(el['...']).toBe(sdDigest(b.disclosures[0] as string, 'sha-256'));
    const salts = disclosureBuilder('sha-512', () => 'S');
    const p = salts.property('name', 5);
    expect(p).toBe(sdDigest(salts.disclosures[0] as string, 'sha-512'));
    expect(JSON.parse(Buffer.from(salts.disclosures[0] as string, 'base64url').toString())).toEqual(['S', 'name', 5]);
    const e2 = salts.element('v');
    expect(e2['...'].length).toBe(86);
  });
  it('resolves property and element disclosures and strips markers', () => {
    const b = disclosureBuilder('sha-256', () => 'S');
    const dprop = b.property('secret', { n: 1 });
    const delem = b.element('x');
    const out = run({ a: 1, _sd: [dprop], list: [delem, 'plain'], _sd_alg: 'sha-256', nested: { _sd: [] } }, b.disclosures);
    expect(out).toEqual({ a: 1, secret: { n: 1 }, list: ['x', 'plain'], nested: {} });
  });
  it('decoy digests and withheld disclosures are ignored', () => {
    expect(run({ _sd: ['unmatched'], l: [{ '...': 'unmatched' }] }, [])).toEqual({ l: [] });
  });
  it('disclosure syntax errors', () => {
    const d = (v: unknown) => throwsMsg(() => run({ _sd: ['x'] }, [raw(v)]));
    expect(d({ a: 1 })).toBe('disclosure: must be a JSON array');
    expect(d('s')).toBe('disclosure: must be a JSON array');
    expect(d([5, 'n', 1])).toBe('disclosure: salt must be a non-empty string');
    expect(d(['', 'n', 1])).toBe('disclosure: salt must be a non-empty string');
    expect(d([null, 1])).toBe('disclosure: salt must be a non-empty string');
    expect(d(['s', 5, 1])).toBe('disclosure: claim name must be a string');
    expect(d(['s', '_sd', 1])).toBe('disclosure: claim name _sd is reserved');
    expect(d(['s', '...', 1])).toBe('disclosure: claim name ... is reserved');
    expect(d(['s'])).toBe('disclosure: array must have 2 or 3 elements');
    expect(d(['s', 'a', 'b', 'c'])).toBe('disclosure: array must have 2 or 3 elements');
    expect(throwsMsg(() => run({}, ['!!!']))).toBe('disclosure: not base64url');
    expect(throwsMsg(() => run({}, [Buffer.from('{bad', 'utf8').toString('base64url')]))).toMatch(/^disclosure: invalid JSON \(/);
    expect(throwsMsg(() => run({}, [raw(['s', 'dup', 1]).replace(/^/, '')].map((x) => Buffer.from(`["s","k",1,2]`, 'utf8').toString('base64url') + x.slice(0, 0))))).toBe('disclosure: array must have 2 or 3 elements');
    expect(throwsMsg(() => run({}, [Buffer.from('["s","a":1]', 'utf8').toString('base64url')]))).toMatch(/^disclosure: invalid JSON/);
    expect(throwsMsg(() => run({}, [Buffer.from('["s","a","b"]', 'utf8').toString('base64url') + 'A']))).toMatch(/^disclosure: (non-canonical|invalid)/);
  });
  it('structural errors', () => {
    const b = disclosureBuilder('sha-256', () => 'S');
    const prop = b.property('p', 1);
    const elem = b.element('e');
    expect(throwsMsg(() => run({ _sd: [prop] }, [b.disclosures[0] as string, b.disclosures[0] as string]))).toBe('SD-JWT: duplicate disclosure');
    expect(throwsMsg(() => run({ _sd: [prop, prop] }, [b.disclosures[0] as string]))).toBe('SD-JWT: a digest is referenced more than once');
    expect(throwsMsg(() => run({ l: [elem, elem] }, [b.disclosures[1] as string]))).toBe('SD-JWT: a digest is referenced more than once');
    expect(throwsMsg(() => run({}, [b.disclosures[0] as string]))).toBe('SD-JWT: a disclosure is not referenced by the signed payload');
    expect(throwsMsg(() => run({ l: [{ '...': prop }] }, [b.disclosures[0] as string]))).toBe('SD-JWT: a property disclosure is referenced from a element position');
    expect(throwsMsg(() => run({ _sd: [elem['...']] }, [b.disclosures[1] as string]))).toBe('SD-JWT: a element disclosure is referenced from a property position');
    expect(throwsMsg(() => run({ p: 1, _sd: [prop] }, [b.disclosures[0] as string]))).toBe('SD-JWT: disclosed claim p collides with an existing claim');
    expect(throwsMsg(() => run({ l: [{ '...': 5 }] }, []))).toBe('SD-JWT: malformed array digest placeholder');
    expect(throwsMsg(() => run({ l: [{ '...': 'x', other: 1 }] }, []))).toBe('SD-JWT: malformed array digest placeholder');
    expect(throwsMsg(() => run({ '...': 'x' }, []))).toBe('SD-JWT: "..." is only valid as the sole key of an array element');
    expect(throwsMsg(() => run({ _sd: 'x' as never }, []))).toBe('SD-JWT: _sd must be an array of strings');
    expect(throwsMsg(() => run({ _sd: [5] as never }, []))).toBe('SD-JWT: _sd must be an array of strings');
    expect(throwsMsg(() => run({ _sd: ['ok', 5] as never }, []))).toBe('SD-JWT: _sd must be an array of strings');
    expect(throwsMsg(() => run({ _sd: {} as never }, []))).toBe('SD-JWT: _sd must be an array of strings');
  });
  it('digests use the stated algorithm', () => {
    const b = disclosureBuilder('sha-384', () => 'S');
    const prop = b.property('p', 1);
    expect(run({ _sd: [prop] }, b.disclosures, 'sha-384')).toEqual({ p: 1 });
    expect(throwsMsg(() => run({ _sd: [prop] }, b.disclosures, 'sha-256'))).toBe('SD-JWT: a disclosure is not referenced by the signed payload');
  });
  it('nesting depth limit of 32 across all four recursion paths', () => {
    const nestObj = (n: number): JsonObject => {
      let v: JsonObject = {};
      for (let i = 0; i < n; i++) v = { a: v };
      return v;
    };
    expect(() => run(nestObj(32), [])).not.toThrow();
    expect(throwsMsg(() => run(nestObj(33), []))).toBe('SD-JWT: nesting too deep');
    expect(throwsMsg(() => run(nestObj(60), []))).toBe('SD-JWT: nesting too deep');
    const nestArr = (n: number): JsonObject => {
      let v: unknown = [];
      for (let i = 1; i < n; i++) v = [v];
      return { a: v } as JsonObject;
    };
    expect(() => run(nestArr(31), [])).not.toThrow();
    expect(throwsMsg(() => run(nestArr(33), []))).toBe('SD-JWT: nesting too deep');
    expect(throwsMsg(() => run(nestArr(60), []))).toBe('SD-JWT: nesting too deep');
    const elemChain = (n: number) => {
      const b = disclosureBuilder('sha-256', () => 'S');
      let v: unknown = 'leaf';
      for (let i = 0; i < n; i++) v = [b.element(v as never)];
      return { payload: { a: v } as JsonObject, ds: b.disclosures };
    };
    const e30 = elemChain(30);
    expect(() => run(e30.payload, e30.ds)).not.toThrow();
    const e60 = elemChain(60);
    expect(throwsMsg(() => run(e60.payload, e60.ds))).toBe('SD-JWT: nesting too deep');
    const propChain = (n: number) => {
      const b = disclosureBuilder('sha-256', () => 'S');
      let v: unknown = 'leaf';
      for (let i = 0; i < n; i++) {
        const d = b.property('p', v as never);
        v = { _sd: [d] };
      }
      return { payload: v as JsonObject, ds: b.disclosures };
    };
    const p10 = propChain(10);
    expect(() => run(p10.payload, p10.ds)).not.toThrow();
    const p60 = propChain(60);
    expect(throwsMsg(() => run(p60.payload, p60.ds))).toBe('SD-JWT: nesting too deep');
  });
});
