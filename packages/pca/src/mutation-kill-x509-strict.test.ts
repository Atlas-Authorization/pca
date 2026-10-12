/**
 * Mutation-kill suite for x509-strict.ts: hand-built DER so each structural refusal, boundary and message is pinned.
 */
import { generateKeyPairSync, createSecretKey, type KeyObject } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { cat, tlv, seq, set, octets, bitString, boolean, integer, oid, ctx } from './test-support/forge-x509';
import { checkChainRoles, ecPointFromKey, parseCertExtensions, parseTbsExtensions, readCertRoleInfo, tbsOfCertificate } from './x509-strict';

const B = (...n: number[]) => Uint8Array.from(n);
const BC = '2.5.29.19';
const KU = '2.5.29.15';
const ext = (oidDer: Uint8Array, value: Uint8Array, crit?: Uint8Array) => seq(oidDer, ...(crit ? [crit] : []), octets(value));
const block = (...exts: Uint8Array[]) => tlv(0xa3, seq(...exts));
const tbs = (...els: Uint8Array[]) => seq(ctx(0, integer(2)), integer(1), ...els);
const cert = (t: Uint8Array) => seq(t, seq(oid('1.2.3.4')), bitString(new Uint8Array(4)));
const certWith = (...exts: Uint8Array[]) => cert(tbs(block(...exts)));
const bcExt = (...inner: Uint8Array[]) => ext(oid(BC), seq(...inner));
const kuExt = (...bytes: number[]) => ext(oid(KU), tlv(0x03, B(...bytes)));
const throwsRange = (f: () => unknown, msg: string) => expect(f).toThrow(new RangeError(msg));

describe('DER header / length handling (via parseTbsExtensions)', () => {
  it('truncated header', () => {
    throwsRange(() => parseTbsExtensions(B()), 'DER: truncated header');
    throwsRange(() => parseTbsExtensions(B(0x30)), 'DER: truncated header');
    expect(parseTbsExtensions(B(0x30, 0x00)).size).toBe(0); // exactly two bytes is a complete empty SEQUENCE
  });
  it('multi-byte tags refused', () => {
    throwsRange(() => parseTbsExtensions(B(0x1f, 0x00)), 'DER: multi-byte tags are not supported');
    throwsRange(() => parseTbsExtensions(B(0x3f, 0x00)), 'DER: multi-byte tags are not supported');
  });
  it('length forms: indefinite / over three length octets refused; one, two and three accepted', () => {
    throwsRange(() => parseTbsExtensions(B(0x30, 0x80, 0x00)), 'DER: unsupported length form');
    throwsRange(() => parseTbsExtensions(B(0x30, 0x84, 0, 0, 0, 0)), 'DER: unsupported length form');
    expect(parseTbsExtensions(B(0x30, 0x81, 0x00)).size).toBe(0);
    expect(parseTbsExtensions(B(0x30, 0x82, 0x00, 0x00)).size).toBe(0);
    expect(parseTbsExtensions(B(0x30, 0x83, 0x00, 0x00, 0x00)).size).toBe(0);
    expect(parseTbsExtensions(B(0x30, 0x82, 0x00, 0x02, 0x05, 0x00)).size).toBe(0); // length 2 in two octets
    expect(parseTbsExtensions(B(0x30, 0x83, 0x00, 0x00, 0x02, 0x05, 0x00)).size).toBe(0);
  });
  it('truncated length octets', () => {
    throwsRange(() => parseTbsExtensions(B(0x30, 0x82, 0x01)), 'DER: truncated length');
    throwsRange(() => parseTbsExtensions(B(0x30, 0x83, 0x01, 0x02)), 'DER: truncated length');
  });
  it('element overruns its parent', () => {
    throwsRange(() => parseTbsExtensions(B(0x30, 0x05, 0x00)), 'DER: element overruns its parent');
    throwsRange(() => parseTbsExtensions(B(0x30, 0x03, 0x05, 0x05, 0x00)), 'DER: element overruns its parent');
  });
  it('an element ending exactly at its parent is fine', () => {
    expect(parseTbsExtensions(tbs()).size).toBe(0);
  });
});

describe('readCertRoleInfo', () => {
  it('outer / tbs tag checks', () => {
    throwsRange(() => readCertRoleInfo(B(0x31, 0x00)), 'certificate is not a DER SEQUENCE');
    throwsRange(() => readCertRoleInfo(seq(set())), 'certificate has no tbsCertificate');
    throwsRange(() => readCertRoleInfo(seq(octets(B(1)))), 'certificate has no tbsCertificate');
  });
  it('no extensions: every flag false and nothing extra', () => {
    expect(readCertRoleInfo(cert(tbs()))).toStrictEqual({ hasBasicConstraints: false, ca: false, hasKeyUsage: false, keyCertSign: false });
    // non-[3] elements are skipped; a [3] block that is not an extension holder is still examined
    expect(readCertRoleInfo(cert(seq(integer(1), octets(B(1)), ctx(1, integer(1)))))).toStrictEqual({ hasBasicConstraints: false, ca: false, hasKeyUsage: false, keyCertSign: false });
  });
  it('extensions structure', () => {
    throwsRange(() => readCertRoleInfo(cert(tbs(tlv(0xa3, set())))), 'extensions is not a SEQUENCE');
    throwsRange(() => readCertRoleInfo(cert(tbs(tlv(0xa3, seq(set()))))), 'extension is not a SEQUENCE');
    throwsRange(() => readCertRoleInfo(certWith(seq(oid(BC), boolean(true), integer(1)))), 'extension value is not an OCTET STRING');
    throwsRange(() => readCertRoleInfo(certWith(seq(oid(BC), integer(1)))), 'extension value is not an OCTET STRING');
  });
  it('BasicConstraints: CA true / false / default, pathLen', () => {
    expect(readCertRoleInfo(certWith(bcExt(boolean(true))))).toStrictEqual({ hasBasicConstraints: true, ca: true, hasKeyUsage: false, keyCertSign: false });
    expect(readCertRoleInfo(certWith(bcExt(boolean(false))))).toStrictEqual({ hasBasicConstraints: true, ca: false, hasKeyUsage: false, keyCertSign: false });
    expect(readCertRoleInfo(certWith(bcExt(tlv(0x01, B(0x01)))))).toMatchObject({ ca: true });
    expect(readCertRoleInfo(certWith(bcExt()))).toStrictEqual({ hasBasicConstraints: true, ca: false, hasKeyUsage: false, keyCertSign: false });
    // pathLen without cA: the INTEGER is the pathLen, not a boolean
    expect(readCertRoleInfo(certWith(bcExt(integer(3))))).toStrictEqual({ hasBasicConstraints: true, ca: false, pathLen: 3, hasKeyUsage: false, keyCertSign: false });
    expect(readCertRoleInfo(certWith(bcExt(boolean(true), integer(0))))).toMatchObject({ ca: true, pathLen: 0 });
    expect(readCertRoleInfo(certWith(bcExt(boolean(true), integer(255))))).toMatchObject({ pathLen: 255 }); // 2 content bytes (00 ff)
    expect(readCertRoleInfo(certWith(bcExt(boolean(true), tlv(0x02, B(0x01, 0x00)))))).toMatchObject({ pathLen: 256 });
    expect(readCertRoleInfo(certWith(bcExt(boolean(true), tlv(0x02, B(0x00, 0x80)))))).toMatchObject({ pathLen: 128 });
  });
  it('BasicConstraints refusals', () => {
    throwsRange(() => readCertRoleInfo(certWith(ext(oid(BC), octets(B(1))))), 'BasicConstraints is not a SEQUENCE');
    throwsRange(() => readCertRoleInfo(certWith(ext(oid(BC), B(0x31, 0x00)))), 'BasicConstraints is not a SEQUENCE');
    throwsRange(() => readCertRoleInfo(certWith(bcExt(tlv(0x01, B(0xff, 0xff))))), 'BasicConstraints cA is not one byte');
    throwsRange(() => readCertRoleInfo(certWith(bcExt(tlv(0x01, B())))), 'BasicConstraints cA is not one byte');
    const pl = 'BasicConstraints pathLenConstraint malformed';
    throwsRange(() => readCertRoleInfo(certWith(bcExt(boolean(true), tlv(0x04, B(1))))), pl); // wrong tag
    throwsRange(() => readCertRoleInfo(certWith(bcExt(boolean(true), tlv(0x02, B())))), pl); // empty
    throwsRange(() => readCertRoleInfo(certWith(bcExt(boolean(true), tlv(0x02, B(1, 2, 3))))), pl); // 3 bytes
    throwsRange(() => readCertRoleInfo(certWith(bcExt(boolean(true), tlv(0x02, B(0x80))))), pl); // negative
    throwsRange(() => readCertRoleInfo(certWith(bcExt(boolean(true), tlv(0x02, B(0xff, 0x01))))), pl); // negative two-byte
    throwsRange(() => readCertRoleInfo(certWith(bcExt(tlv(0x02, B(0x80))))), pl);
    throwsRange(() => readCertRoleInfo(certWith(bcExt(boolean(true), integer(1), integer(2)))), 'BasicConstraints has trailing data');
    throwsRange(() => readCertRoleInfo(certWith(bcExt(boolean(true), boolean(true)))), pl);
    throwsRange(() => readCertRoleInfo(certWith(bcExt(boolean(true)), bcExt(boolean(true)))), 'duplicate BasicConstraints extension');
  });
  it('lookalike OIDs are not BasicConstraints / keyUsage', () => {
    // same content bytes, wrong tag (printable string): must be ignored even though the payload would be malformed as BC
    const fakeTag = seq(tlv(0x13, B(0x55, 0x1d, 0x13)), octets(B(0x01, 0x02)));
    expect(readCertRoleInfo(certWith(fakeTag))).toStrictEqual({ hasBasicConstraints: false, ca: false, hasKeyUsage: false, keyCertSign: false });
    // longer OID sharing the 3-byte prefix
    const longer = seq(tlv(0x06, B(0x55, 0x1d, 0x13, 0x01)), octets(B(0x01, 0x02)));
    expect(readCertRoleInfo(certWith(longer))).toStrictEqual({ hasBasicConstraints: false, ca: false, hasKeyUsage: false, keyCertSign: false });
    const longerKu = seq(tlv(0x06, B(0x55, 0x1d, 0x0f, 0x01)), octets(B(0x01, 0x02)));
    expect(readCertRoleInfo(certWith(longerKu))).toStrictEqual({ hasBasicConstraints: false, ca: false, hasKeyUsage: false, keyCertSign: false });
    // same length, different last byte
    const sameLen = seq(oid('2.5.29.20'), octets(B(0x01, 0x02)));
    expect(readCertRoleInfo(certWith(sameLen)).hasBasicConstraints).toBe(false);
    const otherKu = seq(oid('2.5.29.14'), octets(B(0x01, 0x02)));
    expect(readCertRoleInfo(certWith(otherKu)).hasKeyUsage).toBe(false);
  });
  it('keyUsage: bit reading, criticality flag, refusals', () => {
    expect(readCertRoleInfo(certWith(kuExt(0x01, 0x04)))).toStrictEqual({ hasBasicConstraints: false, ca: false, hasKeyUsage: true, keyCertSign: true });
    expect(readCertRoleInfo(certWith(kuExt(0x01, 0x80)))).toMatchObject({ hasKeyUsage: true, keyCertSign: false });
    expect(readCertRoleInfo(certWith(kuExt(0x07, 0x00)))).toMatchObject({ keyCertSign: false });
    expect(readCertRoleInfo(certWith(kuExt(0x00, 0xfb)))).toMatchObject({ keyCertSign: false });
    expect(readCertRoleInfo(certWith(kuExt(0x02, 0x06)))).toMatchObject({ keyCertSign: true });
    expect(readCertRoleInfo(certWith(ext(oid(KU), tlv(0x03, B(0x01, 0x04)), boolean(true))))).toMatchObject({ keyCertSign: true });
    expect(readCertRoleInfo(certWith(ext(oid(BC), seq(boolean(true)), boolean(true)), kuExt(0x01, 0x04)))).toMatchObject({ ca: true, keyCertSign: true });
    const bad = 'keyUsage is not a BIT STRING';
    throwsRange(() => readCertRoleInfo(certWith(ext(oid(KU), tlv(0x04, B(0x01, 0x04))))), bad);
    throwsRange(() => readCertRoleInfo(certWith(ext(oid(KU), tlv(0x03, B(0x01))))), bad);
    throwsRange(() => readCertRoleInfo(certWith(ext(oid(KU), tlv(0x03, B())))), bad);
    throwsRange(() => readCertRoleInfo(certWith(kuExt(0, 4), kuExt(0, 4))), 'duplicate keyUsage extension');
  });
});

describe('parseTbsExtensions / tbsOfCertificate / parseCertExtensions', () => {
  it('returns value bytes and criticality keyed by dotted OID', () => {
    const m = parseTbsExtensions(tbs(block(ext(oid(BC), seq(boolean(true)), boolean(true)), ext(oid('1.3.6.1.4.1.311.21.7'), B(1, 2, 3)))));
    expect([...m.keys()]).toEqual(['2.5.29.19', '1.3.6.1.4.1.311.21.7']);
    expect(m.get('2.5.29.19')).toEqual({ critical: true, value: seq(boolean(true)) });
    expect(m.get('1.3.6.1.4.1.311.21.7')).toEqual({ critical: false, value: B(1, 2, 3) });
  });
  it('tbs framing', () => {
    throwsRange(() => parseTbsExtensions(set()), 'tbsCertificate is not a SEQUENCE');
    throwsRange(() => parseTbsExtensions(cat(tbs(), B(0))), 'trailing bytes after tbsCertificate');
    expect(parseTbsExtensions(tbs()).size).toBe(0);
  });
  it('extensions block rules', () => {
    throwsRange(() => parseTbsExtensions(tbs(block(ext(oid(BC), B(1))), block(ext(oid(KU), B(1))))), 'duplicate [3] extensions block');
    throwsRange(() => parseTbsExtensions(tbs(tlv(0xa3, set()))), 'extensions is not a SEQUENCE');
    throwsRange(() => parseTbsExtensions(tbs(tlv(0xa3, seq(), B(0x05, 0x00)))), 'trailing bytes after the Extensions SEQUENCE');
    throwsRange(() => parseTbsExtensions(tbs(block())), 'empty Extensions SEQUENCE');
    throwsRange(() => parseTbsExtensions(tbs(block(ext(oid(BC), B(1))), octets(B(1)))), 'extensions block is not the last TBS element');
    expect(parseTbsExtensions(tbs(octets(B(1)), block(ext(oid(BC), B(1))))).size).toBe(1);
    throwsRange(() => parseTbsExtensions(tbs(block(set()))), 'extension is not a SEQUENCE');
  });
  it('extension rules', () => {
    throwsRange(() => parseTbsExtensions(tbs(block(seq(oid(BC), boolean(false), octets(B(1)))))), 'extension 2.5.29.19 has a non-DER critical flag');
    throwsRange(() => parseTbsExtensions(tbs(block(seq(oid(BC), tlv(0x01, B(0x01)), octets(B(1)))))), 'extension 2.5.29.19 has a non-DER critical flag');
    throwsRange(() => parseTbsExtensions(tbs(block(seq(oid(BC), tlv(0x01, B(0xff, 0xff)), octets(B(1)))))), 'extension 2.5.29.19 has a non-DER critical flag');
    throwsRange(() => parseTbsExtensions(tbs(block(seq(oid(BC), tlv(0x01, B()), octets(B(1)))))), 'extension 2.5.29.19 has a non-DER critical flag');
    throwsRange(() => parseTbsExtensions(tbs(block(seq(oid(BC), integer(1))))), 'extension 2.5.29.19 value is not an OCTET STRING');
    throwsRange(() => parseTbsExtensions(tbs(block(seq(oid(BC), boolean(true), integer(1))))), 'extension 2.5.29.19 value is not an OCTET STRING');
    throwsRange(() => parseTbsExtensions(tbs(block(seq(oid(BC), octets(B(1)), octets(B(2)))))), 'extension 2.5.29.19 has trailing bytes');
    throwsRange(() => parseTbsExtensions(tbs(block(ext(oid(BC), B(1)), ext(oid(BC), B(2))))), 'duplicate extension 2.5.29.19');
  });
  it('OID decoding: malformed, truncated, non-minimal, first-arc boundaries, multi-byte arcs', () => {
    const one = (oidDer: Uint8Array) => parseTbsExtensions(tbs(block(seq(oidDer, octets(B(1)))))).keys().next().value;
    throwsRange(() => one(tlv(0x13, B(0x55))), 'extension OID is malformed');
    throwsRange(() => one(tlv(0x06, B())), 'extension OID is malformed');
    throwsRange(() => one(tlv(0x06, B(0x55, 0x81))), 'extension OID is truncated');
    throwsRange(() => one(tlv(0x06, B(0x80, 0x01))), 'extension OID has a non-minimal arc');
    throwsRange(() => one(tlv(0x06, B(0x55, 0x80, 0x01))), 'extension OID has a non-minimal arc');
    expect(one(tlv(0x06, B(0x27)))).toBe('0.39');
    expect(one(tlv(0x06, B(0x28)))).toBe('1.0');
    expect(one(tlv(0x06, B(0x4f)))).toBe('1.39');
    expect(one(tlv(0x06, B(0x50)))).toBe('2.0');
    expect(one(tlv(0x06, B(0x00)))).toBe('0.0');
    expect(one(tlv(0x06, B(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d)))).toBe('1.2.840.113549');
    expect(one(tlv(0x06, B(0x81, 0x00)))).toBe('2.48'); // first arc 128 -> 2.48
    expect(one(oid('2.999.3'))).toBe('2.999.3');
    expect(one(oid('1.3.6.1.5.5.7.48.1.5'))).toBe('1.3.6.1.5.5.7.48.1.5');
  });
  it('tbsOfCertificate slices the TBS and refuses trailing bytes / wrong tags', () => {
    const t = tbs(block(ext(oid(BC), B(1))));
    const c = cert(t);
    expect(tbsOfCertificate(c)).toEqual(t);
    throwsRange(() => tbsOfCertificate(cat(c, B(0))), 'trailing bytes after the certificate');
    throwsRange(() => tbsOfCertificate(B(0x31, 0x00)), 'certificate is not a DER SEQUENCE');
    throwsRange(() => tbsOfCertificate(seq(set())), 'certificate has no tbsCertificate');
    expect(parseCertExtensions(c).get('2.5.29.19')).toEqual({ critical: false, value: B(1) });
  });
});

describe('checkChainRoles', () => {
  const caBc = (pathLen?: number) => bcExt(boolean(true), ...(pathLen === undefined ? [] : [integer(pathLen)]));
  const leaf = certWith(bcExt());
  const ca = (pathLen?: number, ku?: number[]) => certWith(caBc(pathLen), ...(ku ? [kuExt(...ku)] : []));
  it('a good three-certificate chain and single/two-certificate chains pass', () => {
    expect(checkChainRoles([leaf, ca(0), ca(1)])).toBeUndefined();
    expect(checkChainRoles([leaf, ca(undefined, [0, 4]), ca(undefined, [0, 4])])).toBeUndefined();
    expect(checkChainRoles([leaf, ca()])).toBeUndefined();
    expect(checkChainRoles([])).toBeUndefined();
  });
  it('a bare certificate has no leaf/issuer relationship, whatever it asserts', () => {
    expect(checkChainRoles([ca()])).toBeUndefined();
    expect(checkChainRoles([certWith()])).toBeUndefined();
    expect(checkChainRoles([leaf])).toBeUndefined();
  });
  it('leaf asserting CA:TRUE', () => {
    expect(checkChainRoles([ca(), ca()])).toBe('leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)');
  });
  it('issuer rules with exact depth numbers', () => {
    expect(checkChainRoles([leaf, certWith()])).toBe('issuer certificate at depth 1 has no BasicConstraints (not a CA)');
    expect(checkChainRoles([leaf, ca(), certWith()])).toBe('issuer certificate at depth 2 has no BasicConstraints (not a CA)');
    expect(checkChainRoles([leaf, certWith(bcExt())])).toBe('issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)');
    expect(checkChainRoles([leaf, ca(undefined, [0, 0x80])])).toBe('issuer certificate at depth 1 keyUsage lacks keyCertSign');
    expect(checkChainRoles([leaf, ca(), ca(undefined, [0, 0x80])])).toBe('issuer certificate at depth 2 keyUsage lacks keyCertSign');
  });
  it('pathLenConstraint boundary', () => {
    expect(checkChainRoles([leaf, ca(0)])).toBeUndefined(); // 0 intermediates below the root-ish issuer at depth 1
    expect(checkChainRoles([leaf, ca(0), ca(1)])).toBeUndefined();
    expect(checkChainRoles([leaf, ca(0), ca(0)])).toBe('issuer certificate at depth 2 pathLenConstraint 0 is exceeded (1 intermediate(s) below)');
    expect(checkChainRoles([leaf, ca(0), ca(1), ca(1)])).toBe('issuer certificate at depth 3 pathLenConstraint 1 is exceeded (2 intermediate(s) below)');
    expect(checkChainRoles([leaf, ca(0), ca(1), ca(2)])).toBeUndefined();
  });
  it('parse failures are reported with the parser message', () => {
    expect(checkChainRoles([leaf, B(0x31, 0x00)])).toBe('certificate extension parse failed: certificate is not a DER SEQUENCE');
    expect(checkChainRoles([B(0x30)])).toBe('certificate extension parse failed: DER: truncated header');
    expect(checkChainRoles([leaf, certWith(ext(oid(BC), B(0x04, 0x00)))])).toBe('certificate extension parse failed: BasicConstraints is not a SEQUENCE');
  });
});

describe('ecPointFromKey', () => {
  const kp256 = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const kp384 = generateKeyPairSync('ec', { namedCurve: 'P-384' });
  const fake = (jwk: Record<string, unknown>, over: Record<string, unknown> = {}): KeyObject =>
    ({ type: 'public', asymmetricKeyType: 'ec', export: () => jwk, ...over }) as unknown as KeyObject;
  const x32 = Buffer.alloc(32, 7).toString('base64url');
  const y32 = Buffer.alloc(32, 9).toString('base64url');

  it('real keys: 0x04 || X || Y of the exact width', () => {
    const p = ecPointFromKey(kp256.publicKey, 'P-256');
    const jwk = kp256.publicKey.export({ format: 'jwk' });
    expect(p.length).toBe(65);
    expect(p[0]).toBe(4);
    expect(Buffer.from(p.subarray(1, 33)).toString('base64url')).toBe(jwk.x);
    expect(Buffer.from(p.subarray(33)).toString('base64url')).toBe(jwk.y);
    const q = ecPointFromKey(kp384.publicKey, 'P-384');
    expect(q.length).toBe(97);
    expect(q[0]).toBe(4);
    expect(Buffer.from(q.subarray(1, 49)).toString('base64url')).toBe(kp384.publicKey.export({ format: 'jwk' }).x);
  });
  it('wrong curve / key type / visibility', () => {
    expect(() => ecPointFromKey(kp256.publicKey, 'P-384')).toThrow(new TypeError('public key is not on P-384 (got P-256)'));
    expect(() => ecPointFromKey(kp384.publicKey, 'P-256')).toThrow(new TypeError('public key is not on P-256 (got P-384)'));
    expect(() => ecPointFromKey(kp256.privateKey, 'P-256')).toThrow(new TypeError('public key is not EC (got ec)'));
    const rsa = generateKeyPairSync('rsa', { modulusLength: 1024 });
    expect(() => ecPointFromKey(rsa.publicKey, 'P-256')).toThrow(new TypeError('public key is not EC (got rsa)'));
    expect(() => ecPointFromKey(createSecretKey(Buffer.alloc(16)), 'P-256')).toThrow(new TypeError('public key is not EC (got unknown)'));
    const ed = generateKeyPairSync('ed25519');
    expect(() => ecPointFromKey(ed.publicKey, 'P-384')).toThrow(new TypeError('public key is not EC (got ed25519)'));
    expect(() => ecPointFromKey(fake({ kty: 'EC', crv: 'P-256', x: x32, y: y32 }, { asymmetricKeyType: undefined }), 'P-256')).toThrow('(got unknown)');
  });
  it('coordinate decoding: accepts exact-width base64url, refuses everything else with labelled messages', () => {
    const ok = ecPointFromKey(fake({ kty: 'EC', crv: 'P-256', x: x32, y: y32 }), 'P-256');
    expect(Array.from(ok)).toEqual([4, ...new Array(32).fill(7), ...new Array(32).fill(9)]);
    const mk = (x: unknown, y: unknown) => () => ecPointFromKey(fake({ kty: 'EC', crv: 'P-256', x, y }), 'P-256');
    expect(mk(undefined, y32)).toThrow(new TypeError('EC x is not base64url'));
    expect(mk(5, y32)).toThrow(new TypeError('EC x is not base64url'));
    expect(mk('', y32)).toThrow(new TypeError('EC x is not base64url'));
    expect(mk('!' + 'A'.repeat(43), y32)).toThrow(new TypeError('EC x is not base64url'));
    expect(mk('A'.repeat(43) + '!', y32)).toThrow(new TypeError('EC x is not base64url'));
    expect(mk('A'.repeat(43) + '=', y32)).toThrow(new TypeError('EC x is not base64url'));
    expect(mk(x32, undefined)).toThrow(new TypeError('EC y is not base64url'));
    expect(mk(x32, '!' + 'A'.repeat(43))).toThrow(new TypeError('EC y is not base64url'));
    expect(mk(Buffer.alloc(31).toString('base64url'), y32)).toThrow(new TypeError('EC x is 31 bytes, expected 32'));
    expect(mk(x32, Buffer.alloc(33).toString('base64url'))).toThrow(new TypeError('EC y is 33 bytes, expected 32'));
    const p384 = (x: string) => () => ecPointFromKey(fake({ kty: 'EC', crv: 'P-384', x, y: Buffer.alloc(48).toString('base64url') }), 'P-384');
    expect(p384(x32)).toThrow(new TypeError('EC x is 32 bytes, expected 48'));
  });
  it('kty is checked (a non-EC JWK with the right crv text)', () => {
    expect(() => ecPointFromKey(fake({ kty: 'OKP', crv: 'P-256', x: x32, y: y32 }), 'P-256')).toThrow(new TypeError('public key is not on P-256 (got P-256)'));
  });
  it('a private component in the export is refused', () => {
    expect(() => ecPointFromKey(fake({ kty: 'EC', crv: 'P-256', x: x32, y: y32, d: x32 }), 'P-256')).toThrow(new TypeError('unexpected private component'));
  });
});
