/** Mutation-kill tests for the minimal DER reader: hand-built certificates exercise every bound, tag, flag and error message. */
import { describe, expect, it } from 'vitest';
import { readCertFacts } from './der';

type Bytes = number[];
const len = (n: number): Bytes => (n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff]);
const tlv = (tag: number, ...parts: Bytes[]): Bytes => {
  const body = parts.flat();
  return [tag, ...len(body.length), ...body];
};
const oid = (hex: string): Bytes => tlv(0x06, [...Buffer.from(hex, 'hex')]);
const bool = (v: boolean): Bytes => tlv(0x01, [v ? 0xff : 0x00]);
const octet = (...inner: Bytes[]): Bytes => tlv(0x04, ...inner);
const OID_KU = '551d0f';
const OID_SAN = '551d11';
const OID_BC = '551d13';

/** An Extension: SEQUENCE { OID, [critical BOOLEAN], OCTET STRING } */
const ext = (oidHex: string, inner: Bytes, critical?: boolean): Bytes =>
  tlv(0x30, oid(oidHex), ...(critical === undefined ? [] : [bool(critical)]), octet(inner));
/** A certificate whose TBS holds a version-like field and (optionally) the [3] extensions. */
const cert = (exts?: Bytes[]): Uint8Array =>
  new Uint8Array(tlv(0x30, tlv(0x30, tlv(0xa0, tlv(0x02, [2])), ...(exts === undefined ? [] : [tlv(0xa3, tlv(0x30, ...exts))]))));
const facts = (exts?: Bytes[]) => readCertFacts(cert(exts));
const msg = (b: Bytes | Uint8Array): string => {
  try {
    readCertFacts(new Uint8Array(b));
  } catch (e) {
    expect(e).toBeInstanceOf(RangeError);
    return (e as Error).message;
  }
  return 'no error';
};

describe('readCertFacts: structure and bounds', () => {
  it('a certificate without extensions yields the all-false defaults', () => {
    expect(facts()).toEqual({
      basicConstraintsPresent: false,
      isCa: false,
      pathLen: null,
      keyUsagePresent: false,
      digitalSignature: false,
      keyCertSign: false,
      crlSign: false,
      uriSans: [],
      unknownCritical: [],
    });
    expect(facts([])).toEqual(facts());
  });
  it('header bounds', () => {
    expect(msg([0x30])).toBe('der: truncated header');
    expect(msg([])).toBe('der: truncated header');
    expect(msg([0x30, 0x00])).toBe('der: missing tbsCertificate'); // exactly two bytes is a complete header
    expect(msg([0x1f, 0x00])).toBe('der: high-tag-number form is not supported');
    expect(msg([0x3f, 0x00])).toBe('der: high-tag-number form is not supported');
    expect(msg([0x30, 0x80, 0x00, 0x00])).toBe('der: unsupported length form');
    expect(msg([0x30, 0x85, 0, 0, 0, 0, 0, 0])).toBe('der: unsupported length form');
    expect(msg([0x30, 0x82, 0x01])).toBe('der: truncated length');
    expect(msg([0x30, 0x81, 0x00])).toBe('der: missing tbsCertificate'); // length bytes end exactly at the limit
    expect(msg([0x30, 0x05, 0x00])).toBe('der: content exceeds container');
    expect(msg([0x30, 0x84, 0x00, 0x00, 0x00, 0x02, 0x30, 0x00])).toBe('no error'); // 4 length bytes are allowed
    expect(msg([0x30, 0x81, 0x02, 0x30, 0x00])).toBe('no error'); // long form of a short length, last byte ends exactly
  });
  it('the certificate must be one SEQUENCE spanning the input', () => {
    expect(msg([0x31, 0x00])).toBe('der: certificate is not a single SEQUENCE');
    expect(msg([0x30, 0x00, 0x00])).toBe('der: certificate is not a single SEQUENCE');
    expect(msg([0x30, 0x02, 0x31, 0x00])).toBe('der: missing tbsCertificate');
    expect(msg([0x30, 0x00])).toBe('der: missing tbsCertificate');
  });
  it('extensions: wrapper, sequence, entry and value shapes', () => {
    const wrap = (...inner: Bytes[]): Bytes => tlv(0x30, tlv(0x30, tlv(0xa3, ...inner)));
    expect(msg(wrap())).toBe('der: malformed extensions');
    expect(msg(wrap(tlv(0x31)))).toBe('der: malformed extensions');
    expect(msg(wrap(tlv(0x30, tlv(0x30))))).toBe('der: malformed extension'); // empty extension entry
    expect(msg(wrap(tlv(0x30, tlv(0x30, tlv(0x04, [1]), octet([0])))))).toBe('der: malformed extension'); // OID slot is not an OID
    expect(msg(wrap(tlv(0x30, tlv(0x30, oid(OID_KU), tlv(0x05)))))).toBe('der: malformed extension value');
    expect(msg(wrap(tlv(0x30, tlv(0x30, oid('2a0304'), bool(true), tlv(0x02, [1])))))).toBe('der: malformed extension value');
    expect(msg(wrap(tlv(0x30, ext('2a0304', [0x05, 0x00]), ext('2a0304', [0x05, 0x00]))))).toBe('der: duplicate extension');
    expect(msg(wrap(tlv(0x30, ext('2a0304', [0x05, 0x00]), ext('2a0305', [0x05, 0x00]))))).toBe('no error');
  });
});

describe('readCertFacts: criticality', () => {
  const unknown = (inner: Bytes[], critical?: Bytes) =>
    facts([tlv(0x30, oid('2a0304'), ...(critical ? [critical] : []), octet(...inner))]).unknownCritical;
  it('only a BOOLEAN TRUE in the middle slot of a three-part extension is critical', () => {
    expect(unknown([[0x05, 0x00]], bool(true))).toEqual(['2a0304']);
    expect(unknown([[0x05, 0x00]], bool(false))).toEqual([]);
    expect(unknown([[0x05, 0x00]])).toEqual([]);
    expect(unknown([[0x05, 0x00]], tlv(0x02, [0xff]))).toEqual([]); // INTEGER 0xff is not a BOOLEAN
    const four = tlv(0x30, oid('2a0304'), bool(true), tlv(0x05), octet([0x05, 0x00]));
    expect(facts([four]).unknownCritical).toEqual([]);
  });
  it('the understood extensions may be critical; unknown OIDs are listed in order as hex', () => {
    const known = [
      ext(OID_KU, [0x03, 0x02, 0x07, 0x80], true),
      ext(OID_SAN, [0x30, 0x00], true),
      ext(OID_BC, [0x30, 0x00], true),
      ext('551d25', [0x30, 0x00], true),
      ext('551d0e', [0x04, 0x00], true),
      ext('551d23', [0x30, 0x00], true),
    ];
    expect(facts(known).unknownCritical).toEqual([]);
    expect(facts([...known, ext('2a0304', [5, 0], true), ext('2a0305', [5, 0], true), ext('2a0306', [5, 0], false)]).unknownCritical).toEqual(['2a0304', '2a0305']);
    expect(facts([ext('551d0c', [5, 0], true)]).unknownCritical).toEqual(['551d0c']);
  });
});

describe('readCertFacts: basicConstraints', () => {
  const bc = (...children: Bytes[]) => facts([ext(OID_BC, tlv(0x30, ...children), true)]);
  it('cA flag and pathLenConstraint', () => {
    expect(bc()).toMatchObject({ basicConstraintsPresent: true, isCa: false, pathLen: null });
    expect(bc(bool(true))).toMatchObject({ basicConstraintsPresent: true, isCa: true, pathLen: null });
    expect(bc(bool(false))).toMatchObject({ isCa: false });
    expect(bc(bool(true), tlv(0x02, [0]))).toMatchObject({ isCa: true, pathLen: 0 });
    expect(bc(bool(true), tlv(0x02, [5]))).toMatchObject({ pathLen: 5 });
    expect(bc(tlv(0x02, [0x01, 0x00]))).toMatchObject({ pathLen: 256 });
    expect(bc(tlv(0x02, [0x01, 0x02, 0x03]))).toMatchObject({ pathLen: 66051 });
    expect(bc(tlv(0x04, [0x07]))).toMatchObject({ pathLen: null }); // an unrelated child is ignored
    expect(facts([ext(OID_BC, tlv(0x30), true)]).basicConstraintsPresent).toBe(true);
    expect(facts([ext(OID_KU, [0x03, 0x02, 0x00, 0x80])]).basicConstraintsPresent).toBe(false);
  });
});

describe('readCertFacts: keyUsage', () => {
  const ku = (b0: number, lenOverride?: Bytes) => facts([ext(OID_KU, lenOverride ?? [0x03, 0x02, 0x00, b0])]);
  it('decodes each usage bit independently', () => {
    expect(ku(0x80)).toMatchObject({ keyUsagePresent: true, digitalSignature: true, keyCertSign: false, crlSign: false });
    expect(ku(0x04)).toMatchObject({ digitalSignature: false, keyCertSign: true, crlSign: false });
    expect(ku(0x02)).toMatchObject({ digitalSignature: false, keyCertSign: false, crlSign: true });
    expect(ku(0x86)).toMatchObject({ digitalSignature: true, keyCertSign: true, crlSign: true });
    expect(ku(0x00)).toMatchObject({ keyUsagePresent: true, digitalSignature: false, keyCertSign: false, crlSign: false });
    expect(ku(0x79)).toMatchObject({ digitalSignature: false, keyCertSign: false, crlSign: false });
    expect(ku(0x01)).toMatchObject({ digitalSignature: false, keyCertSign: false, crlSign: false });
  });
  it('reads the byte after the unused-bits count', () => {
    expect(facts([ext(OID_KU, [0x03, 0x03, 0x07, 0x80, 0x00])]).digitalSignature).toBe(true);
    expect(facts([ext(OID_KU, [0x03, 0x03, 0x80, 0x00, 0x00])]).digitalSignature).toBe(false);
  });
  it('rejects a keyUsage that is not a BIT STRING of at least two bytes', () => {
    const bad = (inner: Bytes): string => msg(tlv(0x30, tlv(0x30, tlv(0xa3, tlv(0x30, ext(OID_KU, inner))))));
    expect(bad([0x04, 0x02, 0x00, 0x80])).toBe('der: malformed keyUsage');
    expect(bad([0x03, 0x01, 0x05])).toBe('der: malformed keyUsage');
    expect(bad([0x03, 0x00])).toBe('der: malformed keyUsage');
    expect(bad([0x03, 0x02, 0x00, 0x80])).toBe('no error');
  });
});

describe('readCertFacts: subjectAltName', () => {
  it('collects only uniformResourceIdentifier entries, as latin1 text', () => {
    const uri = (s: string): Bytes => tlv(0x86, [...Buffer.from(s, 'latin1')]);
    const dns = tlv(0x82, [...Buffer.from('example.org')]);
    const f = facts([ext(OID_SAN, tlv(0x30, dns, uri('spiffe://a.org/x'), tlv(0x81, [0x41]), uri('spiffe://café')), true)]);
    expect(f.uriSans).toEqual(['spiffe://a.org/x', 'spiffe://café']);
    expect(facts([ext(OID_SAN, tlv(0x30, dns))]).uriSans).toEqual([]);
    expect(facts([ext(OID_SAN, tlv(0x30))]).uriSans).toEqual([]);
  });
});
