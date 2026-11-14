// RFC 3161 timestamp verification and the DER reader beneath it, driven by minted tokens: every structural refusal has its
// exact message, every boundary is tested on both sides.
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { verifyRfc3161, verifySigstoreBundleCore } from './sigstore';
import { forgeKey, integer, octets, oid, seq, set, tlv } from './test-support/forge-x509';
import { HOUR, OID, T0, mint, mintToken, mintTsa, type Minted, type TokenPieces, type Tsa } from './test-support/forge-sigstore';

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const DATA = Uint8Array.from({ length: 70 }, (_, i) => i * 3 + 1);
const tsa = mintTsa();
const FINAL = 'no pinned timestamp authority signed it (valid at its time)';
const tok = (mod?: (p: TokenPieces) => void, genTime?: Date, t: Tsa = tsa): Uint8Array => mintToken(DATA, t, { mod, genTime });
const msg = (t: Uint8Array, pins = [tsa.pinned]): string | number => {
  try {
    return verifyRfc3161(t, DATA, pins);
  } catch (e) {
    return (e as Error).message;
  }
};
const tstOf = (p: TokenPieces): Uint8Array => seq(p.version, p.policy, seq(p.imprintAlg, p.imprintHash), p.serial, p.genTime, ...p.tstExtra);
const ctAttr = (o = OID.tstInfo): Uint8Array => seq(oid(OID.contentType), set(oid(o)));
const mdAttr = (p: TokenPieces, hash?: Uint8Array): Uint8Array => seq(oid(OID.messageDigest), set(octets(hash ?? createHash(p.dAlg).update(tstOf(p)).digest())));
const gen = (s: string, tag = 0x18) => (p: TokenPieces) => { p.genTime = tlv(tag, enc(s)); };

describe('accepted tokens', () => {
  it('a bare token and a TimeStampResp (granted, grantedWithMods) return genTime in ms', () => {
    expect(msg(tok())).toBe(T0);
    expect(msg(tok((p) => { p.status = integer(0); }))).toBe(T0);
    expect(msg(tok((p) => { p.status = integer(1); }))).toBe(T0);
  });
  it('fractions of a second are truncated to milliseconds without float rounding', () => {
    const f = (frac: string) => msg(tok(gen(`20260115120000${frac}Z`)));
    expect(f('')).toBe(T0);
    expect(f('.5')).toBe(T0 + 500);
    expect(f('.12')).toBe(T0 + 120);
    expect(f('.123')).toBe(T0 + 123);
    expect(f('.1234')).toBe(T0 + 123);
    expect(f('.123456789')).toBe(T0 + 123);
    expect(f('.001')).toBe(T0 + 1);
    expect(f('.0019')).toBe(T0 + 1);
  });
  it('SHA-384 and SHA-512 message imprints, and a SHA-384 signer digest', () => {
    for (const [a, o] of [['sha384', OID.sha384], ['sha512', OID.sha512]] as const) {
      expect(msg(tok((p) => { p.imprintAlg = seq(oid(o)); p.imprintHash = octets(createHash(a).update(DATA).digest()); }))).toBe(T0);
    }
    expect(msg(tok((p) => { p.dAlg = 'sha384'; p.signerDigestAlg = seq(oid(OID.sha384)); }))).toBe(T0);
  });
  it('attributes in either order, and unrelated attributes, are fine', () => {
    expect(
      msg(tok((p) => {
        p.tstInfo = tstOf(p);
        p.attrs = [mdAttr(p), seq(oid('1.2.3.4'), set(oid('1.2.3.5'))), ctAttr()];
      })),
    ).toBe(T0);
  });
  it('CMS structure positions: a SET or SEQUENCE where the reader must not look at it', () => {
    // the encapsulated content is the third element; a SEQUENCE earlier in SignedData is not it
    expect(msg(tok((p) => { p.digestAlgs = seq(seq(oid(OID.sha256))); }))).toBe(T0);
    expect(msg(tok((p) => { p.sdVersion = seq(); }))).toBe(T0);
  });
});

describe('the DER reader', () => {
  it('a token that is not one SEQUENCE', () => {
    const one = 'timestamp is not one SEQUENCE';
    expect(msg(cat2(tok(), Uint8Array.of(0)))).toBe(one);
    // right length, wrong tag
    const t = tok();
    const wrong = Uint8Array.from(t);
    wrong[0] = 0x31;
    expect(msg(wrong)).toBe(one);
  });
  it('truncated, multi-byte tag, indefinite and over-long lengths, overruns', () => {
    expect(msg(Uint8Array.of(0x30))).toBe('DER truncated');
    expect(msg(Uint8Array.of())).toBe('DER truncated');
    expect(msg(Uint8Array.of(0x1f, 0x00))).toBe('DER multi-byte tag');
    expect(msg(Uint8Array.of(0x30, 0x80, 0, 0))).toBe('DER length');
    expect(msg(Uint8Array.of(0x30, 0x85, 0, 0, 0, 0, 0, 0))).toBe('DER length');
    expect(msg(Uint8Array.of(0x30, 0x82, 0x00))).toBe('DER length');
    expect(msg(Uint8Array.of(0x30, 0x05, 0x00))).toBe('DER overrun');
    expect(msg(Uint8Array.of(0x30, 0x03, 0x02, 0x01))).toBe('DER overrun');
  });
  it('a four-byte length is read, and a length byte that fits exactly is not a length error', () => {
    // 30 84 00 00 00 02 | 02 00 : one SEQUENCE holding an empty INTEGER, so the first element is not an OID
    expect(msg(Uint8Array.of(0x30, 0x84, 0, 0, 0, 2, 0x02, 0x00))).toBe('not an OID');
    // 30 81 00 : a one-byte long-form length of zero; the SEQUENCE is empty, so there is no first element at all
    expect(() => verifyRfc3161(Uint8Array.of(0x30, 0x81, 0x00), DATA, [tsa.pinned])).toThrow(TypeError);
  });
});

describe('the response wrapper', () => {
  it('a first element that is a SEQUENCE but not a status is not taken for one', () => {
    expect(msg(seq(seq(), tlv(0xa0, seq())))).toBe('not an OID');
    expect(msg(seq(seq(oid('1.2.3')), tlv(0xa0, seq())))).toBe('not an OID');
  });
  it('a status other than granted or grantedWithMods', () => {
    const granted = 'timestamp status is not granted';
    for (const s of [2, 3, 4, 5]) expect(msg(tok((p) => { p.status = integer(s); })), String(s)).toBe(granted);
    expect(msg(tok((p) => { p.status = integer(256); }))).toBe(granted);
    expect(msg(tok((p) => { p.status = tlv(0x02, Uint8Array.of(0, 0)); }))).toBe(granted);
  });
  it('a response without a token', () => {
    expect(msg(seq(seq(integer(0))))).toBe('no timeStampToken');
  });
});

describe('the OID reader', () => {
  const withOid = (body: Uint8Array) => seq(tlv(0x06, body), tlv(0xa0, seq()));
  it('empty, or not an OID at all', () => {
    expect(msg(withOid(Uint8Array.of()))).toBe('not an OID');
    expect(msg(seq(tlv(0x04, Uint8Array.of(1, 2, 3)), tlv(0xa0, seq())))).toBe('not an OID');
  });
  it('an arc that is not minimally encoded', () => {
    const minimal = 'OID arc is not minimally encoded';
    expect(msg(withOid(Uint8Array.of(0x2a, 0x80, 0x01)))).toBe(minimal);
    expect(msg(withOid(Uint8Array.of(0x80, 0x01)))).toBe(minimal);
    // a long OID whose length byte has the high bit set: the first byte is still the start of an arc
    expect(msg(withOid(Uint8Array.from({ length: 128 }, (_, i) => (i === 0 ? 0x80 : 0x01))))).toBe(minimal);
  });
  it('a zero byte inside a multi-byte arc is minimal; an arc cut off by the end is not an OID', () => {
    expect(msg(withOid(Uint8Array.of(0x2a, 0x81, 0x80, 0x00)))).toBe('not CMS SignedData');
    expect(msg(withOid(Uint8Array.of(0x2a, 0x81)))).toBe('OID ends inside an arc');
  });
});

describe('CMS SignedData and TSTInfo', () => {
  it('not SignedData', () => {
    expect(msg(tok((p) => { p.sdOid = oid('1.2.840.113549.1.7.1'); }))).toBe('not CMS SignedData');
    expect(msg(tok((p) => { p.sdTag = 0xa1; }))).toBe('not CMS SignedData');
  });
  it('an encapsulated content that is not a SEQUENCE is not found', () => {
    expect(() => verifyRfc3161(tok((p) => { p.encapSeqTag = 0x31; }), DATA, [tsa.pinned])).toThrow(TypeError);
  });
  it('a SignedData or encapsulated content that stops after its type', () => {
    expect(msg(seq(oid(OID.signedData)))).toBe('not CMS SignedData');
    expect(msg(tok((p) => { p.encap = seq(oid(OID.tstInfo)); }))).toBe('content is not TSTInfo');
  });
  it('content that is not TSTInfo', () => {
    expect(msg(tok((p) => { p.encapOid = oid('1.2.3.4'); }))).toBe('content is not TSTInfo');
    expect(msg(tok((p) => { p.encapTag = 0xa1; }))).toBe('content is not TSTInfo');
    expect(msg(tok((p) => { p.octetTag = 0x0c; }))).toBe('TSTInfo is not an OCTET STRING');
  });
  it('the message imprint', () => {
    expect(msg(tok((p) => { p.imprintAlg = seq(oid('1.2.3.4')); }))).toBe('unsupported digest algorithm');
    expect(msg(tok((p) => { p.imprintAlg = seq(oid('1.3.14.3.2.26')); }))).toBe('unsupported digest algorithm');
    expect(msg(tok((p) => { p.imprintHash = octets(new Uint8Array(32)); }))).toBe('messageImprint is not the hash of the signature');
    expect(msg(tok((p) => { p.imprintHash = octets(createHash('sha256').update(DATA).digest().subarray(0, 31)); }))).toBe('messageImprint is not the hash of the signature');
  });
});

describe('genTime', () => {
  it('only a GeneralizedTime', () => {
    expect(msg(tok(gen('260115120000Z', 0x17)))).toBe('genTime is not a GeneralizedTime');
    expect(msg(tok((p) => { p.genTime = tlv(0x0c, enc('20260115120000Z')); }))).toBe('genTime is not a GeneralizedTime');
  });
  it('the exact form YYYYMMDDHHMMSS[.f{1,9}]Z', () => {
    const bad = 'genTime malformed';
    for (const s of ['20260115120000', 'x20260115120000Z', '20260115120000Zx', '20260115120000.Z', '20260115120000.abcZ', '20260115120000.1234567890Z', '20260115120000z', '2026011512000Z', '202601151200000Z', '20260115120000,5Z', '']) {
      expect(msg(tok(gen(s))), JSON.stringify(s)).toBe(bad);
    }
  });
  it('an impossible date is refused, not rolled over', () => {
    const real = 'genTime is not a real date';
    for (const s of ['20260230120000Z', '20260115240000Z', '20261301120000Z', '20260431120000Z', '20260115126000Z', '20260115120060Z', '20260100120000Z']) {
      expect(msg(tok(gen(s))), s).toBe(real);
    }
  });
});

describe('SignerInfo', () => {
  it('SignerInfos is a SET of exactly one SignerInfo', () => {
    expect(msg(tok((p) => { p.signerInfosTag = 0x30; }))).toBe('no signerInfos');
    expect(msg(tok((p) => { p.signerInfoCount = 2; }))).toBe('exactly one SignerInfo is required');
    expect(msg(tok((p) => { p.signerInfoCount = 0; }))).toBe('exactly one SignerInfo is required');
  });
  it('signed attributes are required, one value each, and commit to the TSTInfo', () => {
    const commit = 'signed attributes do not commit to the TSTInfo';
    expect(msg(tok((p) => { p.attrsTag = 0xa1; }))).toBe('signed attributes are required');
    expect(msg(tok((p) => { p.attrs = [seq(oid(OID.contentType), set(oid(OID.tstInfo), oid(OID.tstInfo)))]; }))).toBe('an attribute must have one value');
    expect(msg(tok((p) => { p.attrs = [seq(oid(OID.messageDigest), set())]; }))).toBe('an attribute must have one value');
    expect(msg(tok((p) => { p.tstInfo = tstOf(p); p.attrs = [mdAttr(p)]; }))).toBe(commit);
    expect(msg(tok((p) => { p.tstInfo = tstOf(p); p.attrs = [ctAttr()]; }))).toBe(commit);
    expect(msg(tok((p) => { p.tstInfo = tstOf(p); p.attrs = [ctAttr('1.2.3.4'), mdAttr(p)]; }))).toBe(commit);
    expect(msg(tok((p) => { p.tstInfo = tstOf(p); p.attrs = [ctAttr(), mdAttr(p, new Uint8Array(32))]; }))).toBe(commit);
  });
  it('the signature is an OCTET STRING', () => {
    expect(msg(tok((p) => { p.sigTag = 0x03; }))).toBe('signature is not an OCTET STRING');
  });
});

describe('which timestamp authority signed it', () => {
  it('none pinned, or none that signed', () => {
    expect(msg(tok(), [])).toBe(FINAL);
    expect(msg(tok((p) => { p.signKey = forgeKey('someone-else', 'P-256'); }))).toBe(FINAL);
    expect(msg(tok(), [mintTsa({ eku: [OID.codeSigning] }).pinned])).toBe(FINAL);
  });
  it("the authority's pinned validity is inclusive at genTime", () => {
    const win = (start: number, end: number) => [{ ...tsa.pinned, valid: { start, end } }];
    expect(msg(tok(), win(T0, T0))).toBe(T0);
    expect(msg(tok(), win(T0 + 1, T0 + HOUR))).toBe(FINAL);
    expect(msg(tok(), win(T0 - HOUR, T0 - 1))).toBe(FINAL);
  });
  it('the time-stamping extended key usage is required of the leaf', () => {
    const other = mintTsa({ eku: [OID.timeStamping, OID.codeSigning] });
    expect(msg(tok(undefined, undefined, other), [other.pinned])).toBe(T0);
    const none = mintTsa({ eku: ['1.3.6.1.5.5.7.3.2'] });
    expect(msg(tok(undefined, undefined, none), [none.pinned])).toBe(FINAL);
  });
  it('the chain must be valid at genTime and made of CA certificates', () => {
    const expired = mintTsa({ leafTo: new Date(T0 - HOUR) });
    expect(msg(tok(undefined, undefined, expired), [expired.pinned])).toBe(FINAL);
    const notYet = mintTsa({ leafFrom: new Date(T0 + HOUR) });
    expect(msg(tok(undefined, undefined, notYet), [notYet.pinned])).toBe(FINAL);
    const flat = mintTsa({ rootIsCa: false });
    expect(msg(tok(undefined, undefined, flat), [flat.pinned])).toBe(FINAL);
    const ok = mintTsa({});
    expect(msg(tok(undefined, undefined, ok), [ok.pinned])).toBe(T0);
  });
  it('a second pinned authority is tried when the first did not sign', () => {
    const other = mintTsa({ eku: [OID.codeSigning] });
    expect(msg(tok(), [other.pinned, tsa.pinned])).toBe(T0);
  });
});

describe('timestamps inside a bundle', () => {
  it('a timestamp failure is reported at the timestamp stage with its message', () => {
    const m = mint({ tsa: [{ mod: (p) => { p.imprintHash = octets(new Uint8Array(32)); } }] });
    const r = verifyBundle(m);
    expect(r).toBe('tsa: fail closed: messageImprint is not the hash of the signature');
  });
});

function verifyBundle(m: Minted): string {
  const r = verifySigstoreBundleCore(m.bundle, { roots: m.roots });
  return r.ok ? 'ok' : `${r.code}: ${r.detail}`;
}
function cat2(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
