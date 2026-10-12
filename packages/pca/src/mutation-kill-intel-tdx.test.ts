/** Mutation-kill suite for attest-intel-tdx.ts, built on the spec-faithful DCAP forger in test-support/forge-dcap.ts. */
import { generateKeyPairSync } from 'node:crypto';
import { p256 } from '@noble/curves/p256';
import { describe, expect, it } from 'vitest';
import {
  INTEL_SGX_ROOT_CA_SPKI_SHA256,
  ecdsaP256PublicKey,
  extractPckFmspcAndTcb,
  parseDcapQuote,
  parseDcapTdReport,
  toHex,
  verifyGenuineTdxQuote,
  verifyIntelPckChainX509,
} from './attest-intel-tdx';
import { attestationBinding, type ExpectedAttestationBinding } from './attestation';
import { DCAP_OFFSETS, TD10_FIELDS, forgeIntelPki, forgeTdxQuote, sgxExtensionValue, type ForgeTdxOptions } from './test-support/forge-dcap';
import { cat, forgeCert, forgeKey, octets, oid, seq, tlv, integer, serialFor, ext, type DnAttr } from './test-support/forge-x509';

const NOW = Date.parse('2026-10-20T00:00:00Z');
const B = (...n: number[]) => Uint8Array.from(n);
const forged = (o: ForgeTdxOptions = {}) => forgeTdxQuote(o);
const GOOD = forged();
const verify = (q: { quote: Uint8Array; rootSpkiSha256: string }, extra: Record<string, unknown> = {}) =>
  verifyGenuineTdxQuote({ quote: q.quote, trustAnchorRootCaSpkiSha256: q.rootSpkiSha256, nowMs: NOW, ...extra } as never);
const patchU32 = (q: Uint8Array, off: number, v: number) => {
  const c = Uint8Array.from(q);
  new DataView(c.buffer).setUint32(off, v, true);
  return c;
};
const patchU16 = (q: Uint8Array, off: number, v: number) => {
  const c = Uint8Array.from(q);
  new DataView(c.buffer).setUint16(off, v, true);
  return c;
};
const parseErr = (q: Uint8Array): string => {
  try {
    parseDcapQuote(q);
  } catch (e) {
    return (e as Error).message;
  }
  return 'NO ERROR';
};

describe('toHex / ecdsaP256PublicKey', () => {
  it('toHex pads every byte', () => {
    expect(toHex(B(0, 1, 15, 16, 255))).toBe('00010f10ff');
    expect(toHex(B())).toBe('');
  });
  it('accepts compressed and uncompressed SEC1 points, returns the uncompressed form', () => {
    const k = forgeKey('t-pt', 'P-256');
    const compressed = p256.ProjectivePoint.fromHex(k.pub).toRawBytes(true);
    expect(Array.from(ecdsaP256PublicKey(compressed).point)).toEqual(Array.from(k.pub));
    expect(Array.from(ecdsaP256PublicKey(k.pub).point)).toEqual(Array.from(k.pub));
    expect(() => ecdsaP256PublicKey(cat(B(4), new Uint8Array(64).fill(1)))).toThrow();
  });
});

describe('parseDcapTdReport', () => {
  it('guards and field offsets', () => {
    expect(() => parseDcapTdReport('x' as never)).toThrow(new TypeError('parseDcapTdReport: expected Uint8Array'));
    expect(() => parseDcapTdReport(new Uint8Array(583))).toThrow(new RangeError('parseDcapTdReport: body too short (583 < 584)'));
    const body = Uint8Array.from({ length: 600 }, (_, i) => (i * 7 + 3) & 0xff);
    const r = parseDcapTdReport(body);
    const at = (off: number, n: number) => Array.from(body.slice(off, off + n));
    expect(Array.from(r.teeTcbSvn)).toEqual(at(0, 16));
    expect(Array.from(r.mrSeam)).toEqual(at(16, 48));
    expect(Array.from(r.mrSignerSeam)).toEqual(at(64, 48));
    expect(Array.from(r.tdAttributes)).toEqual(at(120, 8));
    expect(Array.from(r.mrTd)).toEqual(at(136, 48));
    expect(Array.from(r.mrConfigId)).toEqual(at(184, 48));
    expect(Array.from(r.rtmr0)).toEqual(at(328, 48));
    expect(Array.from(r.rtmr1)).toEqual(at(376, 48));
    expect(Array.from(r.rtmr2)).toEqual(at(424, 48));
    expect(Array.from(r.rtmr3)).toEqual(at(472, 48));
    expect(Array.from(r.reportData)).toEqual(at(520, 64));
    expect(r.raw.length).toBe(584);
    expect(Array.from(r.raw)).toEqual(at(0, 584));
    expect(r.raw.buffer).not.toBe(body.buffer);
    expect(TD10_FIELDS.MRTD).toBe(136);
    expect(parseDcapTdReport(new Uint8Array(584)).raw.length).toBe(584);
  });
});

describe('parseDcapQuote', () => {
  it('exposes every parsed region', () => {
    const p = parseDcapQuote(GOOD.quote);
    expect([p.version, p.attKeyType, p.teeType]).toEqual([4, 2, 0x81]);
    expect(p.header.length).toBe(48);
    expect(Array.from(p.tdReportBody)).toEqual(Array.from(GOOD.tdBody));
    expect(p.quoteSignature.length).toBe(64);
    expect(Array.from(p.akPubRaw)).toEqual(Array.from(GOOD.ak.pub.subarray(1)));
    expect(Array.from(p.qeReportBody)).toEqual(Array.from(GOOD.qeReport));
    expect(p.qeReportSignature.length).toBe(64);
    expect(Array.from(p.qeAuthData)).toEqual(Array.from(GOOD.qeAuth));
    expect(p.pckChainPem).toBe(`${GOOD.pckPem}\0`);
  });
  it('input and length guards', () => {
    expect(() => parseDcapQuote('x' as never)).toThrow(new TypeError('parseDcapQuote: expected Uint8Array'));
    const short = 'parseDcapQuote: too short for header + TD report + sig length';
    expect(parseErr(GOOD.quote.slice(0, 635))).toBe(short);
    expect(parseErr(GOOD.quote.slice(0, 632))).toBe(short);
    expect(parseErr(patchU32(GOOD.quote.slice(0, 636), 632, 0))).toBe('parseDcapQuote: truncated reading quote signature'); // exactly header + body + 4 is not "too short"
    expect(parseErr(new Uint8Array(0))).toBe(short);
  });
  it('version / key type / tee type', () => {
    expect(parseErr(patchU16(GOOD.quote, 0, 3))).toBe('parseDcapQuote: unsupported quote version 3 (expected 4)');
    expect(parseErr(patchU16(GOOD.quote, 2, 3))).toBe('parseDcapQuote: unsupported attestation key type 3 (expected ECDSA-P256 = 2)');
    expect(parseErr(patchU32(GOOD.quote, 4, 0x80))).toBe('parseDcapQuote: unexpected TEE type 0x80 (expected TDX = 0x81)');
  });
  it('declared signature length overrunning the quote; trailing bytes ignored', () => {
    const len = GOOD.quote.length - 636;
    expect(parseErr(patchU32(GOOD.quote, 632, len + 1))).toBe(`parseDcapQuote: signature data (${len + 1}) overruns the quote`);
    expect(parseErr(patchU32(GOOD.quote, 632, len))).toBe('NO ERROR');
    expect(parseErr(forged({ trailingPad: 70 }).quote)).toBe('NO ERROR');
  });
  it('every bounded read reports what was truncated', () => {
    const start = 636;
    const sigEndAt = (q: Uint8Array, x: number) => patchU32(q, 632, x);
    const outerZero = (q: Uint8Array) => patchU32(q, DCAP_OFFSETS.OUTER_SIZE, 0);
    expect(parseErr(sigEndAt(GOOD.quote, 63))).toBe('parseDcapQuote: truncated reading quote signature');
    expect(parseErr(sigEndAt(GOOD.quote, 64))).toBe('parseDcapQuote: truncated reading attestation public key');
    expect(parseErr(sigEndAt(GOOD.quote, 127))).toBe('parseDcapQuote: truncated reading attestation public key');
    expect(parseErr(sigEndAt(GOOD.quote, 128))).toBe('parseDcapQuote: truncated reading outer cert-data header');
    expect(parseErr(sigEndAt(GOOD.quote, 133))).toBe('parseDcapQuote: truncated reading outer cert-data header');
    const afterOuter = 134;
    expect(parseErr(sigEndAt(outerZero(GOOD.quote), afterOuter + 383))).toBe('parseDcapQuote: truncated reading QE report');
    expect(parseErr(sigEndAt(outerZero(GOOD.quote), afterOuter + 384 + 63))).toBe('parseDcapQuote: truncated reading QE report signature');
    expect(parseErr(sigEndAt(outerZero(GOOD.quote), afterOuter + 384 + 64 + 1))).toBe('parseDcapQuote: truncated reading QE auth-data size');
    expect(parseErr(sigEndAt(outerZero(GOOD.quote), afterOuter + 384 + 64 + 2 + 31))).toBe('parseDcapQuote: truncated reading QE auth-data');
    expect(parseErr(sigEndAt(outerZero(GOOD.quote), afterOuter + 384 + 64 + 2 + 32 + 5))).toBe('parseDcapQuote: truncated reading inner cert-data header');
    expect(start).toBe(DCAP_OFFSETS.QUOTE_SIG);
  });
  it('cert-data wrappers', () => {
    expect(parseErr(forged({ outerCertType: 5 }).quote)).toBe('parseDcapQuote: outer cert-data type 5 (expected QE-report-cert-data = 6)');
    expect(parseErr(forged({ innerCertType: 6 }).quote)).toBe('parseDcapQuote: inner cert-data type 6 (expected PCK-cert-chain = 5)');
  });
  it('outer cert-data must fit the signature data; inner must fit the outer', () => {
    const q = forged({ trailingPad: 0 }).quote;
    const sigLen = q.length - 636;
    const outerSize = new DataView(q.buffer, q.byteOffset).getUint32(DCAP_OFFSETS.OUTER_SIZE, true);
    expect(parseErr(patchU32(q, DCAP_OFFSETS.OUTER_SIZE, outerSize + 1))).toBe('parseDcapQuote: outer cert-data overruns signature data');
    expect(parseErr(patchU32(q, DCAP_OFFSETS.OUTER_SIZE, sigLen - 134))).toBe('NO ERROR');
    const innerSizeOff = GOOD.offsets.innerSize;
    const innerSize = new DataView(q.buffer, q.byteOffset).getUint32(innerSizeOff, true);
    expect(parseErr(patchU32(q, innerSizeOff, innerSize + 1))).toBe('parseDcapQuote: inner cert-data overruns outer cert-data');
    expect(parseErr(patchU32(q, innerSizeOff, innerSize - 1))).toBe('NO ERROR');
  });
  it('the PEM is exactly the inner cert-data slice (not the whole quote)', () => {
    const p = parseDcapQuote(forged({ trailingPad: 70, chain: { noNul: true } }).quote);
    expect(p.pckChainPem.startsWith('-----BEGIN CERTIFICATE-----')).toBe(true);
    expect(p.pckChainPem.endsWith('-----END CERTIFICATE-----\n')).toBe(true);
    expect(p.pckChainPem.length).toBe(GOOD.pckPem.length);
  });
});

// ------------------------------------------------------------------------------------------- SGX extension
describe('extractPckFmspcAndTcb', () => {
  const spec = (o: Partial<Parameters<typeof sgxExtensionValue>[0]> = {}) => sgxExtensionValue({ fmspc: '90c06f000000', sgxTcb: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], pcesvn: 13, cpusvn: '05050202060100050000000000000000', ...o });
  const OID_F = B(0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x04);
  const OID_T = B(0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02);
  const SGX = '1.2.840.113741.1.13.1';
  const comp = (n: number, v: Uint8Array) => seq(oid(`${SGX}.2.${n}`), v);
  const fm = (len = 6) => cat(OID_F, octets(new Uint8Array(len).fill(0xab)));
  const msg = (f: () => unknown): string => {
    try {
      f();
    } catch (e) {
      return (e as Error).message;
    }
    return 'NO ERROR';
  };
  it('reads FMSPC, all sixteen SVNs, PCESVN and CPUSVN', () => {
    const t = extractPckFmspcAndTcb(spec());
    expect(toHex(t.fmspc)).toBe('90c06f000000');
    expect(Array.from(t.sgxTcbComponents)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    expect(t.pcesvn).toBe(13);
    expect(toHex(t.cpusvn)).toBe('05050202060100050000000000000000');
    const hi = extractPckFmspcAndTcb(spec({ sgxTcb: [255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 200], pcesvn: 0x1234 }));
    expect(hi.sgxTcbComponents[0]).toBe(255);
    expect(hi.sgxTcbComponents[15]).toBe(200);
    expect(hi.pcesvn).toBe(0x1234);
    expect(extractPckFmspcAndTcb(spec({ pcesvn: 0 })).pcesvn).toBe(0);
  });
  it('FMSPC problems', () => {
    expect(msg(() => extractPckFmspcAndTcb(spec({ omit: ['fmspc'] })))).toBe('extractPckFmspcAndTcb: FMSPC OID not found in certificate');
    expect(msg(() => extractPckFmspcAndTcb(spec({ fmspcLen: 5 })))).toBe('extractPckFmspcAndTcb: malformed FMSPC OCTET STRING');
    expect(msg(() => extractPckFmspcAndTcb(spec({ fmspcLen: 7 })))).toBe('extractPckFmspcAndTcb: malformed FMSPC OCTET STRING');
    expect(msg(() => extractPckFmspcAndTcb(cat(OID_F, B(0x04))))).toBe('extractPckFmspcAndTcb: malformed FMSPC OCTET STRING');
    expect(msg(() => extractPckFmspcAndTcb(cat(OID_F, tlv(0x02, new Uint8Array(6)))))).toBe('extractPckFmspcAndTcb: malformed FMSPC OCTET STRING'); // wrong tag, right length
  });
  it('TCB problems', () => {
    expect(msg(() => extractPckFmspcAndTcb(spec({ omit: ['tcb'] })))).toBe('extractPckFmspcAndTcb: TCB OID not found in certificate');
    expect(msg(() => extractPckFmspcAndTcb(spec({ omit: ['pcesvn'] })))).toBe('extractPckFmspcAndTcb: PCESVN not found in TCB extension');
    expect(msg(() => extractPckFmspcAndTcb(cat(fm(), OID_T)))).toBe('extractPckFmspcAndTcb: malformed TCB SEQUENCE');
    expect(msg(() => extractPckFmspcAndTcb(cat(fm(), OID_T, B(0x31, 0x00))))).toBe('extractPckFmspcAndTcb: malformed TCB SEQUENCE');
    expect(msg(() => extractPckFmspcAndTcb(cat(fm(), OID_T, seq(octets(B(1))))))).toBe('extractPckFmspcAndTcb: malformed TCB component');
    expect(msg(() => extractPckFmspcAndTcb(cat(fm(), OID_T, seq(seq(octets(B(1)))))))).toBe('extractPckFmspcAndTcb: TCB component missing OID');
    expect(msg(() => extractPckFmspcAndTcb(cat(fm(), OID_T, seq(seq(oid(`${SGX}.2.1`))))))).toBe('extractPckFmspcAndTcb: TCB component missing value');
  });
  it('DER length forms inside the walker', () => {
    const empty = (hdr: number[]) => cat(fm(), OID_T, B(...hdr));
    // 0x30 0x80 (indefinite) is not accepted
    expect(msg(() => extractPckFmspcAndTcb(empty([0x30, 0x80, 0x00])))).toBe('extractPckFmspcAndTcb: malformed TCB SEQUENCE');
    // an empty SEQUENCE is fine structurally (then no PCESVN)
    expect(msg(() => extractPckFmspcAndTcb(empty([0x30, 0x00])))).toBe('extractPckFmspcAndTcb: PCESVN not found in TCB extension');
    expect(msg(() => extractPckFmspcAndTcb(empty([0x30, 0x81, 0x00])))).toBe('extractPckFmspcAndTcb: PCESVN not found in TCB extension');
    expect(msg(() => extractPckFmspcAndTcb(empty([0x30, 0x84, 0, 0, 0, 0])))).toBe('extractPckFmspcAndTcb: PCESVN not found in TCB extension');
    // five length octets are refused even when the value would fit
    expect(msg(() => extractPckFmspcAndTcb(cat(fm(), OID_T, B(0x30, 0x85, 0, 0, 0, 0, 3), comp(1, integer(1)).subarray(0, 3))))).toBe('extractPckFmspcAndTcb: malformed TCB SEQUENCE');
    // length octets running off the end of the buffer
    expect(msg(() => extractPckFmspcAndTcb(cat(fm(), OID_T, B(0x30, 0x82, 0x01))))).toBe('extractPckFmspcAndTcb: malformed TCB SEQUENCE');
    expect(msg(() => extractPckFmspcAndTcb(cat(fm(), OID_T, B(0x30, 0x81))))).toBe('extractPckFmspcAndTcb: malformed TCB SEQUENCE');
    // content overrunning the buffer
    expect(msg(() => extractPckFmspcAndTcb(cat(fm(), OID_T, B(0x30, 0x05, 0x00))))).toBe('extractPckFmspcAndTcb: malformed TCB SEQUENCE');
    // a two-octet long-form length is read big-endian
    const comps = cat(...Array.from({ length: 16 }, (_, i) => comp(i + 1, integer(i + 1))), comp(17, integer(7)));
    const body = cat(comps, comp(1, integer(1)));
    const tcb = cat(B(0x30, 0x82, (body.length >> 8) & 0xff, body.length & 0xff), body);
    expect(extractPckFmspcAndTcb(cat(fm(), OID_T, tcb)).pcesvn).toBe(7);
    // the TCB OID may sit at the very start of the buffer
    const first = cat(OID_T, seq(comp(17, integer(9))), fm());
    expect(extractPckFmspcAndTcb(first).pcesvn).toBe(9);
  });
  it('component dispatch: INTEGER arcs 1..16 and 17, OCTET STRING arc 18 only', () => {
    const run = (...cs: Uint8Array[]) => extractPckFmspcAndTcb(cat(fm(), OID_T, seq(...cs, comp(17, integer(1)))));
    const r = run(comp(5, octets(B(9, 9))), comp(18, integer(77)));
    expect(r.cpusvn.length).toBe(0); // octets under arc 5 and an integer under arc 18 are not a CPUSVN
    expect(Array.from(r.sgxTcbComponents)).toEqual(new Array(16).fill(0));
    expect(Array.from(run(comp(18, octets(B(1, 2, 3)))).cpusvn)).toEqual([1, 2, 3]);
    expect(run(comp(18, tlv(0x0c, B(1, 2, 3)))).cpusvn.length).toBe(0); // only an OCTET STRING under arc 18 is the CPUSVN
    const odd = run(comp(0, integer(5)), comp(19, integer(6)));
    expect(Array.from(odd.sgxTcbComponents)).toEqual(new Array(16).fill(0));
    expect(odd.pcesvn).toBe(1);
    expect(run(comp(16, integer(300))).sgxTcbComponents[15]).toBe(300 & 0xff);
    expect(extractPckFmspcAndTcb(cat(fm(), OID_T, seq(comp(17, integer(0x1ffff))))).pcesvn).toBe(0xffff);
  });
  it('at most 65 components are read', () => {
    const filler = (n: number) => Array.from({ length: n }, () => comp(20, integer(1)));
    const at = (k: number) => extractPckFmspcAndTcb(cat(fm(), OID_T, seq(...filler(k), comp(17, integer(5)))));
    expect(at(64).pcesvn).toBe(5); // PCESVN is the 65th component
    expect(msg(() => at(65))).toBe('extractPckFmspcAndTcb: PCESVN not found in TCB extension'); // the 66th is never reached
    expect(msg(() => at(100))).toBe('extractPckFmspcAndTcb: PCESVN not found in TCB extension');
  });
});

// ------------------------------------------------------------------------------------------- chain
describe('verifyIntelPckChainX509', () => {
  const chain = (q: { pckPem: string; rootSpkiSha256: string }, extra: Record<string, unknown> = {}) => verifyIntelPckChainX509({ pckChainPem: q.pckPem, trustAnchorRootCaSpkiSha256: q.rootSpkiSha256, nowMs: NOW, ...extra });
  it('accepts the genuine shape and reports leaf key, DER and depth', async () => {
    const r = await chain(GOOD);
    expect(r.ok).toBe(true);
    expect(r.depth).toBe(3);
    expect(r.reason).toBeUndefined();
    expect(Array.from(r.leafDer!)).toEqual(Array.from(GOOD.pck.der));
    expect(Array.from(r.leafKey!.point)).toEqual(Array.from(GOOD.pckKey.pub));
    expect((await chain(GOOD, { trustAnchorRootCaSpkiSha256: GOOD.rootSpkiSha256.toUpperCase() })).ok).toBe(true);
    expect(INTEL_SGX_ROOT_CA_SPKI_SHA256).toMatch(/^[0-9a-f]{64}$/);
  });
  it('input shape and ordering', async () => {
    const none = { ok: false, reason: 'no PEM certificates in the PCK chain' };
    expect(await verifyIntelPckChainX509({ pckChainPem: '', nowMs: NOW })).toEqual(none);
    expect(await verifyIntelPckChainX509({ pckChainPem: 'junk', nowMs: NOW })).toEqual(none);
    expect(await verifyIntelPckChainX509({ pckChainPem: 5 as never, nowMs: NOW })).toEqual(none);
    const shuffled = forged({ chain: { order: [GOOD.pki.root, GOOD.pck, GOOD.pki.platformCa] } });
    expect((await chain(shuffled)).ok).toBe(true);
  });
  it('orphans, cycles and non-roots', async () => {
    const other = forgeIntelPki('someone-else');
    expect(await chain(forged({ chain: { appendPem: other.root.pem } }))).toEqual({ ok: false, reason: 'PCK chain is not a single connected path (orphan/duplicate certificates)' });
    expect(await chain(forged({ chain: { order: [GOOD.pck, GOOD.pki.platformCa] } }))).toEqual({ ok: false, reason: 'PCK chain does not terminate in a self-signed root' });
    // two certificates that name each other as issuer: must terminate (no endless walk)
    const ka = forgeKey('cyc-a', 'P-256');
    const kb = forgeKey('cyc-b', 'P-256');
    const dnA = [['CN', 'A']] as const;
    const dnB = [['CN', 'B']] as const;
    const mk = (subject: readonly DnAttr[], issuer: readonly DnAttr[], sk: typeof ka, sig: typeof ka, lbl: string) => forgeCert({ subject, issuer, subjectKey: sk, signer: sig, serial: serialFor(lbl), notBefore: new Date('2020-01-01T00:00:00Z'), notAfter: new Date('2040-01-01T00:00:00Z'), extensions: [ext.basicConstraints(true)] });
    const a = mk(dnA, dnB, ka, kb, 'a');
    const b = mk(dnB, dnA, kb, ka, 'b');
    expect(await verifyIntelPckChainX509({ pckChainPem: a.pem + b.pem, nowMs: NOW })).toEqual({ ok: false, reason: 'PCK chain does not terminate in a self-signed root' });
  });
  it('clock', async () => {
    expect(await chain(GOOD, { nowMs: NaN })).toEqual({ ok: false, reason: 'nowMs is not a finite number' });
    expect(await chain(GOOD, { nowMs: Infinity })).toEqual({ ok: false, reason: 'nowMs is not a finite number' });
    const pckFrom = Date.parse(GOOD.pck.der ? new (await import('node:crypto')).X509Certificate(GOOD.pck.der).validFrom : '');
    const pckTo = Date.parse(new (await import('node:crypto')).X509Certificate(GOOD.platformCa.der).validTo); // the earliest-expiring certificate
    expect((await chain(GOOD, { nowMs: pckFrom })).ok).toBe(true);
    expect(await chain(GOOD, { nowMs: pckFrom - 1 })).toEqual({ ok: false, reason: 'PCK chain certificate outside its validity period', failure: 'validity' });
    expect((await chain(GOOD, { nowMs: pckTo })).ok).toBe(true);
    expect(await chain(GOOD, { nowMs: pckTo + 1 })).toEqual({ ok: false, reason: 'PCK chain certificate outside its validity period', failure: 'validity' });
    // an intermediate / root outside its window also fails
    const exp = forged({ pki: forgeIntelPki('expired-ca', { caValidity: [new Date('2018-01-01T00:00:00Z'), new Date('2019-01-01T00:00:00Z')] }) });
    expect((await chain(exp)).failure).toBe('validity');
  });
  it('without nowMs the host clock is used', async () => {
    const r = await verifyIntelPckChainX509({ pckChainPem: GOOD.pckPem, trustAnchorRootCaSpkiSha256: GOOD.rootSpkiSha256 });
    expect(r.ok).toBe(true);
  });
  it('signatures, pin, roles, key type', async () => {
    const badSig = forged({ pck: { issuerKey: forgeKey('wrong-signer', 'P-256') } });
    expect(await chain(badSig)).toEqual({ ok: false, reason: 'certificate at depth 0 is not signed by its issuer' });
    const badCa = forged({ pki: forgeIntelPki('bad-ca-sig', { caSignedBy: forgeKey('wrong-ca-signer', 'P-256') }) });
    expect(await chain(badCa)).toEqual({ ok: false, reason: 'certificate at depth 1 is not signed by its issuer' });
    const notSelf = forged({ pki: forgeIntelPki('not-self', { rootSelfSigned: false }) });
    expect(await chain(notSelf)).toEqual({ ok: false, reason: 'root certificate is not self-signed' });
    expect(await chain(GOOD, { trustAnchorRootCaSpkiSha256: '00'.repeat(32) })).toEqual({ ok: false, reason: 'Intel SGX Root CA does not match the pinned trust anchor' });
    expect(await verifyIntelPckChainX509({ pckChainPem: GOOD.pckPem, nowMs: NOW })).toEqual({ ok: false, reason: 'Intel SGX Root CA does not match the pinned trust anchor' }); // default pin is the real Intel root
    const leafCa = forged({ pck: { ca: true } });
    expect(await chain(leafCa)).toEqual({ ok: false, reason: 'leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)' });
    const caNoBc = forged({ pki: forgeIntelPki('no-bc', { caBasicConstraints: 'absent' }) });
    expect(await chain(caNoBc)).toEqual({ ok: false, reason: 'issuer certificate at depth 1 has no BasicConstraints (not a CA)' });
  });
  it('a non-EC or off-curve leaf key fails closed', async () => {
    const rsaSpki = Uint8Array.from(generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'der' }));
    const rsa = await chain(forged({ pck: { spkiOverride: rsaSpki } }));
    expect(rsa.ok).toBe(false);
    expect(rsa).toEqual({ ok: false, reason: 'PCK leaf key is not EC (got rsa)' });
    const offCurve = cat(forgeKey('x', 'P-256').spki.subarray(0, forgeKey('x', 'P-256').spki.length - 64), new Uint8Array(64).fill(1));
    const r = await chain(forged({ pck: { spkiOverride: offCurve } }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/^PCK chain X\.509 verification error \(fail closed\): /);
  });
});

// ------------------------------------------------------------------------------------------- end to end
describe('verifyGenuineTdxQuote', () => {
  const REPORT_BYTES = (n: number, v: number) => new Uint8Array(n).fill(v);
  const fail = (r: { ok: boolean; reason?: string }, reason: string | RegExp) => {
    expect(r.ok).toBe(false);
    if (typeof reason === 'string') expect(r.reason).toBe(reason);
    else expect(r.reason).toMatch(reason);
  };
  it('accepts and returns every field', async () => {
    const r = await verify(GOOD);
    expect(r.ok).toBe(true);
    expect(r.reason).toBeUndefined();
    expect(r.fmspc).toBe('90c06f000000');
    expect(r.chainDepth).toBe(3);
    expect(r.pckTcb!.pcesvn).toBe(13);
    expect(Array.from(r.pckTcb!.sgxTcbComponents)).toEqual([5, 5, 2, 2, 6, 1, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0]);
    expect(Array.from(r.akPub!.point)).toEqual(Array.from(GOOD.ak.pub));
    expect(Array.from(r.report!.mrTd)).toEqual(Array.from(GOOD.tdBody.slice(136, 184)));
    expect(r.measured).toEqual({ model_id: '', weights_digest: '', weights_measured: false, runtime_measurement: toHex(GOOD.tdBody.slice(136, 184)), operator: '' });
  });
  it('quote parse failures carry the parser text', async () => {
    fail(await verifyGenuineTdxQuote({ quote: new Uint8Array(3), nowMs: NOW }), 'quote parse failed: parseDcapQuote: too short for header + TD report + sig length');
    fail(await verify({ quote: patchU16(GOOD.quote, 0, 3), rootSpkiSha256: GOOD.rootSpkiSha256 }), 'quote parse failed: parseDcapQuote: unsupported quote version 3 (expected 4)');
  });
  it('chain failures are prefixed', async () => {
    fail(await verify(GOOD, { trustAnchorRootCaSpkiSha256: '00'.repeat(32) }), 'PCK chain invalid: Intel SGX Root CA does not match the pinned trust anchor');
    fail(await verify(GOOD, { nowMs: 5 }), 'PCK chain invalid: PCK chain certificate outside its validity period');
  });
  it('FMSPC / TCB extraction failures', async () => {
    const q = forged({ pck: { ext: { omit: ['fmspc'] } } });
    fail(await verify(q), 'PCK FMSPC/TCB extraction failed: extractPckFmspcAndTcb: FMSPC OID not found in certificate');
  });
  it('QE report: signature, debug flag, key binding', async () => {
    fail(await verify(forged({ qe: { signer: forgeKey('other-qe-signer', 'P-256') } })), 'QE report signature does not verify under the PCK leaf');
    fail(await verify(forged({ qe: { attributes: '1500000000000000e700000000000000'.replace(/^15/, '17') } })), 'QE report ATTRIBUTES.DEBUG is set (debug quoting enclave)');
    expect((await verify(forged({ qe: { attributes: '1d00000000000000e700000000000000' } }))).ok).toBe(true); // other flag bits (not bit 1) are fine
    const akBind = 'QE report_data does not bind the attestation key (AK not endorsed by this QE)';
    fail(await verify(forged({ qe: { reportData: REPORT_BYTES(64, 1) } })), akBind);
    const good = Uint8Array.from(parseDcapQuote(GOOD.quote).qeReportBody.slice(320, 384));
    const tail = Uint8Array.from(good);
    tail[63] = 1;
    fail(await verify(forged({ qe: { reportData: tail } })), akBind);
    const head = Uint8Array.from(good);
    head[0]! ^= 1;
    fail(await verify(forged({ qe: { reportData: head } })), akBind);
    const mid = Uint8Array.from(good);
    mid[32] = 1;
    fail(await verify(forged({ qe: { reportData: mid } })), akBind);
  });
  it('structurally invalid signatures (r = s = 0) are refusals, not exceptions', async () => {
    const zero = (q: Uint8Array, off: number) => {
      const c = Uint8Array.from(q);
      c.fill(0, off, off + 64);
      return { quote: c, rootSpkiSha256: GOOD.rootSpkiSha256 };
    };
    fail(await verify(zero(GOOD.quote, DCAP_OFFSETS.QE_SIG)), 'QE report signature does not verify under the PCK leaf');
    fail(await verify(zero(GOOD.quote, DCAP_OFFSETS.QUOTE_SIG)), 'TD quote signature does not verify under the attestation key');
  });
  it('attestation key must be a valid point; TD signature must verify', async () => {
    const real = forgeKey('real-ak', 'P-256');
    const fakeAk = { ...real, pub: cat(B(4), new Uint8Array(64).fill(7)) };
    fail(await verify(forged({ ak: fakeAk, tdSigner: real })), 'attestation public key is not a valid P-256 point');
    fail(await verify(forged({ tdSigner: forgeKey('other-td-signer', 'P-256') })), 'TD quote signature does not verify under the attestation key');
  });
  it('high-S signatures are accepted (ECDSA validity does not require low-S)', async () => {
    const n = p256.CURVE.n;
    const flip = (q: Uint8Array, off: number) => {
      const c = Uint8Array.from(q);
      const s = BigInt(`0x${Buffer.from(c.slice(off + 32, off + 64)).toString('hex')}`);
      const s2 = n - s;
      c.set(Buffer.from(s2.toString(16).padStart(64, '0'), 'hex'), off + 32);
      return { c, high: s2 > n >> 1n || s > n >> 1n };
    };
    // find a signature that becomes HIGH-s when flipped (one of the pair is always high)
    for (const off of [DCAP_OFFSETS.QUOTE_SIG, DCAP_OFFSETS.QE_SIG]) {
      const orig = GOOD.quote.slice(off + 32, off + 64);
      const s = BigInt(`0x${Buffer.from(orig).toString('hex')}`);
      const base = s > n >> 1n ? GOOD.quote : flip(GOOD.quote, off).c; // make it high-s
      const r = await verify({ quote: base, rootSpkiSha256: GOOD.rootSpkiSha256 });
      expect(r.ok, `offset ${off}`).toBe(true);
    }
  });
  it('PCA binding', async () => {
    const exp: ExpectedAttestationBinding = { holderPub: 'h', grantRef: 'g', epoch: 2, nonce: 'n', nonceIssuedAt: NOW };
    const bound = forged({ td: { reportData: attestationBinding(exp) } });
    expect((await verify(bound, { expected: exp })).ok).toBe(true);
    fail(await verify(bound, { expected: { ...exp, nonce: 'm' } }), 'report_data does not bind holder/grant/epoch/nonce');
    fail(await verify(GOOD, { expected: exp }), 'report_data does not bind holder/grant/epoch/nonce');
    fail(await verify(bound, { expected: { ...exp, epoch: -1 } }), 'binding not constructible: binding: epoch must be a non-negative safe integer');
    expect((await verify(GOOD)).ok).toBe(true); // no expected => not checked
  });
  it('TD_ATTRIBUTES.DEBUG', async () => {
    const dbg = forged({ td: { debug: true } });
    const m = 'TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)';
    fail(await verify(dbg), m);
    fail(await verify(dbg, { policy: {} }), m);
    fail(await verify(dbg, { policy: { allowDebug: false } }), m);
    fail(await verify(dbg, { policy: { allowDebug: 'yes' } }), m);
    expect((await verify(dbg, { policy: { allowDebug: true } })).ok).toBe(true);
    expect((await verify(forged({ td: { tdAttributes: '0200000000000000' } }))).ok).toBe(true); // only bit 0 is DEBUG
  });
  it('policy gates: exact reasons, empty-list semantics, case-insensitive, fixed order', async () => {
    const q = forged({ td: { mrSeam: 'ab'.repeat(48), mrSignerSeam: 'cd'.repeat(48), rtmr0: 'ef'.repeat(48), mrTd: '12'.repeat(48) } });
    const mrtd = '12'.repeat(48);
    const run = (policy: Record<string, unknown>) => verify(q, { policy });
    expect((await run({ mrtds: [mrtd] })).ok).toBe(true);
    expect((await run({ mrtds: [mrtd.toUpperCase().replace(/[0-9]/g, (c) => c)] })).ok).toBe(true);
    expect((await run({ mrtds: [] })).ok).toBe(true);
    fail(await run({ mrtds: ['00'.repeat(48)] }), 'MRTD not in policy allowlist');
    expect((await run({ fmspcs: ['90C06F000000'] })).ok).toBe(true);
    expect((await run({ fmspcs: [] })).ok).toBe(true);
    fail(await run({ fmspcs: ['000000000000'] }), 'FMSPC not in policy allowlist');
    expect((await run({ mrSeams: ['ab'.repeat(48)] })).ok).toBe(true);
    expect((await run({ mrSeams: ['AB'.repeat(48)] })).ok).toBe(true);
    fail(await run({ mrSeams: [] }), 'MRSEAM not in policy allowlist');
    fail(await run({ mrSeams: ['00'.repeat(48)] }), 'MRSEAM not in policy allowlist');
    expect((await run({ mrSignerSeams: ['cd'.repeat(48)] })).ok).toBe(true);
    expect((await run({ mrSignerSeams: ['CD'.repeat(48)] })).ok).toBe(true);
    fail(await run({ mrSignerSeams: [] }), 'MRSIGNERSEAM not in policy allowlist');
    fail(await run({ mrSignerSeams: ['00'.repeat(48)] }), 'MRSIGNERSEAM not in policy allowlist');
    expect((await run({ rtmrs: ['ef'.repeat(48)] })).ok).toBe(true);
    expect((await run({ rtmrs: ['EF'.repeat(48)] })).ok).toBe(true);
    expect((await run({ rtmrs: [] })).ok).toBe(true);
    fail(await run({ rtmrs: ['00'.repeat(48)] }), 'RTMR0 not in policy allowlist');
    // rtmrs gates RTMR0 only
    fail(await run({ rtmrs: [toHex(q.tdBody.slice(376, 424))] }), 'RTMR0 not in policy allowlist');
    const bad = '00'.repeat(48);
    fail(await run({ mrtds: [bad], fmspcs: ['000000000000'], mrSeams: [bad], mrSignerSeams: [bad], rtmrs: [bad] }), 'MRTD not in policy allowlist');
    fail(await run({ fmspcs: ['000000000000'], mrSeams: [bad], mrSignerSeams: [bad], rtmrs: [bad] }), 'FMSPC not in policy allowlist');
    fail(await run({ mrSeams: [bad], mrSignerSeams: [bad], rtmrs: [bad] }), 'MRSEAM not in policy allowlist');
    fail(await run({ mrSignerSeams: [bad], rtmrs: [bad] }), 'MRSIGNERSEAM not in policy allowlist');
    expect((await run({ mrtds: [bad, mrtd], fmspcs: ['90c06f000000'], mrSeams: ['ab'.repeat(48)], mrSignerSeams: ['cd'.repeat(48)], rtmrs: ['ef'.repeat(48)] })).ok).toBe(true);
  });
  it('an unexpected exception is reported fail-closed with its message', async () => {
    const r = await verify(GOOD, { policy: { mrtds: [5] } });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/^genuine TDX verification error \(fail closed\): .*toLowerCase/);
    expect(r.report).toBeUndefined();
  });
});
