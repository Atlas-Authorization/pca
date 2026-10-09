/**
 * Branch coverage for the Intel DCAP / PCS verifiers using the TEST-ONLY forger (`test-support/forge-dcap.ts`).
 *
 * Real silicon cannot supply a debug TD, a lower TCB, a different MRTD, a revoked PCK, ... so these tests mint
 * evidence in the REAL Intel wire format (v4 ECDSA-P256 quote, real X.509 PCK chain with the SGX extension, signed PCS
 * TCB-info / QE-identity JSON, CRLs) under a TEST root and inject that root through the verifiers' existing
 * trust-anchor option. The production code is unmodified. Every negative asserts the SPECIFIC rejection reason.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { X509Certificate, createHash, generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  INTEL_SGX_ROOT_CA_SPKI_SHA256,
  ecdsaP256PublicKey,
  extractPckFmspcAndTcb,
  toHex,
  parseDcapQuote,
  parseDcapTdReport,
  verifyGenuineTdxQuote,
  verifyIntelPckChainX509,
} from './attest-intel-tdx';
import { DEFAULT_ACCEPTED_STATUSES, serialIsRevoked, verifyCrl, verifyIntelTdxCollateral, type IntelCollateralPolicy, type TcbStatus } from './attest-intel-collateral';
import { checkAzureRuntimeDataBinding, createIntelDcapVerifier, type IntelDcapEvidence, type IntelDcapPolicy } from './attest-intel-dcap';
import { attestationBinding } from './attestation';
import type { AttestationDocument, ExpectedAttestationBinding } from './attestation';
import {
  DCAP_OFFSETS,
  TD10_FIELDS,
  TD_ATTR_DEBUG,
  forgeIntelPki,
  forgeTdxCollateral,
  forgeTdxQuote,
  sgxExtensionValue,
  type ForgeCollateralOptions,
  type ForgeTdxOptions,
  type ForgedTdxQuote,
} from './test-support/forge-dcap';
import { type Extension, boolean, bytesToHex, cat, derShape, ext, extension, derTime, dn, forgeCert, forgeCrl, forgeKey, generalizedTime, hexToBytes, integer, octets, oid, readDer, seq, tlv, u16, u32 } from './test-support/forge-x509';

// ── helpers ──────────────────────────────────────────────────────────────────────────────────────
const NOW = new Date('2026-10-20T00:00:00Z');
const REAL_QUOTE = new Uint8Array(readFileSync(resolve(__dirname, '..', 'fixtures', 'real-tdx', 'azure-intel-tdx-dcap-quote.bin')));
const EXPECTED: ExpectedAttestationBinding = { holderPub: 'holder-pub-forged', grantRef: 'grant_forged_1', epoch: 7, nonce: 'srv-nonce-forged-0123' };
const BINDING = attestationBinding(EXPECTED);
const CERT_RE = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

const flipAt = (b: Uint8Array, i: number): Uint8Array => {
  const c = new Uint8Array(b);
  c[i] = c[i]! ^ 0x01;
  return c;
};
const patch = (b: Uint8Array, off: number, v: Uint8Array): Uint8Array => {
  const c = new Uint8Array(b);
  c.set(v, off);
  return c;
};
const std = (f: ForgedTdxQuote, extra: Partial<Parameters<typeof verifyGenuineTdxQuote>[0]> = {}) =>
  verifyGenuineTdxQuote({ quote: f.quote, trustAnchorRootCaSpkiSha256: f.rootSpkiSha256, ...extra });
const quoteWith = (o: ForgeTdxOptions = {}) => forgeTdxQuote(o);
const coll = (f: ForgedTdxQuote, o: ForgeCollateralOptions = {}, policy?: IntelCollateralPolicy, now = NOW, quote = f.quote) =>
  verifyIntelTdxCollateral({ quote, collateral: forgeTdxCollateral(f, o), now, trustAnchorRootCaSpkiSha256: f.rootSpkiSha256, ...(policy ? { policy } : {}) });
const BASE = quoteWith();
const hexOf = (b: Uint8Array) => bytesToHex(b);
const sha256 = (...p: Uint8Array[]) => new Uint8Array(createHash('sha256').update(cat(...p)).digest());
const certsOf = (pem: string) => (pem.match(CERT_RE) ?? []).map((b) => new X509Certificate(b));

// ═════════════════════════════════════════════════════════════════════════════════════════════════
describe('forge-dcap: the forged quote is wire-equivalent to a REAL Azure Intel TDX quote', () => {
  const real = parseDcapQuote(REAL_QUOTE);
  const forged = quoteWith({ trailingPad: 70 }); // Azure appends 70 zero bytes after the signature data
  const f = parseDcapQuote(forged.quote);

  it('has the same fixed header fields, region lengths, offsets and signature-data accounting', () => {
    for (const p of [real, f]) {
      expect([p.version, p.attKeyType, p.teeType]).toEqual([4, 2, 0x81]);
      expect(p.header.length).toBe(48);
      expect(p.tdReportBody.length).toBe(584);
      expect(p.quoteSignature.length).toBe(64);
      expect(p.akPubRaw.length).toBe(64);
      expect(p.qeReportBody.length).toBe(384);
      expect(p.qeReportSignature.length).toBe(64);
      expect(p.qeAuthData.length).toBe(32);
    }
    expect(hexOf(f.header.slice(0, 8))).toBe(hexOf(real.header.slice(0, 8))); // version, key type, tee type, reserved
    expect(hexOf(f.header.slice(8, 24))).toBe(hexOf(real.header.slice(8, 24))); // Intel QE vendor id
    const sigLen = (q: Uint8Array, pem: number) => 64 + 64 + 6 + 384 + 64 + 2 + 32 + 6 + pem;
    const dvReal = new DataView(REAL_QUOTE.buffer, REAL_QUOTE.byteOffset);
    const dvForged = new DataView(forged.quote.buffer, forged.quote.byteOffset);
    expect(dvReal.getUint32(DCAP_OFFSETS.SIG_DATA_LEN, true)).toBe(sigLen(REAL_QUOTE, real.pckChainPem.length));
    expect(dvForged.getUint32(DCAP_OFFSETS.SIG_DATA_LEN, true)).toBe(sigLen(forged.quote, f.pckChainPem.length));
    // both fixed-offset cursors land on the same fields
    expect(dvReal.getUint16(DCAP_OFFSETS.OUTER_TYPE, true)).toBe(6);
    expect(dvForged.getUint16(DCAP_OFFSETS.OUTER_TYPE, true)).toBe(6);
    expect(dvReal.getUint16(DCAP_OFFSETS.QE_AUTH_SIZE, true)).toBe(32);
    expect(dvForged.getUint16(DCAP_OFFSETS.QE_AUTH_SIZE, true)).toBe(32);
    expect(forged.offsets.pem).toBe(DCAP_OFFSETS.QE_AUTH + 32 + 6);
    // identical overall framing: real = header+body+len+sigdata+70 pad; forged follows the same recipe
    expect(REAL_QUOTE.length - 70).toBe(48 + 584 + 4 + sigLen(REAL_QUOTE, real.pckChainPem.length));
    expect(forged.quote.length - 70).toBe(48 + 584 + 4 + sigLen(forged.quote, f.pckChainPem.length));
  });

  it('carries the PEM chain the way Intel does: leaf, Platform CA, Root; 64-col lines; trailing NUL', () => {
    for (const p of [real, f]) {
      expect(p.pckChainPem.charCodeAt(p.pckChainPem.length - 1)).toBe(0);
      expect(p.pckChainPem.match(/-----BEGIN CERTIFICATE-----/g)?.length).toBe(3);
      const lines = p.pckChainPem.replace(/\0/g, '').split('\n').filter((l) => l && !l.startsWith('-----'));
      expect(Math.max(...lines.map((l) => l.length))).toBe(64);
    }
    const subj = (pem: string) => certsOf(pem).map((c) => c.subject.split('\n').find((l) => l.startsWith('CN='))!);
    expect(subj(f.pckChainPem)).toEqual(subj(real.pckChainPem));
  });

  it('every certificate has the same ASN.1 skeleton as its real counterpart (DN order, extensions, SGX extension)', () => {
    const rc = certsOf(real.pckChainPem);
    const fc = certsOf(f.pckChainPem);
    for (let i = 0; i < 3; i++) expect(derShape(new Uint8Array(fc[i]!.raw))).toBe(derShape(new Uint8Array(rc[i]!.raw)));
    const sgxShape = (c: X509Certificate) => {
      const d = new Uint8Array(c.raw);
      const exts = readDer(d).children![0]!.children!.at(-1)!.children![0]!;
      const e = exts.children!.find((x) => derShape(d, x).includes('oid:1.2.840.113741.1.13.1,'))!;
      const o = e.children!.at(-1)!;
      const inner = d.subarray(o.start, o.end);
      return derShape(inner, readDer(inner), true);
    };
    expect(sgxShape(fc[0]!)).toBe(sgxShape(rc[0]!));
  });

  it('the production extractor reads the same structure from both PCK leaves', () => {
    const a = extractPckFmspcAndTcb(new Uint8Array(certsOf(real.pckChainPem)[0]!.raw));
    const b = extractPckFmspcAndTcb(new Uint8Array(certsOf(f.pckChainPem)[0]!.raw));
    expect(a.fmspc.length).toBe(b.fmspc.length);
    expect(a.sgxTcbComponents.length).toBe(b.sgxTcbComponents.length);
    expect(a.cpusvn.length).toBe(b.cpusvn.length);
    expect(b.pcesvn).toBe(13);
    expect(hexOf(b.fmspc)).toBe(hexOf(a.fmspc)); // default FMSPC mirrors the real platform family
  });

  it('TD10 body and QE report share the real layout (TD attributes SEPT_VE_DISABLE, QE ISV prod id 2)', () => {
    const rt = parseDcapTdReport(real.tdReportBody);
    const ft = parseDcapTdReport(f.tdReportBody);
    expect(hexOf(ft.tdAttributes)).toBe(hexOf(rt.tdAttributes));
    expect(hexOf(ft.teeTcbSvn)).toBe(hexOf(rt.teeTcbSvn));
    expect(ft.reportData.length).toBe(rt.reportData.length);
    expect(hexOf(f.qeReportBody.slice(128, 160))).toBe(hexOf(real.qeReportBody.slice(128, 160))); // QE MRSIGNER
    expect(hexOf(f.qeReportBody.slice(256, 258))).toBe(hexOf(real.qeReportBody.slice(256, 258))); // ISVPRODID
    expect(hexOf(f.qeReportBody.slice(320 + 32, 384))).toBe('00'.repeat(32)); // report_data tail is zero
  });

  it('is deterministic: the same options always produce the identical byte string', () => {
    expect(hexOf(quoteWith().quote)).toBe(hexOf(quoteWith().quote));
    expect(hexOf(quoteWith({ seed: 'other' }).quote)).not.toBe(hexOf(quoteWith().quote));
  });
});

// ═════════════════════════════════════════════════════════════════════════════════════════════════
describe('verifyGenuineTdxQuote on forged evidence', () => {
  it('accepts a fully valid forged quote and surfaces the parsed identity', async () => {
    const r = await std(BASE);
    expect(r.reason).toBeUndefined();
    expect(r.ok).toBe(true);
    expect(r.fmspc).toBe('90c06f000000');
    expect(r.chainDepth).toBe(3);
    expect(r.pckTcb?.pcesvn).toBe(13);
    expect(Array.from(r.pckTcb!.sgxTcbComponents)).toEqual(BASE.pckSpec.sgxTcb);
    expect(r.measured?.runtime_measurement).toBe(hexOf(BASE.tdBody.subarray(TD10_FIELDS.MRTD, TD10_FIELDS.MRTD + 48)));
  });

  it('does NOT trust the forged root under the production default pin (Intel SGX Root CA)', async () => {
    const r = await verifyGenuineTdxQuote({ quote: BASE.quote });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('PCK chain invalid: Intel SGX Root CA does not match the pinned trust anchor');
    expect(BASE.rootSpkiSha256).not.toBe(INTEL_SGX_ROOT_CA_SPKI_SHA256);
  });

  describe('quote framing / parse branches', () => {
    const q = BASE.quote;
    const cases: [string, Uint8Array, RegExp | string][] = [
      ['too short', q.slice(0, 600), 'quote parse failed: parseDcapQuote: too short for header + TD report + sig length'],
      ['version 3', patch(q, 0, u16(3)), 'quote parse failed: parseDcapQuote: unsupported quote version 3 (expected 4)'],
      ['SGX/other attestation key type', patch(q, 2, u16(3)), 'quote parse failed: parseDcapQuote: unsupported attestation key type 3 (expected ECDSA-P256 = 2)'],
      ['SGX TEE type (0)', patch(q, 4, u32(0)), 'quote parse failed: parseDcapQuote: unexpected TEE type 0x0 (expected TDX = 0x81)'],
      ['signature data overruns the quote', patch(q, DCAP_OFFSETS.SIG_DATA_LEN, u32(q.length)), /signature data \(\d+\) overruns the quote/],
      ['zero signature data', patch(q, DCAP_OFFSETS.SIG_DATA_LEN, u32(0)), 'quote parse failed: parseDcapQuote: truncated reading quote signature'],
      ['signature data ends before the attestation key', patch(q, DCAP_OFFSETS.SIG_DATA_LEN, u32(64)), 'quote parse failed: parseDcapQuote: truncated reading attestation public key'],
      ['signature data ends before the outer cert header', patch(q, DCAP_OFFSETS.SIG_DATA_LEN, u32(128 + 3)), 'quote parse failed: parseDcapQuote: truncated reading outer cert-data header'],
      ['outer cert-data type 5 (not QE-report cert data)', patch(q, DCAP_OFFSETS.OUTER_TYPE, u16(5)), 'quote parse failed: parseDcapQuote: outer cert-data type 5 (expected QE-report-cert-data = 6)'],
      ['outer cert-data size overruns the signature data', patch(q, DCAP_OFFSETS.OUTER_SIZE, u32(1_000_000)), 'quote parse failed: parseDcapQuote: outer cert-data overruns signature data'],
      ['QE auth size larger than the data', patch(q, DCAP_OFFSETS.QE_AUTH_SIZE, u16(0xffff)), 'quote parse failed: parseDcapQuote: truncated reading QE auth-data'],
      ['inner cert-data type 6', patch(q, BASE.offsets.innerType, u16(6)), 'quote parse failed: parseDcapQuote: inner cert-data type 6 (expected PCK-cert-chain = 5)'],
      ['inner cert-data size overruns outer', patch(q, BASE.offsets.innerSize, u32(BASE.offsets.pemLen + 500)), 'quote parse failed: parseDcapQuote: inner cert-data overruns outer cert-data'],
    ];
    for (const [name, bytes, want] of cases) {
      it(`rejects: ${name}`, async () => {
        const r = await verifyGenuineTdxQuote({ quote: bytes, trustAnchorRootCaSpkiSha256: BASE.rootSpkiSha256 });
        expect(r.ok).toBe(false);
        if (typeof want === 'string') expect(r.reason).toBe(want);
        else expect(r.reason).toMatch(want);
      });
    }

    it('rejects a QE report truncated by an understated signature-data length', async () => {
      const f = quoteWith({ sigDataLenDelta: -(BASE.offsets.pemLen + 6 + 32 + 2 + 64 + 100) });
      const r = await std(f);
      expect(r.ok).toBe(false);
      expect(r.reason).toMatch(/^quote parse failed: parseDcapQuote: (outer cert-data overruns signature data|truncated reading)/);
    });

    it('ignores trailing bytes after the declared signature data (Azure pads with 70 zero bytes)', async () => {
      expect((await std(quoteWith({ trailingPad: 70 }))).ok).toBe(true);
    });

    it('a non-Uint8Array quote is rejected as a parse failure', async () => {
      const r = await verifyGenuineTdxQuote({ quote: 'nope' as unknown as Uint8Array, trustAnchorRootCaSpkiSha256: BASE.rootSpkiSha256 });
      expect(r.reason).toBe('quote parse failed: parseDcapQuote: expected Uint8Array');
    });
  });

  describe('PCK chain branches (real X.509 under the test root)', () => {
    const pki = BASE.pki;
    it('accepts the chain in any order (root-first, shuffled)', async () => {
      for (const order of [[pki.root, pki.platformCa, BASE.pck], [pki.platformCa, BASE.pck, pki.root]]) {
        expect((await std(quoteWith({ chain: { order } }))).ok).toBe(true);
      }
    });
    it('rejects an empty PEM', async () => {
      expect((await std(quoteWith({ chain: { pemOverride: '' } }))).reason).toBe('PCK chain invalid: no PEM certificates in the PCK chain');
    });
    it('rejects a chain whose self-signed root does not match the pin', async () => {
      const r = await std(BASE, { trustAnchorRootCaSpkiSha256: 'ab'.repeat(32) });
      expect(r.reason).toBe('PCK chain invalid: Intel SGX Root CA does not match the pinned trust anchor');
    });
    it('accepts an upper-case pin (compared case-insensitively)', async () => {
      expect((await std(BASE, { trustAnchorRootCaSpkiSha256: BASE.rootSpkiSha256.toUpperCase() })).ok).toBe(true);
    });
    it('rejects a chain that is missing the Platform CA (does not terminate in a self-signed root)', async () => {
      const r = await std(quoteWith({ chain: { order: [BASE.pck, pki.root] } }));
      expect(r.reason).toBe('PCK chain invalid: PCK chain does not terminate in a self-signed root');
    });
    it('rejects a chain with a leaf only', async () => {
      const r = await std(quoteWith({ chain: { order: [BASE.pck] } }));
      expect(r.reason).toBe('PCK chain invalid: PCK chain does not terminate in a self-signed root');
    });
    it('rejects an orphan certificate appended to the chain', async () => {
      const k = forgeKey('stranger', 'P-256');
      const stranger = forgeCert({ subject: [['CN', 'Stranger CA']], issuer: [['CN', 'Stranger CA']], subjectKey: k, signer: k, serial: 5n, notBefore: new Date('2020-01-01Z'), notAfter: new Date('2040-01-01Z') });
      const r = await std(quoteWith({ chain: { appendPem: stranger.pem } }));
      expect(r.reason).toBe('PCK chain invalid: PCK chain is not a single connected path (orphan/duplicate certificates)');
    });
    it('rejects a PCK leaf signed by a key that is not the Platform CA', async () => {
      const r = await std(quoteWith({ pck: { issuerKey: forgeKey('evil-ca', 'P-256') } }));
      expect(r.reason).toBe('PCK chain invalid: certificate at depth 0 is not signed by its issuer');
    });
    it('rejects a Platform CA not signed by the root', async () => {
      const r = await std(quoteWith({ pki: forgeIntelPki('p1', { caSignedBy: forgeKey('evil-root', 'P-256') }) }));
      expect(r.reason).toBe('PCK chain invalid: certificate at depth 1 is not signed by its issuer');
    });
    it('rejects a root whose self-signature does not verify', async () => {
      const r = await std(quoteWith({ pki: forgeIntelPki('p2', { rootSelfSigned: false }) }));
      expect(r.reason).toBe('PCK chain invalid: root certificate is not self-signed');
    });
    it('rejects a PCK leaf with a non-EC (RSA) public key', async () => {
      const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'der' });
      const r = await std(quoteWith({ pck: { spkiOverride: new Uint8Array(rsa) } }));
      expect(r.reason).toBe('PCK chain invalid: PCK leaf key is not EC (got rsa)');
    });
    it('rejects a PCK leaf whose EC point is not on the curve', async () => {
      const bad = seq(seq(oid('1.2.840.10045.2.1'), oid('1.2.840.10045.3.1.7')), tlv(0x03, Uint8Array.of(0), Uint8Array.of(4), new Uint8Array(64).fill(7)));
      const r = await std(quoteWith({ pck: { spkiOverride: bad } }));
      expect(r.ok).toBe(false);
      expect(r.reason).toMatch(/^PCK chain invalid: PCK chain X\.509 verification error \(fail closed\)/);
    });
    it('rejects a PCK leaf on the WRONG curve (P-384) with the specific curve reason', async () => {
      const r = await std(quoteWith({ pck: { spkiOverride: forgeKey('wrong-curve', 'P-384').spki } }));
      expect(r.reason).toBe('PCK chain invalid: PCK chain X.509 verification error (fail closed): public key is not on P-256 (got P-384)');
    });
    it('rejects a PCK leaf whose SPKI carries trailing bytes after the point (no byte-scan salvage)', async () => {
      const good = forgeKey('trail', 'P-256').spki;
      const r = await std(quoteWith({ pck: { spkiOverride: cat(good, Uint8Array.of(0, 0, 0)) } }));
      expect(r.ok).toBe(false);
      expect(r.reason).toMatch(/^PCK chain invalid: PCK chain X\.509 verification error \(fail closed\)/);
    });
    it('a COMPRESSED-point SPKI of the true PCK key is normalised by the parser and verifies (no byte-scan involved)', async () => {
      const algId = seq(oid('1.2.840.10045.2.1'), oid('1.2.840.10045.3.1.7'));
      const uncompressed = forgeKey('forge-tdx/pck/leaf', 'P-256').spki.slice(-65);
      const compressed = cat(Uint8Array.of(uncompressed[64]! & 1 ? 3 : 2), uncompressed.slice(1, 33));
      const spki = seq(algId, tlv(0x03, Uint8Array.of(0), compressed));
      expect((await std(quoteWith({ pck: { spkiOverride: spki } }))).ok).toBe(true);
    });
    it('rejects a PCK leaf with a short (31-byte x) point rather than reading neighbouring bytes', async () => {
      const algId = seq(oid('1.2.840.10045.2.1'), oid('1.2.840.10045.3.1.7'));
      const uncompressed = forgeKey('forge-tdx/pck/leaf', 'P-256').spki.slice(-65);
      const spki = seq(algId, tlv(0x03, Uint8Array.of(0), uncompressed.slice(0, 64)));
      const r = await std(quoteWith({ pck: { spkiOverride: spki } }));
      expect(r.ok).toBe(false);
      expect(r.reason).toMatch(/^PCK chain invalid: PCK chain X\.509 verification error \(fail closed\)/);
    });
    it('rejects garbage PEM content', async () => {
      const r = await std(quoteWith({ chain: { pemOverride: '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n' } }));
      expect(r.reason).toMatch(/^PCK chain invalid: PCK chain X\.509 verification error \(fail closed\)/);
    });
    it('verifyIntelPckChainX509 fails closed on a non-string chain', async () => {
      const r = await verifyIntelPckChainX509({ pckChainPem: 5 as unknown as string });
      expect(r).toEqual({ ok: false, reason: 'no PEM certificates in the PCK chain' });
    });
  });

  describe('PCK chain clock + CA-role rules (offline path)', () => {
    const VALIDITY = 'PCK chain invalid: PCK chain certificate outside its validity period';
    it('an EXPIRED PCK leaf is rejected by verifyGenuineTdxQuote itself (no collateral needed)', async () => {
      const f = quoteWith({ pck: { notBefore: new Date('2019-01-01Z'), notAfter: new Date('2020-01-01Z') } });
      expect((await std(f)).reason).toBe(VALIDITY);
      expect((await coll(f)).reason).toBe(`quote invalid: ${VALIDITY}`);
    });
    it('a NOT-YET-VALID PCK leaf is rejected', async () => {
      const f = quoteWith({ pck: { notBefore: new Date('2040-01-01Z'), notAfter: new Date('2041-01-01Z') } });
      expect((await std(f)).reason).toBe(VALIDITY);
    });
    it('an expired intermediate or root is rejected too (every cert is checked, not just the leaf)', async () => {
      const ca = quoteWith({ pki: forgeIntelPki('clk1', { caValidity: [new Date('2018-01-01Z'), new Date('2026-06-01Z')] }) });
      expect((await std(ca)).reason).toBe(VALIDITY);
      const root = quoteWith({ pki: forgeIntelPki('clk2', { rootValidity: [new Date('2018-01-01Z'), new Date('2026-06-01Z')] }) });
      expect((await std(root)).reason).toBe(VALIDITY);
    });
    it('the clock is the supplied nowMs: the same chain passes inside and fails outside its window', async () => {
      const f = quoteWith({ pck: { notBefore: new Date('2026-09-30T16:45:11Z'), notAfter: new Date('2027-01-01Z') } });
      expect((await std(f, { nowMs: Date.parse('2026-12-31T00:00:00Z') })).ok).toBe(true);
      expect((await std(f, { nowMs: Date.parse('2027-01-02T00:00:00Z') })).reason).toBe(VALIDITY);
      expect((await std(f, { nowMs: Date.parse('2026-09-29T00:00:00Z') })).reason).toBe(VALIDITY);
    });
    it('a non-finite nowMs fails closed', async () => {
      expect((await std(BASE, { nowMs: Number.NaN })).reason).toBe('PCK chain invalid: nowMs is not a finite number');
    });
    it('verifyIntelPckChainX509 without nowMs uses the host clock (a fresh chain passes, a long-expired one fails)', async () => {
      const ok = await verifyIntelPckChainX509({ pckChainPem: parseDcapQuote(BASE.quote).pckChainPem, trustAnchorRootCaSpkiSha256: BASE.rootSpkiSha256 });
      expect(ok.ok).toBe(true);
      const old = quoteWith({ pck: { notBefore: new Date('2019-01-01Z'), notAfter: new Date('2020-01-01Z') } });
      const bad = await verifyIntelPckChainX509({ pckChainPem: parseDcapQuote(old.quote).pckChainPem, trustAnchorRootCaSpkiSha256: old.rootSpkiSha256 });
      expect([bad.ok, bad.failure, bad.reason]).toEqual([false, 'validity', 'PCK chain certificate outside its validity period']);
    });
    it('createIntelDcapVerifier passes input.nowMs: the same evidence verifies at one time and not at another', async () => {
      const f = quoteWith({ pck: { notBefore: new Date('2026-09-30T16:45:11Z'), notAfter: new Date('2027-01-01Z') } });
      const v = createIntelDcapVerifier({
        binding: 'report-data',
        policy: { mrtds: [toHex(parseDcapTdReport(parseDcapQuote(f.quote).tdReportBody).mrTd)] },
        trustAnchorRootCaSpkiSha256: f.rootSpkiSha256,
        allowMissingCollateral: true,
        resolveEvidence: () => ({ quote: f.quote }),
      });
      const base = { document: { type: 'x' } as unknown as AttestationDocument, ctx: {} as never, expected: undefined as never };
      const late = await v.verify({ ...base, expected: EXPECTED, nowMs: Date.parse('2028-01-01Z') });
      expect(late.reason).toBe(`DCAP quote invalid: ${VALIDITY}`);
    });

    it('an intermediate WITHOUT BasicConstraints is rejected', async () => {
      const r = await std(quoteWith({ pki: forgeIntelPki('p3a', { caBasicConstraints: 'absent' }) }));
      expect(r.reason).toBe('PCK chain invalid: issuer certificate at depth 1 has no BasicConstraints (not a CA)');
    });
    it('an intermediate marked CA:FALSE is rejected', async () => {
      const r = await std(quoteWith({ pki: forgeIntelPki('p3b', { caBasicConstraints: 'ca-false' }) }));
      expect(r.reason).toBe('PCK chain invalid: issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)');
    });
    it('a PCK leaf that claims CA:TRUE is rejected; a leaf with no BasicConstraints at all is fine (not a CA)', async () => {
      expect((await std(quoteWith({ pck: { ca: true } }))).reason).toBe('PCK chain invalid: leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)');
      expect((await std(quoteWith({ pck: { ca: 'absent' } }))).ok).toBe(true);
    });

    // hand-built chains for the keyUsage / pathLen rules (root -> ca1 -> ca2 -> leaf)
    const mk = (opts: { ca1?: Extension[]; ca2?: Extension[]; leafCa?: boolean }) => {
      const rk = forgeKey('role/root', 'P-256');
      const k1 = forgeKey('role/ca1', 'P-256');
      const k2 = forgeKey('role/ca2', 'P-256');
      const kl = forgeKey('role/leaf', 'P-256');
      const names = (c: string) => [['CN', c]] as const;
      const nb = new Date('2020-01-01Z');
      const na = new Date('2045-01-01Z');
      const root = forgeCert({ subject: names('R'), issuer: names('R'), subjectKey: rk, signer: rk, serial: 1n, notBefore: nb, notAfter: na, extensions: [ext.basicConstraints(true, 5), ext.keyUsage(['keyCertSign', 'cRLSign'])] });
      const ca1 = forgeCert({ subject: names('C1'), issuer: names('R'), subjectKey: k1, signer: rk, serial: 2n, notBefore: nb, notAfter: na, extensions: opts.ca1 ?? [ext.basicConstraints(true, 1), ext.keyUsage(['keyCertSign'])] });
      const ca2 = forgeCert({ subject: names('C2'), issuer: names('C1'), subjectKey: k2, signer: k1, serial: 3n, notBefore: nb, notAfter: na, extensions: opts.ca2 ?? [ext.basicConstraints(true, 0), ext.keyUsage(['keyCertSign'])] });
      const leaf = forgeCert({ subject: names('L'), issuer: names('C2'), subjectKey: kl, signer: k2, serial: 4n, notBefore: nb, notAfter: na, extensions: [ext.basicConstraints(opts.leafCa === true)] });
      return { pem: leaf.pem + ca2.pem + ca1.pem + root.pem, pin: rk.spkiSha256 };
    };
    const chainOf = (c: { pem: string; pin: string }) => verifyIntelPckChainX509({ pckChainPem: c.pem, trustAnchorRootCaSpkiSha256: c.pin, nowMs: Date.parse('2026-10-08Z') });
    it('a well-formed 4-deep chain (pathLen exactly sufficient) is accepted', async () => {
      expect((await chainOf(mk({}))).ok).toBe(true);
    });
    it('pathLenConstraint is enforced: an intermediate with pathLen 0 above another intermediate is rejected', async () => {
      const r = await chainOf(mk({ ca1: [ext.basicConstraints(true, 0), ext.keyUsage(['keyCertSign'])] }));
      expect(r.reason).toBe('issuer certificate at depth 2 pathLenConstraint 0 is exceeded (1 intermediate(s) below)');
    });
    it('keyUsage without keyCertSign on an issuer is rejected; absent keyUsage is tolerated', async () => {
      const bad = await chainOf(mk({ ca2: [ext.basicConstraints(true, 0), ext.keyUsage(['digitalSignature'])] }));
      expect(bad.reason).toBe('issuer certificate at depth 1 keyUsage lacks keyCertSign');
      const none = await chainOf(mk({ ca2: [ext.basicConstraints(true, 0)] }));
      expect(none.ok).toBe(true);
    });
    it('a CA:TRUE extension that is duplicated or malformed fails closed with a parse reason', async () => {
      const dup = await chainOf(mk({ ca2: [ext.basicConstraints(true, 0), ext.basicConstraints(true, 0)] }));
      expect(dup.reason).toBe('certificate extension parse failed: duplicate BasicConstraints extension');
      const trailing = await chainOf(mk({ ca2: [extension('2.5.29.19', true, seq(boolean(true), integer(0), integer(0)))] }));
      expect(trailing.reason).toBe('certificate extension parse failed: BasicConstraints has trailing data');
      const negative = await chainOf(mk({ ca2: [extension('2.5.29.19', true, seq(boolean(true), tlv(0x02, Uint8Array.of(0x80))))] }));
      expect(negative.reason).toBe('certificate extension parse failed: BasicConstraints pathLenConstraint malformed');
    });
    it('the same rules guard the PCS issuer chains: a TCB-signing leaf claiming CA:TRUE is rejected', async () => {
      const f = BASE;
      const rk = f.pki.rootKey;
      const bad = forgeCert({ subject: f.pki.tcbDn, issuer: f.pki.rootDn, subjectKey: f.pki.tcbSigningKey, signer: rk, serial: 77n, notBefore: new Date('2018-05-21Z'), notAfter: new Date('2034-05-21Z'), extensions: [ext.basicConstraints(true)] });
      const r = await coll(f, { tcbInfoChainPem: bad.pem + f.pki.root.pem });
      expect(r.reason).toBe('TCB info: issuer chain invalid: leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)');
    });
    it('an issuer chain whose middle CA is CA:FALSE is rejected for the QE identity too', async () => {
      const f = BASE;
      const midKey = forgeKey('qe-mid', 'P-256');
      const midDn = [['CN', 'Mid Signing CA']] as const;
      const nb = new Date('2018-05-21Z');
      const na = new Date('2034-05-21Z');
      const mid = forgeCert({ subject: midDn, issuer: f.pki.rootDn, subjectKey: midKey, signer: f.pki.rootKey, serial: 78n, notBefore: nb, notAfter: na, extensions: [ext.basicConstraints(false)] });
      const sign = forgeCert({ subject: f.pki.tcbDn, issuer: midDn, subjectKey: f.pki.tcbSigningKey, signer: midKey, serial: 79n, notBefore: nb, notAfter: na, extensions: [ext.basicConstraints(false)] });
      const r = await coll(f, { qeIdentityChainPem: sign.pem + mid.pem + f.pki.root.pem });
      expect(r.reason).toBe('QE identity: issuer chain invalid: issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)');
    });
    it('a debug QE (ATTRIBUTES.FLAGS bit 1) is rejected', async () => {
      const r = await std(quoteWith({ qe: { attributes: '1700000000000000e700000000000000' } }));
      expect(r.reason).toBe('QE report ATTRIBUTES.DEBUG is set (debug quoting enclave)');
    });
  });

  describe('MRSEAM / MRSIGNERSEAM gating', () => {
    const real = parseDcapTdReport(parseDcapQuote(REAL_QUOTE).tdReportBody);
    const f = quoteWith();
    const fr = parseDcapTdReport(parseDcapQuote(f.quote).tdReportBody);
    it('the real Azure quote: its own MRSEAM / MRSIGNERSEAM pass, others are refused with the specific reason', async () => {
      expect(toHex(real.mrSignerSeam)).toBe('00'.repeat(48));
      const ok = await verifyGenuineTdxQuote({ quote: REAL_QUOTE, policy: { mrSeams: [toHex(real.mrSeam)], mrSignerSeams: [toHex(real.mrSignerSeam)] } });
      expect(ok.ok).toBe(true);
      const badSeam = await verifyGenuineTdxQuote({ quote: REAL_QUOTE, policy: { mrSeams: ['11'.repeat(48)] } });
      expect(badSeam.reason).toBe('MRSEAM not in policy allowlist');
      const badSigner = await verifyGenuineTdxQuote({ quote: REAL_QUOTE, policy: { mrSignerSeams: ['22'.repeat(48)] } });
      expect(badSigner.reason).toBe('MRSIGNERSEAM not in policy allowlist');
    });
    it('matching is case-insensitive and exact: a one-byte difference is refused', async () => {
      expect((await std(f, { policy: { mrSeams: [toHex(fr.mrSeam).toUpperCase()] } })).ok).toBe(true);
      const off = toHex(fr.mrSeam).replace(/.$/, (c) => (c === '0' ? '1' : '0'));
      expect((await std(f, { policy: { mrSeams: [off] } })).reason).toBe('MRSEAM not in policy allowlist');
    });
    it('a forged quote whose MRSEAM / MRSIGNERSEAM differ from policy is refused (the seam fields are quote-signed)', async () => {
      const g = quoteWith({ td: { mrSeam: '33'.repeat(48), mrSignerSeam: '44'.repeat(48) } });
      expect((await std(g, { policy: { mrSeams: [toHex(fr.mrSeam)] } })).reason).toBe('MRSEAM not in policy allowlist');
      expect((await std(g, { policy: { mrSignerSeams: [toHex(fr.mrSignerSeam)] } })).reason).toBe('MRSIGNERSEAM not in policy allowlist');
      expect((await std(g, { policy: { mrSeams: ['33'.repeat(48)], mrSignerSeams: ['44'.repeat(48)] } })).ok).toBe(true);
    });
    it('an EMPTY allowlist rejects everything (fail closed)', async () => {
      expect((await std(f, { policy: { mrSeams: [] } })).reason).toBe('MRSEAM not in policy allowlist');
      expect((await std(f, { policy: { mrSignerSeams: [] } })).reason).toBe('MRSIGNERSEAM not in policy allowlist');
    });
    it('createIntelDcapVerifier validates the lists at construction and enforces them at verify time', async () => {
      const mk = (p: Partial<IntelDcapPolicy>) => () => createIntelDcapVerifier({ binding: 'report-data', policy: { mrtds: ['00'.repeat(48)], ...p } });
      expect(mk({ mrSeams: [] })).toThrow('policy.mrSeams, if given, must be a NON-EMPTY list');
      expect(mk({ mrSignerSeams: ['zz'] })).toThrow('every mrSignerSeams entry must be 96 hex chars (48 bytes)');
      const v = createIntelDcapVerifier({
        binding: 'report-data',
        policy: { mrtds: [toHex(fr.mrTd)], mrSeams: ['55'.repeat(48)] },
        trustAnchorRootCaSpkiSha256: f.rootSpkiSha256,
        allowMissingCollateral: true,
        resolveEvidence: () => ({ quote: f.quote }),
      });
      const r = await v.verify({ document: { type: 'x' } as unknown as AttestationDocument, ctx: {} as never, expected: EXPECTED, nowMs: Date.parse('2026-10-20Z') });
      expect(r.reason).toBe('DCAP quote invalid: MRSEAM not in policy allowlist');
    });
  });

  describe('SGX extension branches (FMSPC / TCB)', () => {
    it('fails when the PCK has no SGX extension', async () => {
      expect((await std(quoteWith({ pck: { noSgxExtension: true } }))).reason).toBe('PCK FMSPC/TCB extraction failed: extractPckFmspcAndTcb: FMSPC OID not found in certificate');
    });
    it('fails when the FMSPC sub-extension is absent', async () => {
      expect((await std(quoteWith({ pck: { ext: { omit: ['fmspc'] } } }))).reason).toBe('PCK FMSPC/TCB extraction failed: extractPckFmspcAndTcb: FMSPC OID not found in certificate');
    });
    it('fails when the TCB sub-extension is absent', async () => {
      expect((await std(quoteWith({ pck: { ext: { omit: ['tcb'] } } }))).reason).toBe('PCK FMSPC/TCB extraction failed: extractPckFmspcAndTcb: TCB OID not found in certificate');
    });
    it('fails when PCESVN is absent from the TCB sequence', async () => {
      expect((await std(quoteWith({ pck: { ext: { omit: ['pcesvn'] } } }))).reason).toBe('PCK FMSPC/TCB extraction failed: extractPckFmspcAndTcb: PCESVN not found in TCB extension');
    });
    it('fails on a 5-byte FMSPC', async () => {
      expect((await std(quoteWith({ pck: { ext: { fmspcLen: 5 } } }))).reason).toBe('PCK FMSPC/TCB extraction failed: extractPckFmspcAndTcb: malformed FMSPC OCTET STRING');
    });

    // direct structural unit cases for the DER walker (bytes spliced after the real OIDs)
    const OID_FMSPC = Uint8Array.from([0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x04]);
    const OID_TCB = Uint8Array.from([0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02]);
    const fmspcPart = cat(OID_FMSPC, octets(new Uint8Array(6)));
    const comp = (n: number, v: Uint8Array) => seq(oid(`1.2.840.113741.1.13.1.2.${n}`), v);
    const tlvOf = (tcbContent: Uint8Array) => cat(fmspcPart, OID_TCB, tcbContent);
    it('rejects a TCB value that is not a SEQUENCE', () => {
      expect(() => extractPckFmspcAndTcb(tlvOf(octets(new Uint8Array(3))))).toThrow('malformed TCB SEQUENCE');
    });
    it('rejects a TCB component that is not a SEQUENCE', () => {
      expect(() => extractPckFmspcAndTcb(tlvOf(seq(octets(Uint8Array.of(1)))))).toThrow('malformed TCB component');
    });
    it('rejects a TCB component without an OID', () => {
      expect(() => extractPckFmspcAndTcb(tlvOf(seq(seq(octets(Uint8Array.of(1))))))).toThrow('TCB component missing OID');
    });
    it('rejects a TCB component without a value', () => {
      expect(() => extractPckFmspcAndTcb(tlvOf(seq(seq(oid('1.2.840.113741.1.13.1.2.1')))))).toThrow('TCB component missing value');
    });
    it('rejects a truncated FMSPC length', () => {
      expect(() => extractPckFmspcAndTcb(OID_FMSPC)).toThrow('malformed FMSPC OCTET STRING');
    });
    it('reads a 2-byte PCESVN and the CPUSVN, ignores unknown component types and clamps SVN bytes', () => {
      const leaf = tlvOf(seq(comp(1, tlv(0x02, Uint8Array.of(0x00, 0x90))), comp(17, tlv(0x02, Uint8Array.of(0x01, 0x02))), comp(18, octets(new Uint8Array(16).fill(9))), comp(19, tlv(0x0a, Uint8Array.of(1)))));
      const t = extractPckFmspcAndTcb(leaf);
      expect(t.sgxTcbComponents[0]).toBe(0x90);
      expect(t.pcesvn).toBe(0x0102);
      expect(Array.from(t.cpusvn)).toEqual(new Array(16).fill(9));
    });
    it('sgxExtensionValue enforces 16 components', () => {
      expect(() => sgxExtensionValue({ fmspc: '90c06f000000', sgxTcb: [1], pcesvn: 1, cpusvn: new Uint8Array(16) })).toThrow('sgxTcb needs 16 components');
    });
  });

  describe('QE report + attestation key endorsement', () => {
    it('rejects a QE report signed by a key other than the PCK leaf', async () => {
      const r = await std(quoteWith({ qe: { signer: forgeKey('not-the-pck', 'P-256') } }));
      expect(r.reason).toBe('QE report signature does not verify under the PCK leaf');
    });
    it('rejects every single-byte tamper of the QE report (signed region)', async () => {
      for (const off of [0, 17, 50, 70, 130, 256, 258, 320, 383]) {
        const r = await std(BASE, { quote: flipAt(BASE.quote, DCAP_OFFSETS.QE_REPORT + off) });
        expect(r.reason, `QE report byte ${off}`).toBe('QE report signature does not verify under the PCK leaf');
      }
    });
    it('rejects a tampered QE report signature', async () => {
      expect((await std(BASE, { quote: flipAt(BASE.quote, DCAP_OFFSETS.QE_SIG + 5) })).reason).toBe('QE report signature does not verify under the PCK leaf');
    });
    it('rejects a QE whose report_data does not hash (AK ‖ auth)', async () => {
      const r = await std(quoteWith({ qe: { reportData: cat(sha256(new Uint8Array(64)), new Uint8Array(32)) } }));
      expect(r.reason).toBe('QE report_data does not bind the attestation key (AK not endorsed by this QE)');
    });
    it('rejects a QE report_data whose tail [32:64] is non-zero even when the head is right', async () => {
      const head = sha256(BASE.ak.pub.subarray(1), BASE.qeAuth);
      const tail = new Uint8Array(32);
      tail[31] = 1;
      const r = await std(quoteWith({ qe: { reportData: cat(head, tail) } }));
      expect(r.reason).toBe('QE report_data does not bind the attestation key (AK not endorsed by this QE)');
    });
    it('rejects tampered QE auth data (QE report itself is untouched, so the AK binding catches it)', async () => {
      const r = await std(BASE, { quote: flipAt(BASE.quote, DCAP_OFFSETS.QE_AUTH + 3) });
      expect(r.reason).toBe('QE report_data does not bind the attestation key (AK not endorsed by this QE)');
    });
    it('rejects a swapped attestation key (a valid key the QE never endorsed)', async () => {
      const other = forgeKey('other-ak', 'P-256');
      const r = await std(BASE, { quote: patch(BASE.quote, DCAP_OFFSETS.AK, other.pub.subarray(1)) });
      expect(r.reason).toBe('QE report_data does not bind the attestation key (AK not endorsed by this QE)');
    });
    it('rejects an endorsed AK that is not a valid P-256 point', async () => {
      const bad = { ...forgeKey('bad-ak', 'P-256'), pub: Uint8Array.of(4, ...new Uint8Array(64).fill(3)) };
      const r = await std(quoteWith({ ak: bad }));
      expect(r.reason).toBe('attestation public key is not a valid P-256 point');
    });
  });

  describe('TD quote signature: every signed region is covered', () => {
    it('rejects a quote signed by a key other than the endorsed AK', async () => {
      const r = await std(quoteWith({ tdSigner: forgeKey('rogue-signer', 'P-256') }));
      expect(r.reason).toBe('TD quote signature does not verify under the attestation key');
    });
    const regions: [string, number][] = [
      ['header version-adjacent reserved bytes', 9],
      ['header QE vendor id', 12],
      ['header user data', 40],
      ['TEE_TCB_SVN', TD10_FIELDS.TEE_TCB_SVN],
      ['MRSEAM', TD10_FIELDS.MR_SEAM],
      ['MRSIGNERSEAM', TD10_FIELDS.MR_SIGNER_SEAM],
      ['SEAM attributes', TD10_FIELDS.SEAM_ATTRIBUTES],
      ['TD attributes (the DEBUG bit)', TD10_FIELDS.TD_ATTRIBUTES],
      ['XFAM', TD10_FIELDS.XFAM],
      ['MRTD', TD10_FIELDS.MRTD],
      ['MRCONFIGID', TD10_FIELDS.MR_CONFIG_ID],
      ['MROWNER', TD10_FIELDS.MR_OWNER],
      ['MROWNERCONFIG', TD10_FIELDS.MR_OWNER_CONFIG],
      ['RTMR0', TD10_FIELDS.RTMR0],
      ['RTMR1', TD10_FIELDS.RTMR1],
      ['RTMR2', TD10_FIELDS.RTMR2],
      ['RTMR3', TD10_FIELDS.RTMR3],
      ['REPORT_DATA', TD10_FIELDS.REPORT_DATA],
    ];
    for (const [name, off] of regions) {
      it(`rejects a post-signing flip in ${name}`, async () => {
        const at = (off < 48 && name.startsWith('header') ? 0 : DCAP_OFFSETS.BODY) + off;
        const r = await std(BASE, { quote: flipAt(BASE.quote, name.startsWith('header') ? off : at) });
        expect(r.reason).toBe('TD quote signature does not verify under the attestation key');
      });
    }
    it('rejects a tampered quote signature', async () => {
      expect((await std(BASE, { quote: flipAt(BASE.quote, DCAP_OFFSETS.QUOTE_SIG + 40) })).reason).toBe('TD quote signature does not verify under the attestation key');
    });
    it('rejects tampered PEM chain bytes (parse or signature failure, always under "PCK chain invalid")', async () => {
      for (const delta of [200, 900, 1900, 3000]) {
        const r = await std(BASE, { quote: flipAt(BASE.quote, BASE.offsets.pem + delta) });
        expect(r.ok).toBe(false);
        expect(r.reason, `PEM byte ${delta}`).toMatch(/^PCK chain invalid: /);
      }
    });
  });

  describe('PCA binding via expected{} (report_data == attestationBinding)', () => {
    const bound = quoteWith({ td: { reportData: BINDING } });
    it('accepts the exact binding', async () => {
      expect((await std(bound, { expected: EXPECTED })).ok).toBe(true);
    });
    const variants: [string, ExpectedAttestationBinding][] = [
      ['holderPub', { ...EXPECTED, holderPub: 'someone-else' }],
      ['grantRef', { ...EXPECTED, grantRef: 'grant_other' }],
      ['epoch', { ...EXPECTED, epoch: 8 }],
      ['nonce', { ...EXPECTED, nonce: 'srv-nonce-replayed' }],
    ];
    for (const [field, e] of variants) {
      it(`rejects a relayed quote bound to a different ${field}`, async () => {
        expect((await std(bound, { expected: e })).reason).toBe('report_data does not bind holder/grant/epoch/nonce');
      });
    }
    it('rejects an unbound quote (report_data all zero)', async () => {
      expect((await std(BASE, { expected: EXPECTED })).reason).toBe('report_data does not bind holder/grant/epoch/nonce');
    });
    it('fails with a clear reason when the expected binding cannot be constructed', async () => {
      expect((await std(bound, { expected: { ...EXPECTED, epoch: -1 } })).reason).toBe('binding not constructible: binding: epoch must be a non-negative safe integer');
      expect((await std(bound, { expected: { ...EXPECTED, holderPub: '' } })).reason).toBe('binding not constructible: binding: holderPub required');
    });
  });

  describe('DEBUG TD handling', () => {
    const dbg = quoteWith({ td: { debug: true } });
    it('the debug option sets exactly TD_ATTRIBUTES bit 0 and keeps the SEPT_VE_DISABLE bit', () => {
      const attr = dbg.tdBody.subarray(TD10_FIELDS.TD_ATTRIBUTES, TD10_FIELDS.TD_ATTRIBUTES + 8);
      expect(attr[0]! & TD_ATTR_DEBUG).toBe(1);
      expect(hexOf(attr)).toBe('0100001000000000');
    });
    it('rejects a DEBUG TD by default', async () => {
      expect((await std(dbg)).reason).toBe('TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)');
    });
    it('rejects a DEBUG TD when allowDebug is explicitly false or set to a truthy non-true value', async () => {
      expect((await std(dbg, { policy: { allowDebug: false } })).reason).toBe('TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)');
      expect((await std(dbg, { policy: { allowDebug: 'yes' as unknown as boolean } })).reason).toBe('TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)');
    });
    it('accepts it only with the explicit INSECURE opt-in allowDebug: true', async () => {
      expect((await std(dbg, { policy: { allowDebug: true } })).ok).toBe(true);
    });
    it('only bit 0 matters: other attribute bits (PKS, KL, PERFMON, SEPT_VE_DISABLE) do not trigger it', async () => {
      const f = quoteWith({ td: { tdAttributes: hexToBytes('fe0000f0ff000080') } });
      expect((await std(f)).ok).toBe(true);
    });
  });

  describe('policy allowlists', () => {
    const mrtd = hexOf(BASE.tdBody.subarray(TD10_FIELDS.MRTD, TD10_FIELDS.MRTD + 48));
    const rtmr0 = hexOf(BASE.tdBody.subarray(TD10_FIELDS.RTMR0, TD10_FIELDS.RTMR0 + 48));
    it('MRTD: match (case-insensitive) passes, mismatch is named', async () => {
      expect((await std(BASE, { policy: { mrtds: [mrtd.toUpperCase()] } })).ok).toBe(true);
      expect((await std(BASE, { policy: { mrtds: ['00'.repeat(48)] } })).reason).toBe('MRTD not in policy allowlist');
      expect((await std(BASE, { policy: { mrtds: ['00'.repeat(48), mrtd] } })).ok).toBe(true);
    });
    it('FMSPC: mismatch is named; match passes', async () => {
      expect((await std(BASE, { policy: { fmspcs: ['00a06f000000'] } })).reason).toBe('FMSPC not in policy allowlist');
      expect((await std(BASE, { policy: { fmspcs: ['90C06F000000'] } })).ok).toBe(true);
    });
    it('RTMR0: mismatch is named; match passes', async () => {
      expect((await std(BASE, { policy: { rtmrs: ['11'.repeat(48)] } })).reason).toBe('RTMR0 not in policy allowlist');
      expect((await std(BASE, { policy: { rtmrs: [rtmr0] } })).ok).toBe(true);
    });
    it('a mismatching MRTD built through the forger is rejected by an otherwise valid policy', async () => {
      const f = quoteWith({ td: { mrTd: 'ab'.repeat(48) } });
      expect((await std(f, { policy: { mrtds: [mrtd] } })).reason).toBe('MRTD not in policy allowlist');
    });
    it('empty arrays and an absent policy do not gate', async () => {
      expect((await std(BASE, { policy: { mrtds: [], fmspcs: [], rtmrs: [] } })).ok).toBe(true);
      expect((await std(BASE, { policy: {} })).ok).toBe(true);
    });
  });
});

// ═════════════════════════════════════════════════════════════════════════════════════════════════
describe('createIntelDcapVerifier on forged evidence', () => {
  const DOC = {} as unknown as AttestationDocument;
  const CTX = {} as never;
  const NOW_MS = NOW.getTime();
  const mrtdOf = (f: ForgedTdxQuote) => hexOf(f.tdBody.subarray(TD10_FIELDS.MRTD, TD10_FIELDS.MRTD + 48));
  const runtimeFor = (userData: Uint8Array, extra: Record<string, unknown> = {}) => new TextEncoder().encode(JSON.stringify({ keys: [], 'user-data': bytesToHex(userData), ...extra }));
  const azureQuote = (runtime: Uint8Array, o: ForgeTdxOptions = {}) => quoteWith({ ...o, td: { ...(o.td ?? {}), reportData: cat(sha256(runtime), new Uint8Array(32)) } });

  function mk(f: ForgedTdxQuote, over: { binding?: 'report-data' | 'azure-runtime-data'; policy?: Partial<IntelDcapPolicy>; ev?: Partial<IntelDcapEvidence>; allowMissing?: boolean; collateral?: ForgeCollateralOptions; noCollateral?: boolean; pin?: string } = {}) {
    const ev: IntelDcapEvidence = { quote: f.quote, ...(over.noCollateral ? {} : { collateral: forgeTdxCollateral(f, over.collateral) }), ...over.ev };
    return createIntelDcapVerifier({
      binding: over.binding ?? 'report-data',
      policy: { mrtds: [mrtdOf(f)], ...over.policy },
      trustAnchorRootCaSpkiSha256: over.pin ?? f.rootSpkiSha256,
      ...(over.allowMissing ? { allowMissingCollateral: true } : {}),
      resolveEvidence: () => ev,
    });
  }
  const run = (v: ReturnType<typeof mk>, expected: ExpectedAttestationBinding | null = EXPECTED, nowMs = NOW_MS) => v.verify({ document: DOC, ctx: CTX, nowMs, ...(expected ? { expected } : {}) } as never);
  const bound = quoteWith({ td: { reportData: BINDING } });

  describe('construction', () => {
    it('rejects an unknown binding mode', () => {
      expect(() => createIntelDcapVerifier({ binding: 'nope' as never, policy: { mrtds: ['00'.repeat(48)] } })).toThrow("createIntelDcapVerifier: binding must be 'report-data' or 'azure-runtime-data'");
    });
    it('refuses accept-all (empty or missing MRTD list)', () => {
      expect(() => createIntelDcapVerifier({ binding: 'report-data', policy: { mrtds: [] } })).toThrow('policy.mrtds must be a NON-EMPTY allowlist');
      expect(() => createIntelDcapVerifier({ binding: 'report-data', policy: {} as never })).toThrow('policy.mrtds must be a NON-EMPTY allowlist');
    });
    it('rejects a malformed MRTD', () => {
      expect(() => createIntelDcapVerifier({ binding: 'report-data', policy: { mrtds: ['abcd'] } })).toThrow('every MRTD must be 96 hex chars (48 bytes)');
      expect(() => createIntelDcapVerifier({ binding: 'report-data', policy: { mrtds: ['zz'.repeat(48)] } })).toThrow('every MRTD must be 96 hex chars (48 bytes)');
    });
  });

  describe('evidence plumbing', () => {
    it('fails closed with no resolver', async () => {
      const v = createIntelDcapVerifier({ binding: 'report-data', policy: { mrtds: [mrtdOf(bound)] } });
      expect((await run(v)).reason).toBe('no Intel DCAP evidence resolver configured (fail closed)');
    });
    it('fails closed with no / non-bytes quote', async () => {
      expect((await run(createIntelDcapVerifier({ binding: 'report-data', policy: { mrtds: [mrtdOf(bound)] }, resolveEvidence: () => undefined }))).reason).toBe('no Intel DCAP quote for this action');
      expect((await run(mk(bound, { ev: { quote: 'x' as never } }))).reason).toBe('no Intel DCAP quote for this action');
    });
    it('fails closed with no expected binding', async () => {
      expect((await run(mk(bound), null)).reason).toBe('no expected attestation binding supplied');
    });
    it('turns a throwing resolver into a fail-closed result', async () => {
      const v = createIntelDcapVerifier({
        binding: 'report-data',
        policy: { mrtds: [mrtdOf(bound)] },
        resolveEvidence: () => {
          throw new Error('boom');
        },
      });
      expect((await run(v)).reason).toBe('intel-dcap verification error (fail closed): boom');
    });
    it('rejects the forged root under the default Intel pin', async () => {
      const v = createIntelDcapVerifier({ binding: 'report-data', policy: { mrtds: [mrtdOf(bound)] }, resolveEvidence: () => ({ quote: bound.quote, collateral: forgeTdxCollateral(bound) }) });
      expect((await run(v)).reason).toBe('DCAP quote invalid: PCK chain invalid: Intel SGX Root CA does not match the pinned trust anchor');
    });
  });

  describe("binding 'report-data'", () => {
    it('accepts a bound quote with UpToDate collateral and reports tcb_status + fmspc', async () => {
      const r = await run(mk(bound));
      expect(r.reason).toBeUndefined();
      expect(r).toMatchObject({ ok: true, bound: true, hostAsserted: { attestation_type: 'tdx-dcap', fmspc: '90c06f000000', tcb_status: 'UpToDate' } });
      expect(r.measured?.runtime_measurement).toBe(mrtdOf(bound));
    });
    for (const [field, e] of [
      ['holderPub', { ...EXPECTED, holderPub: 'x' }],
      ['grantRef', { ...EXPECTED, grantRef: 'x' }],
      ['epoch', { ...EXPECTED, epoch: 99 }],
      ['nonce', { ...EXPECTED, nonce: 'x' }],
    ] as const) {
      it(`rejects a relayed quote (${field} differs)`, async () => {
        expect((await run(mk(bound), e)).reason).toBe('report_data does not bind holder/grant/epoch/nonce');
      });
    }
    it('rejects an unconstructible expected binding', async () => {
      expect((await run(mk(bound), { ...EXPECTED, nonce: '' })).reason).toBe('binding not constructible: binding: nonce required');
    });
    it('surfaces the underlying quote failure with the "DCAP quote invalid" prefix (tampered signature)', async () => {
      const v = mk(bound, { ev: { quote: flipAt(bound.quote, DCAP_OFFSETS.QUOTE_SIG) } });
      expect((await run(v)).reason).toBe('DCAP quote invalid: TD quote signature does not verify under the attestation key');
    });
    it('policy: MRTD, FMSPC, RTMR0 and debug flow through to the quote check', async () => {
      expect((await run(mk(bound, { policy: { mrtds: ['00'.repeat(48)] } }))).reason).toBe('DCAP quote invalid: MRTD not in policy allowlist');
      expect((await run(mk(bound, { policy: { fmspcs: ['010203040506'] } }))).reason).toBe('DCAP quote invalid: FMSPC not in policy allowlist');
      expect((await run(mk(bound, { policy: { rtmrs: ['22'.repeat(48)] } }))).reason).toBe('DCAP quote invalid: RTMR0 not in policy allowlist');
      const dbg = quoteWith({ td: { reportData: BINDING, debug: true } });
      expect((await run(mk(dbg))).reason).toBe('DCAP quote invalid: TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)');
      { const r = await run(mk(dbg, { policy: { allowDebug: true } })); expect(r.reason).toBeUndefined(); expect(r.ok).toBe(true); }
    });
    it('case-insensitive MRTD allowlist', async () => {
      expect((await run(mk(bound, { policy: { mrtds: [mrtdOf(bound).toUpperCase()] } }))).ok).toBe(true);
    });
  });

  describe("binding 'azure-runtime-data'", () => {
    const rt = runtimeFor(BINDING);
    const az = azureQuote(rt);
    const azV = (f: ForgedTdxQuote, runtimeData: Uint8Array | undefined, over = {}) => mk(f, { binding: 'azure-runtime-data', ev: { ...(runtimeData ? { runtimeData } : {}) }, ...over });

    it('accepts: hash(runtime) in report_data[0:32], user-data == binding', async () => {
      const r = await run(azV(az, rt));
      expect(r.reason).toBeUndefined();
      expect(r.ok).toBe(true);
    });
    it('needs the runtime-data bytes', async () => {
      expect((await run(azV(az, undefined))).reason).toBe('azure-runtime-data binding needs the runtime-data JSON bytes');
    });
    it('rejects runtime data whose hash is not the quote report_data', async () => {
      expect((await run(azV(az, runtimeFor(BINDING, { extra: 1 })))).reason).toBe('sha256(runtime data) does not equal the quote report_data');
    });
    it('rejects a report_data tail that is not zero', async () => {
      const f = quoteWith({ td: { reportData: cat(sha256(rt), new Uint8Array(32).fill(1)) } });
      expect((await run(azV(f, rt))).reason).toBe('report_data[32:64] is not zero (not an Azure runtime-data hash)');
    });
    it('rejects runtime data that is not JSON / not an object', async () => {
      for (const [txt, want] of [
        ['not json {', 'runtime data is not valid JSON'],
        ['[1,2]', 'runtime data is not a JSON object'],
        ['"str"', 'runtime data is not a JSON object'],
        ['null', 'runtime data is not a JSON object'],
      ] as const) {
        const bytes = new TextEncoder().encode(txt);
        expect((await run(azV(azureQuote(bytes), bytes))).reason, txt).toBe(want);
      }
    });
    it('rejects user-data that is missing, the wrong length, non-hex or not a string', async () => {
      const mkRt = (o: Record<string, unknown>) => new TextEncoder().encode(JSON.stringify(o));
      for (const o of [{}, { 'user-data': 'ab' }, { 'user-data': 'zz'.repeat(64) }, { 'user-data': 12 }, { 'user-data': 'a'.repeat(129) }]) {
        const bytes = mkRt(o);
        expect((await run(azV(azureQuote(bytes), bytes))).reason, JSON.stringify(o)).toBe('runtime data carries no 64-byte hex user-data');
      }
    });
    for (const [field, e] of [
      ['holderPub', { ...EXPECTED, holderPub: 'x' }],
      ['grantRef', { ...EXPECTED, grantRef: 'x' }],
      ['epoch', { ...EXPECTED, epoch: 99 }],
      ['nonce', { ...EXPECTED, nonce: 'x' }],
    ] as const) {
      it(`rejects relayed runtime data (${field} differs)`, async () => {
        expect((await run(azV(az, rt), e)).reason).toBe('runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound quote)');
      });
    }
    it('rejects an unconstructible expected binding', async () => {
      expect((await run(azV(az, rt), { ...EXPECTED, grantRef: '' })).reason).toBe('binding not constructible: binding: grantRef required');
    });
    it('checkAzureRuntimeDataBinding rejects a report_data that is not 64 bytes', () => {
      expect(checkAzureRuntimeDataBinding(new Uint8Array(32), rt, EXPECTED)).toBe('report_data is not 64 bytes');
    });
    it('accepts upper-case hex user-data', async () => {
      const upper = new TextEncoder().encode(JSON.stringify({ 'user-data': bytesToHex(BINDING).toUpperCase() }));
      expect((await run(azV(azureQuote(upper), upper))).ok).toBe(true);
    });
  });

  describe('collateral requirement and TCB status policy', () => {
    it('requires collateral by default', async () => {
      expect((await run(mk(bound, { noCollateral: true }))).reason).toBe('Intel PCS collateral required but not supplied (set allowMissingCollateral to opt out explicitly)');
    });
    it('allowMissingCollateral labels the result "unevaluated"', async () => {
      const r = await run(mk(bound, { noCollateral: true, allowMissing: true }));
      expect(r.ok).toBe(true);
      expect(r.hostAsserted?.tcb_status).toBe('unevaluated');
    });
    it('rejects OutOfDate by default and names the status; advisories are not hidden on failure paths', async () => {
      const v = mk(bound, { collateral: { tcbInfo: { levels: [{ sgx: bound.pckSpec.sgxTcb, pcesvn: 13, tdx: [...bound.tdBody.subarray(0, 16)], status: 'OutOfDate', advisories: ['INTEL-SA-00001'] }] } } });
      expect((await run(v)).reason).toBe('Intel collateral: TCB status OutOfDate is not accepted by policy');
    });
    it('accepts OutOfDate when the policy lists it and surfaces status + sorted advisory ids', async () => {
      const v = mk(bound, {
        policy: { collateral: { acceptStatuses: ['UpToDate', 'OutOfDate'] } },
        collateral: { tcbInfo: { levels: [{ sgx: bound.pckSpec.sgxTcb, pcesvn: 13, tdx: [...bound.tdBody.subarray(0, 16)], status: 'OutOfDate', advisories: ['INTEL-SA-00002', 'INTEL-SA-00001'] }] } },
      });
      const r = await run(v);
      expect(r.ok).toBe(true);
      expect(r.hostAsserted).toMatchObject({ tcb_status: 'OutOfDate', advisory_ids: 'INTEL-SA-00001,INTEL-SA-00002' });
    });
    it('SWHardeningNeeded is accepted by default (and reported)', async () => {
      const v = mk(bound, { collateral: { tcbInfo: { levels: [{ sgx: bound.pckSpec.sgxTcb, pcesvn: 13, tdx: [...bound.tdBody.subarray(0, 16)], status: 'SWHardeningNeeded' }] } } });
      expect((await run(v)).hostAsserted?.tcb_status).toBe('SWHardeningNeeded');
    });
    it('minTcbEvaluationDataNumber flows through the verifier', async () => {
      expect((await run(mk(bound, { policy: { collateral: { minTcbEvaluationDataNumber: 21 } } }))).reason).toBe('Intel collateral: tcbEvaluationDataNumber below policy minimum');
      expect((await run(mk(bound, { policy: { collateral: { minTcbEvaluationDataNumber: 20 } } }))).ok).toBe(true);
    });
    it('uses the verifier clock (nowMs): collateral is rejected as stale after nextUpdate', async () => {
      const r = await run(mk(bound), EXPECTED, Date.parse('2026-12-01T00:00:00Z'));
      expect(r.reason).toBe('Intel collateral: Intel Root CA CRL: CRL is stale (nextUpdate passed)');
    });
    it('a revoked PCK leaf fails the verifier with the collateral reason', async () => {
      expect((await run(mk(bound, { collateral: { pckCrlRevoked: [bound.pck.serialHex] } }))).reason).toBe('Intel collateral: PCK leaf certificate is revoked by the PCK CRL');
    });
  });
});

// ═════════════════════════════════════════════════════════════════════════════════════════════════
describe('verifyIntelTdxCollateral on forged collateral', () => {
  const fix = (o: ForgeTdxOptions = {}) => quoteWith(o);
  const levelFor = (f: ForgedTdxQuote, status: TcbStatus, advisories?: string[]) => ({ sgx: f.pckSpec.sgxTcb, pcesvn: f.pckSpec.pcesvn, tdx: [...f.tdBody.subarray(0, 16)], status, ...(advisories ? { advisories } : {}) });

  describe('baseline', () => {
    it('evaluates the forged platform: everything UpToDate', async () => {
      const r = await coll(BASE);
      expect(r).toEqual({ ok: true, status: 'UpToDate', platformStatus: 'UpToDate', tdxModuleStatus: 'UpToDate', qeStatus: 'UpToDate', advisoryIds: [], tcbEvaluationDataNumber: 20, fmspc: '90c06f000000' });
    });
    it('the default accepted set is UpToDate + SWHardeningNeeded', () => {
      expect([...DEFAULT_ACCEPTED_STATUSES]).toEqual(['UpToDate', 'SWHardeningNeeded']);
    });
    it('rejects incomplete collateral (each field)', async () => {
      const c = forgeTdxCollateral(BASE);
      for (const k of ['tcbInfoJson', 'tcbInfoIssuerChainPem', 'qeIdentityJson', 'qeIdentityIssuerChainPem'] as const) {
        const r = await verifyIntelTdxCollateral({ quote: BASE.quote, collateral: { ...c, [k]: '' }, now: NOW, trustAnchorRootCaSpkiSha256: BASE.rootSpkiSha256 });
        expect(r.reason, k).toBe('collateral incomplete (fail closed)');
      }
      for (const k of ['pckCrlDer', 'rootCrlDer'] as const) {
        const r = await verifyIntelTdxCollateral({ quote: BASE.quote, collateral: { ...c, [k]: new Uint8Array(0) }, now: NOW, trustAnchorRootCaSpkiSha256: BASE.rootSpkiSha256 });
        expect(r.reason, k).toBe('collateral incomplete (fail closed)');
      }
      expect((await verifyIntelTdxCollateral({ quote: BASE.quote, collateral: undefined as never, now: NOW })).reason).toBe('collateral incomplete (fail closed)');
    });
    it('rejects an invalid quote before looking at the collateral', async () => {
      const r = await coll(BASE, {}, undefined, NOW, flipAt(BASE.quote, DCAP_OFFSETS.QUOTE_SIG));
      expect(r.reason).toBe('quote invalid: TD quote signature does not verify under the attestation key');
    });
    it('a DEBUG TD is rejected by the collateral path too, and only the explicit allowDebug opt-in lets it through', async () => {
      const dbg = fix({ td: { debug: true } });
      expect((await coll(dbg)).reason).toBe('quote invalid: TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)');
      const r = await verifyIntelTdxCollateral({ quote: dbg.quote, collateral: forgeTdxCollateral(dbg), now: NOW, trustAnchorRootCaSpkiSha256: dbg.rootSpkiSha256, allowDebug: true });
      expect(r.reason).toBeUndefined();
      expect(r.ok).toBe(true);
    });
    it('accepts Uint8Array JSON and string JSON alike', async () => {
      const c = forgeTdxCollateral(BASE);
      const r = await verifyIntelTdxCollateral({ quote: BASE.quote, collateral: { ...c, tcbInfoJson: new TextEncoder().encode(c.tcbInfoJson as string), qeIdentityJson: new TextEncoder().encode(c.qeIdentityJson as string) }, now: NOW, trustAnchorRootCaSpkiSha256: BASE.rootSpkiSha256 });
      expect(r.ok).toBe(true);
    });
  });

  describe('PCK chain validity at "now"', () => {
    it('expired PCK leaf', async () => {
      expect((await coll(fix({ pck: { notAfter: new Date('2026-10-01Z') } }))).reason).toBe('quote invalid: PCK chain invalid: PCK chain certificate outside its validity period');
    });
    it('not-yet-valid PCK leaf', async () => {
      expect((await coll(fix({ pck: { notBefore: new Date('2026-11-01Z'), notAfter: new Date('2030-01-01Z') } }))).reason).toBe('quote invalid: PCK chain invalid: PCK chain certificate outside its validity period');
    });
    it('expired Platform CA', async () => {
      expect((await coll(fix({ pki: forgeIntelPki('v1', { caValidity: [new Date('2018-01-01Z'), new Date('2026-06-01Z')] }) }))).reason).toBe('quote invalid: PCK chain invalid: PCK chain certificate outside its validity period');
    });
    it('expired root', async () => {
      expect((await coll(fix({ pki: forgeIntelPki('v2', { rootValidity: [new Date('2018-01-01Z'), new Date('2026-06-01Z')] }) }))).reason).toBe('quote invalid: PCK chain invalid: PCK chain certificate outside its validity period');
    });
  });

  describe('CRLs', () => {
    const f = BASE;
    const other = forgeKey('crl-impostor', 'P-256');
    it('Root CRL: signed by a stranger', async () => {
      expect((await coll(f, { rootCrlSigner: other })).reason).toBe('Intel Root CA CRL: CRL signature does not verify under the issuer');
    });
    it('PCK CRL: signed by a stranger (not the PCK CA)', async () => {
      expect((await coll(f, { pckCrlSigner: other })).reason).toBe('PCK CRL: CRL signature does not verify under the issuer');
    });
    it('stale CRLs (nextUpdate passed)', async () => {
      const stale = { crlThisUpdate: new Date('2026-08-01Z'), crlNextUpdate: new Date('2026-09-01Z') };
      expect((await coll(f, stale)).reason).toBe('Intel Root CA CRL: CRL is stale (nextUpdate passed)');
    });
    it('CRLs issued in the future', async () => {
      const fut = { crlThisUpdate: new Date('2026-11-01Z'), crlNextUpdate: new Date('2026-12-01Z') };
      expect((await coll(f, fut)).reason).toBe('Intel Root CA CRL: CRL thisUpdate is in the future');
    });
    it('PCK CRL stale while the root CRL is fresh', async () => {
      const c = forgeTdxCollateral(f);
      const stale = forgeCrl({ issuer: f.pki.caDn, signer: f.pki.caKey, thisUpdate: new Date('2026-08-01Z'), nextUpdate: new Date('2026-09-01Z') });
      const r = await verifyIntelTdxCollateral({ quote: f.quote, collateral: { ...c, pckCrlDer: stale }, now: NOW, trustAnchorRootCaSpkiSha256: f.rootSpkiSha256 });
      expect(r.reason).toBe('PCK CRL: CRL is stale (nextUpdate passed)');
    });
    it('a CRL without nextUpdate is malformed', async () => {
      const c = forgeTdxCollateral(f);
      const bad = forgeCrl({ issuer: f.pki.rootDn, signer: f.pki.rootKey, thisUpdate: new Date('2026-10-08Z'), nextUpdate: new Date('2026-11-08Z'), omitNextUpdate: true });
      const r = await verifyIntelTdxCollateral({ quote: f.quote, collateral: { ...c, rootCrlDer: bad }, now: NOW, trustAnchorRootCaSpkiSha256: f.rootSpkiSha256 });
      expect(r.reason).toBe('Intel Root CA CRL: CRL parse failed: CRL: missing nextUpdate');
    });
    it('garbage / truncated CRL DER', async () => {
      const c = forgeTdxCollateral(f);
      const r1 = await verifyIntelTdxCollateral({ quote: f.quote, collateral: { ...c, rootCrlDer: Uint8Array.of(1, 2, 3) }, now: NOW, trustAnchorRootCaSpkiSha256: f.rootSpkiSha256 });
      expect(r1.reason).toMatch(/^Intel Root CA CRL: CRL parse failed: /);
      const r2 = await verifyIntelTdxCollateral({ quote: f.quote, collateral: { ...c, pckCrlDer: c.pckCrlDer.slice(0, 40) }, now: NOW, trustAnchorRootCaSpkiSha256: f.rootSpkiSha256 });
      expect(r2.reason).toMatch(/^PCK CRL: CRL parse failed: /);
    });
    it('PCK leaf serial on the PCK CRL', async () => {
      expect((await coll(f, { pckCrlRevoked: ['01', f.pck.serialHex.toUpperCase()] })).reason).toBe('PCK leaf certificate is revoked by the PCK CRL');
    });
    it('PCK CA serial on the Root CA CRL', async () => {
      expect((await coll(f, { rootCrlRevoked: [f.platformCa.serialHex] })).reason).toBe('PCK CA certificate is revoked by the Intel Root CA CRL');
    });
    it('unrelated serials on both CRLs do not matter', async () => {
      expect((await coll(f, { rootCrlRevoked: ['0102030405'], pckCrlRevoked: ['0a0b0c'] })).ok).toBe(true);
    });
    it('verifyCrl / serialIsRevoked: leading zeros and case are normalised', () => {
      const crl = forgeCrl({ issuer: f.pki.caDn, signer: f.pki.caKey, revoked: ['00aBcD'], thisUpdate: new Date('2026-10-01Z'), nextUpdate: new Date('2026-12-01Z') });
      const ca = new X509Certificate(f.platformCa.pem);
      const r = verifyCrl(crl, ca.publicKey, NOW);
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(serialIsRevoked(r.revoked, 'ABCD')).toBe(true);
        expect(serialIsRevoked(r.revoked, '00abcd')).toBe(true);
        expect(serialIsRevoked(r.revoked, 'abce')).toBe(false);
      }
    });
  });

  describe('TCB-info / QE-identity signing chain and signature', () => {
    const f = BASE;
    it('chain without the root does not terminate in a self-signed root', async () => {
      expect((await coll(f, { tcbInfoChainPem: f.pki.tcbSigning.pem })).reason).toBe('TCB info: issuer chain invalid: PCK chain does not terminate in a self-signed root');
      expect((await coll(f, { qeIdentityChainPem: f.pki.tcbSigning.pem })).reason).toBe('QE identity: issuer chain invalid: PCK chain does not terminate in a self-signed root');
    });
    it('chain to a foreign root fails the pin', async () => {
      const o = forgeIntelPki('foreign');
      const pem = o.tcbSigning.pem + o.root.pem;
      expect((await coll(f, { tcbInfoChainPem: pem })).reason).toBe('TCB info: issuer chain invalid: Intel SGX Root CA does not match the pinned trust anchor');
      expect((await coll(f, { qeIdentityChainPem: pem })).reason).toBe('QE identity: issuer chain invalid: Intel SGX Root CA does not match the pinned trust anchor');
    });
    it('document signed by a key other than the TCB-signing leaf', async () => {
      const stranger = forgeKey('stranger-signer', 'P-256');
      expect((await coll(f, { signerKey: stranger })).reason).toBe('TCB info: tcbInfo signature does not verify under the TCB Signing certificate');
    });
    it('only the QE identity signed by a stranger', async () => {
      const c = forgeTdxCollateral(f);
      const bad = forgeTdxCollateral(f, { signerKey: forgeKey('stranger-signer', 'P-256') });
      const r = await verifyIntelTdxCollateral({ quote: f.quote, collateral: { ...c, qeIdentityJson: bad.qeIdentityJson }, now: NOW, trustAnchorRootCaSpkiSha256: f.rootSpkiSha256 });
      expect(r.reason).toBe('QE identity: enclaveIdentity signature does not verify under the TCB Signing certificate');
    });
    it('content altered after signing (any byte of the signed object)', async () => {
      expect((await coll(f, { tamperTcbInfo: (raw) => raw.replace('"tcbType":0', '"tcbType":1') })).reason).toBe('TCB info: tcbInfo signature does not verify under the TCB Signing certificate');
      expect((await coll(f, { tamperQeIdentity: (raw) => raw.replace('"isvprodid":2', '"isvprodid":3') })).reason).toBe('QE identity: enclaveIdentity signature does not verify under the TCB Signing certificate');
    });
    it('expired / not-yet-valid TCB-signing certificate', async () => {
      const p1 = forgeIntelPki('s1', { tcbSigningValidity: [new Date('2018-01-01Z'), new Date('2026-10-01Z')] });
      expect((await coll(quoteWith({ pki: p1 }))).reason).toBe('TCB info: issuer chain certificate outside its validity period');
      const p2 = forgeIntelPki('s2', { tcbSigningValidity: [new Date('2026-11-01Z'), new Date('2030-01-01Z')] });
      expect((await coll(quoteWith({ pki: p2 }))).reason).toBe('TCB info: issuer chain certificate outside its validity period');
    });
    it('TCB-signing certificate revoked on the Root CA CRL', async () => {
      expect((await coll(f, { rootCrlRevoked: [f.pki.tcbSigning.serialHex] })).reason).toBe('TCB info: issuer chain certificate is revoked by the Intel Root CA CRL');
    });
    it('malformed document shapes', async () => {
      const c = forgeTdxCollateral(f);
      const run = (over: Partial<typeof c>) => verifyIntelTdxCollateral({ quote: f.quote, collateral: { ...c, ...over }, now: NOW, trustAnchorRootCaSpkiSha256: f.rootSpkiSha256 });
      expect((await run({ tcbInfoJson: '{"nope":{}}' })).reason).toBe('TCB info: tcbInfo not found / malformed');
      expect((await run({ tcbInfoJson: '{"tcbInfo":[1],"signature":"00"}' })).reason).toBe('TCB info: tcbInfo not found / malformed');
      expect((await run({ tcbInfoJson: `${c.tcbInfoJson as string} garbage` })).reason).toBe('TCB info: tcbInfo document is not valid JSON');
      expect((await run({ tcbInfoJson: (c.tcbInfoJson as string).replace(/"signature":"[0-9a-f]+"/, '"signature":"abc"') })).reason).toBe('TCB info: tcbInfo signature missing or malformed');
      expect((await run({ tcbInfoJson: (c.tcbInfoJson as string).replace(/,"signature":"[0-9a-f]+"/, '') })).reason).toBe('TCB info: tcbInfo signature missing or malformed');
      expect((await run({ qeIdentityJson: '{"enclaveIdentity":"x"}' })).reason).toBe('QE identity: enclaveIdentity not found / malformed');
      expect((await run({ qeIdentityJson: '{}' })).reason).toBe('QE identity: enclaveIdentity not found / malformed');
    });
    it('a string with escaped braces/quotes inside the signed object is still extracted exactly', async () => {
      const r = await coll(f, { tcbInfo: { levels: defaultLevels(f) }, tamperTcbInfo: (raw) => raw });
      expect(r.ok).toBe(true);
    });
  });
  const defaultLevels = (f: ForgedTdxQuote) => [levelFor(f, 'UpToDate')];

  describe('freshness + document identity', () => {
    const f = BASE;
    it('TCB info: issueDate in the future / stale / missing', async () => {
      expect((await coll(f, { tcbInfo: { issueDate: '2026-12-01T00:00:00Z', nextUpdate: '2027-01-01T00:00:00Z' } })).reason).toBe('TCB info: issueDate is in the future');
      expect((await coll(f, { tcbInfo: { issueDate: '2026-08-01T00:00:00Z', nextUpdate: '2026-09-01T00:00:00Z' } })).reason).toBe('TCB info: stale (nextUpdate passed)');
      expect((await coll(f, { tcbInfo: { issueDate: 'not a date' } })).reason).toBe('TCB info: issueDate/nextUpdate missing');
    });
    it('QE identity: issueDate in the future / stale / missing', async () => {
      expect((await coll(f, { qeIdentity: { issueDate: '2026-12-01T00:00:00Z', nextUpdate: '2027-01-01T00:00:00Z' } })).reason).toBe('QE identity: issueDate is in the future');
      expect((await coll(f, { qeIdentity: { issueDate: '2026-08-01T00:00:00Z', nextUpdate: '2026-09-01T00:00:00Z' } })).reason).toBe('QE identity: stale (nextUpdate passed)');
      expect((await coll(f, { qeIdentity: { nextUpdate: 'soon' } })).reason).toBe('QE identity: issueDate/nextUpdate missing');
    });
    it('TCB info that is not a TDX v3 document', async () => {
      expect((await coll(f, { tcbInfo: { id: 'SGX' } })).reason).toBe('TCB info is not a TDX v3 document');
      expect((await coll(f, { tcbInfo: { version: 2 } })).reason).toBe('TCB info is not a TDX v3 document');
    });
    it('TCB info for a different FMSPC', async () => {
      expect((await coll(f, { tcbInfo: { fmspc: '00a06f000000' } })).reason).toBe('TCB info FMSPC does not match the quote PCK');
      expect((await coll(f, { tcbInfo: { fmspc: '90C06F000000' } })).ok).toBe(true); // case-insensitive
    });
    it('tcbEvaluationDataNumber: missing in either document, and the policy floor', async () => {
      expect((await coll(f, { tcbInfo: { tcbEvaluationDataNumber: null } })).reason).toBe('tcbEvaluationDataNumber missing');
      expect((await coll(f, { qeIdentity: { tcbEvaluationDataNumber: null } })).reason).toBe('tcbEvaluationDataNumber missing');
      expect((await coll(f, { tcbInfo: { tcbEvaluationDataNumber: 19 } }, { minTcbEvaluationDataNumber: 20 })).reason).toBe('tcbEvaluationDataNumber below policy minimum');
      expect((await coll(f, { qeIdentity: { tcbEvaluationDataNumber: 19 } }, { minTcbEvaluationDataNumber: 20 })).reason).toBe('tcbEvaluationDataNumber below policy minimum');
      const ok = await coll(f, { tcbInfo: { tcbEvaluationDataNumber: 25 }, qeIdentity: { tcbEvaluationDataNumber: 22 } }, { minTcbEvaluationDataNumber: 22 });
      expect(ok.ok).toBe(true);
      expect(ok.tcbEvaluationDataNumber).toBe(22); // min of the two
    });
  });

  describe('platform TCB evaluation', () => {
    const f = BASE;
    const withLevels = (levels: ReturnType<typeof levelFor>[]) => ({ tcbInfo: { levels } });
    it('no tcbLevels at all', async () => {
      expect((await coll(f, { tcbInfo: { levels: [], rawLevels: [] } })).reason).toBe('TCB evaluation: TCB info has no tcbLevels');
    });
    it('PCK SGX component below the lowest level', async () => {
      const lv = levelFor(f, 'UpToDate');
      const sgx = [...lv.sgx];
      sgx[3] = sgx[3]! + 1;
      expect((await coll(f, withLevels([{ ...lv, sgx }]))).reason).toBe('TCB evaluation: platform TCB is below every level in the TCB info');
    });
    it('PCESVN below the lowest level', async () => {
      expect((await coll(f, withLevels([{ ...levelFor(f, 'UpToDate'), pcesvn: 14 }]))).reason).toBe('TCB evaluation: platform TCB is below every level in the TCB info');
    });
    it('TD TEE_TCB_SVN (TDX component) below the lowest level', async () => {
      const lv = levelFor(f, 'UpToDate');
      const tdx = [...lv.tdx];
      tdx[2] = tdx[2]! + 1; // component index 2 participates for a minor>0 module
      expect((await coll(f, withLevels([{ ...lv, tdx }]))).reason).toBe('TCB evaluation: platform TCB is below every level in the TCB info');
    });
    it('with a TDX module minor > 0, components 0-1 are covered by the module identity, not the level', async () => {
      const lv = levelFor(f, 'UpToDate');
      const tdx = [...lv.tdx];
      tdx[0] = 200;
      tdx[1] = 200;
      expect((await coll(f, withLevels([{ ...lv, tdx }]))).ok).toBe(true);
    });
    it('the FIRST matching level wins (descending order), taking its status + advisories', async () => {
      const top = levelFor(f, 'UpToDate');
      const higher = { ...top, sgx: top.sgx.map((s) => s + 5), status: 'UpToDate' as TcbStatus };
      const r = await coll(f, withLevels([higher, { ...top, status: 'SWHardeningNeeded', advisories: ['INTEL-SA-00500'] }, { ...top, status: 'OutOfDate' }]));
      expect(r).toMatchObject({ ok: true, platformStatus: 'SWHardeningNeeded', status: 'SWHardeningNeeded', advisoryIds: ['INTEL-SA-00500'] });
    });
    it('every non-accepted status is rejected with that exact status; all accepted when listed', async () => {
      const all: TcbStatus[] = ['UpToDate', 'SWHardeningNeeded', 'ConfigurationNeeded', 'ConfigurationAndSWHardeningNeeded', 'OutOfDateConfigurationNeeded', 'OutOfDate', 'Revoked'];
      for (const st of all) {
        const o = withLevels([levelFor(f, st)]);
        const r = await coll(f, o);
        const accepted = DEFAULT_ACCEPTED_STATUSES.includes(st);
        expect(r.ok, st).toBe(accepted);
        expect(r.status, st).toBe(st);
        if (!accepted) expect(r.reason, st).toBe(`TCB status ${st} is not accepted by policy`);
        expect((await coll(f, o, { acceptStatuses: all })).ok, `${st} listed`).toBe(true);
      }
    });
    it('an empty acceptStatuses list accepts nothing', async () => {
      expect((await coll(f, {}, { acceptStatuses: [] })).reason).toBe('TCB status UpToDate is not accepted by policy');
    });
    it('malformed levels: not an object, components wrong length, pcesvn not a number, unknown status', async () => {
      const good = levelFor(f, 'UpToDate');
      const comps = (a: readonly number[]) => a.map((svn) => ({ svn }));
      const raw = (tcb: Record<string, unknown>, status: unknown = 'UpToDate') => ({ tcbInfo: { levels: [], rawLevels: [{ tcb, tcbStatus: status }] } });
      expect((await coll(f, { tcbInfo: { levels: [], rawLevels: [5] } })).reason).toBe('TCB evaluation: malformed TCB level');
      expect((await coll(f, { tcbInfo: { levels: [], rawLevels: [{ tcbStatus: 'UpToDate' }] } })).reason).toBe('TCB evaluation: malformed TCB level');
      expect((await coll(f, raw({ sgxtcbcomponents: comps(good.sgx.slice(0, 15)), pcesvn: 13, tdxtcbcomponents: comps(good.tdx) }))).reason).toBe('TCB evaluation: malformed TCB level components');
      expect((await coll(f, raw({ sgxtcbcomponents: comps(good.sgx), pcesvn: '13', tdxtcbcomponents: comps(good.tdx) }))).reason).toBe('TCB evaluation: malformed TCB level components');
      expect((await coll(f, raw({ sgxtcbcomponents: [{ svn: 'x' }, ...comps(good.sgx.slice(1))], pcesvn: 13, tdxtcbcomponents: comps(good.tdx) }))).reason).toBe('TCB evaluation: malformed TCB level components');
      expect((await coll(f, raw({ sgxtcbcomponents: comps(good.sgx), pcesvn: 13, tdxtcbcomponents: comps(good.tdx) }, 'Fantastic'))).reason).toBe('TCB evaluation: TCB level has an unknown tcbStatus');
    });
  });

  describe('TDX module identity', () => {
    it('minor > 0 and the identity is not listed in the TCB info', async () => {
      const f = BASE; // teeTcbSvn[1] = 1 => TDX_01
      expect((await coll(f, { tcbInfo: { tdxModuleIdentities: [] } })).reason).toBe('TCB evaluation: TDX module identity TDX_01 not present in TCB info');
      expect((await coll(f, { tcbInfo: { tdxModuleIdentities: [{ id: 'TDX_03', levels: [{ isvsvn: 1, status: 'UpToDate' }] }] } })).reason).toBe('TCB evaluation: TDX module identity TDX_01 not present in TCB info');
    });
    it('the module id is the upper-case two-digit hex of the minor version', async () => {
      const f = fix({ td: { teeTcbSvn: '0d0a0500000000000000000000000000' } });
      const ok = await coll(f, { tcbInfo: { tdxModuleIdentities: [{ id: 'TDX_0A', levels: [{ isvsvn: 1, status: 'UpToDate' }] }] } });
      expect(ok.reason).toBeUndefined();
      expect((await coll(f, { tcbInfo: { tdxModuleIdentities: [{ id: 'TDX_0a', levels: [{ isvsvn: 1, status: 'UpToDate' }] }] } })).reason).toBe('TCB evaluation: TDX module identity TDX_0A not present in TCB info');
    });
    it('module SVN below every known level', async () => {
      const f = BASE; // svn 13
      expect((await coll(f, { tcbInfo: { tdxModuleIdentities: [{ id: 'TDX_01', levels: [{ isvsvn: 14, status: 'UpToDate' }] }] } })).reason).toBe('TCB evaluation: TDX module TDX_01 SVN 13 is below every known level');
      expect((await coll(f, { tcbInfo: { tdxModuleIdentities: [{ id: 'TDX_01', levels: [] }] } })).reason).toBe('TCB evaluation: TDX module TDX_01 SVN 13 is below every known level');
    });
    it('module level with an unknown tcbStatus', async () => {
      const f = BASE;
      const r = await coll(f, { tcbInfo: { tdxModuleIdentities: [{ id: 'TDX_01', levels: [{ isvsvn: 1, status: 'Weird' as TcbStatus }] }] } });
      expect(r.reason).toBe('TCB evaluation: TDX module level has an unknown tcbStatus');
    });
    it('module status is folded into the final status (worst wins), with its advisories', async () => {
      const f = BASE;
      const r = await coll(f, { tcbInfo: { tdxModuleIdentities: [{ id: 'TDX_01', levels: [{ isvsvn: 20, status: 'UpToDate' }, { isvsvn: 10, status: 'OutOfDate', advisories: ['INTEL-SA-01245'] }] }] } }, { acceptStatuses: ['OutOfDate'] });
      expect(r).toMatchObject({ ok: true, status: 'OutOfDate', platformStatus: 'UpToDate', tdxModuleStatus: 'OutOfDate', advisoryIds: ['INTEL-SA-01245'] });
    });
    it('minor == 0 uses the base tdxModule (and covers TDX component 0-1 in the level)', async () => {
      const f = fix({ td: { teeTcbSvn: '0d000500000000000000000000000000' } });
      const ok = await coll(f, { tcbInfo: {} });
      expect(ok).toMatchObject({ ok: true, tdxModuleStatus: 'UpToDate' });
      const lv = levelFor(f, 'UpToDate');
      const tdx = [...lv.tdx];
      tdx[0] = 14; // now compared for minor == 0
      expect((await coll(f, { tcbInfo: { levels: [{ ...lv, tdx }] } })).reason).toBe('TCB evaluation: platform TCB is below every level in the TCB info');
    });
    it('minor == 0 and no tdxModule in the TCB info', async () => {
      const f = fix({ td: { teeTcbSvn: '0d000500000000000000000000000000' } });
      expect((await coll(f, { tcbInfo: { tdxModule: null } })).reason).toBe('TCB evaluation: TCB info missing tdxModule');
    });
    it('malformed module fields (mrsigner / attributes / mask)', async () => {
      const f = fix({ td: { teeTcbSvn: '0d000500000000000000000000000000' } });
      const mod = { mrsigner: '00'.repeat(48), attributes: '0000000000000000', attributesMask: 'FFFFFFFFFFFFFFFF' };
      for (const bad of [{ mrsigner: '00'.repeat(47) }, { mrsigner: 'zz'.repeat(48) }, { attributes: '00' }, { attributesMask: 7 as unknown as string }]) {
        expect((await coll(f, { tcbInfo: { tdxModule: { ...mod, ...bad } } })).reason, JSON.stringify(bad)).toBe('TCB evaluation: TDX module identity fields malformed');
      }
    });
    it('TD MRSIGNERSEAM must equal the module identity', async () => {
      const f = fix({ td: { mrSignerSeam: 'ee'.repeat(48) } });
      expect((await coll(f)).reason).toBe('TCB evaluation: TD report MRSIGNERSEAM does not match the TDX module identity');
      // …unless the module identity pins that signer
      const ok = await coll(f, { tcbInfo: { tdxModuleIdentities: [{ id: 'TDX_01', mrsigner: 'ee'.repeat(48), levels: [{ isvsvn: 1, status: 'UpToDate' }] }] } });
      expect(ok.ok).toBe(true);
    });
    it('TD SEAM attributes are compared under the identity mask', async () => {
      const f = fix({ td: { seamAttributes: '0100000000000000' } });
      expect((await coll(f)).reason).toBe('TCB evaluation: TD report SEAM attributes do not match the TDX module identity');
      const masked = await coll(f, { tcbInfo: { tdxModuleIdentities: [{ id: 'TDX_01', attributesMask: 'FEFFFFFFFFFFFFFF', levels: [{ isvsvn: 1, status: 'UpToDate' }] }] } });
      expect(masked.ok).toBe(true);
    });
  });

  describe('QE identity evaluation', () => {
    const f = BASE;
    it('wrong id / version', async () => {
      expect((await coll(f, { qeIdentity: { id: 'QE' } })).reason).toBe('QE identity: QE identity id is not TD_QE');
      expect((await coll(f, { qeIdentity: { version: 1 } })).reason).toBe('QE identity: unsupported QE identity version');
    });
    it('malformed identity fields', async () => {
      for (const bad of [{ miscselect: '00' }, { miscselectMask: 'zzzzzzzz' }, { attributes: '11' }, { attributesMask: 'FF' }, { mrsigner: 'AA'.repeat(31) }, { isvprodid: '2' }]) {
        expect((await coll(f, { qeIdentity: bad })).reason, JSON.stringify(bad)).toBe('QE identity: QE identity fields malformed');
      }
    });
    it('MISCSELECT mismatch', async () => {
      const q = fix({ qe: { miscSelect: '01000000' } });
      expect((await coll(q)).reason).toBe('QE identity: QE MISCSELECT does not match the QE identity');
    });
    it('ATTRIBUTES mismatch under the mask; bits outside the mask are ignored', async () => {
      const bad = fix({ qe: { attributes: '1500000000000040e7000000000000000000'.slice(0, 32) } });
      expect((await coll(bad)).reason).toBe('QE identity: QE ATTRIBUTES do not match the QE identity');
      const wrongFlags = fix({ qe: { attributes: '0500000000000000e700000000000000' } });
      expect((await coll(wrongFlags)).reason).toBe('QE identity: QE ATTRIBUTES do not match the QE identity');
      const ignored = fix({ qe: { attributes: '1500000000000000ff00000000000000' } }); // second 8 bytes masked out
      expect((await coll(ignored)).ok).toBe(true);
    });
    it('MRSIGNER mismatch', async () => {
      const q = fix({ qe: { mrSigner: '11'.repeat(32) } });
      expect((await coll(q)).reason).toBe('QE identity: QE MRSIGNER does not match the QE identity');
    });
    it('ISVPRODID mismatch', async () => {
      const q = fix({ qe: { isvProdId: 3 } });
      expect((await coll(q)).reason).toBe('QE identity: QE ISVPRODID does not match the QE identity');
    });
    it('ISVSVN below every known level, and picks the highest level the QE reaches', async () => {
      expect((await coll(f, { qeIdentity: { levels: [{ isvsvn: 8, status: 'UpToDate' }] } })).reason).toBe('QE identity: QE ISVSVN is below every known level');
      expect((await coll(f, { qeIdentity: { levels: [] } })).reason).toBe('QE identity: QE ISVSVN is below every known level');
      const r = await coll(f, { qeIdentity: { levels: [{ isvsvn: 9, status: 'UpToDate' }, { isvsvn: 7, status: 'SWHardeningNeeded', advisories: ['INTEL-SA-00999'] }, { isvsvn: 4, status: 'OutOfDate' }] } });
      expect(r).toMatchObject({ ok: true, qeStatus: 'SWHardeningNeeded', status: 'SWHardeningNeeded', advisoryIds: ['INTEL-SA-00999'] });
    });
    it('QE level with an unknown tcbStatus', async () => {
      expect((await coll(f, { qeIdentity: { levels: [{ isvsvn: 1, status: 'Odd' as TcbStatus }] } })).reason).toBe('QE identity: QE level has an unknown tcbStatus');
    });
    it('the QE status participates in the worst-of merge and advisories are de-duplicated and sorted', async () => {
      const r = await coll(
        f,
        {
          tcbInfo: {
            levels: [levelFor(f, 'ConfigurationNeeded', ['INTEL-SA-00003', 'INTEL-SA-00001'])],
            tdxModuleIdentities: [{ id: 'TDX_01', levels: [{ isvsvn: 1, status: 'SWHardeningNeeded', advisories: ['INTEL-SA-00002', 'INTEL-SA-00001'] }] }],
          },
          qeIdentity: { levels: [{ isvsvn: 1, status: 'OutOfDate', advisories: ['INTEL-SA-00004', 'INTEL-SA-00002'] }] },
        },
        { acceptStatuses: ['OutOfDate'] },
      );
      expect(r).toMatchObject({
        ok: true,
        status: 'OutOfDate',
        platformStatus: 'ConfigurationNeeded',
        tdxModuleStatus: 'SWHardeningNeeded',
        qeStatus: 'OutOfDate',
        advisoryIds: ['INTEL-SA-00001', 'INTEL-SA-00002', 'INTEL-SA-00003', 'INTEL-SA-00004'],
      });
    });
    it('Revoked anywhere makes the merged status Revoked', async () => {
      const r = await coll(f, { qeIdentity: { levels: [{ isvsvn: 1, status: 'Revoked' }] } });
      expect(r).toMatchObject({ ok: false, status: 'Revoked', reason: 'TCB status Revoked is not accepted by policy' });
    });
  });
});

describe('forge-x509 sanity', () => {
  it('forged certificates are parsed by OpenSSL with the expected subject/issuer/serial/validity', () => {
    const c = new X509Certificate(BASE.pck.pem);
    expect(c.subject).toContain('CN=Intel SGX PCK Certificate');
    expect(c.issuer).toContain('CN=Intel SGX PCK Platform CA');
    expect(c.ca).toBe(false);
    expect(c.serialNumber.toLowerCase().replace(/^0+/, '')).toBe(BASE.pck.serialHex);
    expect(new X509Certificate(BASE.platformCa.pem).ca).toBe(true);
    expect(c.checkIssued(new X509Certificate(BASE.platformCa.pem))).toBe(true);
    expect(c.verify(new X509Certificate(BASE.platformCa.pem).publicKey)).toBe(true);
  });
  it('u16/u32 and hex helpers round-trip', () => {
    expect(Array.from(u16(0x0102))).toEqual([2, 1]);
    expect(Array.from(u32(0x01020304))).toEqual([4, 3, 2, 1]);
    expect(bytesToHex(hexToBytes('00ff10'))).toBe('00ff10');
    expect(() => hexToBytes('abc')).toThrow('bad hex');
  });
});

// ═════════════════════════════════════════════════════════════════════════════════════════════════
describe('CRL parser branches (forged DER with a valid signature)', () => {
  const pki = BASE.pki;
  const ca = new X509Certificate(pki.platformCa.pem);
  const t0 = new Date('2026-10-01T00:00:00Z');
  const t1 = new Date('2026-12-01T00:00:00Z');
  const crl = (raw: NonNullable<Parameters<typeof forgeCrl>[0]['raw']>, revoked: string[] = []) => forgeCrl({ issuer: pki.caDn, signer: pki.caKey, thisUpdate: t0, nextUpdate: t1, revoked, raw });
  const check = (der: Uint8Array) => verifyCrl(der, ca.publicKey, NOW);
  const reason = (der: Uint8Array) => {
    const r = check(der);
    return r.ok ? 'OK' : r.reason;
  };
  const ascii = (tag: number, v: string) => tlv(tag, new TextEncoder().encode(v));

  it('accepts a v1 CRL without the version field, and GeneralizedTime update fields', () => {
    expect(reason(crl({ omitVersion: true }))).toBe('OK');
    expect(reason(crl({ thisUpdate: generalizedTime(t0), nextUpdate: generalizedTime(t1) }))).toBe('OK');
  });
  it('UTCTime years 50-99 mean 19xx (an old nextUpdate is stale)', () => {
    expect(reason(crl({ nextUpdate: ascii(0x17, '991231235959Z') }))).toBe('CRL is stale (nextUpdate passed)');
  });
  it('malformed time encodings', () => {
    expect(reason(crl({ thisUpdate: ascii(0x17, 'garbage') }))).toBe('CRL parse failed: bad UTCTime');
    expect(reason(crl({ thisUpdate: ascii(0x18, '2026-10-01') }))).toBe('CRL parse failed: bad GeneralizedTime');
    expect(reason(crl({ thisUpdate: integer(5) }))).toBe('CRL parse failed: not a DER time');
  });
  it('structural violations', () => {
    expect(reason(crl({ tbsTag: 0x31 }))).toBe('CRL parse failed: CRL: bad TBSCertList');
    expect(reason(crl({ trailing: Uint8Array.of(0) }))).toBe('CRL parse failed: CRL: bad outer SEQUENCE');
    expect(reason(crl({ sigTag: 0x04 }))).toBe('CRL parse failed: CRL: bad signature');
    expect(reason(crl({ issuer: integer(1) }))).toBe('CRL parse failed: CRL: bad issuer');
    expect(reason(crl({ entries: [seq(octets(Uint8Array.of(1)))] }))).toBe('CRL parse failed: CRL: bad revoked entry');
  });
  it('DER length-field violations', () => {
    expect(reason(Uint8Array.of(0x30))).toBe('CRL parse failed: DER truncated');
    expect(reason(Uint8Array.of(0x30, 0x80))).toBe('CRL parse failed: DER bad length');
    expect(reason(Uint8Array.of(0x30, 0x85, 0, 0, 0, 0, 0))).toBe('CRL parse failed: DER bad length');
    expect(reason(Uint8Array.of(0x30, 0x05, 1))).toBe('CRL parse failed: DER overrun');
  });
  it('a CRL whose signature does not verify is named before freshness is considered', () => {
    const stale = forgeCrl({ issuer: pki.caDn, signer: forgeKey('x', 'P-256'), thisUpdate: new Date('2025-01-01Z'), nextUpdate: new Date('2025-02-01Z') });
    expect(reason(stale)).toBe('CRL signature does not verify under the issuer');
  });
});

describe('Intel primitives: edge cases the quote path cannot reach', () => {
  it('parseDcapTdReport: type and length guards', () => {
    expect(() => parseDcapTdReport('x' as unknown as Uint8Array)).toThrow('parseDcapTdReport: expected Uint8Array');
    expect(() => parseDcapTdReport(new Uint8Array(10))).toThrow('parseDcapTdReport: body too short (10 < 584)');
    expect(parseDcapTdReport(BASE.tdBody).tdAttributes.length).toBe(8);
  });
  it('ecdsaP256PublicKey: accepts compressed + uncompressed, rejects off-curve points', () => {
    const k = forgeKey('pk', 'P-256');
    const compressed = Uint8Array.of(k.pub[64]! & 1 ? 3 : 2, ...k.pub.subarray(1, 33));
    expect(hexOf(ecdsaP256PublicKey(compressed).point)).toBe(hexOf(k.pub));
    expect(hexOf(ecdsaP256PublicKey(k.pub).point)).toBe(hexOf(k.pub));
    expect(() => ecdsaP256PublicKey(Uint8Array.of(4, ...new Uint8Array(64).fill(3)))).toThrow();
    expect(toHex(Uint8Array.of(0, 15, 255))).toBe('000fff');
  });
  it('extractPckFmspcAndTcb: bounded loop, 3-byte PCESVN truncated to 16 bits, malformed DER lengths', () => {
    const OID_FMSPC = Uint8Array.from([0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x04]);
    const OID_TCB = Uint8Array.from([0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02]);
    const comp = (n: number, v: Uint8Array) => seq(oid(`1.2.840.113741.1.13.1.2.${n}`), v);
    const fmspc = cat(OID_FMSPC, octets(new Uint8Array(6)));
    const many = seq(comp(17, integer(5)), ...Array.from({ length: 80 }, () => comp(99, integer(1))));
    expect(extractPckFmspcAndTcb(cat(fmspc, OID_TCB, many)).pcesvn).toBe(5);
    expect(extractPckFmspcAndTcb(cat(fmspc, OID_TCB, seq(comp(17, tlv(0x02, Uint8Array.of(1, 0x23, 0x45)))))).pcesvn).toBe(0x2345);
    expect(() => extractPckFmspcAndTcb(cat(OID_FMSPC, Uint8Array.of(0x04, 0x85, 0, 0, 0, 0, 0)))).toThrow('malformed FMSPC OCTET STRING');
    expect(() => extractPckFmspcAndTcb(cat(OID_FMSPC, Uint8Array.of(0x04, 0x80)))).toThrow('malformed FMSPC OCTET STRING');
    expect(() => extractPckFmspcAndTcb(cat(fmspc, OID_TCB, Uint8Array.of(0x30, 0x50)))).toThrow('malformed TCB SEQUENCE');
  });
  it('certificate DN encodings differ from a stranger only by content: dn() is stable', () => {
    expect(hexOf(dn([['CN', 'x']]))).toBe(hexOf(dn([['CN', 'x']])));
    expect(hexOf(derTime(new Date('2026-10-20T00:00:00Z')))).toBe(hexOf(ascii17('261020000000Z')));
    function ascii17(v: string) {
      return tlv(0x17, new TextEncoder().encode(v));
    }
  });
});
