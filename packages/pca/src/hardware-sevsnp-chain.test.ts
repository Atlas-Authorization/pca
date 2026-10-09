/**
 * AMD SEV-SNP certificate-chain hardening: CA roles, validity windows against the verifier clock, ASK/ARK order and
 * count, the critical-extension profile, and STRICT X.509 extension parsing for the VCEK values the verifier relies on
 * (hwID / SPLs). The negative cases use chains forged in AMD's real wire format (RSA-4096 RSASSA-PSS ARK/ASK, P-384
 * VCEK, see test-support/forge-amd.ts) under a TEST ARK pin; the positive cases are the committed REAL chains.
 * Every negative asserts the SPECIFIC rejection reason.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { X509Certificate } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { p384 } from '@noble/curves/p384';
import { checkVcekReportBinding, extractTbsCertificate, parseSevSnpReport, splitPemCertificates, verifyAmdCertChain, verifyGenuineSevSnpReport } from './hardware-sevsnp';
import { createAmdSnpVerifier, pemToDer, AMD_ARK_SPKI_SHA384 } from './attest-amd-snp';
import { parseCertExtensions, parseTbsExtensions } from './x509-strict';
import { attestationBinding, type AttestationDocument, type ExpectedAttestationBinding } from './attestation';
import { serializeSevSnpReport } from './test-support/sevsnp-report';
import { forgeCert, forgeKey } from './test-support/forge-x509';
import { AMD_OID, FORGE_CHIP, FORGE_NA, FORGE_NB, amdVcekExtensions, boolean, cat, ctx, ext, extension, forgeAmdChain, integer, octets, oid, pemOf, seq, tlv, type AmdChainOptions } from './test-support/forge-amd';

const NOW = Date.parse('2026-10-08T12:00:00Z');
const day = 86_400_000;

// ── committed REAL chains ────────────────────────────────────────────────────────────────────────
const REAL_GENOA = JSON.parse(readFileSync(resolve(__dirname, '..', 'fixtures', 'real-azure-maa', 'sevsnp-amd-certs.json'), 'utf8')) as { vcekCert: string; certificateChain: string };
const MILAN_DIR = resolve(__dirname, '..', 'testdata', 'sevsnp-real');
const MILAN = { vcek: new Uint8Array(readFileSync(resolve(MILAN_DIR, 'vcek.der'))), pem: readFileSync(resolve(MILAN_DIR, 'chain.pem'), 'utf8') };
const genoaVcek = pemToDer(REAL_GENOA.vcekCert);

describe('REAL AMD chains: pinned, role-checked, inside their validity windows', () => {
  it('Genoa (Azure) chain verifies at the capture date; every cert is a CA/leaf as expected', async () => {
    const r = await verifyAmdCertChain({ vcekDer: genoaVcek, askArkPem: REAL_GENOA.certificateChain, trustAnchorArkSpkiSha384: AMD_ARK_SPKI_SHA384.genoa, nowMs: NOW });
    expect(r.reason).toBeUndefined();
    expect(r.ok).toBe(true);
  });
  it('Milan chain verifies under the Milan pin', async () => {
    const r = await verifyAmdCertChain({ vcekDer: MILAN.vcek, askArkPem: MILAN.pem, trustAnchorArkSpkiSha384: AMD_ARK_SPKI_SHA384.milan, nowMs: NOW });
    expect(r.reason).toBeUndefined();
    expect(r.ok).toBe(true);
  });
  it('each real chain is rejected under every OTHER family pin', async () => {
    for (const fam of ['milan', 'turin'] as const) {
      const r = await verifyAmdCertChain({ vcekDer: genoaVcek, askArkPem: REAL_GENOA.certificateChain, trustAnchorArkSpkiSha384: AMD_ARK_SPKI_SHA384[fam], nowMs: NOW });
      expect(r.reason).toBe('ARK does not match the pinned AMD trust anchor');
    }
    for (const fam of ['genoa', 'turin'] as const) {
      const r = await verifyAmdCertChain({ vcekDer: MILAN.vcek, askArkPem: MILAN.pem, trustAnchorArkSpkiSha384: AMD_ARK_SPKI_SHA384[fam], nowMs: NOW });
      expect(r.reason).toBe('ARK does not match the pinned AMD trust anchor');
    }
  });
  it('the real VCEK window is enforced to the millisecond (not yet valid / expired), via the verifier too', async () => {
    const v = new X509Certificate(Buffer.from(genoaVcek));
    const from = v.validFromDate.getTime();
    const to = v.validToDate.getTime();
    const base = { vcekDer: genoaVcek, askArkPem: REAL_GENOA.certificateChain, trustAnchorArkSpkiSha384: AMD_ARK_SPKI_SHA384.genoa };
    expect((await verifyAmdCertChain({ ...base, nowMs: from - 1 })).reason).toBe('VCEK certificate is not yet valid');
    expect((await verifyAmdCertChain({ ...base, nowMs: from })).ok).toBe(true);
    expect((await verifyAmdCertChain({ ...base, nowMs: to })).ok).toBe(true);
    expect((await verifyAmdCertChain({ ...base, nowMs: to + 1 })).reason).toBe('VCEK certificate has expired');
    // clock skew widens both edges, and only by the stated amount
    expect((await verifyAmdCertChain({ ...base, nowMs: from - 1000, clockSkewMs: 1000 })).ok).toBe(true);
    expect((await verifyAmdCertChain({ ...base, nowMs: from - 1001, clockSkewMs: 1000 })).reason).toBe('VCEK certificate is not yet valid');
  });
  it('the real ASK and ARK are CAs whose windows end well after the VCEK (so VCEK is the binding edge)', () => {
    const [ask, ark] = splitPemCertificates(REAL_GENOA.certificateChain).map((p) => new X509Certificate(p));
    expect(ask!.ca).toBe(true);
    expect(ark!.ca).toBe(true);
    expect(ark!.validToDate.getTime()).toBeGreaterThan(NOW + 365 * day);
    expect(ask!.validToDate.getTime()).toBeGreaterThan(NOW + 365 * day);
  });
  it('requires the clock: missing / non-finite nowMs and a bad skew fail closed with the specific reason', async () => {
    const base = { vcekDer: genoaVcek, askArkPem: REAL_GENOA.certificateChain, trustAnchorArkSpkiSha384: AMD_ARK_SPKI_SHA384.genoa };
    expect((await verifyAmdCertChain({ ...base } as never)).reason).toBe('nowMs (verifier clock) is required for the AMD chain validity check');
    expect((await verifyAmdCertChain({ ...base, nowMs: Number.NaN })).reason).toBe('nowMs (verifier clock) is required for the AMD chain validity check');
    expect((await verifyAmdCertChain({ ...base, nowMs: NOW, clockSkewMs: -1 })).reason).toBe('clockSkewMs must be a non-negative number');
    expect((await verifyAmdCertChain({ ...base, nowMs: NOW, clockSkewMs: Number.NaN })).reason).toBe('clockSkewMs must be a non-negative number');
  });
});

// ── forged chains (RSA-4096 keys are generated once and cached per label) ──────────────────────────
const chainCache = new Map<string, ReturnType<typeof forgeAmdChain>>();
function chain(name: string, o: AmdChainOptions = {}) {
  const key = `${name}`;
  let c = chainCache.get(key);
  if (!c) {
    c = forgeAmdChain({ label: 'amd-test', ...o });
    chainCache.set(key, c);
  }
  return c;
}
const verify = (c: ReturnType<typeof forgeAmdChain>, over: { pem?: string; vcekDer?: Uint8Array; pin?: string; nowMs?: number } = {}) =>
  verifyAmdCertChain({ vcekDer: over.vcekDer ?? c.vcekDer, askArkPem: over.pem ?? c.askArkPem, trustAnchorArkSpkiSha384: over.pin ?? c.arkPin, nowMs: over.nowMs ?? NOW });

describe('forged AMD-format chain', () => {
  it('baseline: the forged chain verifies (RSA-PSS ARK/ASK + P-384 VCEK)', async () => {
    const r = await verify(chain('ok'));
    expect(r.reason).toBeUndefined();
    expect(r.ok).toBe(true);
  }, 120_000);

  it('CA roles: a non-CA ASK is rejected', async () => {
    const c = chain('askNotCa', { ask: { extensions: [ext.basicConstraints(false), ext.keyUsage(['keyCertSign'])] } });
    expect((await verify(c)).reason).toBe('AMD chain role check failed: issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)');
  }, 120_000);
  it('CA roles: an ASK with no BasicConstraints at all is rejected', async () => {
    const c = chain('askNoBc', { ask: { extensions: [ext.keyUsage(['keyCertSign'])] } });
    expect((await verify(c)).reason).toBe('AMD chain role check failed: issuer certificate at depth 1 has no BasicConstraints (not a CA)');
  }, 120_000);
  it('CA roles: an ASK whose keyUsage lacks keyCertSign is rejected', async () => {
    const c = chain('askKu', { ask: { extensions: [ext.basicConstraints(true, 0), ext.keyUsage(['digitalSignature'])] } });
    expect((await verify(c)).reason).toBe('AMD chain role check failed: issuer certificate at depth 1 keyUsage lacks keyCertSign');
  }, 120_000);
  it('CA roles: a non-CA ARK is rejected', async () => {
    const c = chain('arkNotCa', { ark: { extensions: [ext.basicConstraints(false), ext.keyUsage(['keyCertSign'])] } });
    expect((await verify(c)).reason).toBe('AMD chain role check failed: issuer certificate at depth 2 is not a CA (BasicConstraints CA:FALSE)');
  }, 120_000);
  it('CA roles: an ARK pathLenConstraint that cannot admit the ASK is rejected', async () => {
    const c = chain('arkPathLen', { ark: { extensions: [ext.basicConstraints(true, 0), ext.keyUsage(['keyCertSign'])] } });
    expect((await verify(c)).reason).toBe('AMD chain role check failed: issuer certificate at depth 2 pathLenConstraint 0 is exceeded (1 intermediate(s) below)');
  }, 120_000);
  it('CA roles: a VCEK asserting CA:TRUE is rejected', async () => {
    const c = chain('vcekCa', { vcek: { extensions: [ext.basicConstraints(true), ...amdVcekExtensions({ chip: FORGE_CHIP, bl: 7, tee: 0, snp: 3, ucode: 0 })] } });
    expect((await verify(c)).reason).toBe('AMD chain role check failed: leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)');
  }, 120_000);
  it('critical flags: BasicConstraints on a CA must be critical', async () => {
    const nonCritical = extension('2.5.29.19', false, seq(boolean(true), integer(0)));
    const c = chain('askBcNonCrit', { ask: { extensions: [nonCritical, ext.keyUsage(['keyCertSign'])] } });
    expect((await verify(c)).reason).toBe('ASK certificate BasicConstraints is not marked critical');
  }, 120_000);
  it('critical flags: an unrecognised critical extension on the VCEK is fatal (RFC 5280)', async () => {
    const c = chain('vcekCrit', { vcek: { extensions: [extension('1.2.3.4.5', true, octets(new Uint8Array([1]))), ...amdVcekExtensions({ chip: FORGE_CHIP, bl: 7, tee: 0, snp: 3, ucode: 0 })] } });
    expect((await verify(c)).reason).toBe('VCEK certificate has an unrecognised critical extension 1.2.3.4.5');
  }, 120_000);

  for (const [name, who] of [['VCEK', 'vcek'], ['ASK', 'ask'], ['ARK', 'ark']] as const) {
    it(`validity: ${name} not yet valid / expired are rejected independently`, async () => {
      const early = chain(`${who}-early`, { [who]: { notBefore: new Date(NOW + day), notAfter: FORGE_NA } });
      expect((await verify(early)).reason).toBe(`${name} certificate is not yet valid`);
      const late = chain(`${who}-late`, { [who]: { notBefore: FORGE_NB, notAfter: new Date(NOW - day) } });
      expect((await verify(late)).reason).toBe(`${name} certificate has expired`);
    }, 120_000);
  }

  it('order/count: [ARK, ASK] is rejected as out of order', async () => {
    const c = chain('ok');
    expect((await verify(c, { pem: pemOf(c.arkDer) + pemOf(c.askDer) })).reason).toBe('second certificate of the chain is not a self-signed ARK (chain out of order?)');
  }, 120_000);
  it('order/count: [ARK, ARK] (no ASK) is rejected', async () => {
    const c = chain('ok');
    expect((await verify(c, { pem: pemOf(c.arkDer) + pemOf(c.arkDer) })).reason).toBe('first certificate of the chain is self-signed, not an ASK (chain out of order?)');
  }, 120_000);
  it('order/count: one certificate, or three, is rejected', async () => {
    const c = chain('ok');
    expect((await verify(c, { pem: pemOf(c.askDer) })).reason).toBe('ASK+ARK chain must contain exactly two certificates (ASK then ARK)');
    expect((await verify(c, { pem: pemOf(c.askDer) + pemOf(c.arkDer) + pemOf(c.arkDer) })).reason).toBe('ASK+ARK chain must contain exactly two certificates (ASK then ARK)');
  }, 120_000);
  it('order/count: handing the ASK in the VCEK slot is rejected (subject/issuer mismatch)', async () => {
    const c = chain('ok');
    expect((await verify(c, { vcekDer: c.askDer })).reason).toBe('ASK subject does not match the VCEK issuer');
  }, 120_000);

  it('signatures: an ASK not issued by the ARK, and a VCEK not issued by the ASK, are rejected', async () => {
    const foreignAsk = chain('askForeign', { askSignedBy: 'other-amd' });
    expect((await verify(foreignAsk)).reason).toBe('ASK is not signed by ARK');
    const foreignVcek = chain('vcekForeign', { vcekSignedBy: 'other-amd' });
    expect((await verify(foreignVcek)).reason).toBe('VCEK is not signed by ASK');
  }, 240_000);

  it('pin: a valid chain is rejected under a different family pin, and under a malformed pin', async () => {
    const c = chain('ok');
    for (const fam of ['milan', 'genoa', 'turin'] as const) {
      expect((await verify(c, { pin: AMD_ARK_SPKI_SHA384[fam] })).reason).toBe('ARK does not match the pinned AMD trust anchor');
    }
    expect((await verify(c, { pin: 'zz' })).reason).toBe('ARK does not match the pinned AMD trust anchor');
  }, 120_000);

  it('end to end: verifyGenuineSevSnpReport accepts a report signed by the forged VCEK, and rejects it past expiry', async () => {
    const c = chain('ok');
    const expected: ExpectedAttestationBinding = { holderPub: 'h', grantRef: 'g', epoch: 1, nonce: 'n', nonceIssuedAt: 1 };
    const fields = { version: 2, vmpl: 0, reported_tcb: 0x0003_0000_0000_0007n, report_data: attestationBinding(expected), measurement: new Uint8Array(48).fill(9), chip_id: FORGE_CHIP };
    const parsed = parseSevSnpReport(serializeSevSnpReport(fields));
    const sig = p384.sign(p384.CURVE.hash(parsed.signed), c.vcekKey.priv, { lowS: false }).toCompactRawBytes();
    const le72 = (b: Uint8Array) => {
      const o = new Uint8Array(72);
      o.set(Uint8Array.from(b).reverse(), 0);
      return o;
    };
    const report = serializeSevSnpReport({ ...fields, signature: { r: le72(sig.subarray(0, 48)), s: le72(sig.subarray(48, 96)) } });
    const base = { report, vcekDer: c.vcekDer, askArkPem: c.askArkPem, trustAnchorArkSpkiSha384: c.arkPin, expected };
    const ok = await verifyGenuineSevSnpReport({ ...base, nowMs: NOW });
    expect(ok.reason).toBeUndefined();
    expect(ok.ok).toBe(true);
    const old = await verifyGenuineSevSnpReport({ ...base, nowMs: FORGE_NA.getTime() + day });
    expect(old.reason).toBe('cert chain invalid: VCEK certificate has expired');
    const noClock = await verifyGenuineSevSnpReport({ ...base } as never);
    expect(noClock.reason).toBe('cert chain invalid: nowMs (verifier clock) is required for the AMD chain validity check');
  }, 120_000);
});

// ── strict extension parsing + the VCEK values the verifier relies on ───────────────────────────────
const REPORT = parseSevSnpReport(
  serializeSevSnpReport({ version: 2, vmpl: 0, reported_tcb: 0x0003_0000_0000_0007n, report_data: new Uint8Array(64), measurement: new Uint8Array(48), chip_id: FORGE_CHIP }),
);
const spl = { chip: FORGE_CHIP, bl: 7, tee: 0, snp: 3, ucode: 0 };

const hdr = (b: Uint8Array): number => (b[1]! & 0x80 ? 2 + (b[1]! & 0x7f) : 2);
/** Offset of the [3] extensions element inside a TBS. */
function blockStart(tbs: Uint8Array): number {
  let p = hdr(tbs);
  while (p < tbs.length) {
    if (tbs[p] === 0xa3) return p;
    const l = tbs[p + 1]!;
    const n = l & 0x80 ? l & 0x7f : 0;
    let len = n ? 0 : l;
    for (let i = 0; i < n; i++) len = len * 256 + tbs[p + 2 + i]!;
    p += 2 + n + len;
  }
  throw new Error('no extensions block');
}
/** TBS of a certificate whose extensions are exactly `extensions`; `rawBlock` replaces the whole [3] element. */
function tbsWith(extensions: Uint8Array[], rawBlock?: Uint8Array): Uint8Array {
  const cert = forgeCert({ subject: [['CN', 'v']], issuer: [['CN', 'i']], subjectKey: forgeKey('s', 'P-384'), signer: forgeKey('g', 'P-384'), serial: 1n, notBefore: FORGE_NB, notAfter: FORGE_NA, extensions: extensions.length > 0 ? extensions : [ext.basicConstraints(false)] });
  const tbs = extractTbsCertificate(cert.der);
  if (!rawBlock) return tbs;
  return tlv(0x30, tbs.slice(hdr(tbs), blockStart(tbs)), rawBlock);
}
const binding = (extensions: Uint8Array[]) => checkVcekReportBinding(tbsWith(extensions), REPORT);
const goodExts = () => amdVcekExtensions(spl); // [bl, tee, snp, ucode, hwid]
const splExt = (which: 'bl' | 'tee' | 'snp' | 'ucode', value: Uint8Array, critical = false) => extension(AMD_OID[which], critical, value);

describe('VCEK extension values: strict parsing', () => {
  it('baseline: the well-formed AMD extension set binds to the matching report', () => {
    expect(binding(goodExts())).toBeNull();
    // a 2-byte SPL with the DER sign pad (>= 128) parses and binds
    const hiReport = parseSevSnpReport(serializeSevSnpReport({ version: 2, vmpl: 0, reported_tcb: 0xdb03_0000_0000_0007n, report_data: new Uint8Array(64), measurement: new Uint8Array(48), chip_id: FORGE_CHIP }));
    expect(checkVcekReportBinding(tbsWith(amdVcekExtensions({ ...spl, ucode: 0xdb })), hiReport)).toBeNull();
  });
  it('a duplicated hwID extension is rejected (an attacker cannot hide a second value)', () => {
    expect(binding([...goodExts(), extension(AMD_OID.hwid, false, new Uint8Array(64).fill(1))])).toBe(`VCEK extensions malformed: duplicate extension ${AMD_OID.hwid}`);
  });
  it('a duplicated SPL extension is rejected', () => {
    expect(binding([...goodExts(), extension(AMD_OID.snp, false, integer(3))])).toBe(`VCEK extensions malformed: duplicate extension ${AMD_OID.snp}`);
  });
  it('the AMD OID bytes appearing inside another extension value are NOT mistaken for extensions', () => {
    const decoy = extension('1.2.3.4.5', false, octets(cat(...[AMD_OID.hwid, AMD_OID.bl, AMD_OID.tee, AMD_OID.snp, AMD_OID.ucode].map((o) => oid(o)), new Uint8Array(70))));
    expect(binding([decoy])).toBe('VCEK certificate has no CHIP_ID (hwID) extension');
  });
  it('hwID of the wrong length (63, 65, or the old 66-byte inner-wrapped form) is rejected', () => {
    for (const bad of [new Uint8Array(63), new Uint8Array(65), cat(Uint8Array.of(0x04, 0x40), FORGE_CHIP)]) {
      expect(binding([...goodExts().slice(0, 4), extension(AMD_OID.hwid, false, bad)])).toBe(`VCEK CHIP_ID (hwID) extension is ${bad.length} bytes, expected 64`);
    }
  });
  it('a critical hwID / SPL extension is rejected (the AMD profile is non-critical)', () => {
    expect(binding([...goodExts().slice(0, 4), extension(AMD_OID.hwid, true, FORGE_CHIP)])).toBe('VCEK CHIP_ID (hwID) extension is marked critical (the AMD profile is non-critical)');
    expect(binding([splExt('bl', integer(7), true), ...goodExts().slice(1)])).toBe('VCEK bootloader SPL extension is marked critical (the AMD profile is non-critical)');
  });
  it('a mismatching chip id is rejected', () => {
    expect(binding([...goodExts().slice(0, 4), extension(AMD_OID.hwid, false, new Uint8Array(64).fill(1))])).toBe('VCEK CHIP_ID does not match report chip_id');
  });
  it('missing SPL extensions are named', () => {
    const a = goodExts();
    expect(binding([a[1]!, a[2]!, a[3]!, a[4]!])).toBe('VCEK certificate has no bootloader SPL extension');
    expect(binding([a[0]!, a[2]!, a[3]!, a[4]!])).toBe('VCEK certificate has no tee SPL extension');
    expect(binding([a[0]!, a[1]!, a[3]!, a[4]!])).toBe('VCEK certificate has no snp SPL extension');
    expect(binding([a[0]!, a[1]!, a[2]!, a[4]!])).toBe('VCEK certificate has no microcode SPL extension');
  });
  it('malformed SPL encodings are rejected with the specific reason', () => {
    const withBl = (v: Uint8Array) => [splExt('bl', v), ...goodExts().slice(1)];
    expect(binding(withBl(Uint8Array.of(0x07)))).toBe('VCEK bootloader SPL extension is not a DER INTEGER'); // bare byte (the old tolerated form)
    expect(binding(withBl(Uint8Array.of(0x04, 0x01, 0x07)))).toBe('VCEK bootloader SPL extension is not a DER INTEGER');
    expect(binding(withBl(Uint8Array.of(0x02, 0x03, 0x00, 0x00, 0x07)))).toBe('VCEK bootloader SPL extension has a wrong-length INTEGER');
    expect(binding(withBl(Uint8Array.of(0x02, 0x00)))).toBe('VCEK bootloader SPL extension is not a DER INTEGER');
    expect(binding(withBl(Uint8Array.of(0x02, 0x01, 0x07, 0x00)))).toBe('VCEK bootloader SPL extension has a wrong-length INTEGER'); // trailing byte
    expect(binding(withBl(Uint8Array.of(0x02, 0x01, 0x87)))).toBe('VCEK bootloader SPL extension is negative');
    expect(binding(withBl(Uint8Array.of(0x02, 0x02, 0x01, 0x07)))).toBe('VCEK bootloader SPL extension is out of range (> 255)');
    expect(binding(withBl(Uint8Array.of(0x02, 0x02, 0x00, 0x07)))).toBe('VCEK bootloader SPL extension is a non-minimal INTEGER');
  });
  it('an SPL that disagrees with the report is a TCB downgrade', () => {
    expect(checkVcekReportBinding(tbsWith(amdVcekExtensions({ ...spl, bl: 2 })), REPORT)).toBe('VCEK bootloader SPL 2 does not match report reported_tcb (7) — TCB downgrade?');
  });
  it('a structurally broken extension table surfaces as a malformed-extensions failure (fail closed)', () => {
    expect(checkVcekReportBinding(Uint8Array.of(1, 2, 3), REPORT)).toMatch(/^VCEK extensions malformed: /);
  });
});

describe('parseTbsExtensions / parseCertExtensions: structural strictness', () => {
  const asBlock = (...exts: Uint8Array[]) => ctx(3, seq(...exts));
  it('returns each extension with its critical flag and exact value bytes', () => {
    const m = parseTbsExtensions(tbsWith([ext.basicConstraints(true, 0), ...goodExts()]));
    expect(m.get('2.5.29.19')?.critical).toBe(true);
    expect(m.get(AMD_OID.hwid)?.critical).toBe(false);
    expect([...m.get(AMD_OID.hwid)!.value]).toEqual([...FORGE_CHIP]);
    expect(m.size).toBe(6);
  });
  it('rejects trailing bytes after the TBS, after the certificate, an empty block, and a duplicate [3] block', () => {
    expect(() => parseTbsExtensions(cat(tbsWith(goodExts()), Uint8Array.of(0)))).toThrow('trailing bytes after tbsCertificate');
    const cert = forgeCert({ subject: [['CN', 'v']], issuer: [['CN', 'i']], subjectKey: forgeKey('s', 'P-384'), signer: forgeKey('g', 'P-384'), serial: 1n, notBefore: FORGE_NB, notAfter: FORGE_NA, extensions: goodExts() });
    expect(() => parseCertExtensions(cat(cert.der, Uint8Array.of(0)))).toThrow('trailing bytes after the certificate');
    expect(parseCertExtensions(cert.der).size).toBe(5);
    expect(() => parseTbsExtensions(tbsWith(goodExts(), asBlock()))).toThrow('empty Extensions SEQUENCE');
    const block = asBlock(...goodExts());
    expect(() => parseTbsExtensions(tbsWith(goodExts(), cat(block, block)))).toThrow('duplicate [3] extensions block');
  });
  it('rejects a [3] block that is not last, and trailing bytes inside the Extensions SEQUENCE', () => {
    expect(() => parseTbsExtensions(tbsWith(goodExts(), cat(asBlock(...goodExts()), tlv(0xa1, Uint8Array.of(1)))))).toThrow('extensions block is not the last TBS element');
    expect(() => parseTbsExtensions(tbsWith(goodExts(), ctx(3, cat(seq(...goodExts()), Uint8Array.of(0, 0)))))).toThrow('trailing bytes after the Extensions SEQUENCE');
    expect(() => parseTbsExtensions(tbsWith(goodExts(), ctx(3, tlv(0x31, Uint8Array.of()))))).toThrow('extensions is not a SEQUENCE');
  });
  it('rejects non-DER critical flags, trailing bytes inside an Extension, a non-OCTET value, and a bad OID', () => {
    const one = (inner: Uint8Array) => () => parseTbsExtensions(tbsWith([], asBlock(inner)));
    expect(one(seq(oid('1.2.3'), tlv(0x01, Uint8Array.of(0x00)), octets(Uint8Array.of(1))))).toThrow('extension 1.2.3 has a non-DER critical flag');
    expect(one(seq(oid('1.2.3'), tlv(0x01, Uint8Array.of(0x01)), octets(Uint8Array.of(1))))).toThrow('extension 1.2.3 has a non-DER critical flag');
    expect(one(seq(oid('1.2.3'), octets(Uint8Array.of(1)), octets(Uint8Array.of(2))))).toThrow('extension 1.2.3 has trailing bytes');
    expect(one(seq(oid('1.2.3'), tlv(0x04 + 1, Uint8Array.of(1))))).toThrow('extension 1.2.3 value is not an OCTET STRING');
    expect(one(tlv(0x31, Uint8Array.of()))).toThrow('extension is not a SEQUENCE');
    expect(one(seq(tlv(0x04, Uint8Array.of(0x2a)), octets(Uint8Array.of(1))))).toThrow('extension OID is malformed');
    expect(one(seq(tlv(0x06, Uint8Array.of(0x2a, 0x80, 0x01)), octets(Uint8Array.of(1))))).toThrow('extension OID has a non-minimal arc');
    expect(one(seq(tlv(0x06, Uint8Array.of(0x2a, 0x83)), octets(Uint8Array.of(1))))).toThrow('extension OID is truncated');
    expect(one(seq(tlv(0x06, Uint8Array.of()), octets(Uint8Array.of(1))))).toThrow('extension OID is malformed');
  });
  it('decodes first-arc forms (0.x, 1.x, 2.x) and a critical TRUE flag', () => {
    const m = parseTbsExtensions(tbsWith([], asBlock(extension('0.9.1', true, octets(Uint8Array.of(1))), extension('1.39.5', false, octets(Uint8Array.of(1))), extension('2.100.3', false, octets(Uint8Array.of(1))))));
    expect([...m.keys()]).toEqual(['0.9.1', '1.39.5', '2.100.3']);
    expect(m.get('0.9.1')?.critical).toBe(true);
  });
});

describe('createAmdSnpVerifier: clock + failure surfaces (REAL Genoa evidence)', () => {
  const fx = (f: string) => readFileSync(resolve(__dirname, '..', 'fixtures', 'real-azure-maa', f));
  const HCL = new Uint8Array(fx('sevsnp-hcl-report.bin'));
  const report = HCL.slice(32, 32 + 1184);
  const evidence = { report, vcekDer: genoaVcek, askArkPem: REAL_GENOA.certificateChain, runtimeData: new Uint8Array(fx('sevsnp-runtime-data.json')) };
  const meas = Buffer.from(parseSevSnpReport(report).measurement).toString('hex');
  const EXPECTED: ExpectedAttestationBinding = { holderPub: 'pca-realsilicon-azure-tdx-holder', grantRef: 'grant_pca_azure_maa_realsilicon', epoch: 1, nonce: 'srv-nonce-maa-5d3b8e1f9a27c604' };
  const DOC = {} as unknown as AttestationDocument;
  const mk = (resolveEvidence: () => unknown, clockSkewMs?: number) =>
    createAmdSnpVerifier({ family: 'genoa', binding: 'azure-runtime-data', policy: { measurements: [meas] }, resolveEvidence: resolveEvidence as never, ...(clockSkewMs !== undefined ? { clockSkewMs } : {}) });
  const run = (v: ReturnType<typeof mk>, nowMs: number) => v.verify({ document: DOC, ctx: {} as never, nowMs, expected: EXPECTED });
  const vcekCert = new X509Certificate(Buffer.from(genoaVcek));

  it('threads input.nowMs to the chain check: past the VCEK expiry it fails with the chain reason', async () => {
    expect(await run(mk(() => evidence), vcekCert.validToDate.getTime() + 1)).toEqual({ ok: false, reason: 'SEV-SNP report invalid: cert chain invalid: VCEK certificate has expired' });
    expect(await run(mk(() => evidence), vcekCert.validFromDate.getTime() - 1)).toEqual({ ok: false, reason: 'SEV-SNP report invalid: cert chain invalid: VCEK certificate is not yet valid' });
  });
  it('clockSkewMs lets a slightly-early clock through the not-before edge', async () => {
    const early = vcekCert.validFromDate.getTime() - 5000;
    const r = await run(mk(() => evidence, 10_000), early);
    expect(r.reason).toBeUndefined();
    expect(r.ok).toBe(true);
  });
  it('a throwing evidence resolver fails closed with its message', async () => {
    const r = await run(mk(() => { throw new Error('boom'); }), NOW);
    expect(r).toEqual({ ok: false, reason: 'amd-snp verification error (fail closed): boom' });
  });
  it('missing evidence / missing expected binding fail closed with the specific reason', async () => {
    expect(await run(mk(() => undefined), NOW)).toEqual({ ok: false, reason: 'no AMD SEV-SNP evidence for this action' });
    const v = mk(() => evidence);
    expect(await v.verify({ document: DOC, ctx: {} as never, nowMs: NOW } as never)).toEqual({ ok: false, reason: 'no expected attestation binding supplied' });
  });
  it('azure-runtime-data binding without the runtime JSON fails closed', async () => {
    const { runtimeData: _drop, ...noRt } = evidence;
    expect(await run(mk(() => noRt), NOW)).toEqual({ ok: false, reason: 'azure-runtime-data binding needs the runtime-data JSON bytes' });
  });
});
