/**
 * Tests for NVIDIA GPU-CC collateral: REAL RIMs (driver + VBIOS) fetched from NVIDIA's RIM service on 2026-10-08,
 * the REAL H100 report from `fixtures/real-nvidia-cc`, and NVIDIA's REAL CRLs. Revocation of a listed serial is
 * exercised against a clearly-labelled SYNTHETIC P-384 chain (we hold no NVIDIA CA keys).
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it, expect } from 'vitest';
import {
  createNvidiaSpdmVerifier,
  parseNvidiaSpdmEvidence,
  parsePemChain,
  type ParsedNvidiaSpdmReport,
} from './attest-nvidia-spdm';
import {
  verifyNvidiaRim,
  nvidiaRimIdsForReport,
  compareReportToRims,
  checkNvidiaChainRevocation,
  nvidiaCollateralHook,
  formatVbiosVersion,
  fetchNvidiaRim,
  type NvidiaCollateralBundle,
  type NvidiaFirmwarePolicy,
} from './attest-nvidia-rim';
import type { AttestationDocument, ExpectedAttestationBinding } from './attestation';

const FX = (...p: string[]) => resolve(__dirname, '..', 'fixtures', 'real-nvidia-cc', ...p);
const text = (...p: string[]) => readFileSync(FX(...p), 'utf8');
const bytes = (...p: string[]) => new Uint8Array(readFileSync(FX(...p)));

const REPORT = bytes('h100-gpu-attestation-report.bin');
const CHAIN_PEM = text('h100-device-cert-chain.pem');
const DRIVER_XML = text('collateral', 'driver-rim-NV_GPU_DRIVER_GH100_580.95.05.xml');
const VBIOS_XML = text('collateral', 'vbios-rim-NV_GPU_VBIOS_G520_0280_895_9600D00003.xml');
const L2 = bytes('collateral', 'l2-gh100.crl');
const L1 = bytes('collateral', 'l1-root.crl');

const DEVICE_ROOT_SPKI = 'a90c4eb5acfd3e3d03a25db6a26b84f720ad0503196c627c21ddd48dd85b06a4';
/** NVIDIA CoRIM signing root — equals verifier_RIM_root.pem shipped with NVIDIA's local verifier. */
const RIM_ROOT_SPKI = 'dec1dc316477aa851eebdf51327ae9f864bc8d89254657ed1e7eb9168af1e1a3';
const NOW_MS = 1_791_498_000_000;
const EXPECTED: ExpectedAttestationBinding = {
  holderPub: 'pca-realsilicon-nvidia-h100-holder',
  grantRef: 'grant_pca_nvidia_gpucc_realsilicon',
  epoch: 1,
  nonce: 'srv-nonce-nv-7c1e9f2a4b8d0536',
};

const report = parseNvidiaSpdmEvidence(REPORT);
/** Flip the last hex digit of the first golden hash (deterministic, always changes the document). */
const withFlippedHash = (xml: string) => xml.replace(/Hash0="([0-9a-f]{95})([0-9a-f])"/, (_m, a: string, b: string) => `Hash0="${a}${b === '0' ? '1' : '0'}"`);
const verifyRim = (xml: string, spki = RIM_ROOT_SPKI, nowMs = NOW_MS) => verifyNvidiaRim(xml, { rimRootSpkiSha256: [spki], nowMs });

async function realRims() {
  const d = await verifyRim(DRIVER_XML);
  const v = await verifyRim(VBIOS_XML);
  if (!d.ok || !v.ok) throw new Error('real RIMs must verify');
  return { d: d.rim, v: v.rim };
}

describe('NVIDIA RIM — REAL signed manifests', () => {
  it('names the RIMs from the GPU report exactly as NVIDIA does', () => {
    const ids = nvidiaRimIdsForReport(report)!;
    expect(ids.driver).toBe('NV_GPU_DRIVER_GH100_580.95.05');
    expect(ids.vbios).toBe('NV_GPU_VBIOS_G520_0280_895_9600D00003');
    expect(formatVbiosVersion(Uint8Array.from([0x00, 0xd0, 0x00, 0x96, 0x03, 0, 0, 0]))).toBe('96.00.d0.00.03');
  });

  it('verifies the real driver and VBIOS RIMs (XMLDSig, C14N 1.1, ECDSA-SHA384, chain to the pinned root)', async () => {
    const { d, v } = await realRims();
    expect(d.version).toBe('580.95.05');
    expect(d.product).toBe('GH100');
    expect([...d.golden.values()].filter((g) => g.active).length).toBe(22);
    expect(v.version).toBe('96.00.D0.00.03');
    expect([...v.golden.values()].filter((g) => g.active).length).toBe(12);
    expect(d.signerSubject).toContain('HCC RIM');
  });

  it('the real H100 report matches NVIDIA golden values at 33 indices (block 35 exempt: NVDEC0 disabled)', async () => {
    const { d, v } = await realRims();
    const r = compareReportToRims(report, d, v);
    expect(r).toEqual({ ok: true, checked: 33 });
  });

  it('NVDEC0 rule: block 35 is ignored when NVDEC0 is DISABLED and enforced when ENABLED', async () => {
    const { d, v } = await realRims();
    const corrupt = (opaqueStatus: number): ParsedNvidiaSpdmReport => {
      const ms = report.response.measurements.map((m) => ({ ...m, digest: new Uint8Array(m.digest) }));
      const b35 = ms.find((m) => m.index === 35)!;
      b35.digest[0] = (b35.digest[0] ?? 0) ^ 0x01;
      const opaque = new Map(report.response.opaque);
      opaque.set(11, Uint8Array.from([opaqueStatus]));
      return { ...report, response: { ...report.response, measurements: ms, opaque } };
    };
    expect(compareReportToRims(corrupt(0x55), d, v)).toEqual({ ok: true, checked: 33 }); // disabled: skipped
    const enabled = compareReportToRims(corrupt(0xaa), d, v); // enabled: compared
    expect(enabled.ok).toBe(false);
    if (!enabled.ok) expect(enabled.mismatches).toEqual([{ index: 34, source: 'driver' }]);
    // and the untouched real report passes either way (its block 35 equals the golden value)
    const opaque = new Map(report.response.opaque);
    opaque.set(11, Uint8Array.from([0xaa]));
    expect(compareReportToRims({ ...report, response: { ...report.response, opaque } }, d, v)).toEqual({ ok: true, checked: 34 });
  });

  it('fails closed on a changed measurement, a missing block, and a driver/VBIOS index conflict', async () => {
    const { d, v } = await realRims();
    const ms = report.response.measurements.map((m) => ({ ...m, digest: new Uint8Array(m.digest) }));
    ms[1]!.digest[0] = (ms[1]!.digest[0] ?? 0) ^ 0x01; // block 2 = golden index 1
    expect(compareReportToRims({ ...report, response: { ...report.response, measurements: ms } }, d, v).ok).toBe(false);
    const fewer = report.response.measurements.slice(0, 10);
    expect(compareReportToRims({ ...report, response: { ...report.response, measurements: fewer } }, d, v).ok).toBe(false);
    expect(compareReportToRims(report, d, d).ok).toBe(false); // same active indices in both
  });

  it('fails closed: tampered golden hash, tampered signature, wrong root pin, outside signer validity', async () => {
    expect(withFlippedHash(DRIVER_XML)).not.toBe(DRIVER_XML);
    expect((await verifyRim(withFlippedHash(DRIVER_XML))).ok).toBe(false);
    const sigVal = DRIVER_XML.match(/<ds:SignatureValue>([^<]+)</)?.[1] ?? DRIVER_XML.match(/<SignatureValue[^>]*>([^<]+)</)?.[1];
    expect(sigVal).toBeTruthy();
    const badSig = Buffer.from(sigVal!.replace(/\s+/g, ''), 'base64');
    badSig[5] = (badSig[5] ?? 0) ^ 0x01;
    expect((await verifyRim(DRIVER_XML.replace(sigVal!, badSig.toString('base64')))).ok).toBe(false);
    expect((await verifyRim(DRIVER_XML, '00'.repeat(32))).ok).toBe(false);
    expect((await verifyRim(DRIVER_XML, RIM_ROOT_SPKI, 0)).ok).toBe(false);
  });

  it('fails closed on XMLDSig profile violations (wrapping, comments, DTD, wrong algorithms, URI)', async () => {
    const sigBlock = DRIVER_XML.match(/<ds:Signature[\s\S]*<\/ds:Signature>/)![0];
    // signature wrapping: a second Signature element
    expect((await verifyRim(DRIVER_XML.replace('</SoftwareIdentity>', `${sigBlock}</SoftwareIdentity>`))).ok).toBe(false);
    // comment injected into the signed content
    expect((await verifyRim(DRIVER_XML.replace('<ns0:Payload', '<!-- x --><ns0:Payload'))).ok).toBe(false);
    // DOCTYPE
    expect((await verifyRim(`<!DOCTYPE SoftwareIdentity [<!ENTITY a "b">]>${DRIVER_XML}`)).ok).toBe(false);
    // downgraded algorithms / reference URI
    expect((await verifyRim(DRIVER_XML.replace('xmldsig-more#ecdsa-sha384', 'xmldsig-more#ecdsa-sha256'))).ok).toBe(false);
    expect((await verifyRim(DRIVER_XML.replace(/Reference URI=""/, 'Reference URI="#x"'))).ok).toBe(false);
    // xml:* attribute (breaks the C14N 1.1 == 1.0 precondition)
    expect((await verifyRim(DRIVER_XML.replace('<ns0:Payload', '<ns0:Payload xml:lang="en"'))).ok).toBe(false);
    // garbage / empty
    expect((await verifyRim('')).ok).toBe(false);
    expect((await verifyRim('<not-xml')).ok).toBe(false);
  });
});

describe('NVIDIA chain revocation', () => {
  const chain = parsePemChain(CHAIN_PEM);

  it('passes with NVIDIA\'s real CRLs (both currently empty) and covers the required issuers', () => {
    const r = checkNvidiaChainRevocation(chain, [L2, L1], NOW_MS, ['NVIDIA GH100 Identity', 'NVIDIA Device Identity CA']);
    expect(r).toEqual({ ok: true, verifiedCrls: 2 });
  });

  it('fails closed: no CRLs, a corrupted CRL, a stale clock, a foreign CRL, a missing required issuer', () => {
    expect(checkNvidiaChainRevocation(chain, [], NOW_MS).ok).toBe(false);
    const bad = new Uint8Array(L2);
    bad[bad.length - 3] = (bad[bad.length - 3] ?? 0) ^ 0x01;
    expect(checkNvidiaChainRevocation(chain, [bad], NOW_MS).ok).toBe(false);
    expect(checkNvidiaChainRevocation(chain, [L2, L1], new Date('2031-01-01').getTime()).ok).toBe(false);
    const foreign = bytes('collateral', 'synthetic', 'ica-clean.der');
    expect(checkNvidiaChainRevocation(chain, [foreign], NOW_MS).ok).toBe(false);
    expect(checkNvidiaChainRevocation(chain, [L1], NOW_MS, ['NVIDIA GH100 Identity']).ok).toBe(false);
  });

  it('SYNTHETIC chain: a CRL that lists the leaf serial is rejected; the clean CRL passes', () => {
    const SYNTH_NOW = Date.parse('2027-01-01T00:00:00Z'); // after the CRLs were generated (thisUpdate must not be in the future)
    const synth = parsePemChain(text('collateral', 'synthetic', 'chain.pem'));
    expect(checkNvidiaChainRevocation(synth, [bytes('collateral', 'synthetic', 'ica-clean.der')], SYNTH_NOW).ok).toBe(true);
    const r = checkNvidiaChainRevocation(synth, [bytes('collateral', 'synthetic', 'ica-revoked.der')], SYNTH_NOW);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain('revoked');
  });
});

describe('NVIDIA collateral wired into the SPDM verifier (postVerify hook)', () => {
  const DOC = {} as unknown as AttestationDocument;
  const CTX = {} as never;
  const bundle = (over: Partial<NvidiaCollateralBundle> = {}): NvidiaCollateralBundle => ({ driverRimXml: DRIVER_XML, vbiosRimXml: VBIOS_XML, crls: [L2, L1], ...over });
  const verifier = (b: NvidiaCollateralBundle | undefined, extra: { requireCrls?: boolean } = {}) =>
    createNvidiaSpdmVerifier({
      rootSpkiSha256: [DEVICE_ROOT_SPKI],
      policy: { measurements: {}, leafSubjectIncludes: 'GH100' },
      resolveEvidence: () => ({ evidence: REPORT, certChainPem: CHAIN_PEM }),
      postVerify: nvidiaCollateralHook({
        rimRootSpkiSha256: [RIM_ROOT_SPKI],
        resolve: () => b,
        requireCrlIssuers: ['NVIDIA GH100 Identity', 'NVIDIA Device Identity CA'],
        ...extra,
      }),
    });
  const run = (v: ReturnType<typeof verifier>, expected = EXPECTED) => v.verify({ document: DOC, ctx: CTX, nowMs: NOW_MS, expected });

  it('verifies the real H100 end to end with NO operator-pinned digests: RIM golden values + revocation instead', async () => {
    const r = await run(verifier(bundle()));
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.bound).toBe(true);
  });

  it('still enforces binding, signature and chain before collateral', async () => {
    expect((await run(verifier(bundle()), { ...EXPECTED, holderPub: 'someone-else' })).ok).toBe(false);
  });

  it('fails closed: no collateral, swapped RIMs, tampered RIM, missing CRLs', async () => {
    expect((await run(verifier(undefined))).ok).toBe(false);
    expect((await run(verifier(bundle({ driverRimXml: VBIOS_XML, vbiosRimXml: DRIVER_XML })))).ok).toBe(false);
    expect((await run(verifier(bundle({ driverRimXml: withFlippedHash(DRIVER_XML) })))).ok).toBe(false);
    expect((await run(verifier(bundle({ crls: [] })))).ok).toBe(false);
  });

  it('refuses accept-all: empty pinned measurements AND no collateral hook', () => {
    expect(() => createNvidiaSpdmVerifier({ rootSpkiSha256: [DEVICE_ROOT_SPKI], policy: { measurements: {} } })).toThrow();
    expect(() => nvidiaCollateralHook({ rimRootSpkiSha256: [], resolve: () => undefined })).toThrow();
  });
});

describe('NVIDIA collateral: OCSP revocation through the same hook (real responses from ocsp.ndis.nvidia.com)', () => {
  const DOC = {} as unknown as AttestationDocument;
  const CTX = {} as never;
  const OCSP_NOW = Date.parse('2026-10-08T23:08:00Z'); // responses were produced 23:07:30Z, valid 24h
  const resp = (n: string) => bytes('ocsp', `${n}.nononce.resp.der`);
  const GOOD = [resp('1-brom'), resp('2-provisioner-ica'), resp('3-identity')];
  const verifier = (b: NvidiaCollateralBundle, revocation: 'crl' | 'ocsp' | 'both') =>
    createNvidiaSpdmVerifier({
      rootSpkiSha256: [DEVICE_ROOT_SPKI],
      policy: { measurements: {}, leafSubjectIncludes: 'GH100' },
      resolveEvidence: () => ({ evidence: REPORT, certChainPem: CHAIN_PEM }),
      postVerify: nvidiaCollateralHook({ rimRootSpkiSha256: [RIM_ROOT_SPKI], resolve: () => b, revocation, requireCrlIssuers: ['NVIDIA GH100 Identity', 'NVIDIA Device Identity CA'] }),
    });
  const run = (v: ReturnType<typeof verifier>) => v.verify({ document: DOC, ctx: CTX, nowMs: OCSP_NOW, expected: EXPECTED });
  const base = (): NvidiaCollateralBundle => ({ driverRimXml: DRIVER_XML, vbiosRimXml: VBIOS_XML });

  it('revocation "ocsp": RIM golden values + NVIDIA OCSP "good" for the chain, with NO CRLs', async () => {
    expect((await run(verifier({ ...base(), ocsp: GOOD }, 'ocsp'))).ok).toBe(true);
  });

  it('revocation "both": CRLs and OCSP must both hold', async () => {
    expect((await run(verifier({ ...base(), crls: [L2, L1], ocsp: GOOD }, 'both'))).ok).toBe(true);
    expect((await run(verifier({ ...base(), ocsp: GOOD }, 'both'))).ok).toBe(false); // CRLs required but absent
    expect((await run(verifier({ ...base(), crls: [L2, L1] }, 'both'))).ok).toBe(false); // OCSP required but absent
  });

  it('fails closed: no OCSP evidence when required, a tampered response, the responder\'s "unauthorized" for the leaf', async () => {
    expect((await run(verifier({ ...base() }, 'ocsp'))).ok).toBe(false);
    const bad = new Uint8Array(GOOD[1]!);
    bad[bad.length - 8] = (bad[bad.length - 8] ?? 0) ^ 0x01;
    expect((await run(verifier({ ...base(), ocsp: [GOOD[0]!, bad, GOOD[2]!] }, 'ocsp'))).ok).toBe(false);
    const withLeaf = await run(verifier({ ...base(), ocsp: [resp('0-leaf-fmc'), ...GOOD] }, 'ocsp'));
    expect(withLeaf.ok).toBe(false);
  });

  it('fails closed: a stale clock rejects otherwise-good OCSP responses', async () => {
    const v = verifier({ ...base(), ocsp: GOOD }, 'ocsp');
    const r = await v.verify({ document: DOC, ctx: CTX, nowMs: OCSP_NOW + 30 * 3600 * 1000, expected: EXPECTED });
    expect(r.ok).toBe(false);
  });
});

describe('NVIDIA firmware version policy (min / deny, on the versions the GPU itself reports)', () => {
  const DOC = {} as unknown as AttestationDocument;
  const CTX = {} as never;
  const verifier = (firmware: Parameters<typeof nvidiaCollateralHook>[0]['firmware']) =>
    createNvidiaSpdmVerifier({
      rootSpkiSha256: [DEVICE_ROOT_SPKI],
      policy: { measurements: {}, leafSubjectIncludes: 'GH100' },
      resolveEvidence: () => ({ evidence: REPORT, certChainPem: CHAIN_PEM }),
      postVerify: nvidiaCollateralHook({ rimRootSpkiSha256: [RIM_ROOT_SPKI], resolve: () => ({ driverRimXml: DRIVER_XML, vbiosRimXml: VBIOS_XML, crls: [L2, L1] }), ...(firmware ? { firmware } : {}) }),
    });
  const run = (v: ReturnType<typeof verifier>) => v.verify({ document: DOC, ctx: CTX, nowMs: NOW_MS, expected: EXPECTED });
  // the fixture GPU reports driver 580.95.05 and VBIOS 96.00.d0.00.03

  it('accepts at / above the floor; compares numerically (not as strings) and VBIOS as hex', async () => {
    expect((await run(verifier({ minDriverVersion: '580.95.05' }))).ok).toBe(true);
    expect((await run(verifier({ minDriverVersion: '580.9.99' }))).ok).toBe(true); // 95 > 9 numerically
    expect((await run(verifier({ minDriverVersion: '570' }))).ok).toBe(true);
    expect((await run(verifier({ minVbiosVersion: '96.00.9f.00.04' }))).ok).toBe(true); // 0xd0 > 0x9f
    expect((await run(verifier({ minVbiosVersion: '96.00.d0.00.03' }))).ok).toBe(true);
  });

  it('rejects below the floor, on the deny list, and says which rule', async () => {
    const cases: Array<[NvidiaFirmwarePolicy, RegExp]> = [
      [{ minDriverVersion: '580.95.06' }, /below the minimum/],
      [{ minDriverVersion: '595.71.05' }, /below the minimum/],
      [{ minVbiosVersion: '96.00.d0.00.04' }, /VBIOS .* below/],
      [{ denyDriverVersions: ['580.95.05'] }, /deny list/],
      [{ denyVbiosVersions: ['96.00.D0.00.03'] }, /deny list/],
    ];
    for (const [fw, rx] of cases) {
      const r = await run(verifier(fw));
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toMatch(rx);
    }
  });

  it('rejects malformed policy strings at construction (no silent no-op)', () => {
    for (const fw of [{ minDriverVersion: 'abc' }, { minVbiosVersion: '96.zz' }, { denyDriverVersions: ['5.x'] }, { minDriverVersion: '' + '580..1' }]) {
      expect(() => nvidiaCollateralHook({ rimRootSpkiSha256: [RIM_ROOT_SPKI], resolve: () => undefined, firmware: fw })).toThrow();
    }
  });
});

describe('guarded fetch helpers', () => {
  it('fetchNvidiaRim decodes the service envelope and rejects bad ids / HTTP errors', async () => {
    const fakeFetch = (async (url: string) => ({ ok: true, status: 200, json: async () => ({ rim: Buffer.from(`<x id="${url.split('/').pop()}"/>`).toString('base64') }) })) as unknown as typeof fetch;
    expect(await fetchNvidiaRim('NV_GPU_DRIVER_GH100_580.95.05', { fetch: fakeFetch })).toContain('NV_GPU_DRIVER_GH100_580.95.05');
    await expect(fetchNvidiaRim('../etc/passwd', { fetch: fakeFetch })).rejects.toThrow();
    const notFound = (async () => ({ ok: false, status: 404 })) as unknown as typeof fetch;
    await expect(fetchNvidiaRim('NV_GPU_DRIVER_GH100_0', { fetch: notFound })).rejects.toThrow(/404/);
  });
});
