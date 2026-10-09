/**
 * Branch coverage for the NVIDIA GPU-CC verifiers (SPDM, RIM, CRL, OCSP) using the TEST-ONLY forger
 * (`test-support/forge-spdm.ts`).
 *
 * Real NVIDIA evidence cannot be re-signed, so a captured H100 report can never show a different golden measurement,
 * a mismatching driver, a revoked device certificate, an expired chain, ... These tests mint evidence in the REAL wire
 * formats (SPDM 1.1 transcript, 5-cert P-384 X.509 chain with NVIDIA's names, SWID RIM with enveloped XMLDSig, CRLs,
 * RFC 6960 OCSP) under a TEST root injected through the verifiers' existing SPKI pins. Production code is unmodified;
 * every negative asserts the SPECIFIC rejection reason.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { X509Certificate, createHash, verify as cryptoVerify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  NVIDIA_OPAQUE,
  createNvidiaSpdmVerifier,
  nvidiaSpdmChallenge,
  parseNvidiaSpdmEvidence,
  parsePemChain,
  spkiSha256Hex,
  verifyNvidiaDeviceChain,
  type NvidiaSpdmEvidence,
} from './attest-nvidia-spdm';
import {
  checkNvidiaChainRevocation,
  compareReportToRims,
  formatVbiosVersion,
  nvidiaCollateralHook,
  nvidiaRimIdsForReport,
  verifyNvidiaRim,
  type NvidiaCollateralBundle,
  type NvidiaCollateralOptions,
} from './attest-nvidia-rim';
import { checkNvidiaChainOcsp, verifyNvidiaOcspResponse } from './attest-nvidia-ocsp';
import type { AttestationDocument, ExpectedAttestationBinding } from './attestation';
import {
  NVDEC_GOLDEN_INDEX,
  OPAQUE_TYPE,
  RIM_ALG,
  SPDM,
  defaultOpaque,
  forgeCorimPki,
  forgeNvidiaCrl,
  forgeNvidiaDevicePki,
  forgeNvidiaScenario,
  forgeOcspResponderCert,
  forgeOcspResponse,
  forgeRim,
  forgeSpdmTranscript,
  goldenDigest,
  nvidiaDeviceNames,
  rimDigestB64,
  rimSignedInfoCanonical,
  type ForgeOcspOptions,
  type ForgeSpdmOptions,
  type ForgedNvidiaScenario,
  type RimMeasurementSpec,
} from './test-support/forge-spdm';
import { bytesToHex, derShape, forgeKey, hexToBytes, readDer } from './test-support/forge-x509';

// ── fixtures + helpers ───────────────────────────────────────────────────────────────────────────
const FX = (...p: string[]) => resolve(__dirname, '..', 'fixtures', 'real-nvidia-cc', ...p);
const bytes = (...p: string[]) => new Uint8Array(readFileSync(FX(...p)));
const text = (...p: string[]) => readFileSync(FX(...p), 'utf8');
const CERT_RE = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

const EXPECTED: ExpectedAttestationBinding = { holderPub: 'holder-forged-gpu', grantRef: 'grant_forged_gpu', epoch: 3, nonce: 'srv-nonce-gpu-forged' };
const CHALLENGE = nvidiaSpdmChallenge(EXPECTED);
const DOC = {} as unknown as AttestationDocument;
const CTX = {} as never;

const S = forgeNvidiaScenario({ challenge: CHALLENGE });
const NOW = S.nowMs;
const REPORT = parseNvidiaSpdmEvidence(S.spdm.evidence);
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
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
const names = nvidiaDeviceNames();

/** A fresh signed transcript from the scenario's device key. */
const transcript = (over: Partial<ForgeSpdmOptions> = {}, sc: ForgedNvidiaScenario = S) =>
  forgeSpdmTranscript({ signer: sc.device.leafKey, challenge: CHALLENGE, opaque: defaultOpaque(), ...over });
const evidenceOf = (over: Partial<ForgeSpdmOptions> = {}, sc: ForgedNvidiaScenario = S): NvidiaSpdmEvidence => ({ evidence: transcript(over, sc).evidence, certChainPem: sc.device.chainPem });
const bundleOf = (sc: ForgedNvidiaScenario = S, over: Partial<NvidiaCollateralBundle> = {}): NvidiaCollateralBundle => ({ driverRimXml: sc.driverRimXml, vbiosRimXml: sc.vbiosRimXml, crls: sc.crls, ocsp: sc.ocsp, ...over });
const hookOpts = (sc: ForgedNvidiaScenario, b: NvidiaCollateralBundle | undefined, over: Partial<NvidiaCollateralOptions> = {}): NvidiaCollateralOptions => ({
  rimRootSpkiSha256: [sc.rimRootSpkiSha256],
  resolve: () => b,
  revocation: 'both',
  ...over,
});
function verifierOf(sc: ForgedNvidiaScenario, ev: NvidiaSpdmEvidence | undefined, b: NvidiaCollateralBundle | undefined, over: Partial<NvidiaCollateralOptions> = {}, policy: { measurements?: Record<number, string>; leafSubjectIncludes?: string } = {}) {
  return createNvidiaSpdmVerifier({
    rootSpkiSha256: [sc.deviceRootSpkiSha256],
    policy: { measurements: policy.measurements ?? {}, leafSubjectIncludes: policy.leafSubjectIncludes ?? 'GH100' },
    resolveEvidence: () => ev,
    postVerify: nvidiaCollateralHook(hookOpts(sc, b, over)),
  });
}
const run = (v: ReturnType<typeof verifierOf>, expected: ExpectedAttestationBinding | null = EXPECTED, nowMs = NOW) => v.verify({ document: DOC, ctx: CTX, nowMs, ...(expected ? { expected } : {}) } as never);
/** Full pipeline on the scenario with optional overrides; returns the failure reason (or undefined on success). */
async function reasonOf(over: { ev?: NvidiaSpdmEvidence; bundle?: Partial<NvidiaCollateralBundle>; hook?: Partial<NvidiaCollateralOptions>; sc?: ForgedNvidiaScenario; nowMs?: number; expected?: ExpectedAttestationBinding } = {}) {
  const sc = over.sc ?? S;
  const r = await run(verifierOf(sc, over.ev ?? sc.evidence, bundleOf(sc, over.bundle), over.hook), over.expected ?? EXPECTED, over.nowMs ?? NOW);
  return r.ok ? undefined : r.reason;
}

const spec = (index: number, hash: string, over: Partial<RimMeasurementSpec> = {}): RimMeasurementSpec => ({ index, active: true, hashes: [hash], size: 48, ...over });
const verifyRim = (xml: string, sc: ForgedNvidiaScenario = S, nowMs = NOW) => verifyNvidiaRim(xml, { rimRootSpkiSha256: [sc.rimRootSpkiSha256], nowMs });
const rimXml = (measurements: readonly RimMeasurementSpec[], over: Partial<Parameters<typeof forgeRim>[0]> = {}, sc: ForgedNvidiaScenario = S) =>
  forgeRim({ version: '595.71.05', measurements, signerChain: sc.corim.certs, signerKey: sc.corim.signerKey, ...over });
const M1 = [spec(0, '11'.repeat(48))];

// ═════════════════════════════════════════════════════════════════════════════════════════════════
describe('forge-spdm: forged evidence is wire-equivalent to REAL H100 evidence', () => {
  const realReport = bytes('own-h100', 'h100-gpu-attestation-report.bin');
  const real = parseNvidiaSpdmEvidence(realReport);

  it('the transcript has the same size, framing, block layout and opaque TLV sequence as the real one', () => {
    expect(S.spdm.evidence.length).toBe(realReport.length); // 4129 bytes
    expect(S.spdm.request.length).toBe(SPDM.REQ_LEN);
    expect(hex(S.spdm.evidence.slice(0, 4))).toBe(hex(realReport.slice(0, 4))); // 11 e0 01 ff
    expect(hex(S.spdm.evidence.slice(37, 41))).toBe(hex(realReport.slice(37, 41))); // 11 60 00 00
    expect(REPORT.request.slot).toBe(real.request.slot);
    expect(REPORT.response.numBlocks).toBe(real.response.numBlocks);
    expect(hex(S.spdm.evidence.slice(45, 45 + 5))).toBe(hex(realReport.slice(45, 45 + 5))); // block 1 header (index, spec, size, type)
    expect(hex(S.spdm.evidence.slice(45 + 5, 45 + 7))).toBe(hex(realReport.slice(45 + 5, 45 + 7))); // DMTF size
    expect(REPORT.response.measurements.map((m) => [m.index, m.valueType, m.digest.length])).toEqual(real.response.measurements.map((m) => [m.index, m.valueType, m.digest.length]));
    expect([...REPORT.response.opaque.keys()]).toEqual([...real.response.opaque.keys()]);
    expect([...REPORT.response.opaque.values()].map((v) => v.length)).toEqual([...real.response.opaque.values()].map((v) => v.length));
    expect(S.spdm.layout.opaqueLen).toBe(434);
    expect(REPORT.response.signature.length).toBe(96);
    expect(REPORT.response.responderNonce.length).toBe(32);
  });

  it('the opaque fields name the same RIMs as the real report does (same derivation, same shape)', () => {
    const a = nvidiaRimIdsForReport(REPORT)!;
    const b = nvidiaRimIdsForReport(real)!;
    expect(a.driver).toBe('NV_GPU_DRIVER_GH100_595.71.05');
    expect(a.vbios).toBe(b.vbios); // identical project/sku/chip/vbios as the captured Azure H100
    expect(a.vbiosVersion).toBe('96.00.9f.00.04');
  });

  it('the device chain has the same ASN.1 skeleton, names and validity encodings as the real five certificates', () => {
    const rc = text('own-h100', 'h100-device-cert-chain.pem').match(CERT_RE)!.map((b) => new X509Certificate(b));
    const fc = S.device.chainPem.match(CERT_RE)!.map((b) => new X509Certificate(b));
    expect(fc.length).toBe(5);
    for (let i = 0; i < 5; i++) {
      const rd = new Uint8Array(rc[i]!.raw);
      const fd = new Uint8Array(fc[i]!.raw);
      expect(derShape(fd, readDer(fd), true), `cert ${i}`).toBe(derShape(rd, readDer(rd), true));
      expect(fc[i]!.subject.replace(/=[^\n]*/g, '=')).toBe(rc[i]!.subject.replace(/=[^\n]*/g, '='));
    }
    expect(fc.map((c) => c.subject.split('\n').find((l) => l.startsWith('CN=')))).toEqual(rc.map((c) => c.subject.split('\n').find((l) => l.startsWith('CN='))));
  });

  it('the CRLs match the real l2-gh100 / l1-root CRL skeleton (ecdsa-with-SHA256, CRL number + AKI)', () => {
    for (const [forged, file] of [[S.crls[0]!, 'l2-gh100.crl'], [S.crls[1]!, 'l1-root.crl']] as const) {
      const r = bytes('collateral', file);
      expect(derShape(forged, readDer(forged))).toBe(derShape(r, readDer(r)));
    }
  });

  it('the OCSP responses match the real responder layout (byKey id, nextUpdate, nonce extension, embedded delegated responder)', () => {
    const basic = (d: Uint8Array) => {
      const o = readDer(d).children![1]!.children![0]!.children![1]!;
      const inner = d.subarray(o.start, o.end);
      return derShape(inner, readDer(inner), false);
    };
    const responder = forgeOcspResponderCert(S.device.certs[3]!, S.device.keys[3]!);
    const forged = forgeOcspResponse({ cert: S.device.certs[2]!, issuer: S.device.certs[3]!, thisUpdate: new Date(NOW - 1000), nextUpdate: new Date(NOW + 86400_000), nonce: new Uint8Array(16).fill(5), responder: { kind: 'delegated', cert: responder } });
    expect(basic(forged)).toBe(basic(bytes('ocsp', '2-provisioner-ica.nonce.resp.der')));
    const noNonce = forgeOcspResponse({ cert: S.device.certs[2]!, issuer: S.device.certs[3]!, thisUpdate: new Date(NOW - 1000), nextUpdate: new Date(NOW + 86400_000), responder: { kind: 'delegated', cert: responder } });
    expect(basic(noNonce)).toBe(basic(bytes('ocsp', '2-provisioner-ica.nononce.resp.der')));
  });

  describe('RIM', () => {
    const realXml = text('own-h100', 'vbios-rim.xml');
    const lines = (x: string) =>
      x
        .replace(/="[^"]*"/g, '=""')
        .replace(/>[A-Za-z0-9+/=\s]{16,}</g, '><')
        .split('\n');
    it('has the same element/attribute skeleton, whitespace and Signature structure as a real NVIDIA RIM', () => {
      const isRes = (l: string) => l.includes('<ns0:Resource');
      const f = lines(S.vbiosRimXml);
      const r = lines(realXml);
      expect(f.filter((l) => !isRes(l))).toEqual(r.filter((l) => !isRes(l)));
      const realShapes = new Set(r.filter(isRes));
      for (const l of new Set(f.filter(isRes))) expect(realShapes.has(l), l).toBe(true);
      expect(f.filter(isRes).length).toBe(r.filter(isRes).length); // both carry 64 resources
    });
    it("the forger's enveloped-signature digest reproduces the REAL RIM's DigestValue (C14N/transform equivalence)", () => {
      expect(rimDigestB64(realXml)).toBe(/<ds:DigestValue>([^<]+)<\/ds:DigestValue>/.exec(realXml)![1]);
    });
    it("the forger's canonical SignedInfo verifies the REAL RIM's signature under NVIDIA's signer certificate", () => {
      const sig = Buffer.from(/<ds:SignatureValue>([^<]+)<\/ds:SignatureValue>/.exec(realXml)![1]!, 'base64');
      const leaf = new X509Certificate(`-----BEGIN CERTIFICATE-----\n${/<ds:X509Certificate>([^<]+)<\/ds:X509Certificate>/.exec(realXml)![1]!.replace(/\s+/g, '')}\n-----END CERTIFICATE-----`);
      expect(cryptoVerify('sha384', Buffer.from(rimSignedInfoCanonical(realXml), 'utf8'), { key: leaf.publicKey, dsaEncoding: 'ieee-p1363' }, sig)).toBe(true);
    });
  });

  it('is deterministic: identical options give byte-identical evidence', () => {
    const a = forgeNvidiaScenario({ challenge: CHALLENGE });
    expect(hex(a.spdm.evidence)).toBe(hex(S.spdm.evidence));
    expect(a.driverRimXml).toBe(S.driverRimXml);
    expect(a.device.chainPem).toBe(S.device.chainPem);
  });
});

// ═════════════════════════════════════════════════════════════════════════════════════════════════
describe('NVIDIA SPDM verifier on forged evidence (full chain: SPDM + RIM + CRL + OCSP)', () => {
  it('accepts the fully consistent forged scenario and surfaces driver / VBIOS versions in the NVIDIA rendering', async () => {
    const r = await run(verifierOf(S, S.evidence, bundleOf()));
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.bound).toBe(true);
      expect(r.hostAsserted).toMatchObject({ attestation_type: 'nvidia-gpu-cc', driver_version: '595.71.05', vbios_version: '96.00.9f.00.04' });
      expect(r.hostAsserted?.leaf_subject).toContain('CN=GH100 A01 GSP FMC LF');
      expect(r.measured?.runtime_measurement).toBe('');
    }
  });

  it('does not trust the forged root under NVIDIA\'s real pins', async () => {
    const v = createNvidiaSpdmVerifier({
      rootSpkiSha256: ['a90c4eb5acfd3e3d03a25db6a26b84f720ad0503196c627c21ddd48dd85b06a4'],
      policy: { measurements: { 2: hex(goldenDigest(2)) } },
      resolveEvidence: () => S.evidence,
    });
    expect((await run(v)).reason).toBe('chain root is not a pinned NVIDIA root');
    expect(S.deviceRootSpkiSha256).not.toBe('a90c4eb5acfd3e3d03a25db6a26b84f720ad0503196c627c21ddd48dd85b06a4');
    expect(await verifyRim(S.driverRimXml, { ...S, rimRootSpkiSha256: 'dec1dc316477aa851eebdf51327ae9f864bc8d89254657ed1e7eb9168af1e1a3' })).toEqual({ ok: false, reason: 'RIM signer chain: chain root is not a pinned NVIDIA root' });
  });

  describe('construction + plumbing', () => {
    it('refuses accept-all and out-of-range indices', () => {
      expect(() => createNvidiaSpdmVerifier({ rootSpkiSha256: [], policy: { measurements: { 1: 'aa' } } })).toThrow('rootSpkiSha256 must pin at least one NVIDIA root');
      expect(() => createNvidiaSpdmVerifier({ rootSpkiSha256: ['aa'], policy: { measurements: {} } })).toThrow('policy.measurements must be a NON-EMPTY pinned set');
      expect(() => createNvidiaSpdmVerifier({ rootSpkiSha256: ['aa'], policy: { measurements: { 256: 'aa' } } })).toThrow('measurement index out of range');
      expect(() => createNvidiaSpdmVerifier({ rootSpkiSha256: ['aa'], policy: { measurements: { 1.5: 'aa' } } })).toThrow('measurement index out of range');
      expect(() => nvidiaCollateralHook({ rimRootSpkiSha256: [], resolve: () => undefined })).toThrow('rimRootSpkiSha256 must pin at least one root');
    });
    it('fails closed with no resolver / no or non-bytes evidence / no expected binding / throwing resolver', async () => {
      const base = { rootSpkiSha256: [S.deviceRootSpkiSha256], policy: { measurements: { 2: hex(goldenDigest(2)) } } };
      expect((await run(createNvidiaSpdmVerifier(base))).reason).toBe('no NVIDIA GPU evidence resolver configured (fail closed)');
      expect((await run(createNvidiaSpdmVerifier({ ...base, resolveEvidence: () => undefined }))).reason).toBe('no NVIDIA GPU evidence for this action');
      expect((await run(createNvidiaSpdmVerifier({ ...base, resolveEvidence: () => ({ evidence: 'x' as never, certChainPem: S.device.chainPem }) }))).reason).toBe('no NVIDIA GPU evidence for this action');
      expect((await run(createNvidiaSpdmVerifier({ ...base, resolveEvidence: () => S.evidence }), null)).reason).toBe('no expected attestation binding supplied');
      const thrower = createNvidiaSpdmVerifier({
        ...base,
        resolveEvidence: () => {
          throw new Error('kaput');
        },
      });
      expect((await run(thrower)).reason).toBe('nvidia-spdm verification error (fail closed): kaput');
    });
    it('deriveIdentity is used when supplied', async () => {
      const v = createNvidiaSpdmVerifier({
        rootSpkiSha256: [S.deviceRootSpkiSha256],
        policy: { measurements: { 2: hex(goldenDigest(2)) }, deriveIdentity: (r) => ({ model_id: 'm', weights_digest: 'w', weights_measured: true, runtime_measurement: hex(r.response.measurements[0]!.digest), operator: 'op' }) },
        resolveEvidence: () => S.evidence,
      });
      const r = await run(v);
      expect(r.ok).toBe(true);
      expect(r.measured).toMatchObject({ model_id: 'm', operator: 'op', weights_measured: true });
    });
    it('an unbound binding is not constructible', async () => {
      const v = createNvidiaSpdmVerifier({ rootSpkiSha256: [S.deviceRootSpkiSha256], policy: { measurements: { 2: hex(goldenDigest(2)) } }, resolveEvidence: () => S.evidence });
      expect((await run(v, { ...EXPECTED, holderPub: '' })).reason).toBe('binding not constructible: binding: holderPub required');
    });
    it('a postVerify hook rejection is passed through verbatim; a missing hook with pinned digests passes', async () => {
      const v = createNvidiaSpdmVerifier({ rootSpkiSha256: [S.deviceRootSpkiSha256], policy: { measurements: { 2: hex(goldenDigest(2)) } }, resolveEvidence: () => S.evidence, postVerify: () => 'vetoed by policy' });
      expect((await run(v)).reason).toBe('vetoed by policy');
      const ok = createNvidiaSpdmVerifier({ rootSpkiSha256: [S.deviceRootSpkiSha256], policy: { measurements: { 2: hex(goldenDigest(2)) } }, resolveEvidence: () => S.evidence });
      expect((await run(ok)).ok).toBe(true);
    });
  });

  describe('PCA binding (SPDM request nonce)', () => {
    for (const [field, bad] of [
      ['holderPub', { ...EXPECTED, holderPub: 'other' }],
      ['grantRef', { ...EXPECTED, grantRef: 'other' }],
      ['epoch', { ...EXPECTED, epoch: 4 }],
      ['nonce', { ...EXPECTED, nonce: 'other' }],
    ] as const) {
      it(`rejects a relayed report (${field} differs)`, async () => {
        expect(await reasonOf({ expected: bad })).toBe('SPDM request nonce does not bind holder/grant/epoch/nonce (relayed or unbound report)');
      });
    }
    it('rejects a report with an unrelated challenge, even when validly signed', async () => {
      const ev = evidenceOf({ challenge: new Uint8Array(32).fill(7) });
      expect(await reasonOf({ ev })).toBe('SPDM request nonce does not bind holder/grant/epoch/nonce (relayed or unbound report)');
    });
  });

  describe('signature coverage', () => {
    it('a bad signature is rejected', async () => {
      expect(await reasonOf({ ev: evidenceOf({ signature: 'bad' }) })).toBe('GPU attestation report signature does not verify under the device identity key');
    });
    it('a report signed by a certificate other than the device leaf is rejected (every chain key tried)', async () => {
      for (const i of [1, 2, 3, 4]) {
        const ev = evidenceOf({ signer: S.device.keys[i]! });
        expect(await reasonOf({ ev }), `signed by chain key ${i}`).toBe('GPU attestation report signature does not verify under the device identity key');
      }
    });
    it('a report signed by an unrelated key is rejected', async () => {
      expect(await reasonOf({ ev: evidenceOf({ signer: forgeKey('rogue-gpu', 'P-384') }) })).toBe('GPU attestation report signature does not verify under the device identity key');
    });
    it('a flip in ANY signed region breaks the signature: request, measurement digest, DMTF header, responder nonce, opaque TLV', async () => {
      const L = S.spdm.layout;
      const offsets: [string, number][] = [
        ['request version', 0],
        ['request nonce', 10],
        ['request slot', 36],
        ['response header', L.responseOff + 1],
        ['block 1 index', L.recordsOff],
        ['block 1 digest', L.recordsOff + 8],
        ['block 64 digest', L.recordsOff + L.recordsLen - 5],
        ['responder nonce', L.responderNonceOff + 3],
        ['driver version TLV', L.opaqueTlvOff[OPAQUE_TYPE.DRIVER_VERSION]!],
        ['NVDEC0 status TLV', L.opaqueTlvOff[OPAQUE_TYPE.NVDEC0_STATUS]!],
      ];
      for (const [what, off] of offsets) {
        const ev = { evidence: flipAt(S.spdm.evidence, off), certChainPem: S.device.chainPem };
        const r = await reasonOf({ ev });
        expect(r, what).toMatch(/^(GPU attestation report signature does not verify under the device identity key|GPU attestation report parse failed: )/);
      }
      // the data-only fields (no length semantics) must specifically fail the signature
      for (const off of [10, L.recordsOff + 8, L.responderNonceOff + 3, L.opaqueTlvOff[OPAQUE_TYPE.DRIVER_VERSION]!]) {
        expect(await reasonOf({ ev: { evidence: flipAt(S.spdm.evidence, off), certChainPem: S.device.chainPem } })).toBe('GPU attestation report signature does not verify under the device identity key');
      }
    });
    it('a tampered signature byte is rejected', async () => {
      expect(await reasonOf({ ev: { evidence: flipAt(S.spdm.evidence, S.spdm.evidence.length - 3), certChainPem: S.device.chainPem } })).toBe('GPU attestation report signature does not verify under the device identity key');
    });
  });

  describe('transcript parser branches (valid signature, malformed structure)', () => {
    const parseFail = (over: Partial<ForgeSpdmOptions>) => {
      try {
        parseNvidiaSpdmEvidence(transcript(over).evidence);
        return undefined;
      } catch (e) {
        return e instanceof Error ? e.message : String(e);
      }
    };
    it('too short', () => {
      expect(() => parseNvidiaSpdmEvidence(new Uint8Array(100))).toThrow('parseNvidiaSpdmEvidence: transcript too short (100)');
      expect(() => parseNvidiaSpdmEvidence('x' as unknown as Uint8Array)).toThrow('expected Uint8Array');
    });
    it('request is not GET_MEASUREMENTS', () => {
      expect(parseFail({ requestCode: 0xe1 })).toBe('parseNvidiaSpdmEvidence: request code 0xe1 is not GET_MEASUREMENTS');
    });
    it('response is not MEASUREMENTS', () => {
      expect(parseFail({ responseCode: 0x61 })).toBe('parseNvidiaSpdmEvidence: response code is not MEASUREMENTS');
    });
    it('record length overruns the transcript', () => {
      expect(parseFail({ recLenDelta: 5000 })).toBe('parseNvidiaSpdmEvidence: measurement record length overruns transcript');
    });
    it('truncated measurement block header (2 stray bytes at the end of the record area)', () => {
      expect(parseFail({ recLenDelta: -53 })).toBe('parseNvidiaSpdmEvidence: truncated measurement block header');
    });
    it('measurement block longer than the record', () => {
      expect(parseFail({ measurements: [{ index: 1, digest: new Uint8Array(48), blockSizeDelta: 400 }] })).toBe('parseNvidiaSpdmEvidence: measurement block overruns record');
    });
    it('measurement block smaller than the DMTF header (size < 3)', () => {
      expect(parseFail({ measurements: [{ index: 1, digest: new Uint8Array(48), blockSizeDelta: -49 }] })).toBe('parseNvidiaSpdmEvidence: measurement block overruns record');
    });
    it('DMTF value overruns its block', () => {
      expect(parseFail({ measurements: [{ index: 1, digest: new Uint8Array(48), dmtfSizeDelta: 10 }] })).toBe('parseNvidiaSpdmEvidence: DMTF value overruns measurement block');
    });
    it('block count in the header disagrees with the records', () => {
      expect(parseFail({ numBlocksHeader: 63 })).toBe('parseNvidiaSpdmEvidence: header says 63 blocks, parsed 64');
    });
    it('opaque length that does not exactly fill the transcript (short, long, trailing bytes)', () => {
      const msg = 'parseNvidiaSpdmEvidence: opaque length + signature do not exactly fill the transcript';
      expect(parseFail({ opaqueLenDelta: 1 })).toBe(msg);
      expect(parseFail({ opaqueLenDelta: -1 })).toBe(msg);
      expect(parseFail({ trailing: Uint8Array.of(0) })).toBe(msg);
    });
    it('truncated opaque TLV header', () => {
      expect(parseFail({ opaqueTail: Uint8Array.of(1, 2, 3) })).toBe('parseNvidiaSpdmEvidence: truncated opaque TLV header');
    });
    it('opaque TLV overrunning the opaque data', () => {
      const t = transcript();
      const lenOff = t.layout.opaqueTlvOff[OPAQUE_TYPE.FEATURE_FLAG]! - 2;
      expect(() => parseNvidiaSpdmEvidence(patch(t.evidence, lenOff, Uint8Array.of(0xff, 0x00)))).toThrow('parseNvidiaSpdmEvidence: opaque TLV overruns opaque data');
    });
    it('every one of those reaches the verifier as "GPU attestation report parse failed"', async () => {
      const bad = evidenceOf({ numBlocksHeader: 63 });
      expect(await reasonOf({ ev: bad })).toBe('GPU attestation report parse failed: parseNvidiaSpdmEvidence: header says 63 blocks, parsed 64');
      expect(await reasonOf({ ev: evidenceOf({ opaqueTail: Uint8Array.of(9) }) })).toBe('GPU attestation report parse failed: parseNvidiaSpdmEvidence: truncated opaque TLV header');
    });
    it('a transcript with zero blocks parses and then fails the pinned-measurement check by name', async () => {
      const ev = evidenceOf({ blocks: 0 });
      const v = createNvidiaSpdmVerifier({ rootSpkiSha256: [S.deviceRootSpkiSha256], policy: { measurements: { 2: hex(goldenDigest(2)) } }, resolveEvidence: () => ev });
      expect((await run(v)).reason).toBe('measurement block 2 missing from report');
    });
    it('duplicate opaque types: the last TLV wins (documented)', () => {
      const p = parseNvidiaSpdmEvidence(transcript({ opaque: [[3, new TextEncoder().encode('1.0.0')], [3, new TextEncoder().encode('2.0.0')]] }).evidence);
      expect(Buffer.from(p.response.opaque.get(3)!).toString()).toBe('2.0.0');
    });
  });

  describe('operator-pinned measurement digests (policy.measurements)', () => {
    const pin = (m: Record<number, string>, ev = S.evidence) => run(createNvidiaSpdmVerifier({ rootSpkiSha256: [S.deviceRootSpkiSha256], policy: { measurements: m }, resolveEvidence: () => ev }));
    it('matches every pinned block (case-insensitive) and names the first mismatching / missing one', async () => {
      expect((await pin({ 1: hex(goldenDigest(1)).toUpperCase(), 64: hex(goldenDigest(64)) })).ok).toBe(true);
      for (const idx of [1, 2, 17, 35, 64]) {
        const wrong = hex(goldenDigest(idx)).replace(/^./, (c) => (c === '0' ? '1' : '0'));
        expect((await pin({ [idx]: wrong })).reason, `block ${idx}`).toBe(`measurement block ${idx} does not match the pinned digest`);
      }
      expect((await pin({ 65: hex(goldenDigest(1)) })).reason).toBe('measurement block 65 missing from report');
    });
    it('a digest that differs only in length is not equal', async () => {
      expect((await pin({ 1: hex(goldenDigest(1)).slice(0, 94) })).reason).toBe('measurement block 1 does not match the pinned digest');
    });
    it('a different report digest at a pinned block breaks the match (signed correctly)', async () => {
      const ev = evidenceOf({ digests: { 5: new Uint8Array(48).fill(9) } });
      expect((await pin({ 5: hex(goldenDigest(5)) }, ev)).reason).toBe('measurement block 5 does not match the pinned digest');
    });
  });

  describe('leaf subject policy', () => {
    it('a mismatching family string is named', async () => {
      const v = createNvidiaSpdmVerifier({ rootSpkiSha256: [S.deviceRootSpkiSha256], policy: { measurements: { 1: hex(goldenDigest(1)) }, leafSubjectIncludes: 'GB100' }, resolveEvidence: () => S.evidence });
      expect((await run(v)).reason).toBe("device leaf subject does not contain 'GB100'");
    });
  });
});

// ═════════════════════════════════════════════════════════════════════════════════════════════════
describe('device certificate chain branches (verifyNvidiaDeviceChain on real X.509)', () => {
  const chainOf = (o: Parameters<typeof forgeNvidiaDevicePki>[0] = {}) => forgeNvidiaDevicePki({ seed: 'chain-variant', ...o });
  const verify = (pki: ReturnType<typeof chainOf>, pins: string[] = [pki.rootSpkiSha256], nowMs = NOW, pem = pki.chainPem) => verifyNvidiaDeviceChain(pem, pins, nowMs);
  const fail = (r: ReturnType<typeof verify>) => (r.ok ? 'OK' : r.reason);

  it('accepts the 5-cert chain and returns leaf + chain', () => {
    const r = verify(S.device);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.chain.length).toBe(5);
      expect(spkiSha256Hex(r.chain[4]!)).toBe(S.device.rootSpkiSha256);
      expect(r.leaf.subject).toContain('GH100 A01 GSP FMC LF');
    }
  });
  it('accepts an upper-case pin and a multi-pin list containing the right one', () => {
    expect(verify(S.device, [S.device.rootSpkiSha256.toUpperCase()]).ok).toBe(true);
    expect(verify(S.device, ['00'.repeat(32), S.device.rootSpkiSha256]).ok).toBe(true);
  });
  it('rejects a root that is not pinned', () => {
    expect(fail(verify(S.device, ['00'.repeat(32)]))).toBe('chain root is not a pinned NVIDIA root');
    expect(fail(verify(S.device, []))).toBe('chain root is not a pinned NVIDIA root');
  });
  it('rejects empty, garbage and too-long PEM', () => {
    expect(fail(verify(S.device, undefined, NOW, ''))).toBe('device chain unparseable: parsePemChain: no certificates found');
    expect(fail(verify(S.device, undefined, NOW, '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n'))).toMatch(/^device chain unparseable: /);
    const six = chainOf({ names: [names[0]!, names[1]!, names[2]!, [['CN', 'Extra CA'], ['O', 'NVIDIA']], names[3]!, names[4]!] });
    expect(fail(verify(six))).toBe('device chain unparseable: parsePemChain: chain longer than 5');
    expect(() => parsePemChain(six.chainPem)).toThrow('chain longer than 5');
  });
  it('rejects a leaf-only chain (the leaf is not a self-signed CA)', () => {
    expect(fail(verify(S.device, undefined, NOW, S.device.certs[0]!.pem))).toBe('device chain root is not a self-signed CA');
  });
  it('rejects a chain whose last certificate is an intermediate (root dropped)', () => {
    expect(fail(verify(S.device, undefined, NOW, S.device.certs.slice(0, 4).map((c) => c.pem).join('')))).toBe('device chain root is not a self-signed CA');
  });
  it('rejects a reversed chain (root first): the link signatures do not verify', () => {
    const rev = [...S.device.certs].reverse().map((c) => c.pem).join('');
    expect(fail(verify(S.device, undefined, NOW, rev))).toBe('device chain link #0 signature does not verify under its issuer');
  });
  it('rejects swapped intermediates', () => {
    const c = S.device.certs;
    expect(fail(verify(S.device, undefined, NOW, [c[0]!, c[2]!, c[1]!, c[3]!, c[4]!].map((x) => x.pem).join('')))).toBe('device chain link #0 signature does not verify under its issuer');
  });
  it('rejects skipped intermediates', () => {
    const c = S.device.certs;
    expect(fail(verify(S.device, undefined, NOW, [c[0]!, c[4]!].map((x) => x.pem).join('')))).toBe('device chain link #0 signature does not verify under its issuer');
  });
  for (const i of [0, 1, 2, 3, 4] as const) {
    it(`rejects a P-256 key at chain position ${i}`, () => {
      expect(fail(verify(chainOf({ override: { [i]: { curve: 'P-256' } } })))).toBe(`device chain cert #${i} is not an ECDSA P-384 key`);
    });
    it(`rejects an expired certificate at position ${i}`, () => {
      expect(fail(verify(chainOf({ override: { [i]: { notBefore: new Date('2020-01-01Z'), notAfter: new Date('2026-01-01Z') } } })))).toBe(`device chain cert #${i} is outside its validity window`);
    });
    it(`rejects a not-yet-valid certificate at position ${i}`, () => {
      expect(fail(verify(chainOf({ override: { [i]: { notBefore: new Date('2031-01-01Z'), notAfter: new Date('2040-01-01Z') } } })))).toBe(`device chain cert #${i} is outside its validity window`);
    });
  }
  it('the validity window is inclusive at the boundaries and exclusive just outside', () => {
    const pki = chainOf({ override: { 0: { notBefore: new Date('2026-10-01T00:00:00Z'), notAfter: new Date('2026-12-01T00:00:00Z') } } });
    expect(verify(pki, undefined, Date.parse('2026-10-01T00:00:00Z')).ok).toBe(true);
    expect(verify(pki, undefined, Date.parse('2026-12-01T00:00:00Z')).ok).toBe(true);
    expect(fail(verify(pki, undefined, Date.parse('2026-09-30T23:59:59Z')))).toBe('device chain cert #0 is outside its validity window');
    expect(fail(verify(pki, undefined, Date.parse('2026-12-01T00:00:01Z')))).toBe('device chain cert #0 is outside its validity window');
  });
  for (const k of [1, 2, 3] as const) {
    it(`rejects an issuer that is not a CA at position ${k} (CA:FALSE and BasicConstraints absent)`, () => {
      for (const ca of [false, 'absent'] as const) {
        expect(fail(verify(chainOf({ override: { [k]: { ca } } })))).toBe(`device chain cert #${k} issues a certificate but is not a CA`);
      }
    });
  }
  for (const i of [0, 1, 2, 3] as const) {
    it(`rejects a link signed by a stranger at position ${i}`, () => {
      expect(fail(verify(chainOf({ override: { [i]: { signedBy: forgeKey('stranger-ca', 'P-384') } } })))).toBe(`device chain link #${i} signature does not verify under its issuer`);
    });
  }
  it('rejects a root that is not self-signed, and a root that is not a CA', () => {
    expect(fail(verify(chainOf({ override: { 4: { signedBy: forgeKey('other-root', 'P-384') } } })))).toBe('device chain root is not a self-signed CA');
    // the root issues the Identity certificate, so a CA:FALSE root is caught by the "issuer is a CA" rule first
    expect(fail(verify(chainOf({ override: { 4: { ca: false } } })))).toBe('device chain cert #4 issues a certificate but is not a CA');
  });
  it('the production-side checks run in a fixed order: validity/curve of ALL certs precede CA/link checks', () => {
    const pki = chainOf({ override: { 1: { ca: false }, 4: { curve: 'P-256' } } });
    expect(fail(verify(pki))).toBe('device chain cert #4 is not an ECDSA P-384 key');
  });
});

// ═════════════════════════════════════════════════════════════════════════════════════════════════
describe('RIM (SWID / XMLDSig) verification on forged manifests', () => {
  it('accepts the scenario RIMs and extracts version, product and the golden map', async () => {
    const d = await verifyRim(S.driverRimXml);
    const v = await verifyRim(S.vbiosRimXml);
    expect(d.ok && v.ok).toBe(true);
    if (d.ok && v.ok) {
      expect(d.rim.version).toBe('595.71.05');
      expect(v.rim.version).toBe('96.00.9F.00.04');
      expect(d.rim.product).toBe('GH100');
      expect(d.rim.golden.size).toBe(64);
      expect([...d.rim.golden.values()].filter((g) => g.active).map((g) => g.index)).toEqual(Array.from({ length: 23 }, (_, i) => i + 12));
      expect([...v.rim.golden.values()].filter((g) => g.active).length).toBe(12);
      expect(d.rim.signerSubject).toContain('CN=HCC RIM L4 Signer');
      expect(d.rim.golden.get(12)!.hashes[0]).toBe(hex(goldenDigest(13)));
    }
  });
  it('is not trusted under a different RIM pin', async () => {
    expect(await verifyNvidiaRim(S.driverRimXml, { rimRootSpkiSha256: ['00'.repeat(32)], nowMs: NOW })).toEqual({ ok: false, reason: 'RIM signer chain: chain root is not a pinned NVIDIA root' });
  });

  describe('document-level guards', () => {
    it('empty / oversized / unpinned / unparseable', async () => {
      const o = { rimRootSpkiSha256: [S.rimRootSpkiSha256], nowMs: NOW };
      expect(await verifyNvidiaRim('', o)).toEqual({ ok: false, reason: 'RIM: empty or oversized document' });
      expect(await verifyNvidiaRim('x'.repeat(4_000_001), o)).toEqual({ ok: false, reason: 'RIM: empty or oversized document' });
      expect(await verifyNvidiaRim(S.driverRimXml, { rimRootSpkiSha256: [], nowMs: NOW })).toEqual({ ok: false, reason: 'RIM: no pinned RIM root configured' });
      for (const bad of ['<<<not xml', 'plain text', '<SoftwareIdentity xmlns:x="a"><x:y</SoftwareIdentity>']) {
        const r = await verifyNvidiaRim(bad, o);
        expect(r.ok, bad).toBe(false);
        if (!r.ok) expect(r.reason, bad).toMatch(/^RIM: verification error \(fail closed\): /);
      }
      expect(await verifyNvidiaRim('<?xml version="1.0"?>', o)).toEqual({ ok: false, reason: 'RIM: XML processing instructions are not permitted' });
    });
    it('root element must be SoftwareIdentity', async () => {
      const r = await verifyRim(rimXml(M1, { rootName: 'Other' }));
      expect(r).toEqual({ ok: false, reason: 'RIM: root element is not SoftwareIdentity' });
    });
  });

  describe('strict XML profile (validly signed documents that still must be refused)', () => {
    it('XML comments', async () => expect(await verifyRim(rimXml(M1, { comment: true }))).toEqual({ ok: false, reason: 'RIM: XML comments are not permitted' }));
    it('processing instructions', async () => expect(await verifyRim(rimXml(M1, { processingInstruction: true }))).toEqual({ ok: false, reason: 'RIM: XML processing instructions are not permitted' }));
    it('DTD / DOCTYPE', async () => expect(await verifyRim(rimXml(M1, { doctype: true }))).toEqual({ ok: false, reason: 'RIM: DTD / DOCTYPE is not permitted' }));
    it('xml:* attributes (C14N 1.1 profile)', async () => expect(await verifyRim(rimXml(M1, { xmlAttrOnPayload: true }))).toEqual({ ok: false, reason: "RIM: xml:* attribute 'xml:space' is not permitted (C14N 1.1 profile)" }));
    it('a second Signature as a sibling', async () => expect(await verifyRim(rimXml(M1, { extraSignature: 'sibling' }))).toEqual({ ok: false, reason: 'RIM: expected exactly one Signature element' }));
    it('a second Signature nested in the payload', async () => expect(await verifyRim(rimXml(M1, { extraSignature: 'nested' }))).toEqual({ ok: false, reason: 'RIM: expected exactly one Signature element' }));
    it('a (single) Signature wrapped inside another element — signature-wrapping defence', async () => expect(await verifyRim(rimXml(M1, { wrapSignature: true }))).toEqual({ ok: false, reason: 'RIM: the Signature must be a direct child of the root' }));
  });

  describe('XMLDSig structure + algorithm profile', () => {
    const cases: [string, Partial<Parameters<typeof forgeRim>[0]>, string][] = [
      ['C14N method other than 1.1', { c14nUri: 'http://www.w3.org/2001/10/xml-exc-c14n#' }, 'RIM: CanonicalizationMethod must be C14N 1.1'],
      ['RSA signature method', { sigMethodUri: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384' }, 'RIM: SignatureMethod must be ECDSA-SHA384'],
      ['ECDSA-SHA256 signature method', { sigMethodUri: 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256' }, 'RIM: SignatureMethod must be ECDSA-SHA384'],
      ['SHA-256 digest method', { digestMethodUri: 'http://www.w3.org/2001/04/xmlenc#sha256' }, 'RIM: DigestMethod must be SHA-384'],
      ['Reference URI "#id"', { referenceUri: '#payload' }, 'RIM: Reference URI must be "" (the whole document)'],
      ['a second Reference', { extraReference: true }, 'RIM: expected exactly one Reference'],
      ['transforms in the wrong order', { transforms: [RIM_ALG.C14N11, RIM_ALG.ENVELOPED] }, 'RIM: transforms must be exactly [enveloped-signature, C14N 1.1]'],
      ['no enveloped-signature transform', { transforms: [RIM_ALG.C14N11] }, 'RIM: transforms must be exactly [enveloped-signature, C14N 1.1]'],
      ['an extra transform', { transforms: [RIM_ALG.ENVELOPED, RIM_ALG.C14N11, RIM_ALG.C14N11] }, 'RIM: transforms must be exactly [enveloped-signature, C14N 1.1]'],
      ['no DigestValue', { omitDigestValue: true }, 'RIM: missing DigestValue / SignatureValue'],
      ['no SignatureValue', { omitSignatureValue: true }, 'RIM: missing DigestValue / SignatureValue'],
      ['no KeyInfo certificates', { omitKeyInfo: true }, 'RIM: no signer certificates in KeyInfo'],
      ['a 64-byte (P-256 sized) SignatureValue', { signatureBytes: 64 }, 'RIM: SignatureValue is not a 96-byte P-384 signature'],
      ['a 100-byte SignatureValue', { signatureBytes: 100 }, 'RIM: SignatureValue is not a 96-byte P-384 signature'],
    ];
    for (const [name, over, reason] of cases) {
      it(`rejects ${name}`, async () => {
        expect(await verifyRim(rimXml(M1, over))).toEqual({ ok: false, reason });
      });
    }
  });

  describe('signature + digest', () => {
    it('SignedInfo signed by a key other than the signer certificate', async () => {
      expect(await verifyRim(rimXml(M1, { signWith: forgeKey('rogue-rim-signer', 'P-384') }))).toEqual({ ok: false, reason: 'RIM: SignedInfo signature does not verify under the signer certificate' });
    });
    it('a valid signature over a DigestValue that does not match the document', async () => {
      expect(await verifyRim(rimXml(M1, { digestOverride: Buffer.alloc(48, 1).toString('base64') }))).toEqual({ ok: false, reason: 'RIM: document digest does not match the signed DigestValue' });
    });
    it('payload edited after signing (a golden hash nibble)', async () => {
      const xml = rimXml(M1).replace(`Hash0="${'11'.repeat(48)}"`, `Hash0="${'12'.repeat(48)}"`);
      expect(await verifyRim(xml)).toEqual({ ok: false, reason: 'RIM: document digest does not match the signed DigestValue' });
    });
    it('DigestValue edited after signing breaks the SignedInfo signature', async () => {
      const xml = rimXml(M1);
      const d = /<ds:DigestValue>([^<]+)<\/ds:DigestValue>/.exec(xml)![1]!;
      const edited = xml.replace(d, d.replace(/^./, (c) => (c === 'A' ? 'B' : 'A')));
      expect(await verifyRim(edited)).toEqual({ ok: false, reason: 'RIM: SignedInfo signature does not verify under the signer certificate' });
    });
    it('whitespace-only edits inside the signed document change the digest (no XML malleability)', async () => {
      const xml = rimXml(M1).replace('<ns0:Entity', '<ns0:Entity  ');
      // extra whitespace inside a start tag is normalised by C14N, so it must STILL verify…
      expect((await verifyRim(xml)).ok).toBe(true);
      // …but added text content is not
      const withText = rimXml(M1).replace('</ns0:Payload>', ' </ns0:Payload>');
      expect(await verifyRim(withText)).toEqual({ ok: false, reason: 'RIM: document digest does not match the signed DigestValue' });
    });
  });

  describe('signer chain (CoRIM PKI) branches', () => {
    const fromPki = (o: Parameters<typeof forgeCorimPki>[0], over: Partial<Parameters<typeof forgeRim>[0]> = {}) => {
      const pki = forgeCorimPki({ seed: 'corim-variant', ...o });
      return { pki, xml: forgeRim({ version: '595.71.05', measurements: M1, signerChain: pki.certs, signerKey: pki.signerKey, ...over }) };
    };
    it('verifies a different valid CoRIM PKI under its own pin', async () => {
      const { pki, xml } = fromPki({});
      expect((await verifyNvidiaRim(xml, { rimRootSpkiSha256: [pki.rootSpkiSha256], nowMs: NOW })).ok).toBe(true);
    });
    const chainFail = async (o: Parameters<typeof forgeCorimPki>[0], nowMs = NOW) => {
      const { pki, xml } = fromPki(o);
      const r = await verifyNvidiaRim(xml, { rimRootSpkiSha256: [pki.rootSpkiSha256], nowMs });
      return r.ok ? 'OK' : r.reason;
    };
    it('expired / not-yet-valid signer leaf', async () => {
      expect(await chainFail({ leafValidity: [new Date('2024-01-01Z'), new Date('2025-01-01Z')] })).toBe('RIM signer chain: device chain cert #0 is outside its validity window');
      expect(await chainFail({ leafValidity: [new Date('2030-01-01Z'), new Date('2031-01-01Z')] })).toBe('RIM signer chain: device chain cert #0 is outside its validity window');
    });
    it('uses the verifier clock for the signer window', async () => {
      expect(await chainFail({}, Date.parse('2026-03-12T23:38:12Z'))).toBe('RIM signer chain: device chain cert #0 is outside its validity window');
      expect(await chainFail({}, Date.parse('2028-03-11T23:38:14Z'))).toBe('RIM signer chain: device chain cert #0 is outside its validity window');
    });
    it('P-256 signer key', async () => {
      expect(await chainFail({ override: { 0: { curve: 'P-256' } } })).toBe('RIM signer chain: device chain cert #0 is not an ECDSA P-384 key');
    });
    it('an intermediate that is not a CA', async () => {
      expect(await chainFail({ override: { 2: { ca: false } } })).toBe('RIM signer chain: device chain cert #2 issues a certificate but is not a CA');
    });
    it('a link signed by a stranger', async () => {
      expect(await chainFail({ override: { 1: { signedBy: forgeKey('stranger-l3', 'P-384') } } })).toBe('RIM signer chain: device chain link #1 signature does not verify under its issuer');
    });
    it('only the leaf in KeyInfo', async () => {
      const { pki } = fromPki({});
      const xml = forgeRim({ version: '1', measurements: M1, signerChain: [pki.certs[0]!], signerKey: pki.signerKey });
      expect(await verifyNvidiaRim(xml, { rimRootSpkiSha256: [pki.rootSpkiSha256], nowMs: NOW })).toEqual({ ok: false, reason: 'RIM signer chain: device chain root is not a self-signed CA' });
    });
  });

  describe('golden measurement extraction', () => {
    const good = hex(goldenDigest(1));
    const reason = async (m: readonly RimMeasurementSpec[]) => {
      const r = await verifyRim(rimXml(m));
      return r.ok ? 'OK' : r.reason;
    };
    it('no Measurement resources at all', async () => {
      expect(await reason([spec(0, good, { type: 'Other' })])).toBe('RIM: no measurements');
    });
    it('non-Measurement resources are ignored', async () => {
      const r = await verifyRim(rimXml([spec(0, good), spec(1, 'zz', { type: 'Other' })]));
      expect(r.ok && r.rim.golden.size).toBe(1);
    });
    it('duplicate index', async () => {
      expect(await reason([spec(3, good), spec(3, good)])).toBe('RIM: duplicate Measurement index 3');
    });
    it('hash count inconsistent with alternatives', async () => {
      expect(await reason([spec(4, good, { alternatives: 2 })])).toBe('RIM: Measurement 4 hash list is inconsistent with alternatives/size');
    });
    it('hash length inconsistent with size', async () => {
      expect(await reason([spec(4, good, { size: 32 })])).toBe('RIM: Measurement 4 hash list is inconsistent with alternatives/size');
    });
    it('non-hex hash', async () => {
      expect(await reason([spec(4, 'zz'.repeat(48))])).toBe('RIM: Measurement 4 hash list is inconsistent with alternatives/size');
    });
    it('malformed index / alternatives / size attributes', async () => {
      const bad = 'RIM: malformed Measurement resource';
      expect(await reason([{ ...spec(0, good), index: Number.NaN }])).toBe(bad);
      expect(await reason([spec(-1, good)])).toBe(bad);
      expect(await reason([spec(1, good, { alternatives: 0 })])).toBe(bad);
      expect(await reason([spec(1, good, { size: 0 })])).toBe(bad);
    });
    it('multiple alternatives are parsed in Hash order', async () => {
      const r = await verifyRim(rimXml([spec(0, good, { hashes: ['aa'.repeat(48), 'bb'.repeat(48), 'cc'.repeat(48)] })]));
      expect(r.ok && r.rim.golden.get(0)!.hashes).toEqual(['aa'.repeat(48), 'bb'.repeat(48), 'cc'.repeat(48)]);
    });
    it('missing Meta / Payload', async () => {
      expect(await verifyRim(rimXml(M1, { omitMeta: true }))).toEqual({ ok: false, reason: 'RIM: missing Meta / Payload' });
      expect(await verifyRim(rimXml(M1, { omitPayload: true }))).toEqual({ ok: false, reason: 'RIM: missing Meta / Payload' });
    });
  });
});

// ═════════════════════════════════════════════════════════════════════════════════════════════════
describe('report ↔ RIM comparison (compareReportToRims) on forged reports', () => {
  const rimsPromise = Promise.all([verifyRim(S.driverRimXml), verifyRim(S.vbiosRimXml)]).then(([d, v]) => {
    if (!d.ok || !v.ok) throw new Error('scenario RIMs must verify');
    return { d: d.rim, v: v.rim };
  });
  const reportOf = (over: Partial<ForgeSpdmOptions> = {}) => parseNvidiaSpdmEvidence(transcript(over).evidence);

  it('the consistent scenario matches at 34 indices (NVDEC0 block 35 exempt while NVDEC0 is DISABLED)', async () => {
    const { d, v } = await rimsPromise;
    expect(compareReportToRims(reportOf(), d, v)).toEqual({ ok: true, checked: 34 });
  });

  it('a mismatch at EACH active golden index is detected, attributed to the right RIM and reported as that index', async () => {
    const { d, v } = await rimsPromise;
    for (let g = 0; g <= 33; g++) {
      const r = compareReportToRims(reportOf({ digests: { [g + 1]: new Uint8Array(48).fill(0xee) } }), d, v);
      expect(r, `index ${g}`).toEqual({ ok: false, reason: 'runtime measurements differ from the golden RIM values at 1 index(es)', mismatches: [{ index: g, source: g < 12 ? 'vbios' : 'driver' }] });
    }
  });
  it('NVDEC0 DISABLED (0x55): a mismatch at block 35 is ignored, and so is a match', async () => {
    const { d, v } = await rimsPromise;
    expect(compareReportToRims(reportOf({ digests: { 35: new Uint8Array(48).fill(1) } }), d, v)).toEqual({ ok: true, checked: 34 });
  });
  it('NVDEC0 ENABLED (any value except 0x55) or ABSENT or EMPTY: block 35 is enforced', async () => {
    const { d, v } = await rimsPromise;
    const bad = { 35: new Uint8Array(48).fill(1) };
    const withNvdec = (val: Uint8Array | null) => defaultOpaque().filter(([t]) => t !== OPAQUE_TYPE.NVDEC0_STATUS).concat(val === null ? [] : [[OPAQUE_TYPE.NVDEC0_STATUS, val]]);
    for (const [what, val] of [['0x00', Uint8Array.of(0)], ['0xAA', Uint8Array.of(0xaa)], ['absent', null], ['empty', new Uint8Array(0)]] as const) {
      const r = compareReportToRims(reportOf({ digests: bad, opaque: withNvdec(val) }), d, v);
      expect(r, what).toEqual({ ok: false, reason: 'runtime measurements differ from the golden RIM values at 1 index(es)', mismatches: [{ index: NVDEC_GOLDEN_INDEX, source: 'driver' }] });
      // with a correct digest the same enabled state passes and counts 35
      expect(compareReportToRims(reportOf({ opaque: withNvdec(val) }), d, v), `${what} ok`).toEqual({ ok: true, checked: 35 });
    }
  });
  it('several simultaneous mismatches are all listed, sorted by index', async () => {
    const { d, v } = await rimsPromise;
    const r = compareReportToRims(reportOf({ digests: { 30: new Uint8Array(48).fill(2), 3: new Uint8Array(48).fill(2), 20: new Uint8Array(48).fill(2) } }), d, v);
    expect(r).toMatchObject({ ok: false, mismatches: [{ index: 2, source: 'vbios' }, { index: 19, source: 'driver' }, { index: 29, source: 'driver' }] });
  });
  it('an inactive golden entry is never compared', async () => {
    const { d, v } = await rimsPromise;
    expect(compareReportToRims(reportOf({ digests: { 50: new Uint8Array(48).fill(3), 64: hexToBytes('00'.repeat(48)) } }), d, v).ok).toBe(true);
  });
  it('a digest of the wrong size is a mismatch even if its prefix equals the golden value', async () => {
    const { d, v } = await rimsPromise;
    const ms = Array.from({ length: 64 }, (_, k) => ({ index: k + 1, digest: k === 4 ? goldenDigest(5).slice(0, 32) : goldenDigest(k + 1) }));
    expect(compareReportToRims(reportOf({ measurements: ms }), d, v)).toMatchObject({ ok: false, mismatches: [{ index: 4, source: 'vbios' }] });
  });
  it('a missing block for an active index is a mismatch (the block count still suffices)', async () => {
    const { d, v } = await rimsPromise;
    const ms = Array.from({ length: 64 }, (_, k) => k + 1).filter((i) => i !== 10).map((i) => ({ index: i, digest: goldenDigest(i) })).concat([{ index: 65, digest: goldenDigest(65) }]);
    expect(compareReportToRims(reportOf({ measurements: ms }), d, v)).toMatchObject({ ok: false, mismatches: [{ index: 9, source: 'vbios' }] });
  });
  it('the RIMs list more active measurements than the report carries', async () => {
    const { d, v } = await rimsPromise;
    expect(compareReportToRims(reportOf({ blocks: 10 }), d, v)).toEqual({ ok: false, reason: 'RIMs list more active measurements than the report carries' });
  });
  it('driver and VBIOS RIMs both active at the same index', async () => {
    const sc = forgeNvidiaScenario({ seed: 'conflict', challenge: CHALLENGE, vbiosIndices: [0, 1, 2, 5], driverIndices: [5, 6, 7] });
    const d = await verifyRim(sc.driverRimXml, sc);
    const v = await verifyRim(sc.vbiosRimXml, sc);
    if (!d.ok || !v.ok) throw new Error('rims');
    expect(compareReportToRims(parseNvidiaSpdmEvidence(sc.spdm.evidence), d.rim, v.rim)).toEqual({ ok: false, reason: 'driver and VBIOS RIMs both have an active measurement at index 5' });
  });
  it('RIMs with no active measurements at all', async () => {
    const sc = forgeNvidiaScenario({ seed: 'none-active', challenge: CHALLENGE, vbiosIndices: [], driverIndices: [] });
    const d = await verifyRim(sc.driverRimXml, sc);
    const v = await verifyRim(sc.vbiosRimXml, sc);
    if (!d.ok || !v.ok) throw new Error('rims');
    expect(compareReportToRims(parseNvidiaSpdmEvidence(sc.spdm.evidence), d.rim, v.rim)).toEqual({ ok: false, reason: 'RIMs carry no active golden measurements' });
  });
  it('alternatives: the report may match ANY listed alternative, but not none', async () => {
    const sc = forgeNvidiaScenario({ seed: 'alts', challenge: CHALLENGE });
    const alts = [hex(goldenDigest(1)).replace(/^../, 'ff'), hex(goldenDigest(1)), 'ab'.repeat(48)];
    const driver = sc.rim('595.71.05', [spec(0, alts[0]!, { hashes: alts, alternatives: 3 })]);
    const vbios = sc.rim('96.00.9F.00.04', [spec(1, hex(goldenDigest(2)))]);
    const d = await verifyRim(driver, sc);
    const v = await verifyRim(vbios, sc);
    if (!d.ok || !v.ok) throw new Error('rims');
    expect(compareReportToRims(parseNvidiaSpdmEvidence(sc.spdm.evidence), d.rim, v.rim)).toEqual({ ok: true, checked: 2 });
    const other = parseNvidiaSpdmEvidence(forgeSpdmTranscript({ signer: sc.device.leafKey, challenge: CHALLENGE, digests: { 1: new Uint8Array(48).fill(4) } }).evidence);
    expect(compareReportToRims(other, d.rim, v.rim)).toMatchObject({ ok: false, mismatches: [{ index: 0, source: 'driver' }] });
  });
});

// ═════════════════════════════════════════════════════════════════════════════════════════════════
describe('driver / VBIOS version binding + firmware policy (nvidiaCollateralHook)', () => {
  it('names the RIMs exactly from the signed opaque data', () => {
    expect(nvidiaRimIdsForReport(REPORT)).toEqual({ chip: 'GH100', driver: S.driverId, vbios: S.vbiosId, driverVersion: '595.71.05', vbiosVersion: '96.00.9f.00.04' });
    expect(formatVbiosVersion(hexToBytes('009f009604000000'))).toBe('96.00.9f.00.04');
  });
  it('reports a missing resolver result', async () => {
    const v = verifierOf(S, S.evidence, undefined);
    expect((await run(v)).reason).toBe('no RIM collateral supplied for this report');
  });
  it('hands the derived RIM ids to the resolver', async () => {
    let seen: unknown;
    const v = createNvidiaSpdmVerifier({ rootSpkiSha256: [S.deviceRootSpkiSha256], policy: { measurements: {} }, resolveEvidence: () => S.evidence, postVerify: nvidiaCollateralHook({ rimRootSpkiSha256: [S.rimRootSpkiSha256], resolve: (ids) => ((seen = ids), bundleOf()) }) });
    expect((await run(v)).ok).toBe(true);
    expect(seen).toMatchObject({ driver: 'NV_GPU_DRIVER_GH100_595.71.05', vbios: 'NV_GPU_VBIOS_1010_0210_886_96009F0004' });
  });
  for (const [name, type] of [['driver version', OPAQUE_TYPE.DRIVER_VERSION], ['VBIOS version', OPAQUE_TYPE.VBIOS_VERSION], ['project', OPAQUE_TYPE.PROJECT], ['project SKU', OPAQUE_TYPE.PROJECT_SKU], ['chip SKU', OPAQUE_TYPE.CHIP_SKU]] as const) {
    it(`a report without the ${name} opaque field cannot name its RIMs`, async () => {
      const ev = evidenceOf({ opaque: defaultOpaque().filter(([t]) => t !== type) });
      expect(await reasonOf({ ev })).toBe('GPU report does not carry the opaque fields needed to name its RIMs');
    });
  }
  it('an all-zero driver version string cannot name its RIMs either', async () => {
    const ev = evidenceOf({ opaque: defaultOpaque().map(([t, v]) => (t === OPAQUE_TYPE.DRIVER_VERSION ? ([t, new Uint8Array(10)] as [number, Uint8Array]) : [t, v])) });
    expect(await reasonOf({ ev })).toBe('GPU report does not carry the opaque fields needed to name its RIMs');
  });

  it('driver RIM for a different driver version', async () => {
    const sc = forgeNvidiaScenario({ seed: 'drv-mismatch', challenge: CHALLENGE, driverRimVersion: '595.71.04' });
    expect(await reasonOf({ sc })).toBe("driver RIM version '595.71.04' does not match the report's driver '595.71.05'");
  });
  it('VBIOS RIM for a different VBIOS version', async () => {
    const sc = forgeNvidiaScenario({ seed: 'vb-mismatch', challenge: CHALLENGE, vbiosRimVersion: '96.00.9F.00.05' });
    expect(await reasonOf({ sc })).toBe("VBIOS RIM version '96.00.9F.00.05' does not match the report's VBIOS '96.00.9f.00.04'");
  });
  it('VBIOS version comparison ignores dots and case', async () => {
    for (const vbiosRimVersion of ['96009f0004', '96.00.9f.00.04', '96009F0004']) {
      expect(await reasonOf({ sc: forgeNvidiaScenario({ seed: `vb-${vbiosRimVersion}`, challenge: CHALLENGE, vbiosRimVersion }) }), vbiosRimVersion).toBeUndefined();
    }
  });
  it('a different (but internally consistent) driver build is accepted as long as the RIM says so', async () => {
    const sc = forgeNvidiaScenario({ seed: 'drv-new', challenge: CHALLENGE, driver: '600.1.2' });
    expect(await reasonOf({ sc })).toBeUndefined();
    expect(sc.driverId).toBe('NV_GPU_DRIVER_GH100_600.1.2');
  });
  it('a RIM that fails verification is attributed to the right document', async () => {
    const bad = rimXml(M1, { signWith: forgeKey('x', 'P-384') });
    expect(await reasonOf({ bundle: { driverRimXml: bad } })).toBe('driver RIM: RIM: SignedInfo signature does not verify under the signer certificate');
    expect(await reasonOf({ bundle: { vbiosRimXml: bad } })).toBe('VBIOS RIM: RIM: SignedInfo signature does not verify under the signer certificate');
  });
  it('swapped RIMs (driver RIM supplied as VBIOS) are caught by the version binding', async () => {
    const r = await reasonOf({ bundle: { driverRimXml: S.vbiosRimXml, vbiosRimXml: S.driverRimXml } });
    expect(r).toBe("driver RIM version '96.00.9F.00.04' does not match the report's driver '595.71.05'");
  });
  it('a golden mismatch surfaces through the hook with the comparison reason', async () => {
    const ev = evidenceOf({ digests: { 20: new Uint8Array(48).fill(1) } });
    expect(await reasonOf({ ev })).toBe('runtime measurements differ from the golden RIM values at 1 index(es)');
  });

  describe('firmware min / deny policy', () => {
    const fw = (firmware: NonNullable<NvidiaCollateralOptions['firmware']>) => reasonOf({ hook: { firmware } });
    it('accepts at / above the floor and compares numerically, not lexically', async () => {
      expect(await fw({ minDriverVersion: '595.71.05' })).toBeUndefined();
      expect(await fw({ minDriverVersion: '595.9.0' })).toBeUndefined(); // 71 > 9
      expect(await fw({ minDriverVersion: '580' })).toBeUndefined();
      expect(await fw({ minVbiosVersion: '96.00.9f.00.04' })).toBeUndefined();
      expect(await fw({ minVbiosVersion: '96.00.0a.00.04' })).toBeUndefined(); // 0x9f > 0x0a
    });
    it('rejects below the floor and says which rule', async () => {
      expect(await fw({ minDriverVersion: '595.71.06' })).toBe('firmware policy: driver 595.71.05 is below the minimum 595.71.06');
      expect(await fw({ minDriverVersion: '596' })).toBe('firmware policy: driver 595.71.05 is below the minimum 596');
      expect(await fw({ minVbiosVersion: '96.00.9f.00.05' })).toBe('firmware policy: VBIOS 96.00.9f.00.04 is below the minimum 96.00.9f.00.05');
      expect(await fw({ minVbiosVersion: '97.00.00.00.00' })).toBe('firmware policy: VBIOS 96.00.9f.00.04 is below the minimum 97.00.00.00.00');
    });
    it('deny lists are exact after numeric normalisation', async () => {
      expect(await fw({ denyDriverVersions: ['595.71.05'] })).toBe('firmware policy: driver 595.71.05 is on the deny list');
      expect(await fw({ denyDriverVersions: ['595.71.5'] })).toBe('firmware policy: driver 595.71.05 is on the deny list');
      expect(await fw({ denyDriverVersions: ['595.71.05.0'] })).toBe('firmware policy: driver 595.71.05 is on the deny list');
      expect(await fw({ denyDriverVersions: ['595.71.06', '1.2.3'] })).toBeUndefined();
      expect(await fw({ denyVbiosVersions: ['96.00.9F.00.04'] })).toBe('firmware policy: VBIOS 96.00.9f.00.04 is on the deny list');
      expect(await fw({ denyVbiosVersions: ['96.00.9f.00.05'] })).toBeUndefined();
    });
    it('rule order: minimums are checked before deny lists, driver before VBIOS', async () => {
      expect(await fw({ minDriverVersion: '999', denyDriverVersions: ['595.71.05'] })).toContain('is below the minimum 999');
      expect(await fw({ minVbiosVersion: '99.00.00.00.00', minDriverVersion: '999' })).toContain('driver 595.71.05 is below');
    });
    it('the firmware policy is evaluated BEFORE any collateral is fetched', async () => {
      let called = false;
      const v = createNvidiaSpdmVerifier({
        rootSpkiSha256: [S.deviceRootSpkiSha256],
        policy: { measurements: {} },
        resolveEvidence: () => S.evidence,
        postVerify: nvidiaCollateralHook({ rimRootSpkiSha256: [S.rimRootSpkiSha256], firmware: { minDriverVersion: '999' }, resolve: () => ((called = true), bundleOf()) }),
      });
      expect((await run(v)).reason).toBe('firmware policy: driver 595.71.05 is below the minimum 999');
      expect(called).toBe(false);
    });
    it('an unparseable driver string in the (signed) report is rejected when a firmware policy exists', async () => {
      const ev = evidenceOf({ opaque: defaultOpaque({ driver: '595.x.05' }) });
      expect(await reasonOf({ ev, hook: { firmware: {} } })).toBe("firmware policy: driver version '595.x.05' in the GPU report is not parseable");
    });
    it('an empty VBIOS version field is rejected when a firmware policy exists', async () => {
      const ev = evidenceOf({ opaque: defaultOpaque().map(([t, v]) => (t === OPAQUE_TYPE.VBIOS_VERSION ? ([t, new Uint8Array(0)] as [number, Uint8Array]) : [t, v])) });
      expect(await reasonOf({ ev, hook: { firmware: {} } })).toBe("firmware policy: VBIOS version '' in the GPU report is not parseable");
    });
    it('malformed policy strings are rejected at construction', () => {
      const mk = (firmware: NonNullable<NvidiaCollateralOptions['firmware']>) => () => nvidiaCollateralHook({ rimRootSpkiSha256: ['aa'], resolve: () => undefined, firmware });
      expect(mk({ minDriverVersion: '595.x' })).toThrow("nvidiaCollateralHook: malformed minDriverVersion '595.x'");
      expect(mk({ minVbiosVersion: '96.zz' })).toThrow("malformed minVbiosVersion '96.zz'");
      expect(mk({ denyDriverVersions: ['1..2'] })).toThrow("malformed denyDriverVersions entry '1..2'");
      expect(mk({ denyVbiosVersions: ['xyz'] })).toThrow("malformed denyVbiosVersions entry 'xyz'");
    });
  });
});

// ═════════════════════════════════════════════════════════════════════════════════════════════════
describe('revocation via CRL on the forged device chain', () => {
  const chain = S.device.certs.map((c) => new X509Certificate(c.pem));
  const crl = (idx: number, revoked: string[] = [], o: Parameters<typeof forgeNvidiaCrl>[2] = {}) => forgeNvidiaCrl(S.device, idx, { revoked, ...o });
  const rev = (crls: Uint8Array[], now = NOW, need: string[] = []) => checkNvidiaChainRevocation(chain, crls, now, need);
  const subj = (i: number) => chain[i]!.subject.replace(/\n/g, ', ');

  it('empty CRLs from the Identity CA and the root cover the chain', () => {
    expect(rev(S.crls)).toEqual({ ok: true, verifiedCrls: 2 });
  });
  it('requires at least one CRL', () => {
    expect(rev([])).toEqual({ ok: false, reason: 'no CRLs supplied' });
  });
  for (const [issuer, victim] of [[1, 0], [2, 1], [3, 2], [4, 3]] as const) {
    it(`a CRL from "${names[issuer]!.find((a) => a[0] === 'CN')![1]}" revoking "${names[victim]!.find((a) => a[0] === 'CN')![1]}" is fatal`, () => {
      const r = rev([crl(issuer, [S.device.certs[victim]!.serialHex.toUpperCase()])]);
      expect(r).toEqual({ ok: false, reason: `chain certificate '${subj(victim)}' is revoked` });
    });
  }
  it('serial matching ignores case and leading zeros', () => {
    const s = S.device.certs[2]!.serialHex;
    expect(rev([crl(3, [`00${s.toUpperCase()}`])])).toEqual({ ok: false, reason: `chain certificate '${subj(2)}' is revoked` });
  });
  it('a revoked serial is only honoured on a CRL issued by the certificate\'s DIRECT issuer (documented behaviour)', () => {
    expect(rev([crl(4, [S.device.certs[0]!.serialHex])]).ok).toBe(true); // root CRL naming the leaf: not its issuer's CRL
    expect(rev([crl(3, [S.device.certs[0]!.serialHex])]).ok).toBe(true);
  });
  it('unrelated serials do not matter', () => {
    expect(rev([crl(3, ['0102030405', 'ffee'])]).ok).toBe(true);
  });
  it('a CRL signed by a stranger is rejected', () => {
    expect(rev([crl(3, [], { signer: forgeKey('stranger-crl', 'P-384') })])).toEqual({ ok: false, reason: 'CRL #0 rejected: CRL signature does not verify under the issuer' });
  });
  it('a stale CRL is reported as stale (not as a signature failure) wherever its issuer sits in the chain', () => {
    for (const idx of [2, 3, 4]) {
      expect(rev([crl(idx, [], { thisUpdate: new Date('2026-01-01Z'), nextUpdate: new Date('2026-06-01Z') })]), `issuer ${idx}`).toEqual({ ok: false, reason: 'CRL #0 rejected: CRL is stale (nextUpdate passed)' });
    }
  });
  it('a CRL that is not yet valid', () => {
    expect(rev([crl(3, [], { thisUpdate: new Date('2027-01-01Z'), nextUpdate: new Date('2028-01-01Z') })])).toEqual({ ok: false, reason: 'CRL #0 rejected: CRL thisUpdate is in the future' });
  });
  it('a CRL without nextUpdate / garbage DER', () => {
    expect(rev([crl(3, [], { omitNextUpdate: true })])).toEqual({ ok: false, reason: 'CRL #0 rejected: CRL parse failed: CRL: missing nextUpdate' });
    const r = rev([Uint8Array.of(1, 2, 3)]);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/^CRL #0 rejected: CRL parse failed: /);
  });
  it('the second CRL is the one reported when only it is bad', () => {
    expect(rev([crl(3), crl(4, [], { signer: forgeKey('stranger-crl2', 'P-384') })])).toEqual({ ok: false, reason: 'CRL #1 rejected: CRL signature does not verify under the issuer' });
  });
  it('requireIssuers: a verified CRL must exist for each named issuer', () => {
    expect(rev(S.crls, NOW, ['NVIDIA GH100 Identity', 'NVIDIA Device Identity CA']).ok).toBe(true);
    expect(rev([crl(4)], NOW, ['NVIDIA GH100 Identity'])).toEqual({ ok: false, reason: "no verified CRL issued by a certificate matching 'NVIDIA GH100 Identity'" });
    expect(rev([crl(3)], NOW, ['NVIDIA Device Identity CA'])).toEqual({ ok: false, reason: "no verified CRL issued by a certificate matching 'NVIDIA Device Identity CA'" });
  });
  it('through the hook: a revoked chain certificate is reported under "revocation:"', async () => {
    const r = await reasonOf({ bundle: { crls: [crl(3, [S.device.certs[2]!.serialHex]), crl(4)] }, hook: { revocation: 'crl' } });
    expect(r).toBe(`revocation: chain certificate '${subj(2)}' is revoked`);
  });
  it('through the hook: CRL mode requires CRLs; legacy requireCrls:false makes them optional but still enforces supplied ones', async () => {
    expect(await reasonOf({ bundle: { crls: [], ocsp: S.ocsp }, hook: { revocation: 'crl' } })).toBe('revocation: no CRLs supplied');
    expect(await reasonOf({ bundle: { crls: [], ocsp: S.ocsp }, hook: { revocation: undefined, requireCrls: false } })).toBeUndefined();
    expect(await reasonOf({ bundle: { crls: [crl(3, [S.device.certs[2]!.serialHex])], ocsp: S.ocsp }, hook: { revocation: undefined, requireCrls: false } })).toBe(`revocation: chain certificate '${subj(2)}' is revoked`);
  });
  it('through the hook: requireCrlIssuers names a missing issuer', async () => {
    expect(await reasonOf({ bundle: { crls: [crl(4)] }, hook: { revocation: 'crl', requireCrlIssuers: ['GH100 Identity'] } })).toBe("revocation: no verified CRL issued by a certificate matching 'GH100 Identity'");
  });
});

// ═════════════════════════════════════════════════════════════════════════════════════════════════
describe('revocation via OCSP on the forged device chain', () => {
  const chain = S.device.certs.map((c) => new X509Certificate(c.pem));
  const dc = S.device.certs;
  const since = new Date(NOW - 3600_000);
  const until = new Date(NOW + 86400_000);
  const resp = (i: number, over: Partial<ForgeOcspOptions> = {}) => forgeOcspResponse({ cert: dc[i]!, issuer: dc[i + 1]!, thisUpdate: since, nextUpdate: until, ...over });
  const subj = (i: number) => chain[i]!.subject.replace(/\n/g, ', ');
  const chainOcsp = (rs: Uint8Array[], opts: Parameters<typeof checkNvidiaChainOcsp>[3] = {}, now = NOW) => checkNvidiaChainOcsp(chain, rs, now, opts);
  const single = (der: Uint8Array, i: number, extra: Partial<Parameters<typeof verifyNvidiaOcspResponse>[1]> = {}) => verifyNvidiaOcspResponse(der, { cert: chain[i]!, issuer: chain[i + 1]!, chain, nowMs: NOW, ...extra });
  const responder = (i: number, o: Parameters<typeof forgeOcspResponderCert>[2] = {}) => forgeOcspResponderCert(dc[i + 1]!, S.device.keys[i + 1]!, { seed: `resp${i}`, ...o });

  it('GOOD from the issuer itself (byName), for every non-root certificate', async () => {
    for (const i of [0, 1, 2, 3]) {
      expect(await single(resp(i), i), `cert ${i}`).toMatchObject({ ok: true, status: 'good', responder: 'issuer' });
    }
  });
  it('GOOD from the issuer by key hash, and with every CertID hash algorithm', async () => {
    expect(await single(resp(2, { responderId: 'key' }), 2)).toMatchObject({ ok: true, status: 'good' });
    for (const certIdHash of ['sha1', 'sha256', 'sha384', 'sha512'] as const) {
      expect(await single(resp(2, { certIdHash }), 2), certIdHash).toMatchObject({ ok: true, status: 'good' });
    }
  });
  it('REVOKED is reported with time + reason, and fails the chain check naming the certificate', async () => {
    const at = new Date(NOW - 7200_000);
    const der = resp(2, { status: 'revoked', revokedAt: at, reason: 1 });
    expect(await single(der, 2)).toMatchObject({ ok: true, status: 'revoked', revokedAt: at.getTime(), revocationReason: 1 });
    expect(await chainOcsp([der])).toMatchObject({ ok: false, reason: `chain certificate '${subj(2)}' is revoked (OCSP)` });
    expect(await single(resp(2, { status: 'revoked' }), 2)).toMatchObject({ ok: true, status: 'revoked' }); // no reason code
  });
  for (const i of [0, 1, 2, 3]) {
    it(`a REVOKED response for chain position ${i} is fatal through the hook`, async () => {
      const ocsp = [1, 2, 3].filter((x) => x !== i).map((x) => resp(x)).concat([resp(i, { status: 'revoked' })]);
      expect(await reasonOf({ bundle: { ocsp }, hook: { revocation: 'ocsp' } })).toBe(`revocation (OCSP): chain certificate '${subj(i)}' is revoked (OCSP)`);
    });
  }
  it('UNKNOWN: tolerated for a certificate that is not required, fatal for a required one', async () => {
    const der = resp(0, { status: 'unknown' });
    expect(await single(der, 0)).toMatchObject({ ok: true, status: 'unknown' });
    expect(await chainOcsp([der], { requireGood: [] })).toMatchObject({ ok: true, statuses: { 0: 'unknown', 1: 'absent' } });
    expect(await chainOcsp([der], { requireGood: [0] })).toMatchObject({ ok: false, reason: `no GOOD OCSP response for required certificate '${subj(0)}' (status: unknown)` });
  });
  it('the default policy requires GOOD only for certificates that advertise an OCSP URL (the ICA and Identity)', async () => {
    expect(await chainOcsp([resp(2), resp(3)])).toMatchObject({ ok: true, verifiedOcsp: 2, statuses: { 0: 'absent', 1: 'absent', 2: 'good', 3: 'good' } });
    expect(await chainOcsp([resp(2)])).toMatchObject({ ok: false, reason: `no GOOD OCSP response for required certificate '${subj(3)}' (status: absent)` });
    expect(await chainOcsp([resp(2), resp(3)], { requireGood: 'all' })).toMatchObject({ ok: false, reason: expect.stringContaining('(status: absent)') });
    expect(await chainOcsp([resp(0), resp(1), resp(2), resp(3)], { requireGood: 'all' })).toMatchObject({ ok: true, verifiedOcsp: 4 });
  });
  it('chain-level guards', async () => {
    expect(await checkNvidiaChainOcsp([chain[0]!], [resp(0)], NOW)).toEqual({ ok: false, reason: 'chain too short for OCSP' });
    expect(await chainOcsp([])).toEqual({ ok: false, reason: 'no OCSP responses supplied' });
    expect(await chainOcsp([resp(2)], { requireGood: [4] })).toEqual({ ok: false, reason: 'requireGood index 4 is not a non-root chain certificate' });
    expect(await chainOcsp([resp(2)], { requireGood: [-1] })).toEqual({ ok: false, reason: 'requireGood index -1 is not a non-root chain certificate' });
  });
  it('a response matching no chain certificate is rejected; duplicates are rejected', async () => {
    const stranger = forgeNvidiaScenario({ seed: 'other-device' }).device;
    const foreign = forgeOcspResponse({ cert: stranger.certs[2]!, issuer: stranger.certs[3]!, thisUpdate: since, nextUpdate: until });
    expect(await chainOcsp([foreign], { requireGood: [] })).toMatchObject({ ok: false, reason: 'OCSP response #0 rejected: no SingleResponse matches the certificate (serial / issuer hashes differ)' });
    expect(await chainOcsp([resp(2), resp(2)], { requireGood: [] })).toMatchObject({ ok: false, reason: 'duplicate OCSP responses for chain certificate #2' });
  });
  it('responseStatus other than successful, and the wrong response type', async () => {
    for (const code of [1, 2, 3, 5, 6]) expect(await single(resp(2, { responseStatus: code }), 2)).toEqual({ ok: false, reason: `OCSP responseStatus is ${code} (not successful)` });
    expect(await single(resp(2, { responseType: '1.3.6.1.5.5.7.48.1.2' }), 2)).toEqual({ ok: false, reason: 'responseType is not id-pkix-ocsp-basic' });
  });
  it('trailing bytes, garbage, truncation', async () => {
    expect(await single(resp(2, { trailing: Uint8Array.of(0) }), 2)).toEqual({ ok: false, reason: 'trailing bytes after OCSPResponse' });
    expect((await single(Uint8Array.of(1, 2, 3), 2)).ok).toBe(false);
    expect((await single(resp(2).slice(0, 80), 2)).ok).toBe(false);
  });
  it('the CertID must match: wrong serial, wrong issuer', async () => {
    const wrongSerial = resp(2, { serialOverride: hexToBytes('0102030405') });
    expect(await single(wrongSerial, 2)).toEqual({ ok: false, reason: 'no SingleResponse matches the certificate (serial / issuer hashes differ)' });
    expect(await single(resp(2), 2, { issuer: chain[2]! })).toEqual({ ok: false, reason: 'no SingleResponse matches the certificate (serial / issuer hashes differ)' });
  });
  it('two matching SingleResponses are ambiguous', async () => {
    expect(await single(resp(2, { duplicate: true }), 2)).toEqual({ ok: false, reason: 'ambiguous: multiple SingleResponses match the certificate' });
  });

  describe('responder authentication', () => {
    it('delegated responder (EKU OCSPSigning, signed by the issuer), byName and byKey', async () => {
      for (const responderId of ['name', 'key'] as const) {
        const rc = responder(2);
        expect(await single(resp(2, { responder: { kind: 'delegated', cert: rc }, responderId }), 2), responderId).toMatchObject({ ok: true, status: 'good', responder: 'delegated' });
      }
    });
    it('delegated responder signed by a CA ABOVE the issuer (the root) is accepted — chain slice(issuerIdx)', async () => {
      const rc = forgeOcspResponderCert(dc[4]!, S.device.keys[4]!, { seed: 'root-signed' });
      expect(await single(resp(2, { responder: { kind: 'delegated', cert: rc } }), 2)).toMatchObject({ ok: true, responder: 'delegated' });
    });
    it('a delegated responder without the id-kp-OCSPSigning EKU, or with the wrong EKU', async () => {
      for (const eku of [null, ['1.3.6.1.5.5.7.3.1']] as const) {
        const rc = responder(2, { eku: eku === null ? null : [...eku] });
        expect(await single(resp(2, { responder: { kind: 'delegated', cert: rc } }), 2)).toEqual({ ok: false, reason: 'delegated responder certificate lacks the id-kp-OCSPSigning EKU' });
      }
    });
    it('an expired / not-yet-valid delegated responder', async () => {
      for (const v of [{ notBefore: new Date('2020-01-01Z'), notAfter: new Date('2026-01-01Z') }, { notBefore: new Date('2027-01-01Z'), notAfter: new Date('2030-01-01Z') }]) {
        const rc = responder(2, v);
        expect(await single(resp(2, { responder: { kind: 'delegated', cert: rc } }), 2)).toEqual({ ok: false, reason: 'delegated responder certificate is outside its validity window' });
      }
    });
    it('a delegated responder issued by a stranger CA', async () => {
      const k = forgeKey('rogue-ocsp-ca', 'P-384');
      const rogueCa = forgeOcspResponderCert(dc[3]!, k, { seed: 'rogue-ca-cert' });
      const rc = forgeOcspResponderCert(rogueCa, k, { seed: 'rogue-resp' });
      expect(await single(resp(2, { responder: { kind: 'delegated', cert: rc } }), 2)).toEqual({ ok: false, reason: 'delegated responder certificate is not signed by the supplied NVIDIA chain' });
    });
    it('a delegated responder that is not embedded in the response', async () => {
      const rc = responder(2);
      expect(await single(resp(2, { responder: { kind: 'delegated', cert: rc, embed: false } }), 2)).toEqual({ ok: false, reason: 'no embedded responder certificate verifies the response' });
    });
    it('a response whose responderID does not match the embedded certificate', async () => {
      const embedded = responder(2);
      const named = responder(2, { seed: 'other-responder', cn: 'Somebody Else' });
      for (const responderId of ['name', 'key'] as const) {
        const der = resp(2, { responder: { kind: 'delegated', cert: named }, embedCerts: [embedded], responderId });
        expect(await single(der, 2), responderId).toEqual({ ok: false, reason: 'embedded certificates do not match the responderID' });
      }
    });
    it('a delegated responder whose key did not sign the response', async () => {
      const rc = responder(2);
      expect(await single(resp(2, { responder: { kind: 'delegated', cert: rc }, signer: forgeKey('wrong-key', 'P-384') }), 2)).toEqual({ ok: false, reason: 'OCSP response signature does not verify under the delegated responder key' });
    });
    it('the issuer named as responder but the signature is by a stranger key', async () => {
      expect(await single(resp(2, { signer: forgeKey('imposter', 'P-384') }), 2)).toEqual({ ok: false, reason: 'OCSP response signature does not verify under the issuer key' });
    });
  });

  describe('nonce + freshness', () => {
    const nonce = new Uint8Array(16).fill(0xab);
    it('echoes the nonce: match accepted; absent / mismatching rejected', async () => {
      expect(await single(resp(2, { nonce }), 2, { expectedNonce: nonce })).toMatchObject({ ok: true });
      expect(await single(resp(2), 2, { expectedNonce: nonce })).toEqual({ ok: false, reason: 'response does not echo the nonce' });
      expect(await single(resp(2, { nonce: new Uint8Array(16).fill(1) }), 2, { expectedNonce: nonce })).toEqual({ ok: false, reason: 'response nonce does not match the request nonce' });
    });
    it('chain-level expectedNonces apply per chain index', async () => {
      expect(await chainOcsp([resp(2, { nonce }), resp(3)], { expectedNonces: [undefined, undefined, nonce] })).toMatchObject({ ok: true });
      expect(await chainOcsp([resp(2), resp(3)], { expectedNonces: [undefined, undefined, nonce] })).toMatchObject({ ok: false, reason: `OCSP response #0 for '${subj(2)}' rejected: response does not echo the nonce` });
    });
    it('stale (past nextUpdate)', async () => {
      expect(await single(resp(2, { thisUpdate: new Date(NOW - 2 * 86400_000), nextUpdate: new Date(NOW - 86400_000) }), 2)).toEqual({ ok: false, reason: 'response is stale (past nextUpdate)' });
    });
    it('thisUpdate / producedAt in the future (clock skew tolerated only when granted)', async () => {
      const fut = new Date(NOW + 3600_000);
      expect(await single(resp(2, { thisUpdate: fut, nextUpdate: new Date(NOW + 86400_000), producedAt: since }), 2)).toEqual({ ok: false, reason: 'response thisUpdate is in the future' });
      expect(await single(resp(2, { producedAt: fut }), 2)).toEqual({ ok: false, reason: 'response producedAt is in the future' });
      expect(await single(resp(2, { thisUpdate: new Date(NOW + 60_000), producedAt: since }), 2, { clockSkewMs: 120_000 })).toMatchObject({ ok: true });
    });
    it('nextUpdate before thisUpdate is invalid', async () => {
      expect(await single(resp(2, { thisUpdate: since, nextUpdate: new Date(since.getTime() - 1000) }), 2)).toEqual({ ok: false, reason: 'response nextUpdate is invalid' });
    });
    it('without nextUpdate the response is bounded by the maximum age (default 7 days)', async () => {
      const old = new Date(NOW - 8 * 86400_000);
      expect(await single(forgeOcspResponse({ cert: dc[2]!, issuer: dc[3]!, thisUpdate: old, producedAt: old }), 2)).toEqual({ ok: false, reason: 'response is older than the maximum accepted age' });
      expect(await single(forgeOcspResponse({ cert: dc[2]!, issuer: dc[3]!, thisUpdate: old, producedAt: old }), 2, { maxAgeMs: 10 * 86400_000 })).toMatchObject({ ok: true, status: 'good' });
      expect(await single(forgeOcspResponse({ cert: dc[2]!, issuer: dc[3]!, thisUpdate: since }), 2)).toMatchObject({ ok: true });
    });
    it('a response older than maxAge is rejected even before nextUpdate', async () => {
      expect(await single(resp(2, { thisUpdate: new Date(NOW - 3 * 86400_000), nextUpdate: until }), 2, { maxAgeMs: 86400_000 })).toEqual({ ok: false, reason: 'response is older than the maximum accepted age' });
    });
  });

  describe('through nvidiaCollateralHook', () => {
    it('the consistent scenario passes with revocation "ocsp" and "both"', async () => {
      expect(await reasonOf({ hook: { revocation: 'ocsp' } })).toBeUndefined();
      expect(await reasonOf({ hook: { revocation: 'both' } })).toBeUndefined();
    });
    it('"ocsp" mode demands OCSP evidence', async () => {
      expect(await reasonOf({ bundle: { ocsp: [] }, hook: { revocation: 'ocsp' } })).toBe('revocation (OCSP): no OCSP responses supplied');
    });
    it('a missing response for an AIA-advertising certificate', async () => {
      expect(await reasonOf({ bundle: { ocsp: [S.ocsp[0]!, S.ocsp[1]!] }, hook: { revocation: 'ocsp' } })).toBe(`revocation (OCSP): no GOOD OCSP response for required certificate '${subj(3)}' (status: absent)`);
    });
    it('a stale clock rejects otherwise-good responses', async () => {
      const r = await reasonOf({ nowMs: NOW + 40 * 86400_000, hook: { revocation: 'ocsp' }, bundle: { crls: [] } });
      expect(r).toBe(`revocation (OCSP): OCSP response #0 for '${subj(1)}' rejected: response is stale (past nextUpdate)`);
    });
    it('CRLs supplied under "ocsp" mode are still enforced', async () => {
      const r = await reasonOf({ bundle: { crls: [forgeNvidiaCrl(S.device, 3, { revoked: [dc[2]!.serialHex] })] }, hook: { revocation: 'ocsp' } });
      expect(r).toBe(`revocation: chain certificate '${subj(2)}' is revoked`);
    });
  });
});
