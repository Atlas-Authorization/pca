/**
 * NVIDIA BLACKWELL (GB100) GPU-CC, end to end, on REAL evidence (fixtures/real-nvidia-cc/blackwell): two physical GPUs
 * of one 8x GB100 node, NVIDIA's signed driver + VBIOS RIMs, NVIDIA's published GB100 CRLs and live OCSP responses.
 *
 * Blackwell differs from Hopper in how the driver RIM is NAMED (`NV_GPU_CC_DRIVER_<chip>_<ver>`, chip = the report's
 * signed opaque field 35) and the Hopper-style id returns a validly signed but WRONG manifest (product GH100), so the
 * hook must bind each RIM's `product` and the device-certificate family to the chip the GPU reports.
 * Every negative asserts the specific rejection reason.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createNvidiaSpdmVerifier, parseNvidiaSpdmEvidence, parsePemChain, verifyNvidiaDeviceChain, NVIDIA_OPAQUE } from './attest-nvidia-spdm';
import { nvidiaCollateralHook, nvidiaRimIdsForReport, verifyNvidiaRim, type NvidiaCollateralBundle } from './attest-nvidia-rim';
import type { AttestationDocument, ExpectedAttestationBinding } from './attestation';

const FX = (...p: string[]) => resolve(__dirname, '..', 'fixtures', 'real-nvidia-cc', ...p);
const text = (...p: string[]) => readFileSync(FX(...p), 'utf8');
const bytes = (...p: string[]) => new Uint8Array(readFileSync(FX(...p)));

const GPU0 = { report: bytes('blackwell', 'gb100-gpu-attestation-report.bin'), chain: text('blackwell', 'gb100-device-cert-chain.pem'), brom: 'gpu0-1-brom' };
const GPU1 = { report: bytes('blackwell', 'gb100-gpu1-attestation-report.bin'), chain: text('blackwell', 'gb100-gpu1-device-cert-chain.pem'), brom: 'gpu1-1-brom' };
const HOPPER = { report: bytes('own-h100', 'h100-gpu-attestation-report.bin'), chain: text('own-h100', 'h100-device-cert-chain.pem') };

const DEVICE_ROOT_SPKI = 'a90c4eb5acfd3e3d03a25db6a26b84f720ad0503196c627c21ddd48dd85b06a4';
const RIM_ROOT_SPKI = 'dec1dc316477aa851eebdf51327ae9f864bc8d89254657ed1e7eb9168af1e1a3';
/** Just after the OCSP capture (2026-10-09T00:32:35Z); OCSP responses are valid for 24 h. */
const NOW_MS = Date.parse('2026-10-09T00:33:00Z');
const EXPECTED: ExpectedAttestationBinding = {
  holderPub: 'pca-realsilicon-nvidia-h100-holder',
  grantRef: 'grant_pca_nvidia_gpucc_realsilicon',
  epoch: 1,
  nonce: 'srv-nonce-nv-7c1e9f2a4b8d0536',
};
const DOC = {} as unknown as AttestationDocument;
const CTX = {} as never;

const BW_DRIVER_RIM = text('blackwell', 'driver-rim.xml');
const BW_VBIOS_RIM = text('blackwell', 'vbios-rim.xml');
const HOP_DRIVER_RIM = text('collateral', 'driver-rim-NV_GPU_DRIVER_GH100_580.95.05.xml');
const HOP_VBIOS_RIM = text('collateral', 'vbios-rim-NV_GPU_VBIOS_G520_0280_895_9600D00003.xml');
const BW_CRLS = [bytes('blackwell', 'l2-gb100.crl'), bytes('blackwell', 'l1-root.crl')];
const bundleFor = (gpu: typeof GPU0, over: Partial<NvidiaCollateralBundle> = {}): NvidiaCollateralBundle => ({
  driverRimXml: BW_DRIVER_RIM,
  vbiosRimXml: BW_VBIOS_RIM,
  crls: BW_CRLS,
  ocsp: [bytes('blackwell', 'ocsp', `${gpu.brom}.nonce.resp.der`), bytes('blackwell', 'ocsp', '2-provisioner-ica.nonce.resp.der'), bytes('blackwell', 'ocsp', '3-identity.nonce.resp.der')],
  ...over,
});

function verifier(gpu: { report: Uint8Array; chain: string }, bundle: NvidiaCollateralBundle, o: { leaf?: string; revocation?: 'crl' | 'ocsp' | 'both'; hook?: Partial<Parameters<typeof nvidiaCollateralHook>[0]> } = {}) {
  return createNvidiaSpdmVerifier({
    rootSpkiSha256: [DEVICE_ROOT_SPKI],
    policy: { measurements: {}, leafSubjectIncludes: o.leaf ?? 'GB100' },
    resolveEvidence: () => ({ evidence: gpu.report, certChainPem: gpu.chain }),
    postVerify: nvidiaCollateralHook({
      rimRootSpkiSha256: [RIM_ROOT_SPKI],
      resolve: () => bundle,
      revocation: o.revocation ?? 'both',
      requireCrlIssuers: ['NVIDIA GB100 Identity', 'NVIDIA Device Identity CA'],
      ...(o.hook ?? {}),
    }),
  });
}
const run = (v: ReturnType<typeof verifier>, nowMs = NOW_MS) => v.verify({ document: DOC, ctx: CTX, nowMs, expected: EXPECTED });

describe('Blackwell RIM naming (from the GPU-signed opaque data)', () => {
  it('both GB100 GPUs report chip GB100 and name the CC driver RIM + VBIOS RIM', () => {
    for (const gpu of [GPU0, GPU1]) {
      const rep = parseNvidiaSpdmEvidence(gpu.report);
      expect(Buffer.from(rep.response.opaque.get(NVIDIA_OPAQUE.CHIP_INFO)!).toString('latin1').replace(/\0+$/, '')).toBe('GB100');
      expect(nvidiaRimIdsForReport(rep)).toEqual({
        chip: 'GB100',
        driver: 'NV_GPU_CC_DRIVER_GB100_595.91.07',
        vbios: 'NV_GPU_VBIOS_G525_0220_886_9700E4001E',
        driverVersion: '595.91.07',
        vbiosVersion: '97.00.e4.00.1e',
      });
    }
  });
  it('a Hopper report (no field 35) keeps the Hopper naming and chip GH100', () => {
    const rep = parseNvidiaSpdmEvidence(HOPPER.report);
    expect(rep.response.opaque.has(NVIDIA_OPAQUE.CHIP_INFO)).toBe(false);
    const ids = nvidiaRimIdsForReport(rep)!;
    expect([ids.chip, ids.driver]).toEqual(['GH100', 'NV_GPU_DRIVER_GH100_595.71.05']);
  });
  it('a present-but-malformed CHIP_INFO fails closed (no ids), including through the hook', async () => {
    for (const bad of ['', 'gb100', 'GB 100', '1B100', 'GB100/../x']) {
      const rep = parseNvidiaSpdmEvidence(GPU0.report);
      rep.response.opaque.set(NVIDIA_OPAQUE.CHIP_INFO, new TextEncoder().encode(bad));
      expect(nvidiaRimIdsForReport(rep), `chip '${bad}'`).toBeUndefined();
    }
    const rep = parseNvidiaSpdmEvidence(GPU0.report);
    rep.response.opaque.set(NVIDIA_OPAQUE.CHIP_INFO, new TextEncoder().encode('gb100'));
    const chain = parsePemChain(GPU0.chain);
    const hook = nvidiaCollateralHook({ rimRootSpkiSha256: [RIM_ROOT_SPKI], resolve: () => bundleFor(GPU0) });
    expect(await hook({ report: rep, chain, leaf: chain[0]!, nowMs: NOW_MS })).toBe('GPU report does not carry the opaque fields needed to name its RIMs');
  });
});

describe('Blackwell RIMs and device chain are genuine', () => {
  it('both RIMs verify under the pinned CoRIM root and are product GB100 for the report\'s versions', async () => {
    for (const [xml, version] of [[BW_DRIVER_RIM, '595.91.07'], [BW_VBIOS_RIM, '97.00.E4.00.1E']] as const) {
      const r = await verifyNvidiaRim(xml, { rimRootSpkiSha256: [RIM_ROOT_SPKI], nowMs: NOW_MS });
      expect(r.ok).toBe(true);
      if (r.ok) expect([r.rim.product, r.rim.version]).toEqual(['GB100', version]);
    }
  });
  it('both chains verify to the SAME pinned Device Identity CA and have different leaves', () => {
    const a = verifyNvidiaDeviceChain(GPU0.chain, [DEVICE_ROOT_SPKI], NOW_MS);
    const b = verifyNvidiaDeviceChain(GPU1.chain, [DEVICE_ROOT_SPKI], NOW_MS);
    expect([a.ok, b.ok]).toEqual([true, true]);
    if (a.ok && b.ok) {
      expect(a.leaf.serialNumber).not.toBe(b.leaf.serialNumber);
      expect(a.chain[3]!.subject).toContain('NVIDIA GB100 Identity');
    }
  });
});

describe('Blackwell GPU-CC end to end (real silicon, real RIMs, real CRLs + OCSP)', () => {
  for (const [name, gpu] of [['GPU 0', GPU0], ['GPU 1', GPU1]] as const) {
    it(`${name}: chain + signature + PCA binding + driver/VBIOS RIM golden values + GB100 CRLs + OCSP all verify, no operator-pinned digests`, async () => {
      const r = await run(verifier(gpu, bundleFor(gpu)));
      expect(r.reason).toBeUndefined();
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(r.bound).toBe(true);
        expect(r.hostAsserted?.driver_version).toBe('595.91.07');
        expect(r.hostAsserted?.vbios_version).toBe('97.00.e4.00.1e');
        expect(r.hostAsserted?.leaf_subject).toContain('GB100 A01 GSP FMC LF');
      }
    });
  }
  it('CRL-only and OCSP-only revocation each suffice on their own', async () => {
    expect((await run(verifier(GPU0, bundleFor(GPU0, { ocsp: [] }), { revocation: 'crl' }))).ok).toBe(true);
    expect((await run(verifier(GPU0, bundleFor(GPU0, { crls: [] }), { revocation: 'ocsp' }))).ok).toBe(true);
  });
  it('the firmware floor is enforced on the GPU-reported Blackwell versions', async () => {
    const hook = { firmware: { minDriverVersion: '595.91.08' } };
    expect((await run(verifier(GPU0, bundleFor(GPU0), { hook }))).reason).toBe('firmware policy: driver 595.91.07 is below the minimum 595.91.08');
    expect((await run(verifier(GPU0, bundleFor(GPU0), { hook: { firmware: { minDriverVersion: '595.91.07', minVbiosVersion: '97.00.e4.00.1e' } } }))).ok).toBe(true);
  });
});

describe('Blackwell NEGATIVES: wrong-family manifests, wrong identity, wrong collateral', () => {
  it('HOPPER RIMs supplied for a Blackwell report are rejected with the product-mismatch reason (driver first)', async () => {
    const r = await run(verifier(GPU0, bundleFor(GPU0, { driverRimXml: HOP_DRIVER_RIM, vbiosRimXml: HOP_VBIOS_RIM })));
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("driver RIM product 'GH100' does not match the GPU chip 'GB100' (wrong-family manifest)");
  });
  it('only the VBIOS RIM being Hopper is rejected with the VBIOS product-mismatch reason', async () => {
    const r = await run(verifier(GPU0, bundleFor(GPU0, { vbiosRimXml: HOP_VBIOS_RIM })));
    expect(r.reason).toBe("VBIOS RIM product 'GH100' does not match the GPU chip 'GB100' (wrong-family manifest)");
  });
  it('BLACKWELL RIMs supplied for a Hopper report are rejected with the product-mismatch reason', async () => {
    const r = await run(verifier(HOPPER, bundleFor(GPU0, { ocsp: [] }), { leaf: 'GH100', revocation: 'crl', hook: { requireCrlIssuers: [] } }));
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("driver RIM product 'GB100' does not match the GPU chip 'GH100' (wrong-family manifest)");
  });
  it('the Hopper-style id is exactly what the OLD code asked for: it differs from the Blackwell id', () => {
    const ids = nvidiaRimIdsForReport(parseNvidiaSpdmEvidence(GPU0.report))!;
    expect(ids.driver).not.toBe(`NV_GPU_DRIVER_GH100_${ids.driverVersion}`);
  });
  it('a Hopper device leaf cannot satisfy a Blackwell report at the hook (chip-family mismatch)', async () => {
    const rep = parseNvidiaSpdmEvidence(GPU0.report);
    const chain = parsePemChain(HOPPER.chain);
    const hook = nvidiaCollateralHook({ rimRootSpkiSha256: [RIM_ROOT_SPKI], resolve: () => bundleFor(GPU0) });
    const why = await hook({ report: rep, chain, leaf: chain[0]!, nowMs: NOW_MS });
    expect(why).toMatch(/^device leaf subject '.*GH100 A01 GSP FMC LF' is not a GB100 device certificate \(chip family mismatch\)$/);
  });
  it('a Hopper chain fails the verifier-level leaf-subject gate for a GB100 policy', async () => {
    const r = await run(verifier(HOPPER, bundleFor(GPU0)));
    expect(r.reason).toBe("device leaf subject does not contain 'GB100'");
  });
  it('GPU 1\'s device chain cannot vouch for GPU 0\'s report (cross-GPU impersonation)', async () => {
    const r = await run(verifier({ report: GPU0.report, chain: GPU1.chain }, bundleFor(GPU0)));
    expect(r.reason).toBe('GPU attestation report signature does not verify under the device identity key');
  });
  it('a flipped measurement byte breaks the GPU signature before any collateral is consulted', async () => {
    const m = new Uint8Array(GPU0.report);
    m[37 + 8 + 4 + 3 + 5] = m[37 + 8 + 4 + 3 + 5]! ^ 0x01;
    const r = await run(verifier({ report: m, chain: GPU0.chain }, bundleFor(GPU0)));
    expect(r.reason).toBe('GPU attestation report signature does not verify under the device identity key');
  });
  it('the HOPPER CRL set cannot stand in for the GB100 chain (no verified CRL from the GB100 Identity CA)', async () => {
    const hopperCrls = [bytes('collateral', 'l2-gh100.crl'), bytes('collateral', 'l1-root.crl')];
    const r = await run(verifier(GPU0, bundleFor(GPU0, { crls: hopperCrls }), { revocation: 'crl' }));
    expect(r.reason).toMatch(/^revocation: CRL #0 rejected: /);
  });
  it('the root CRL alone does not cover the GB100 Identity CA (requireCrlIssuers enforced)', async () => {
    const r = await run(verifier(GPU0, bundleFor(GPU0, { crls: [bytes('blackwell', 'l1-root.crl')] }), { revocation: 'crl' }));
    expect(r.reason).toBe("revocation: no verified CRL issued by a certificate matching 'NVIDIA GB100 Identity'");
  });
  it('GPU 1\'s BROM OCSP response does not vouch for GPU 0 (response matches no chain certificate)', async () => {
    const r = await run(verifier(GPU0, bundleFor(GPU0, { ocsp: [bytes('blackwell', 'ocsp', 'gpu1-1-brom.nonce.resp.der'), bytes('blackwell', 'ocsp', '2-provisioner-ica.nonce.resp.der'), bytes('blackwell', 'ocsp', '3-identity.nonce.resp.der')] }), { revocation: 'ocsp' }));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/^revocation \(OCSP\): OCSP response #0 rejected: /);
  });
  it('OCSP evidence that is more than its freshness window old is refused', async () => {
    const r = await run(verifier(GPU0, bundleFor(GPU0), { revocation: 'ocsp' }), NOW_MS + 72 * 3600_000);
    expect(r.reason).toBe("revocation (OCSP): OCSP response #0 for 'serialNumber=41F8BB31A7970FD1EC, C=US, O=NVIDIA Corporation, CN=GB100 A01 GSP BROM' rejected: response is stale (past nextUpdate)");
  });
  it('a relayed PCA binding is refused before any collateral is consulted', async () => {
    const v = verifier(GPU0, bundleFor(GPU0));
    const r = await v.verify({ document: DOC, ctx: CTX, nowMs: NOW_MS, expected: { ...EXPECTED, holderPub: 'someone-else' } });
    expect(r.reason).toBe('SPDM request nonce does not bind holder/grant/epoch/nonce (relayed or unbound report)');
  });
});
