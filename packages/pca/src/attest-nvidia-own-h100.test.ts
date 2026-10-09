/**
 * NVIDIA GPU-CC on hardware WE OPERATE. Evidence captured 2026-10-08 from an Azure NCC40ads_H100_v5 confidential VM in
 * our own subscription (H100 NVL, driver 595.71.05, VBIOS 96.00.9f.00.04, CC status ON, CPU CC = AMD SEV-SNP vTOM),
 * collected with NVIDIA's own tooling over the PCA challenge. NVIDIA's local verifier independently reported
 * "GPU Attestation is Successful" (driver RIM, VBIOS RIM and runtime-vs-golden measurements) on the same boot.
 * This is a second, different physical GPU/SKU from the Phala capture in `fixtures/real-nvidia-cc`.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it, expect } from 'vitest';
import { createNvidiaSpdmVerifier, parseNvidiaSpdmEvidence, parsePemChain } from './attest-nvidia-spdm';
import { nvidiaCollateralHook, nvidiaRimIdsForReport, type NvidiaCollateralBundle } from './attest-nvidia-rim';
import type { AttestationDocument, ExpectedAttestationBinding } from './attestation';

const FX = (...p: string[]) => resolve(__dirname, '..', 'fixtures', 'real-nvidia-cc', ...p);
const text = (...p: string[]) => readFileSync(FX(...p), 'utf8');
const bytes = (...p: string[]) => new Uint8Array(readFileSync(FX(...p)));

const OWN_REPORT = bytes('own-h100', 'h100-gpu-attestation-report.bin');
const OWN_CHAIN = text('own-h100', 'h100-device-cert-chain.pem');
const OWN_BUNDLE: NvidiaCollateralBundle = {
  driverRimXml: text('own-h100', 'driver-rim.xml'),
  vbiosRimXml: text('own-h100', 'vbios-rim.xml'),
  crls: [bytes('collateral', 'l2-gh100.crl'), bytes('collateral', 'l1-root.crl')],
};
const OTHER_REPORT = bytes('h100-gpu-attestation-report.bin');
const OTHER_CHAIN = text('h100-device-cert-chain.pem');

const DEVICE_ROOT_SPKI = 'a90c4eb5acfd3e3d03a25db6a26b84f720ad0503196c627c21ddd48dd85b06a4';
const RIM_ROOT_SPKI = 'dec1dc316477aa851eebdf51327ae9f864bc8d89254657ed1e7eb9168af1e1a3';
const NOW_MS = Date.parse('2026-10-09T00:00:00Z');
const EXPECTED: ExpectedAttestationBinding = {
  holderPub: 'pca-realsilicon-nvidia-h100-holder',
  grantRef: 'grant_pca_nvidia_gpucc_realsilicon',
  epoch: 1,
  nonce: 'srv-nonce-nv-7c1e9f2a4b8d0536',
};
const DOC = {} as unknown as AttestationDocument;
const CTX = {} as never;

function verifier(evidence: { evidence: Uint8Array; certChainPem: string }, bundle: NvidiaCollateralBundle = OWN_BUNDLE) {
  return createNvidiaSpdmVerifier({
    rootSpkiSha256: [DEVICE_ROOT_SPKI],
    policy: { measurements: {}, leafSubjectIncludes: 'GH100' },
    resolveEvidence: () => evidence,
    postVerify: nvidiaCollateralHook({ rimRootSpkiSha256: [RIM_ROOT_SPKI], resolve: () => bundle, requireCrlIssuers: ['NVIDIA GH100 Identity', 'NVIDIA Device Identity CA'] }),
  });
}
const run = (v: ReturnType<typeof verifier>, expected = EXPECTED) => v.verify({ document: DOC, ctx: CTX, nowMs: NOW_MS, expected });

describe('NVIDIA GPU-CC — our own Azure H100 NVL (driver 595.71.05)', () => {
  it('names RIMs for THIS gpu (different SKU/VBIOS/driver than the Phala capture)', () => {
    const own = nvidiaRimIdsForReport(parseNvidiaSpdmEvidence(OWN_REPORT))!;
    const other = nvidiaRimIdsForReport(parseNvidiaSpdmEvidence(OTHER_REPORT))!;
    expect(own.driver).toBe('NV_GPU_DRIVER_GH100_595.71.05');
    expect(own.vbios).toBe('NV_GPU_VBIOS_1010_0210_886_96009F0004');
    expect(other.driver).not.toBe(own.driver);
    expect(other.vbios).not.toBe(own.vbios);
  });

  it('two physically different GPUs: different device leaf certificates', () => {
    const a = parsePemChain(OWN_CHAIN)[0]!;
    const b = parsePemChain(OTHER_CHAIN)[0]!;
    expect(a.serialNumber).not.toBe(b.serialNumber);
  });

  it('verifies end to end with NO operator-pinned digests: chain + signature + PCA binding + RIM golden values + CRLs', async () => {
    const r = await run(verifier({ evidence: OWN_REPORT, certChainPem: OWN_CHAIN }));
    expect(r.reason).toBeUndefined();
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.bound).toBe(true);
      expect(r.hostAsserted?.driver_version).toBe('595.71.05');
      expect(r.hostAsserted?.leaf_subject).toContain('GH100');
    }
  });

  it('fails closed: another GPU\'s RIMs (Phala H100) do not match this GPU', async () => {
    const wrong: NvidiaCollateralBundle = {
      ...OWN_BUNDLE,
      driverRimXml: text('collateral', 'driver-rim-NV_GPU_DRIVER_GH100_580.95.05.xml'),
      vbiosRimXml: text('collateral', 'vbios-rim-NV_GPU_VBIOS_G520_0280_895_9600D00003.xml'),
    };
    const r = await run(verifier({ evidence: OWN_REPORT, certChainPem: OWN_CHAIN }, wrong));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/driver RIM version|VBIOS RIM version/);
  });

  it('fails closed: one GPU\'s device chain cannot vouch for another GPU\'s report (cross-GPU impersonation)', async () => {
    const a = await run(verifier({ evidence: OWN_REPORT, certChainPem: OTHER_CHAIN }));
    expect(a.ok).toBe(false);
    if (!a.ok) expect(a.reason).toContain('signature does not verify');
    const b = await run(verifier({ evidence: OTHER_REPORT, certChainPem: OWN_CHAIN }));
    expect(b.ok).toBe(false);
  });

  it('fails closed: relayed binding, flipped measurement, tampered signature', async () => {
    const v = verifier({ evidence: OWN_REPORT, certChainPem: OWN_CHAIN });
    expect((await run(v, { ...EXPECTED, holderPub: 'someone-else' })).ok).toBe(false);
    const m = new Uint8Array(OWN_REPORT);
    m[37 + 8 + 4 + 3 + 5] = (m[37 + 8 + 4 + 3 + 5] ?? 0) ^ 0x01;
    expect((await run(verifier({ evidence: m, certChainPem: OWN_CHAIN }))).ok).toBe(false);
    const s = new Uint8Array(OWN_REPORT);
    s[s.length - 1] = (s[s.length - 1] ?? 0) ^ 0x01;
    expect((await run(verifier({ evidence: s, certChainPem: OWN_CHAIN }))).ok).toBe(false);
  });
});
