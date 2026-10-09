import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { X509Certificate, type KeyObject } from 'node:crypto';
import { parseSevSnpReport, toHex } from '@atlasauth/pca';
import {
  AMD_MILAN_ARK_SPKI_SHA384,
  KNOWN_AMD_ARK_SPKI_SHA384,
  AMD_SEV_SNP_HARDWARE_ROOT_LABEL,
  buildEAT,
  evidenceFromReport,
  generateEatKeyPair,
  issueNonce,
  measuredFromReport,
  verifyAmdAttestation,
  verifyFreshAttestedEAT,
  type AmdAttestationInput,
} from './index';

// GENUINE AMD SEV-SNP evidence, verified through the HARDENED @atlasauth/pca chain (this package keeps no AMD
// crypto of its own):
//   Genoa — a real Azure Confidential VM (vTPM HCL blob: the SNP report is bytes [32, 32+1184)) with the AMD KDS
//           chain Azure served for THIS chip (packages/pca/fixtures/real-azure-maa).
//   Milan — an older real Azure capture (packages/pca/testdata/sevsnp-real).
const PCA = join(__dirname, '..', '..', 'pca');
const NOW = Date.parse('2026-10-08T12:00:00Z');
const PEM_BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

const genoaCerts = JSON.parse(readFileSync(join(PCA, 'fixtures', 'real-azure-maa', 'sevsnp-amd-certs.json'), 'utf8')) as { vcekCert: string; certificateChain: string };
const [genoaAsk, genoaArk] = genoaCerts.certificateChain.match(PEM_BLOCK) as [string, string];
const GENOA = {
  report: new Uint8Array(readFileSync(join(PCA, 'fixtures', 'real-azure-maa', 'sevsnp-hcl-report.bin')).subarray(32, 32 + 1184)),
  vcek: genoaCerts.vcekCert,
  ask: genoaAsk,
  ark: genoaArk,
};
const milanChain = readFileSync(join(PCA, 'testdata', 'sevsnp-real', 'chain.pem'), 'utf8').match(PEM_BLOCK) as [string, string];
const MILAN = {
  report: new Uint8Array(readFileSync(join(PCA, 'testdata', 'sevsnp-real', 'snp_report.bin'))),
  vcek: new Uint8Array(readFileSync(join(PCA, 'testdata', 'sevsnp-real', 'vcek.der'))),
  ask: milanChain[0],
  ark: milanChain[1],
};

const genoaInput = (over: Partial<AmdAttestationInput> = {}): AmdAttestationInput => ({ vcek: GENOA.vcek, ask: GENOA.ask, ark: GENOA.ark, family: 'genoa', nowMs: NOW, ...over });
const milanInput = (over: Partial<AmdAttestationInput> = {}): AmdAttestationInput => ({ vcek: MILAN.vcek, ask: MILAN.ask, ark: MILAN.ark, family: 'milan', nowMs: NOW, ...over });

describe('REAL AMD SEV-SNP silicon through the core-hardened verifier', () => {
  it('the Genoa report is 1184 bytes and the pins are the core per-family AMD KDS values', () => {
    expect(GENOA.report.length).toBe(1184);
    expect(Object.keys(KNOWN_AMD_ARK_SPKI_SHA384).sort()).toEqual(['genoa', 'milan', 'turin']);
    expect(KNOWN_AMD_ARK_SPKI_SHA384.milan).toBe(AMD_MILAN_ARK_SPKI_SHA384);
    for (const fp of Object.values(KNOWN_AMD_ARK_SPKI_SHA384)) expect(fp).toMatch(/^[0-9a-f]{96}$/);
  });

  it('verifies the real GENOA report end to end (the old Milan-only pin could not)', async () => {
    const r = await verifyAmdAttestation(GENOA.report, genoaInput());
    expect(r.reason).toBeUndefined();
    expect(r.ok).toBe(true);
    expect(r.hardwareRoot).toBe(AMD_SEV_SNP_HARDWARE_ROOT_LABEL);
    const parsed = parseSevSnpReport(GENOA.report);
    expect(r.evidence).toEqual(evidenceFromReport(parsed));
    expect(r.measured).toEqual(measuredFromReport(parsed));
  });

  it('verifies the real MILAN report under the milan pin', async () => {
    const r = await verifyAmdAttestation(MILAN.report, milanInput());
    expect(r.reason).toBeUndefined();
    expect(r.ok).toBe(true);
  });

  it('accepts DER and PEM certificate encodings identically', async () => {
    const der = (pem: string): Uint8Array => new Uint8Array(new X509Certificate(pem).raw);
    const r = await verifyAmdAttestation(GENOA.report, genoaInput({ vcek: der(GENOA.vcek), ask: der(GENOA.ask), ark: der(GENOA.ark) }));
    expect(r.reason).toBeUndefined();
    expect(r.ok).toBe(true);
  });

  it('rejects each real chain under every OTHER family pin (wrong family)', async () => {
    for (const family of ['milan', 'turin'] as const) {
      const r = await verifyAmdAttestation(GENOA.report, genoaInput({ family }));
      expect(r.ok).toBe(false);
      expect(r.reason).toBe('cert chain invalid: ARK does not match the pinned AMD trust anchor');
    }
    for (const family of ['genoa', 'turin'] as const) {
      const r = await verifyAmdAttestation(MILAN.report, milanInput({ family }));
      expect(r.ok).toBe(false);
      expect(r.reason).toBe('cert chain invalid: ARK does not match the pinned AMD trust anchor');
    }
  });

  it('requires exactly one ARK pin source and a known family (the root is never inferred)', async () => {
    const neither = await verifyAmdAttestation(GENOA.report, { vcek: GENOA.vcek, ask: GENOA.ask, ark: GENOA.ark, nowMs: NOW });
    expect(neither.reason).toBe('exactly one of family or trustAnchorArkSpkiSha384 must be supplied (the ARK pin is never inferred)');
    const both = await verifyAmdAttestation(GENOA.report, genoaInput({ trustAnchorArkSpkiSha384: KNOWN_AMD_ARK_SPKI_SHA384.genoa }));
    expect(both.reason).toBe('exactly one of family or trustAnchorArkSpkiSha384 must be supplied (the ARK pin is never inferred)');
    const unknown = await verifyAmdAttestation(GENOA.report, genoaInput({ family: 'zen9' as never }));
    expect(unknown.reason).toBe('unknown AMD family zen9 (expected milan | genoa | turin)');
    const proto = await verifyAmdAttestation(GENOA.report, genoaInput({ family: 'constructor' as never }));
    expect(proto.reason).toBe('unknown AMD family constructor (expected milan | genoa | turin)');
  });

  it('an explicit trustAnchorArkSpkiSha384 pin works, and a wrong one is rejected', async () => {
    const ok = await verifyAmdAttestation(GENOA.report, { vcek: GENOA.vcek, ask: GENOA.ask, ark: GENOA.ark, trustAnchorArkSpkiSha384: KNOWN_AMD_ARK_SPKI_SHA384.genoa, nowMs: NOW });
    expect(ok.ok).toBe(true);
    const bad = await verifyAmdAttestation(GENOA.report, { vcek: GENOA.vcek, ask: GENOA.ask, ark: GENOA.ark, trustAnchorArkSpkiSha384: '00'.repeat(48), nowMs: NOW });
    expect(bad.reason).toBe('cert chain invalid: ARK does not match the pinned AMD trust anchor');
  });

  it('the verifier clock is mandatory and enforced to the millisecond (not yet valid / expired)', async () => {
    const vcek = new X509Certificate(GENOA.vcek);
    const from = vcek.validFromDate.getTime();
    const to = vcek.validToDate.getTime();
    expect((await verifyAmdAttestation(GENOA.report, genoaInput({ nowMs: from - 1 }))).reason).toBe('cert chain invalid: VCEK certificate is not yet valid');
    expect((await verifyAmdAttestation(GENOA.report, genoaInput({ nowMs: from }))).ok).toBe(true);
    expect((await verifyAmdAttestation(GENOA.report, genoaInput({ nowMs: to }))).ok).toBe(true);
    expect((await verifyAmdAttestation(GENOA.report, genoaInput({ nowMs: to + 1 }))).reason).toBe('cert chain invalid: VCEK certificate has expired');
    expect((await verifyAmdAttestation(GENOA.report, genoaInput({ nowMs: to + 1000, clockSkewMs: 1000 }))).ok).toBe(true);
    expect((await verifyAmdAttestation(GENOA.report, genoaInput({ nowMs: to + 1001, clockSkewMs: 1000 }))).reason).toBe('cert chain invalid: VCEK certificate has expired');
    const noClock = await verifyAmdAttestation(GENOA.report, { vcek: GENOA.vcek, ask: GENOA.ask, ark: GENOA.ark, family: 'genoa' } as never);
    expect(noClock.reason).toBe('cert chain invalid: nowMs (verifier clock) is required for the AMD chain validity check');
  });

  it('rejects an ASK/ARK handed in the wrong order', async () => {
    const r = await verifyAmdAttestation(GENOA.report, genoaInput({ ask: GENOA.ark, ark: GENOA.ask }));
    expect(r.reason).toBe('cert chain invalid: second certificate of the chain is not a self-signed ARK (chain out of order?)');
  });

  it('rejects the ARK supplied twice (no ASK)', async () => {
    const r = await verifyAmdAttestation(GENOA.report, genoaInput({ ask: GENOA.ark }));
    expect(r.reason).toBe('cert chain invalid: first certificate of the chain is self-signed, not an ASK (chain out of order?)');
  });

  it('rejects a PEM input that is not exactly one certificate', async () => {
    const two = await verifyAmdAttestation(GENOA.report, genoaInput({ ask: GENOA.ask + GENOA.ark }));
    expect(two.reason).toBe('certificate parse failed: expected exactly one PEM certificate, found 2');
    const none = await verifyAmdAttestation(GENOA.report, genoaInput({ vcek: 'not a certificate' }));
    expect(none.reason).toBe('certificate parse failed: expected exactly one PEM certificate, found 0');
  });

  it('fails closed if the real report body is tampered (signature)', async () => {
    const bad = Uint8Array.from(GENOA.report);
    bad[128] = (bad[128] ?? 0) ^ 0xff;
    const r = await verifyAmdAttestation(bad, genoaInput());
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('report signature does not verify under VCEK');
  });

  it('fails closed on a report too short to parse', async () => {
    const r = await verifyAmdAttestation(new Uint8Array(16), genoaInput());
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/^report parse failed/);
  });

  it('a Genoa report presented with the MILAN chain is rejected (chain valid, but the report was not signed by that VCEK)', async () => {
    const r = await verifyAmdAttestation(GENOA.report, { ...milanInput(), nowMs: NOW });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('report signature does not verify under VCEK');
  });

  it('gates the launch measurement against the real report', async () => {
    const m = toHex(parseSevSnpReport(GENOA.report).measurement);
    expect((await verifyAmdAttestation(GENOA.report, genoaInput({ expectedMeasurement: m.toUpperCase() }))).ok).toBe(true);
    const wrong = await verifyAmdAttestation(GENOA.report, genoaInput({ expectedMeasurement: 'f'.repeat(96) }));
    expect(wrong.reason).toBe('measurement not in policy allowlist');
  });

  it('wiring: a real Genoa attestation lifts a fresh, channel-bound EAT to affirming-hw-rooted', async () => {
    const parsed = parseSevSnpReport(GENOA.report);
    const evidence = evidenceFromReport(parsed);
    const measured = measuredFromReport(parsed);
    const { publicKey, privateKey } = generateEatKeyPair();
    const now = NOW;
    const nonce = issueNonce({ now }).value;
    const iss = 'https://attester.atlasauth.net';
    const channelId = 'tls-exporter-real-genoa';
    const eat = buildEAT({ issuer: iss, nonce, channelId, measured, sevsnp: evidence, oemid: 'oem-amd', dbgstat: 'disabled', key: privateKey, now });
    const policy = { endorsements: { issuers: [iss], oemids: ['oem-amd'], operators: [measured.operator] }, referenceValues: { measurements: [measured.runtime_measurement], requireDebugDisabled: true } };
    const common = { nonce, channelId, policy, verifyKey: publicKey as KeyObject, now, issuer: iss };
    const soft = await verifyFreshAttestedEAT(eat, common);
    expect(soft.tier).toBe('affirming');
    const hard = await verifyFreshAttestedEAT(eat, { ...common, amd: { rawReport: GENOA.report, vcek: GENOA.vcek, ask: GENOA.ask, ark: GENOA.ark, family: 'genoa' } });
    expect(hard.reasons.join(' | ')).toMatch(/hardware root verified/);
    expect(hard.ok).toBe(true);
    expect(hard.tier).toBe('affirming-hw-rooted');
    // wrong family -> the whole verdict fails closed with the chain reason
    const wrongFam = await verifyFreshAttestedEAT(eat, { ...common, amd: { rawReport: GENOA.report, vcek: GENOA.vcek, ask: GENOA.ask, ark: GENOA.ark, family: 'milan' } });
    expect(wrongFam.ok).toBe(false);
    expect(wrongFam.tier).toBe('contraindicated');
    expect(wrongFam.reasons.join(' | ')).toContain('AMD hardware root verification failed: cert chain invalid: ARK does not match the pinned AMD trust anchor');
    // the verifier clock used for the chain is the call's `now`: past VCEK expiry it fails closed
    const late = await verifyFreshAttestedEAT(eat, { ...common, now: new X509Certificate(GENOA.vcek).validToDate.getTime() + 1, maxAgeMs: 10 * 365 * 24 * 3600 * 1000, amd: { rawReport: GENOA.report, vcek: GENOA.vcek, ask: GENOA.ask, ark: GENOA.ark, family: 'genoa' } });
    expect(late.ok).toBe(false);
    expect(late.reasons.join(' | ')).toContain('cert chain invalid: VCEK certificate has expired');
  });
});
