import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { verifySevSnpSignature, verifyAmdCertChain, verifyAmdAttestation } from './index';

// Genuine AMD SEV-SNP output captured from a real Azure Confidential VM (AMD Milan, Standard_DC4as_v5):
//   report.bin — a real v3 attestation report read from the vTPM HCL blob (NV index 0x01400001)
//   vcek/ask/ark.pem — the real AMD KDS cert chain for THIS chip's reported TCB
// This proves the verifier works on actual silicon, not only the synthetic in-test chain.
const fx = (n: string): string => join(__dirname, '..', 'fixtures', 'real-sevsnp', n);
const report = readFileSync(fx('report.bin'));
const vcek = readFileSync(fx('vcek.pem'), 'utf8');
const ask = readFileSync(fx('ask.pem'), 'utf8');
const ark = readFileSync(fx('ark.pem'), 'utf8');

describe('REAL AMD SEV-SNP silicon (Azure Confidential VM, Milan)', () => {
  it('the report body is the expected 1184 bytes', () => {
    expect(report.length).toBe(1184);
  });

  it('verifies the genuine report signature under the KDS VCEK', () => {
    const r = verifySevSnpSignature(report, vcek);
    expect(r).toMatchObject({ ok: true });
  });

  it('verifies the real VCEK -> ASK -> ARK chain against the pinned Milan root', () => {
    const r = verifyAmdCertChain(vcek, ask, ark, {});
    expect(r).toMatchObject({ ok: true });
  });

  it('verifies end-to-end attestation on real hardware output (default Milan pin)', () => {
    const r = verifyAmdAttestation(report, { vcek, ask, ark });
    expect(r).toMatchObject({ ok: true });
  });

  it('fails closed if the real report body is tampered', () => {
    const bad = Uint8Array.from(report);
    bad[128] = (bad[128] ?? 0) ^ 0xff;
    expect(verifySevSnpSignature(bad, vcek).ok).toBe(false);
  });
});
