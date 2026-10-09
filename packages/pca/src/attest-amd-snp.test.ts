/**
 * Tests for the AMD SEV-SNP `HardwareAttestationVerifier` on a GENUINE Genoa report (Azure DC2as_v5, italynorth,
 * 2026-10-08): the 1184-byte SNP report from the HCL, the VCEK + ASK/ARK chain served by Azure's metadata service,
 * and the runtime-data JSON carrying the PCA binding. The PCA binding is checked directly against AMD's signature.
 * The same boot was also attested by Azure MAA (fixtures/real-azure-maa/sevsnp-token.jwt) — see the 2-of-2 test.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it, expect } from 'vitest';
import { createAmdSnpVerifier, pemToDer, AMD_ARK_SPKI_SHA384, type AmdSnpEvidence } from './attest-amd-snp';
import { createAzureMaaVerifier, parseMaaJwt, type MaaJwks } from './attest-azure-maa';
import { createMultiRootVerifier } from './attestation';
import { parseSevSnpReport, toHex } from './hardware-sevsnp';
import type { AttestationDocument, ExpectedAttestationBinding } from './attestation';

const fx = (f: string) => readFileSync(resolve(__dirname, '..', 'fixtures', 'real-azure-maa', f));
const HCL = new Uint8Array(fx('sevsnp-hcl-report.bin'));
const REPORT = HCL.slice(32, 32 + 1184);
const RUNTIME = new Uint8Array(fx('sevsnp-runtime-data.json'));
const AMD = JSON.parse(fx('sevsnp-amd-certs.json').toString('utf8')) as { vcekCert: string; certificateChain: string };
const EVIDENCE: AmdSnpEvidence = { report: REPORT, vcekDer: pemToDer(AMD.vcekCert), askArkPem: AMD.certificateChain, runtimeData: RUNTIME };
const MEAS = toHex(parseSevSnpReport(REPORT).measurement);

const EXPECTED: ExpectedAttestationBinding = {
  holderPub: 'pca-realsilicon-azure-tdx-holder',
  grantRef: 'grant_pca_azure_maa_realsilicon',
  epoch: 1,
  nonce: 'srv-nonce-maa-5d3b8e1f9a27c604',
};
const DOC = {} as unknown as AttestationDocument;
const CTX = {} as never;
const NOW_MS = Date.parse('2026-10-09T00:30:00Z');

function verifier(over: { ev?: Partial<AmdSnpEvidence>; family?: 'milan' | 'genoa' | 'turin'; meas?: string[]; binding?: 'report-data' | 'azure-runtime-data'; policy?: Record<string, unknown> } = {}) {
  return createAmdSnpVerifier({
    family: over.family ?? 'genoa',
    binding: over.binding ?? 'azure-runtime-data',
    policy: { measurements: over.meas ?? [MEAS], ...over.policy },
    resolveEvidence: () => ({ ...EVIDENCE, ...over.ev }),
  });
}
const run = (v: ReturnType<typeof verifier>, expected = EXPECTED) => v.verify({ document: DOC, ctx: CTX, nowMs: NOW_MS, expected });

describe('AMD SEV-SNP root — REAL Azure Genoa report', () => {
  it('verifies end to end: VCEK→ASK→ARK(Genoa) + P-384 report signature + runtime-data PCA binding', async () => {
    const r = await run(verifier());
    expect(r.reason).toBeUndefined();
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.bound).toBe(true);
      expect(r.hostAsserted?.family).toBe('genoa');
      expect(r.hostAsserted?.measurement).toBe(MEAS);
    }
  });

  it('the family pin matters: this Genoa chain is rejected under the Milan or Turin roots', async () => {
    for (const family of ['milan', 'turin'] as const) {
      const r = await run(verifier({ family }));
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toContain('cert chain invalid');
    }
    expect(AMD_ARK_SPKI_SHA384.genoa).not.toBe(AMD_ARK_SPKI_SHA384.milan);
  });

  it('fails closed: relayed binding (any field)', async () => {
    for (const bad of [{ ...EXPECTED, holderPub: 'x' }, { ...EXPECTED, grantRef: 'g' }, { ...EXPECTED, epoch: 2 }, { ...EXPECTED, nonce: 'n' }]) {
      const r = await run(verifier(), bad);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toContain('does not bind');
    }
  });

  it('fails closed: tampered report, tampered runtime data, missing runtime data, direct binding (Azure report_data is a hash)', async () => {
    const t = new Uint8Array(REPORT);
    t[0x90 + 4] = (t[0x90 + 4] ?? 0) ^ 0x01; // inside the signed region (measurement)
    expect((await run(verifier({ ev: { report: t } }))).ok).toBe(false);
    const rt = new Uint8Array(RUNTIME);
    rt[RUNTIME.length - 3] = (rt[RUNTIME.length - 3] ?? 0) ^ 0x01;
    const a = await run(verifier({ ev: { runtimeData: rt } }));
    expect(a.ok).toBe(false);
    if (!a.ok) expect(a.reason).toContain('sha256(runtime data)');
    expect((await run(verifier({ ev: { runtimeData: undefined } }))).ok).toBe(false);
    expect((await run(verifier({ binding: 'report-data' }))).ok).toBe(false);
  });

  it('fails closed: wrong measurement allowlist, tampered VCEK, wrong chain, no evidence', async () => {
    expect((await run(verifier({ meas: ['00'.repeat(48)] }))).ok).toBe(false);
    const v = new Uint8Array(EVIDENCE.vcekDer);
    v[v.length - 10] = (v[v.length - 10] ?? 0) ^ 0x01;
    expect((await run(verifier({ ev: { vcekDer: v } }))).ok).toBe(false);
    expect((await run(verifier({ ev: { askArkPem: '' } }))).ok).toBe(false);
    const none = createAmdSnpVerifier({ family: 'genoa', binding: 'azure-runtime-data', policy: { measurements: [MEAS] } });
    expect((await run(none)).ok).toBe(false);
  });

  it('refuses accept-all / unknown family / unknown binding at construction', () => {
    expect(() => createAmdSnpVerifier({ family: 'genoa', binding: 'azure-runtime-data', policy: { measurements: [] } })).toThrow();
    expect(() => createAmdSnpVerifier({ family: 'zen9' as never, binding: 'azure-runtime-data', policy: { measurements: [MEAS] } })).toThrow();
    expect(() => createAmdSnpVerifier({ family: 'genoa', binding: 'nope' as never, policy: { measurements: [MEAS] } })).toThrow();
  });
});

describe('REAL 2-of-2: AMD-signed report + Microsoft-signed token over the same Azure SEV-SNP boot', () => {
  const TOKEN = fx('sevsnp-token.jwt').toString('utf8').trim();
  const JWKS = JSON.parse(fx('maa-signing-certs-eus.json').toString('utf8')) as MaaJwks;
  const claims = parseMaaJwt(TOKEN).payload as Record<string, unknown>;
  const MAA_NOW = ((claims['iat'] as number) + 3600) * 1000;
  const policy = (over: { report?: Uint8Array; token?: string } = {}) =>
    createMultiRootVerifier({
      threshold: 2,
      roots: [
        { id: 'amd-snp', suite: 'ecdsa-p384', verifier: createAmdSnpVerifier({ family: 'genoa', binding: 'azure-runtime-data', policy: { measurements: [MEAS] }, resolveEvidence: () => ({ ...EVIDENCE, report: over.report ?? REPORT }) }) },
        { id: 'azure-maa', suite: 'rs256', verifier: createAzureMaaVerifier({
          trustedIssuers: ['https://sharedeus.eus.attest.azure.net'],
          trustAnchors: { rootSpkiSha256: ['97cda3af47e762fb8673d1664066082ad7a9e82120eb9523da1a39f6a84de3cc'] },
          policy: { sevSnpMeasurements: [MEAS], runtimeUserDataBinding: true },
          resolveEvidence: () => ({ token: over.token ?? TOKEN, jwks: JWKS }),
        }) },
      ],
    });
  const go = (v: ReturnType<typeof policy>) => v.verify({ document: DOC, ctx: CTX, nowMs: MAA_NOW, expected: EXPECTED });

  it("AMD's launch measurement equals the one Microsoft attests (independent roots agree)", () => {
    expect(MEAS).toBe(String(claims['x-ms-sevsnpvm-launchmeasurement']));
  });

  it('both independent roots corroborate and reconcile to one identity', async () => {
    const r = await go(policy());
    expect(r.reason).toBeUndefined();
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.measured?.runtime_measurement).toBe(MEAS);
  });

  it('breaking either root drops below threshold', async () => {
    const t = new Uint8Array(REPORT);
    t[0x90 + 4] = (t[0x90 + 4] ?? 0) ^ 0x01;
    const a = await go(policy({ report: t }));
    expect(a.ok).toBe(false);
    if (!a.ok) expect(a.reason).toContain('below threshold (1/2');
    const [h, p, s] = TOKEN.split('.');
    const sig = Buffer.from(s!, 'base64url');
    sig[0] = (sig[0] ?? 0) ^ 0x01;
    const b = await go(policy({ token: `${h}.${p}.${sig.toString('base64url')}` }));
    expect(b.ok).toBe(false);
    if (!b.ok) expect(b.reason).toContain('below threshold (1/2');
  });
});
