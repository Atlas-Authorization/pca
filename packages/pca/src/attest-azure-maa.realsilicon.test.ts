/**
 * REAL-SILICON test for the Azure MAA root.
 *
 * Evidence: genuine Microsoft Azure Attestation tokens (RS256, instance sharedwus.wus.attest.azure.net) issued
 * over GENUINE Intel TDX quotes captured from Azure DC4es_v6 confidential VMs on 2026-10-08.
 *   - `pcabound-tdxvm-token.jwt` — the PCA challenge was written into the guest's runtime `user-data` (vTPM NV
 *     0x01400002) BEFORE the quote was taken; the runtime data was then submitted to MAA, which validated
 *     sha256(runtimeData) == quote report_data[0:32] and emitted `x-ms-runtime` (incl. the PCA binding).
 *   - `tdxvm-token.jwt` — a token over a different boot's quote with Azure's default report_data (no PCA binding):
 *     the negative control.
 * Trust anchor: the MAA instance signing cert, pinned by SPKI. See fixtures/real-azure-maa/README.md.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { describe, it, expect } from 'vitest';
import { createAzureMaaVerifier, parseMaaJwt, type MaaJwks } from './attest-azure-maa';
import { parseDcapQuote, parseDcapTdReport } from './attest-intel-tdx';
import type { AttestationDocument, ExpectedAttestationBinding } from './attestation';

const FIX = (f: string) => resolve(__dirname, '..', 'fixtures', 'real-azure-maa', f);
const BOUND = readFileSync(FIX('pcabound-tdxvm-token.jwt'), 'utf8').trim();
const UNBOUND = readFileSync(FIX('tdxvm-token.jwt'), 'utf8').trim();
const JWKS = JSON.parse(readFileSync(FIX('maa-signing-certs.json'), 'utf8')) as MaaJwks;
const RUNTIME = new Uint8Array(readFileSync(FIX('pcabound-runtime-data.json')));
const QUOTE = new Uint8Array(readFileSync(FIX('pcabound-tdx-dcap-quote.bin')));

const ISSUER = 'https://sharedwus.wus.attest.azure.net';
/** SPKI SHA-256 of the MAA instance signing certificate (kid XxRc2vLh…), pinned. */
const SIGNER_SPKI = 'fe4fa28d5b2e89f088d484f260363a12bcab53d9a9e0d6725507336fc8b6a71e';
const EXPECTED: ExpectedAttestationBinding = {
  holderPub: 'pca-realsilicon-azure-tdx-holder',
  grantRef: 'grant_pca_azure_maa_realsilicon',
  epoch: 1,
  nonce: 'srv-nonce-maa-5d3b8e1f9a27c604',
};
const bound = parseMaaJwt(BOUND).payload as Record<string, unknown>;
const MRTD = String(bound['tdx_mrtd']);
const NOW_MS = ((bound['iat'] as number) + 3600) * 1000;

const DOC = {} as unknown as AttestationDocument;
const CTX = {} as never;

function verifier(token: string, over: { mrtds?: string[]; spki?: string[]; runtimeBinding?: boolean; allowDebug?: boolean; tcb?: string[] } = {}) {
  return createAzureMaaVerifier({
    trustedIssuers: [ISSUER],
    trustAnchors: { rootSpkiSha256: over.spki ?? [SIGNER_SPKI] },
    policy: {
      tdxMrtds: over.mrtds ?? [MRTD],
      runtimeUserDataBinding: over.runtimeBinding ?? true,
      ...(over.tcb ? { tdxAllowedTcbStatuses: over.tcb } : {}),
    },
    resolveEvidence: () => ({ token, jwks: JWKS }),
  });
}
const run = (v: ReturnType<typeof verifier>, expected = EXPECTED, nowMs = NOW_MS) =>
  v.verify({ document: DOC, ctx: CTX, nowMs, expected });

describe('Azure MAA — REAL Azure Intel TDX silicon', () => {
  it('the MAA claims are exactly the raw quote contents (token <-> DCAP quote consistency)', () => {
    const td = parseDcapTdReport(parseDcapQuote(QUOTE).tdReportBody);
    expect(Buffer.from(td.mrTd).toString('hex')).toBe(MRTD);
    expect(Buffer.from(td.reportData).toString('hex')).toBe(String(bound['tdx_report_data']));
    // Azure sets report_data[0:32] = sha256(runtime data JSON); the guest's user-data lives inside that JSON.
    expect(createHash('sha256').update(RUNTIME).digest('hex')).toBe(Buffer.from(td.reportData.slice(0, 32)).toString('hex'));
    expect(JSON.parse(Buffer.from(RUNTIME).toString('utf8'))['user-data']).toBe((bound['x-ms-runtime'] as Record<string, unknown>)['user-data']);
  });

  it('verifies end-to-end with the PCA challenge bound through runtime user-data', async () => {
    const r = await run(verifier(BOUND));
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.bound).toBe(true);
      expect(r.measured?.runtime_measurement).toBe(MRTD);
      expect(r.hostAsserted?.attestation_type).toBe('tdxvm');
      expect(r.hostAsserted?.tcb_status).toBe('UpToDate');
    }
  });

  it('fails closed: relayed binding (different holder / grant / epoch / nonce)', async () => {
    for (const bad of [
      { ...EXPECTED, holderPub: 'someone-else' },
      { ...EXPECTED, grantRef: 'grant_other' },
      { ...EXPECTED, epoch: 2 },
      { ...EXPECTED, nonce: 'srv-nonce-other' },
    ]) {
      const r = await run(verifier(BOUND), bad);
      expect(r.ok).toBe(false);
    }
  });

  it('fails closed: tampered signature, tampered payload', async () => {
    const [h, p, s] = BOUND.split('.');
    const sig = Buffer.from(s!, 'base64url');
    sig[0] = (sig[0] ?? 0) ^ 0x01;
    expect((await run(verifier(`${h}.${p}.${sig.toString('base64url')}`))).ok).toBe(false);
    const payload = JSON.parse(Buffer.from(p!, 'base64url').toString('utf8')) as Record<string, unknown>;
    payload['attester_tcb_status'] = 'UpToDate';
    payload['tdx_mrtd'] = '00'.repeat(48);
    expect((await run(verifier(`${h}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${s}`))).ok).toBe(false);
  });

  it('fails closed: a token without runtime data cannot satisfy runtime user-data binding', async () => {
    const r = await run(verifier(UNBOUND, { mrtds: [String(parseMaaJwt(UNBOUND).payload['tdx_mrtd'])] }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain('x-ms-runtime');
  });

  it('fails closed: direct report_data binding does not hold on Azure TDX (report_data is a runtime-data hash)', async () => {
    const r = await run(verifier(BOUND, { runtimeBinding: false }));
    expect(r.ok).toBe(false);
  });

  it('fails closed: MRTD not allowlisted / untrusted signer pin / untrusted issuer / outside validity', async () => {
    expect((await run(verifier(BOUND, { mrtds: ['00'.repeat(48)] }))).ok).toBe(false);
    expect((await run(verifier(BOUND, { spki: ['00'.repeat(32)] }))).ok).toBe(false);
    const wrongIssuer = createAzureMaaVerifier({
      trustedIssuers: ['https://evil.example'],
      trustAnchors: { rootSpkiSha256: [SIGNER_SPKI] },
      policy: { tdxMrtds: [MRTD], runtimeUserDataBinding: true },
      resolveEvidence: () => ({ token: BOUND, jwks: JWKS }),
    });
    expect((await run(wrongIssuer)).ok).toBe(false);
    expect((await run(verifier(BOUND), EXPECTED, ((bound['exp'] as number) + 10) * 1000)).ok).toBe(false);
    expect((await run(verifier(BOUND), EXPECTED, ((bound['iat'] as number) - 100) * 1000)).ok).toBe(false);
  });

  it('fails closed: a TCB status the policy does not accept', async () => {
    const r = await run(verifier(BOUND, { tcb: ['OutOfDate'] }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain('TCB status');
  });
});

// ── AMD SEV-SNP (DC2as_v5, Genoa) — the other isolation technology Azure attests ──
describe('Azure MAA — REAL Azure AMD SEV-SNP silicon (Genoa)', () => {
  const SNP_TOKEN = readFileSync(FIX('sevsnp-token.jwt'), 'utf8').trim();
  const JWKS_EUS = JSON.parse(readFileSync(FIX('maa-signing-certs-eus.json'), 'utf8')) as MaaJwks;
  const SNP_ISSUER = 'https://sharedeus.eus.attest.azure.net';
  /** SPKI SHA-256 of the sharedeus instance signing certificate (kid rFl9xM+g…), pinned. */
  const SNP_SIGNER_SPKI = '97cda3af47e762fb8673d1664066082ad7a9e82120eb9523da1a39f6a84de3cc';
  const claims = parseMaaJwt(SNP_TOKEN).payload as Record<string, unknown>;
  const MEAS = String(claims['x-ms-sevsnpvm-launchmeasurement']);
  const SNP_NOW = ((claims['iat'] as number) + 3600) * 1000;
  const snpVerifier = (over: { token?: string; meas?: string[]; spki?: string[]; runtime?: boolean; allowDebug?: boolean } = {}) =>
    createAzureMaaVerifier({
      trustedIssuers: [SNP_ISSUER],
      trustAnchors: { rootSpkiSha256: over.spki ?? [SNP_SIGNER_SPKI] },
      policy: { sevSnpMeasurements: over.meas ?? [MEAS], runtimeUserDataBinding: over.runtime ?? true, ...(over.allowDebug ? { allowDebug: true } : {}) },
      resolveEvidence: () => ({ token: over.token ?? SNP_TOKEN, jwks: JWKS_EUS }),
    });
  const runSnp = (v: ReturnType<typeof snpVerifier>, expected = EXPECTED, nowMs = SNP_NOW) => v.verify({ document: DOC, ctx: CTX, nowMs, expected });

  it('the token claims match the raw HCL/SNP report (token <-> report consistency, chip family Genoa)', () => {
    const hcl = new Uint8Array(readFileSync(FIX('sevsnp-hcl-report.bin')));
    const runtime = new Uint8Array(readFileSync(FIX('sevsnp-runtime-data.json')));
    const snp = hcl.subarray(32, 32 + 1184);
    const reportData = Buffer.from(snp.subarray(0x50, 0x90)).toString('hex');
    expect(reportData).toBe(String(claims['x-ms-sevsnpvm-reportdata']));
    expect(createHash('sha256').update(runtime).digest('hex')).toBe(reportData.slice(0, 64));
    expect(reportData.slice(64)).toBe('0'.repeat(64));
    expect(JSON.parse(Buffer.from(runtime).toString('utf8'))['user-data']).toBe((claims['x-ms-runtime'] as Record<string, unknown>)['user-data']);
    expect(claims['x-ms-sevsnpvm-chip-family']).toBe('Genoa');
  });

  it('verifies end to end with the PCA challenge bound through runtime user-data', async () => {
    const r = await runSnp(snpVerifier());
    expect(r.reason).toBeUndefined();
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.bound).toBe(true);
      expect(r.measured?.runtime_measurement).toBe(MEAS);
      expect(r.hostAsserted?.attestation_type).toBe('sevsnpvm');
    }
  });

  it('fails closed: relayed binding, tampered signature, wrong measurement, wrong pin, outside validity, direct report_data binding', async () => {
    expect((await runSnp(snpVerifier(), { ...EXPECTED, nonce: 'other' })).ok).toBe(false);
    const [h, p, s] = SNP_TOKEN.split('.');
    const sig = Buffer.from(s!, 'base64url');
    sig[0] = (sig[0] ?? 0) ^ 0x01;
    expect((await runSnp(snpVerifier({ token: `${h}.${p}.${sig.toString('base64url')}` }))).ok).toBe(false);
    expect((await runSnp(snpVerifier({ meas: ['00'.repeat(48)] }))).ok).toBe(false);
    expect((await runSnp(snpVerifier({ spki: ['00'.repeat(32)] }))).ok).toBe(false);
    expect((await runSnp(snpVerifier(), EXPECTED, ((claims['exp'] as number) + 10) * 1000)).ok).toBe(false);
    expect((await runSnp(snpVerifier({ runtime: false }))).ok).toBe(false); // report_data is a runtime-data hash on Azure
  });

  it('sevSnpMinTcb against the REAL token (bootloader 10, snpfw 27, microcode 88, tee 0): at-floor passes, one above fails', async () => {
    const mk = (min: { bootloader?: number; snp?: number; microcode?: number; tee?: number }) =>
      createAzureMaaVerifier({
        trustedIssuers: [SNP_ISSUER],
        trustAnchors: { rootSpkiSha256: [SNP_SIGNER_SPKI] },
        policy: { sevSnpMeasurements: [MEAS], runtimeUserDataBinding: true, sevSnpMinTcb: min },
        resolveEvidence: () => ({ token: SNP_TOKEN, jwks: JWKS_EUS }),
      });
    const ok = await runSnp(mk({ bootloader: 10, snp: 27, microcode: 88, tee: 0 }));
    expect(ok.ok).toBe(true);
    if (ok.ok) expect(ok.hostAsserted).toMatchObject({ bootloader_svn: '10', snpfw_svn: '27', microcode_svn: '88', tee_svn: '0' });
    expect((await runSnp(mk({ bootloader: 11 }))).reason).toBe('SEV-SNP bootloader SVN 10 is below the policy minimum 11');
    expect((await runSnp(mk({ snp: 28 }))).reason).toBe('SEV-SNP snp SVN 27 is below the policy minimum 28');
    expect((await runSnp(mk({ microcode: 89 }))).reason).toBe('SEV-SNP microcode SVN 88 is below the policy minimum 89');
    expect((await runSnp(mk({ tee: 1 }))).reason).toBe('SEV-SNP tee SVN 0 is below the policy minimum 1');
  });

  it('a TDX token cannot satisfy an SEV-SNP policy and vice versa (isolation type is enforced)', async () => {
    const cross = createAzureMaaVerifier({
      trustedIssuers: ['https://sharedwus.wus.attest.azure.net'],
      trustAnchors: { rootSpkiSha256: [SIGNER_SPKI] },
      policy: { sevSnpMeasurements: [MEAS], runtimeUserDataBinding: true }, // SNP-only policy
      resolveEvidence: () => ({ token: BOUND, jwks: JWKS }),
    });
    expect((await run(cross)).ok).toBe(false);
  });
});
